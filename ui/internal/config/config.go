// Package config holds the declarative appliance configuration: a single
// versioned JSON document that is the source of truth. The engine renders it
// into pf.conf, Unbound, Kea, and WireGuard configs (renderers TODO), applies
// atomically, and supports rollback (plan.md §7).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type Config struct {
	Version    int         `json:"version"`
	System     System      `json:"system"`
	Interfaces []Interface `json:"interfaces"`
	NAT        NAT         `json:"nat"`
	DHCP       DHCP        `json:"dhcp"`
	DNS        DNS         `json:"dns"`
	WireGuard  WireGuard   `json:"wireguard"`
	Shell      Shell       `json:"shell"`
	Users      []User      `json:"users"`
}

// Shell configures the web terminal (docs/shell.md). It is dark by default:
// with Enabled false there is no /shell route, no nav entry, and no listener,
// so a fresh appliance ships with no web-shell attack surface. SSH remains the
// recommended admin path.
type Shell struct {
	Enabled     bool   `json:"enabled"`      // master switch; false => feature off
	Shell       string `json:"shell"`        // login shell; "" => /bin/sh
	User        string `json:"user"`         // target unix user; "" => current/root
	IdleTimeout int    `json:"idle_timeout"` // seconds of no I/O before kill; 0 => 15m
	MaxSessions int    `json:"max_sessions"` // concurrent ttys; 0 => 1
}

// IdleSeconds returns the effective idle timeout, applying the 15-minute
// default when unset.
func (s Shell) IdleSeconds() int {
	if s.IdleTimeout <= 0 {
		return 15 * 60
	}
	return s.IdleTimeout
}

// Sessions returns the effective concurrency cap (default 1).
func (s Shell) Sessions() int {
	if s.MaxSessions <= 0 {
		return 1
	}
	return s.MaxSessions
}

// Command returns the shell binary to exec, defaulting to /bin/sh.
func (s Shell) Command() string {
	if s.Shell == "" {
		return "/bin/sh"
	}
	return s.Shell
}

// User is a WebUI login. The hash is an argon2id PHC string (see the auth
// package). Users live in the config document so the single-file backup
// carries them (plan.md §7). An empty list means first-run setup is pending.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	// TOTPSecret is the base32 RFC 6238 secret; empty = 2FA not enrolled.
	TOTPSecret string `json:"totp_secret,omitempty"`
}

type System struct {
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	Timezone string `json:"timezone"`
}

// Interface maps a logical role (wan, lan, opt) to a physical device.
type Interface struct {
	Name       string `json:"name"`
	Role       string `json:"role"` // wan | lan | opt
	Device     string `json:"device"`
	IPv4       string `json:"ipv4,omitempty"` // CIDR; empty when DHCPClient
	DHCPClient bool   `json:"dhcp_client,omitempty"`
}

type NAT struct {
	OutboundMode string        `json:"outbound_mode"` // automatic | manual
	PortForwards []PortForward `json:"port_forwards"`
}

type PortForward struct {
	ID       string `json:"id"` // stable handle for edit/delete; survives reordering
	Name     string `json:"name"`
	Proto    string `json:"proto"` // tcp | udp | tcp/udp
	WANPort  int    `json:"wan_port"`
	DestIP   string `json:"dest_ip"`
	DestPort int    `json:"dest_port"`
	Enabled  bool   `json:"enabled"`
}

type DHCP struct {
	Enabled      bool          `json:"enabled"`
	RangeStart   string        `json:"range_start"`
	RangeEnd     string        `json:"range_end"`
	LeaseSeconds int           `json:"lease_seconds"`
	StaticLeases []StaticLease `json:"static_leases"`
}

type StaticLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

type DNS struct {
	Enabled   bool           `json:"enabled"`
	Adblock   Adblock        `json:"adblock"`
	Overrides []HostOverride `json:"overrides"`
}

type Adblock struct {
	Enabled bool     `json:"enabled"`
	Lists   []string `json:"lists"` // blocklist URLs, compiled to unbound local-zone data
}

type HostOverride struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
}

type WireGuard struct {
	Enabled bool       `json:"enabled"`
	Tunnels []WGTunnel `json:"tunnels"`
}

type WGTunnel struct {
	Name       string `json:"name"`
	Address    string `json:"address"` // CIDR
	ListenPort int    `json:"listen_port"`
	PrivateKey string `json:"private_key"` // base64; generated via NewWGKeypair
	// EndpointHost is the public host[:port] mobile clients dial; it goes
	// into generated peer configs. Port defaults to ListenPort.
	EndpointHost string   `json:"endpoint_host,omitempty"`
	Peers        []WGPeer `json:"peers"`
}

type WGPeer struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"` // comma-separated CIDRs
	Endpoint   string `json:"endpoint,omitempty"`
	Keepalive  int    `json:"keepalive,omitempty"` // seconds; for peers behind NAT
	// PrivateKey is kept only when the appliance generated the peer's
	// keypair, so the client config/QR stays downloadable. Empty when the
	// user supplied their own public key.
	PrivateKey string `json:"private_key,omitempty"`
}

// Default returns the out-of-box configuration: LAN on 192.168.1.1/24 with
// DHCP, WAN as DHCP client, DNS with adblock off.
func Default() Config {
	return Config{
		Version: 1,
		System:  System{Hostname: "firewall", Domain: "lan", Timezone: "UTC"},
		Interfaces: []Interface{
			{Name: "WAN", Role: "wan", Device: "igc0", DHCPClient: true},
			{Name: "LAN", Role: "lan", Device: "igc1", IPv4: "192.168.1.1/24"},
			{Name: "OPT1", Role: "opt", Device: "igc2"},
		},
		NAT: NAT{OutboundMode: "automatic"},
		DHCP: DHCP{
			Enabled:      true,
			RangeStart:   "192.168.1.100",
			RangeEnd:     "192.168.1.199",
			LeaseSeconds: 7200,
		},
		DNS: DNS{Enabled: true},
	}
}

func (c *Config) Validate() error {
	if c.System.Hostname == "" {
		return errors.New("system: hostname is required")
	}
	roles := map[string]int{}
	for _, ifc := range c.Interfaces {
		switch ifc.Role {
		case "wan", "lan", "opt":
			roles[ifc.Role]++
		default:
			return fmt.Errorf("interface %s: unknown role %q", ifc.Name, ifc.Role)
		}
	}
	if roles["wan"] != 1 || roles["lan"] != 1 {
		return errors.New("exactly one wan and one lan interface required")
	}
	if err := c.validateInterfaces(); err != nil {
		return err
	}
	if err := c.NAT.validate(); err != nil {
		return err
	}
	if err := c.validateDHCP(); err != nil {
		return err
	}
	if err := c.DNS.validate(); err != nil {
		return err
	}
	if err := c.WireGuard.validate(); err != nil {
		return err
	}
	if err := c.validateUsers(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateInterfaces() error {
	devices := map[string]bool{}
	for _, ifc := range c.Interfaces {
		where := fmt.Sprintf("interface %s", ifc.Name)
		if ifc.Device == "" {
			return fmt.Errorf("%s: device is required", where)
		}
		if devices[ifc.Device] {
			return fmt.Errorf("%s: device %s already assigned", where, ifc.Device)
		}
		devices[ifc.Device] = true
		if ifc.DHCPClient && ifc.IPv4 != "" {
			return fmt.Errorf("%s: dhcp client and static address are exclusive", where)
		}
		if ifc.IPv4 != "" {
			if _, _, err := net.ParseCIDR(ifc.IPv4); err != nil {
				return fmt.Errorf("%s: address must be CIDR (e.g. 192.168.1.1/24): %w", where, err)
			}
		}
		if ifc.Role == "lan" && ifc.IPv4 == "" {
			return fmt.Errorf("%s: lan needs a static address", where)
		}
		if ifc.Role == "wan" && !ifc.DHCPClient && ifc.IPv4 == "" {
			return fmt.Errorf("%s: wan needs dhcp or a static address", where)
		}
	}
	return nil
}

func (d *DNS) validate() error {
	urls := map[string]bool{}
	for _, u := range d.Adblock.Lists {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("dns: blocklist %q: must be an http(s) url", u)
		}
		if urls[u] {
			return fmt.Errorf("dns: blocklist %q: duplicate", u)
		}
		urls[u] = true
	}
	hosts := map[string]bool{}
	for _, o := range d.Overrides {
		if o.Host == "" || strings.ContainsAny(o.Host, " \t") {
			return fmt.Errorf("dns: override %q: invalid hostname", o.Host)
		}
		if hosts[o.Host] {
			return fmt.Errorf("dns: override %q: duplicate host", o.Host)
		}
		hosts[o.Host] = true
		if net.ParseIP(o.IP) == nil {
			return fmt.Errorf("dns: override %q: invalid ip %q", o.Host, o.IP)
		}
	}
	return nil
}

func (wg *WireGuard) validate() error {
	if !wg.Enabled {
		return nil
	}
	ports := map[int]bool{}
	names := map[string]bool{}
	for _, t := range wg.Tunnels {
		where := fmt.Sprintf("wireguard tunnel %q", t.Name)
		if t.Name == "" {
			return errors.New("wireguard tunnel: name is required")
		}
		if names[t.Name] {
			return fmt.Errorf("%s: duplicate name", where)
		}
		names[t.Name] = true
		if _, _, err := net.ParseCIDR(t.Address); err != nil {
			return fmt.Errorf("%s: address must be CIDR: %w", where, err)
		}
		if t.ListenPort < 1 || t.ListenPort > 65535 {
			return fmt.Errorf("%s: listen port must be 1-65535", where)
		}
		if ports[t.ListenPort] {
			return fmt.Errorf("%s: listen port %d already in use", where, t.ListenPort)
		}
		ports[t.ListenPort] = true
		if !validWGKey(t.PrivateKey) {
			return fmt.Errorf("%s: invalid private key", where)
		}
		peerNames := map[string]bool{}
		for _, p := range t.Peers {
			if p.Name == "" {
				return fmt.Errorf("%s peer: name is required", where)
			}
			if peerNames[p.Name] {
				return fmt.Errorf("%s peer %q: duplicate name", where, p.Name)
			}
			peerNames[p.Name] = true
			if !validWGKey(p.PublicKey) {
				return fmt.Errorf("%s peer %q: invalid public key", where, p.Name)
			}
			if p.PrivateKey != "" && !validWGKey(p.PrivateKey) {
				return fmt.Errorf("%s peer %q: invalid private key", where, p.Name)
			}
			if p.AllowedIPs == "" {
				return fmt.Errorf("%s peer %q: allowed ips required", where, p.Name)
			}
			for _, cidr := range strings.Split(p.AllowedIPs, ",") {
				if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
					return fmt.Errorf("%s peer %q: allowed ips: %w", where, p.Name, err)
				}
			}
		}
	}
	return nil
}

func (c *Config) validateUsers() error {
	seen := map[string]bool{}
	for _, u := range c.Users {
		if u.Username == "" {
			return errors.New("user: username is required")
		}
		if seen[u.Username] {
			return fmt.Errorf("user %q: duplicate username", u.Username)
		}
		seen[u.Username] = true
		if !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
			return fmt.Errorf("user %q: password hash must be argon2id", u.Username)
		}
	}
	return nil
}

// LAN returns the lan-role interface. Validate guarantees exactly one exists.
func (c *Config) LAN() Interface {
	for _, ifc := range c.Interfaces {
		if ifc.Role == "lan" {
			return ifc
		}
	}
	return Interface{}
}

func (c *Config) validateDHCP() error {
	d := c.DHCP
	if !d.Enabled {
		return nil
	}
	lan := c.LAN()
	if lan.IPv4 == "" {
		return errors.New("dhcp: lan interface needs a static address")
	}
	_, lanNet, err := net.ParseCIDR(lan.IPv4)
	if err != nil {
		return fmt.Errorf("dhcp: lan address: %w", err)
	}
	start, end := net.ParseIP(d.RangeStart), net.ParseIP(d.RangeEnd)
	if start == nil || end == nil {
		return errors.New("dhcp: invalid pool range")
	}
	if !lanNet.Contains(start) || !lanNet.Contains(end) {
		return fmt.Errorf("dhcp: pool must be inside %s", lanNet)
	}
	if d.LeaseSeconds < 60 {
		return errors.New("dhcp: lease must be at least 60 seconds")
	}
	macs, ips := map[string]bool{}, map[string]bool{}
	for _, l := range d.StaticLeases {
		hw, err := net.ParseMAC(l.MAC)
		if err != nil {
			return fmt.Errorf("dhcp: static lease %q: invalid mac", l.Hostname)
		}
		if macs[hw.String()] {
			return fmt.Errorf("dhcp: static lease %q: duplicate mac %s", l.Hostname, l.MAC)
		}
		macs[hw.String()] = true
		if ip := net.ParseIP(l.IP); ip == nil || !lanNet.Contains(ip) {
			return fmt.Errorf("dhcp: static lease %q: ip must be inside %s", l.Hostname, lanNet)
		}
		if ips[l.IP] {
			return fmt.Errorf("dhcp: static lease %q: duplicate ip %s", l.Hostname, l.IP)
		}
		ips[l.IP] = true
	}
	return nil
}

func (n *NAT) validate() error {
	ids := map[string]bool{}
	ports := map[string]bool{}
	for _, pf := range n.PortForwards {
		where := fmt.Sprintf("port forward %q", pf.Name)
		if pf.ID == "" {
			return fmt.Errorf("%s: missing id", where)
		}
		if ids[pf.ID] {
			return fmt.Errorf("%s: duplicate id %s", where, pf.ID)
		}
		ids[pf.ID] = true
		if pf.Name == "" {
			return fmt.Errorf("port forward %s: name is required", pf.ID)
		}
		switch pf.Proto {
		case "tcp", "udp", "tcp/udp":
		default:
			return fmt.Errorf("%s: proto must be tcp, udp, or tcp/udp", where)
		}
		if pf.WANPort < 1 || pf.WANPort > 65535 {
			return fmt.Errorf("%s: wan port must be 1-65535", where)
		}
		if pf.DestPort < 1 || pf.DestPort > 65535 {
			return fmt.Errorf("%s: destination port must be 1-65535", where)
		}
		if net.ParseIP(pf.DestIP) == nil {
			return fmt.Errorf("%s: invalid destination ip %q", where, pf.DestIP)
		}
		key := pf.Proto + "/" + strconv.Itoa(pf.WANPort)
		if ports[key] {
			return fmt.Errorf("%s: wan port %d/%s already forwarded", where, pf.WANPort, pf.Proto)
		}
		ports[key] = true
	}
	return nil
}

// NewID returns a short random identifier for config list entries.
func NewID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return hex.EncodeToString(b[:])
}

// Store is the on-disk config with serialized access. Writes are atomic
// (temp file + rename) so a crash never leaves a torn config.
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

// Open loads the config at path, writing the default config first if the
// file does not exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.cfg = Default()
		if err := s.save(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, &s.cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return s, nil
}

// Get returns a deep copy of the current configuration, so callers can never
// mutate live state through shared slices.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.clone()
}

// Replace swaps in a whole new config (restore-from-backup), validates, and
// persists. Same discard-on-failure contract as Update.
func (s *Store) Replace(next Config) error {
	return s.Update(func(c *Config) error {
		*c = next
		return nil
	})
}

// clone deep-copies via the JSON round trip — Config is a JSON document, so
// this is exact. A struct assignment is NOT enough: the slices inside would
// share backing arrays and in-place edits would leak into the original.
func (c Config) clone() Config {
	data, err := json.Marshal(c)
	if err != nil {
		panic(err) // Config is always marshalable; see save()
	}
	var out Config
	if err := json.Unmarshal(data, &out); err != nil {
		panic(err)
	}
	return out
}

// Update mutates the config under lock, validates, and persists. The mutation
// is discarded if validation or save fails.
func (s *Store) Update(fn func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg.clone()
	if err := fn(&next); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	prev := s.cfg
	s.cfg = next
	if err := s.save(); err != nil {
		s.cfg = prev
		return err
	}
	return nil
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".fw-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
