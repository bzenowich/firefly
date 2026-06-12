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
	Name       string   `json:"name"`
	Address    string   `json:"address"` // CIDR
	ListenPort int      `json:"listen_port"`
	Peers      []WGPeer `json:"peers"`
}

type WGPeer struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
	Endpoint   string `json:"endpoint,omitempty"`
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
	if err := c.NAT.validate(); err != nil {
		return err
	}
	if err := c.validateDHCP(); err != nil {
		return err
	}
	// TODO: validate interface addresses, wireguard keys.
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
	for _, l := range d.StaticLeases {
		if _, err := net.ParseMAC(l.MAC); err != nil {
			return fmt.Errorf("dhcp: static lease %q: invalid mac", l.Hostname)
		}
		if ip := net.ParseIP(l.IP); ip == nil || !lanNet.Contains(ip) {
			return fmt.Errorf("dhcp: static lease %q: ip must be inside %s", l.Hostname, lanNet)
		}
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

// Apply renders the configuration into pf.conf, Unbound, Kea, and WireGuard
// configs, validates them (pfctl -nf), and reloads the affected services with
// a confirm-or-rollback window. Stubbed until the renderers land.
func Apply(Config) error {
	return errors.New("apply: renderers not implemented yet")
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

// Get returns a copy of the current configuration.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Update mutates the config under lock, validates, and persists. The mutation
// is discarded if validation or save fails.
func (s *Store) Update(fn func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
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
