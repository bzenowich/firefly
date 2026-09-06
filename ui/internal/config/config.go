// Package config holds the declarative appliance configuration: a single
// versioned JSON document that is the source of truth. The engine renders it
// into pf.conf, Unbound, Kea, and WireGuard configs (renderers TODO), applies
// atomically, and supports rollback (plan.md §7).
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"firewall/ui/internal/auth"
)

type Config struct {
	Version    int          `json:"version"`
	System     System       `json:"system"`
	Interfaces []Interface  `json:"interfaces"`
	Services   []Service    `json:"services"`
	NAT        NAT          `json:"nat"`
	DHCP       []DHCPServer `json:"dhcp"`
	DNS        DNS          `json:"dns"`
	WireGuard  WireGuard    `json:"wireguard"`
	Devices    []Device     `json:"devices,omitempty"`
	Flow       Flow         `json:"flow"`
	Visibility Visibility   `json:"visibility"`
	Shell      Shell        `json:"shell"`
	SMTP       SMTP         `json:"smtp"`
	Users      []User       `json:"users"`
}

// SMTP is the relay the appliance uses to email things to admins and VPN
// clients (e.g. WireGuard client configs). Empty Host => email disabled; the
// UI then falls back to download/QR only. Password is stored in the config
// document so the single-file backup carries it (plan.md §7).
type SMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"` // default 587 for starttls, 465 for tls
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`               // envelope + header From address
	Security string `json:"security,omitempty"` // starttls | tls | none; default starttls
}

// Enabled reports whether a relay is configured well enough to send.
func (m SMTP) Enabled() bool { return m.Host != "" && m.From != "" }

// EffectivePort returns the port to dial, defaulting by security mode.
func (m SMTP) EffectivePort() int {
	if m.Port > 0 {
		return m.Port
	}
	if m.Security == "tls" {
		return 465
	}
	return 587
}

// Flow configures the baseline network-visibility pipeline (plan.md §8,
// docs/visibility-design.md): the kernel's pflow(4) exporter ships the pf state
// table as IPFIX to an in-process Go collector that summarizes flows into
// SQLite for the native Flows view. This is the always-on, dependency-free
// summary (no Redis, no ntopng, no C in the data path) — distinct from the
// opt-in ntopng power tier below. On by default: pflow runs in the kernel with
// no userland packet copy, so the cost is negligible.
type Flow struct {
	Enabled bool `json:"enabled"`
	// Interfaces optionally narrows the per-interface breakdown to these
	// interface Names. Empty means every configured interface. pflow exports
	// the whole pf state table, so this is a collector-side filter, not a
	// capture switch.
	Interfaces []string `json:"interfaces,omitempty"`
	// Port is the localhost UDP port the collector binds and pflow exports to.
	// 0 => the FlowDefaultPort default.
	Port int `json:"port,omitempty"`
}

// FlowDefaultPort is the localhost UDP port pflow exports to and the collector
// binds when Flow.Port is unset. Matches flow.DefaultAddr.
const FlowDefaultPort = 9996

// CollectorPort returns the effective localhost UDP port (default
// FlowDefaultPort).
func (f Flow) CollectorPort() int {
	if f.Port <= 0 {
		return FlowDefaultPort
	}
	return f.Port
}

// IsMonitored reports whether the named interface is shown in the per-interface
// breakdown. An empty Interfaces list means every interface.
func (f Flow) IsMonitored(name string) bool {
	if len(f.Interfaces) == 0 {
		return true
	}
	for _, n := range f.Interfaces {
		if n == name {
			return true
		}
	}
	return false
}

// Visibility configures on-box network traffic analysis: ntopng with nDPI
// deep-packet inspection on the appliance's own interfaces (plan.md §8). It is
// the power-user deep-dive that complements the always-on Traffic page. Off by
// default — ntopng captures and inspects packets, so a fresh box ships with no
// extra CPU load or attack surface until the admin opts in. ntopng binds its
// web UI to localhost only; the WebUI reverse-proxies it under /visibility
// behind the session, so the appliance auth is the single gate.
type Visibility struct {
	Enabled bool `json:"enabled"` // master switch; false => no capture
	// Interfaces lists interface Names (the wan/lan/opt logical roles) to
	// monitor. Empty means every configured interface — the sensible default
	// for full north-south + inter-segment visibility.
	Interfaces []string `json:"interfaces,omitempty"`
	HTTPPort   int      `json:"http_port,omitempty"` // localhost port ntopng's UI binds; 0 => 3000
}

// IsMonitored reports whether the named interface is captured. An empty
// Interfaces list means every interface, so the templates can render the
// per-interface checkboxes without special-casing the default.
func (v Visibility) IsMonitored(name string) bool {
	if len(v.Interfaces) == 0 {
		return true
	}
	for _, n := range v.Interfaces {
		if n == name {
			return true
		}
	}
	return false
}

// Port returns the effective localhost port for ntopng's web UI (default 3000).
func (v Visibility) Port() int {
	if v.HTTPPort <= 0 {
		return 3000
	}
	return v.HTTPPort
}

// Monitored returns the interface names ntopng should capture on: the explicit
// list when set, otherwise every configured interface.
func (v Visibility) Monitored(c *Config) []string {
	if len(v.Interfaces) > 0 {
		return v.Interfaces
	}
	var all []string
	for _, ifc := range c.Interfaces {
		all = append(all, ifc.Name)
	}
	return all
}

// Shell configures the web terminal (docs/shell.md). It is dark by default:
// with Enabled false there is no /shell route, no nav entry, and no listener,
// so a fresh appliance ships with no web-shell attack surface. SSH remains the
// recommended admin path.
type Shell struct {
	Enabled bool   `json:"enabled"` // master switch; false => feature off
	Shell   string `json:"shell"`   // login shell; "" => /bin/sh
	// User is the unix account the terminal runs as. Empty means the safe
	// default (an unprivileged account — server.defaultShellUser), never the
	// account fwd itself runs as: a web terminal that silently lands on a
	// root prompt turns one stolen session cookie into the whole box. Set
	// "root" explicitly to accept that.
	User        string `json:"user"`
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
	// Role is what this account may do (docs/security-plan.md SEC-7). Empty
	// means RoleAdmin, so every account in an existing config document keeps
	// exactly the access it had.
	Role string `json:"role,omitempty"`
}

// Account roles, ordered by what they may do.
//
// Every account used to be able to do everything: edit the firewall, read every
// flow, download every secret, open a shell. There was no way to give someone
// the Devices page without also giving them pf, and no read-only account for
// "let me see what the network is doing" — so in practice everyone who needed
// to look at anything got the keys to the whole appliance.
const (
	// RoleViewer may read. It is the role for someone who needs to see traffic
	// and device activity and nothing else.
	RoleViewer = "viewer"
	// RoleOperator may additionally change the network: interfaces, NAT, DHCP,
	// DNS, WireGuard, and apply. It may not touch accounts, the security
	// settings that protect them, or anything that hands out a secret.
	RoleOperator = "operator"
	// RoleAdmin may do everything, including managing accounts.
	RoleAdmin = "admin"
)

// roleRank orders the roles for comparison. Unknown or empty ranks as admin —
// see Role().
var roleRank = map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// EffectiveRole returns the account's role, resolving the unset case.
//
// An unset role is admin, not viewer. That is the migration-safe direction: a
// config document written before roles existed describes accounts that could do
// everything, and silently demoting them on upgrade would lock an operator out
// of their own appliance. Provisioning a *new* account defaults to admin only
// because the UI makes the choice explicit.
func (u User) EffectiveRole() string {
	if _, ok := roleRank[u.Role]; ok {
		return u.Role
	}
	return RoleAdmin
}

// AtLeast reports whether the account's role is at or above want.
func (u User) AtLeast(want string) bool {
	return roleRank[u.EffectiveRole()] >= roleRank[want]
}

// Admins counts the accounts that can manage accounts. Used to refuse the last
// one being deleted or demoted, which would leave an appliance nobody can
// administer.
func (c Config) Admins() int {
	n := 0
	for _, u := range c.Users {
		if u.EffectiveRole() == RoleAdmin {
			n++
		}
	}
	return n
}

// User looks up an account by name.
func (c Config) User(name string) (User, bool) {
	for _, u := range c.Users {
		if u.Username == name {
			return u, true
		}
	}
	return User{}, false
}

type System struct {
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	Timezone string `json:"timezone"`
	// DNSServers are the upstream resolvers the appliance forwards to. A
	// non-empty Hostname turns on DNS-over-TLS and is the name verified
	// against the server's certificate.
	DNSServers []DNSServer `json:"dns_servers,omitempty"`
	// NTPServers are the time sources ntpd syncs against. Hostnames or bare
	// addresses only: ntp.conf's server directive takes no port, so one is
	// rejected rather than silently dropped (render.NTP).
	NTPServers []string `json:"ntp_servers,omitempty"`
	// Management restricts who may reach the WebUI and sshd (SEC-5).
	Management Management `json:"management,omitempty"`
}

// DNSServer is one upstream resolver. Address is the IP; Hostname, when set,
// enables DNS-over-TLS (port 853) and is checked against the presented cert.
type DNSServer struct {
	Address  string `json:"address"`
	Hostname string `json:"hostname,omitempty"`
}

// Timezones is the fixed list of UTC-offset zones offered on the System page.
// We expose offsets rather than the full IANA database: the appliance only
// needs wall-clock offset for logs and schedules, and offsets are unambiguous.
func Timezones() []string {
	return []string{
		"UTC-12:00", "UTC-11:00", "UTC-10:00", "UTC-09:30", "UTC-09:00",
		"UTC-08:00", "UTC-07:00", "UTC-06:00", "UTC-05:00", "UTC-04:00",
		"UTC-03:30", "UTC-03:00", "UTC-02:00", "UTC-01:00", "UTC+00:00",
		"UTC+01:00", "UTC+02:00", "UTC+03:00", "UTC+03:30", "UTC+04:00",
		"UTC+04:30", "UTC+05:00", "UTC+05:30", "UTC+05:45", "UTC+06:00",
		"UTC+06:30", "UTC+07:00", "UTC+08:00", "UTC+08:45", "UTC+09:00",
		"UTC+09:30", "UTC+10:00", "UTC+10:30", "UTC+11:00", "UTC+12:00",
		"UTC+12:45", "UTC+13:00", "UTC+14:00",
	}
}

// validTimezone accepts the offset list plus the bare "UTC" alias, which older
// configs (and Default before offsets existed) stored for +00:00.
func validTimezone(tz string) bool {
	if tz == "UTC" {
		return true
	}
	for _, z := range Timezones() {
		if z == tz {
			return true
		}
	}
	return false
}

// Interface maps a logical role (wan, lan, opt) to a physical device.
type Interface struct {
	Name       string `json:"name"`
	Role       string `json:"role"` // wan | lan | opt
	Device     string `json:"device"`
	IPv4       string `json:"ipv4,omitempty"` // CIDR; empty when DHCPClient
	DHCPClient bool   `json:"dhcp_client,omitempty"`
	// Gateway is the next hop installed as the default route. It belongs to
	// a statically addressed wan; a DHCP wan gets the router from its lease
	// and other roles do not carry a default route at all.
	Gateway string `json:"gateway,omitempty"`
	// HardwareOffload re-enables the NIC's segmentation/checksum offloads.
	// The zero value (off) is what every appliance port wants: TSO/LRO
	// coalesce segments in the NIC, which is wrong for a box that forwards
	// and firewalls other people's packets, and it hands the flow
	// classifier merged super-frames that break dissection. Set it only on
	// a port that is a plain host interface and is not captured.
	HardwareOffload bool `json:"hardware_offload,omitempty"`
	// MTU overrides the interface MTU; 0 leaves the driver default.
	MTU int `json:"mtu,omitempty"`
	// Trust is the segment's access to the rest of the appliance
	// (docs/security-plan.md SEC-5). Empty means TrustTrusted, which is what
	// every interface behaved as before this existed.
	Trust string `json:"trust,omitempty"`
}

// Interface trust levels.
//
// pf previously emitted "pass in on $if inet all" for the LAN *and* for every
// OPT interface, under a comment calling them trusted. That made OPT — the
// natural home for a guest or IoT segment — a network with full access to the
// LAN and to the firewall itself, which is the opposite of why someone
// separates a segment in the first place.
//
// The levels are ordered by what they can reach:
//
//	trusted   the LAN: everything, including the admin UI (subject to
//	          Management below)
//	guest     the internet and appliance services (DNS, DHCP), but not the
//	          LAN and not the admin UI
//	isolated  the internet only: no appliance services beyond DHCP, no LAN,
//	          no admin UI, and no other isolated host
const (
	TrustTrusted  = "trusted"
	TrustGuest    = "guest"
	TrustIsolated = "isolated"
)

// TrustLevel returns the effective trust for an interface, defaulting to
// trusted so an existing config document behaves exactly as it did.
func (i Interface) TrustLevel() string {
	switch i.Trust {
	case TrustGuest, TrustIsolated:
		return i.Trust
	default:
		return TrustTrusted
	}
}

// ServesDHCP reports whether an interface can host a DHCP server: any non-WAN
// interface with a static address, i.e. a subnet to hand out from.
func (i Interface) ServesDHCP() bool {
	return i.Role != "wan" && i.IPv4 != ""
}

// Service is one reachable destination on the network (host IP + port + proto).
// The catalog is defined once on the Services page and referenced from both NAT
// port forwards and WireGuard remote-access access grants, so a host's address
// lives in exactly one place.
type Service struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Proto string `json:"proto"` // tcp | udp | tcp/udp
}

// Service looks up a catalog entry by ID.
func (c *Config) Service(id string) (Service, bool) {
	for _, svc := range c.Services {
		if svc.ID == id {
			return svc, true
		}
	}
	return Service{}, false
}

type NAT struct {
	OutboundMode string        `json:"outbound_mode"` // automatic | manual
	PortForwards []PortForward `json:"port_forwards"`
}

// PortForward exposes one Service to the WAN on WANPort. The destination
// address, port, and protocol come from the referenced Service.
type PortForward struct {
	ID        string `json:"id"` // stable handle for edit/delete; survives reordering
	Name      string `json:"name"`
	ServiceID string `json:"service_id"`
	WANPort   int    `json:"wan_port"`
	Enabled   bool   `json:"enabled"`
}

// DHCPServer is the DHCP service for one interface's subnet. The appliance
// runs an independent server per non-WAN interface, so each LAN/OPT segment
// gets its own pool, lease time, and reservations.
type DHCPServer struct {
	Interface    string        `json:"interface"` // interface Name this server binds to
	Enabled      bool          `json:"enabled"`
	RangeStart   string        `json:"range_start"`
	RangeEnd     string        `json:"range_end"`
	LeaseSeconds int           `json:"lease_seconds"`
	StaticLeases []StaticLease `json:"static_leases"`
}

// DHCPFor returns the DHCP server bound to the named interface, or a zero
// server (with Interface set) when none is configured yet, so templates and
// handlers can treat "absent" and "present" uniformly.
func (c Config) DHCPFor(iface string) DHCPServer {
	for _, d := range c.DHCP {
		if d.Interface == iface {
			return d
		}
	}
	return DHCPServer{Interface: iface}
}

type StaticLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// Device is a user-assigned identity for a host on the network, keyed by its
// hardware MAC. It is naming/metadata only — deliberately not a policy target:
// docs/parental.md argues segment-based policy over per-MAC rules, and MAC
// randomization makes MAC-as-policy fragile. The registry exists so the Devices
// page and the flow views can show "Living-room TV" instead of a bare
// 10.0.0.14, and because it is keyed by MAC it survives DHCP lease churn and IP
// reassignment. Stored in the config document so the single-file backup carries
// it (plan.md §7). The live device table (internal/devices) joins this registry
// with the ARP/NDP tables, DHCP leases, and flow byte totals at request time —
// only the durable naming lives here.
type Device struct {
	MAC  string `json:"mac"`            // canonical lower-case colon form (see NormalizeMAC)
	Name string `json:"name"`           // friendly label the admin assigns
	Note string `json:"note,omitempty"` // optional freeform note
}

// DeviceByMAC returns the registry entry for a MAC (already normalized), if any.
func (c *Config) DeviceByMAC(mac string) (Device, bool) {
	for _, d := range c.Devices {
		if d.MAC == mac {
			return d, true
		}
	}
	return Device{}, false
}

// NormalizeMAC parses and canonicalizes a hardware address to lower-case
// colon-separated form, so registry lookups and joins against ARP/lease output
// compare equal regardless of the input's case or separator.
func NormalizeMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	return strings.ToLower(hw.String()), nil
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
	Server  WGServer   `json:"server"`
}

// WGServer is the remote-access ("road warrior") WireGuard server: a single
// wan-bound interface that mobile clients dial in to. Distinct from Tunnels,
// which are site-to-site links. Every client is default-deny and reaches only
// the Services explicitly granted to it (WGClient.ServiceIDs); pf enforces this
// on the server interface (render.WGServerDevice).
type WGServer struct {
	Enabled      bool       `json:"enabled"`
	Address      string     `json:"address"`                 // CIDR, server's tunnel IP, e.g. 10.9.0.1/24
	ListenPort   int        `json:"listen_port"`             // UDP; default 51820
	EndpointHost string     `json:"endpoint_host,omitempty"` // public DNS name clients dial (NAT case)
	PrivateKey   string     `json:"private_key"`             // base64; generated when the server is set up
	Clients      []WGClient `json:"clients"`
}

// Port returns the effective UDP listen port, defaulting to 51820.
func (s WGServer) Port() int {
	if s.ListenPort > 0 {
		return s.ListenPort
	}
	return 51820
}

// WGClient is one remote-access peer. The appliance always generates the
// keypair (so the config can be emailed/re-sent), keyed by a stable ID since
// the email address is the human label.
type WGClient struct {
	ID         string   `json:"id"`
	Email      string   `json:"email"`
	Address    string   `json:"address"` // tunnel IP, /32
	PublicKey  string   `json:"public_key"`
	PrivateKey string   `json:"private_key"` // generated here; lets us (re)send the config
	ServiceIDs []string `json:"service_ids"` // explicit grants; default deny
	Created    string   `json:"created"`     // RFC3339
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
		System: System{
			Hostname: "firewall", Domain: "lan", Timezone: "UTC+00:00",
			DNSServers: []DNSServer{{Address: "1.1.1.1", Hostname: "cloudflare-dns.com"}},
			NTPServers: []string{"pool.ntp.org"},
		},
		Interfaces: []Interface{
			{Name: "WAN", Role: "wan", Device: "igc0", DHCPClient: true},
			{Name: "LAN", Role: "lan", Device: "igc1", IPv4: "192.168.1.1/24"},
			{Name: "OPT1", Role: "opt", Device: "igc2"},
		},
		NAT: NAT{OutboundMode: "automatic"},
		DHCP: []DHCPServer{{
			Interface:    "LAN",
			Enabled:      true,
			RangeStart:   "192.168.1.100",
			RangeEnd:     "192.168.1.199",
			LeaseSeconds: 7200,
		}},
		DNS:  DNS{Enabled: true},
		Flow: Flow{Enabled: true}, // baseline visibility ships on; kernel-side, near-zero cost
	}
}

func (c *Config) Validate() error {
	if c.System.Hostname == "" {
		return errors.New("system: hostname is required")
	}
	if err := c.validateStrings(); err != nil {
		return err
	}
	// The shell-context sweep runs next to the quoting-context one, not buried
	// in validateInterfaces, because it is the boundary that keeps a config
	// value out of a root-executed rc.d script (docs/security-plan.md SEC-1).
	if err := c.validateShellSafe(); err != nil {
		return err
	}
	if err := c.validateShell(); err != nil {
		return err
	}
	if err := c.validateSystem(); err != nil {
		return err
	}
	if err := c.validateManagement(); err != nil {
		return err
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
	svc, err := c.validateServices()
	if err != nil {
		return err
	}
	if err := c.NAT.validate(svc); err != nil {
		return err
	}
	if err := c.validateDHCP(); err != nil {
		return err
	}
	if err := c.DNS.validate(); err != nil {
		return err
	}
	if err := c.WireGuard.validate(svc); err != nil {
		return err
	}
	if err := c.SMTP.validate(); err != nil {
		return err
	}
	if err := c.validateVisibility(); err != nil {
		return err
	}
	if err := c.validateFlow(); err != nil {
		return err
	}
	if err := c.validateDevices(); err != nil {
		return err
	}
	if err := c.validateUsers(); err != nil {
		return err
	}
	return nil
}

// validateDevices checks the device registry: every entry needs a name and a
// well-formed, unique MAC. MACs are normalized in place so stored config always
// holds the canonical form the runtime join keys on.
func (c *Config) validateDevices() error {
	seen := map[string]bool{}
	for i := range c.Devices {
		d := &c.Devices[i]
		if strings.TrimSpace(d.Name) == "" {
			return fmt.Errorf("device %q: name is required", d.MAC)
		}
		mac, err := NormalizeMAC(d.MAC)
		if err != nil {
			return fmt.Errorf("device %q: invalid mac", d.Name)
		}
		d.MAC = mac
		if seen[mac] {
			return fmt.Errorf("device %s: duplicate mac", mac)
		}
		seen[mac] = true
	}
	return nil
}

// Management is the admin plane policy (docs/security-plan.md SEC-5).
//
// Before this, the rendered ruleset passed everything on the LAN, so every
// device on it — a thermostat, a TV, a guest's laptop — could reach the WebUI
// and sshd. That is a large attack surface for a service only one person uses,
// and it is the surface every credential attack starts against.
type Management struct {
	// Sources restricts who may reach the admin plane. Empty means the whole
	// LAN, which is the pre-existing behaviour and the safe default to migrate
	// to: locking an admin out of their own firewall on upgrade would be worse
	// than the exposure it closes.
	Sources []string `json:"sources,omitempty"`
	// Ports is the admin plane itself. Defaults to the WebUI and SSH.
	Ports []int `json:"ports,omitempty"`
}

// ManagementPorts returns the effective admin-plane port list.
func (m Management) ManagementPorts() []int {
	if len(m.Ports) > 0 {
		return m.Ports
	}
	return []int{8443, 22}
}

func (c *Config) validateManagement() error {
	for _, src := range c.System.Management.Sources {
		if _, _, err := net.ParseCIDR(src); err != nil {
			if net.ParseIP(src) == nil {
				return fmt.Errorf("management source %q: not an ip address or CIDR prefix", src)
			}
		}
	}
	for _, p := range c.System.Management.ManagementPorts() {
		if p < 1 || p > 65535 {
			return fmt.Errorf("management port %d is out of range", p)
		}
	}
	return nil
}

func (c *Config) validateSystem() error {
	if c.System.Timezone != "" && !validTimezone(c.System.Timezone) {
		return fmt.Errorf("system: unknown timezone %q", c.System.Timezone)
	}
	seen := map[string]bool{}
	// forward-tls-upstream is a property of the whole forward zone, not of
	// one address, so unbound cannot mix a DoT upstream with a plaintext one.
	// Reject the mixture here rather than silently sending some queries in
	// the clear that the admin believes are encrypted.
	dot, plain := 0, 0
	for _, d := range c.System.DNSServers {
		if d.Hostname != "" {
			dot++
		} else {
			plain++
		}
	}
	if dot > 0 && plain > 0 {
		return errors.New("system: dns servers must either all set a hostname (DNS-over-TLS) or none may")
	}
	for _, d := range c.System.DNSServers {
		if net.ParseIP(d.Address) == nil {
			return fmt.Errorf("system: dns server %q: invalid ip", d.Address)
		}
		if seen[d.Address] {
			return fmt.Errorf("system: dns server %s: duplicate", d.Address)
		}
		seen[d.Address] = true
		if d.Hostname != "" {
			if err := validHostname(d.Hostname); err != nil {
				return fmt.Errorf("system: dns server %s: hostname %q: %w", d.Address, d.Hostname, err)
			}
		}
	}
	ntp := map[string]bool{}
	for _, n := range c.System.NTPServers {
		if n == "" || strings.ContainsAny(n, " \t") {
			return fmt.Errorf("system: ntp server %q: invalid", n)
		}
		// ntp.conf's "server" directive has no port field. Reject rather than
		// quietly render a host the admin did not ask for.
		if _, _, err := net.SplitHostPort(n); err == nil {
			return fmt.Errorf("system: ntp server %q: a port is not supported", n)
		}
		if err := validHostname(n); err != nil {
			return fmt.Errorf("system: ntp server %q: %w", n, err)
		}
		if ntp[n] {
			return fmt.Errorf("system: ntp server %s: duplicate", n)
		}
		ntp[n] = true
	}
	return nil
}

// validConfigValue rejects strings that would break out of the single-line,
// quoted contexts the renderers put them in: pf.conf comments, unbound
// local-data, wg-quick keys. The newline is the dangerous one — it ends a
// comment and starts a directive that pfctl -nf then happily accepts, so a
// pasted name could silently add a pass rule — but quotes, backslashes, and
// control characters corrupt the surrounding syntax just as effectively.
//
// Every free-text field that reaches a renderer runs through this. It is
// enforced centrally in validateStrings rather than at each call site so a new
// field cannot quietly skip it.
func validConfigValue(s string) error {
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r':
			return errors.New("must be a single line")
		case r == '"' || r == '\\':
			return errors.New("must not contain quotes or backslashes")
		case r < 0x20 || r == 0x7f:
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

// --- Shell-context validation (docs/security-plan.md SEC-1) ---------------
//
// validConfigValue above is the boundary for *quoting* contexts: pf comments,
// unbound local-data, Kea JSON. It rejects the characters that break those
// (newline, quote, backslash, control) and nothing else, because nothing else
// matters there.
//
// render.Network and render.Pflow are a different kind of context. They emit
// /usr/local/etc/rc.d scripts at mode 0755 that root executes at every apply
// and every boot, so a value interpolated into one is not data — it is code.
// `;`, `&`, `|`, `$`, backtick, `(`, `)` and a bare space all pass
// validConfigValue and all end a shell word. A device name of
// "igc1; touch /tmp/pwned" used to render as
//
//	if fwnetwork_have igc1; touch /tmp/pwned; then
//
// Two independent defenses, because one of them is always one forgotten field
// away from failing: the renderers shell-quote every interpolation
// (render.shellQuote), and everything that reaches one is charset-validated
// here against a grammar that has no metacharacters in it at all.

// deviceNamePattern is a FreeBSD network interface name: a driver name, a unit
// number, and an optional VLAN suffix — igc0, vtnet1, lagg0, wg0, igc0.100.
// Anything a real board or a cloned interface can be called matches; nothing
// with shell meaning does.
var deviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}[0-9](\.[0-9]{1,4})?$`)

// validDeviceName reports whether s can name a network interface.
func validDeviceName(s string) error {
	if !deviceNamePattern.MatchString(s) {
		return errors.New("must be an interface name like igc0 or igc0.100")
	}
	return nil
}

// unixNamePattern is a unix account name, per the same rules pw(8) enforces.
var unixNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// usernamePattern is a WebUI login name. It is deliberately narrower than
// anything it flows into: audit lines, the TOTP enrollment URL, and the session
// and limiter map keys.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// hostLabelPattern is one DNS label: letters, digits and inner hyphens.
var hostLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// validHostname accepts a DNS name or an IP literal. Callers already reject
// whitespace via validConfigValue and their own checks; this adds the shape, so
// a value that will be handed to a resolver or written into a config file as a
// host is one at the point the admin types it rather than at 3am.
func validHostname(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	if net.ParseIP(s) != nil {
		return nil
	}
	if len(s) > 253 {
		return errors.New("must be at most 253 characters")
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if !hostLabelPattern.MatchString(label) {
			return errors.New("must be a hostname or ip address")
		}
	}
	return nil
}

// shellBinaries is the closed set of login shells the web terminal may exec.
// Shell.Shell is not settable from the UI, but POST /system/restore accepts a
// whole config document, so without this an uploaded backup naming an
// arbitrary binary is an arbitrary-command channel (docs/security-plan.md
// SEC-3a).
var shellBinaries = []string{
	"/bin/sh", "/bin/csh", "/bin/tcsh",
	"/usr/local/bin/bash", "/usr/local/bin/zsh", "/usr/local/bin/fish",
}

// validateShell checks the web terminal's two exec-adjacent fields. Neither is
// reachable from a form; both are reachable from a restored backup.
func (c *Config) validateShell() error {
	if s := c.Shell.Shell; s != "" {
		if !slices.Contains(shellBinaries, s) {
			return fmt.Errorf("shell: %q is not one of the permitted login shells (%s)",
				s, strings.Join(shellBinaries, ", "))
		}
	}
	if u := c.Shell.User; u != "" && !unixNamePattern.MatchString(u) {
		return fmt.Errorf("shell: user %q is not a valid account name", u)
	}
	if c.Shell.IdleTimeout < 0 {
		return errors.New("shell: idle timeout must not be negative")
	}
	if c.Shell.MaxSessions < 0 {
		return errors.New("shell: max sessions must not be negative")
	}
	return nil
}

// validateShellSafe is the authority on every operator-settable value that
// render/ interpolates into a *generated shell script*. It is deliberately
// separate from validateStrings, and deliberately re-checks fields other
// validators also cover (an interface's gateway is parsed as an IP in
// validateInterfaces too): this list is what someone adding a renderer has to
// read, so it must be complete on its own rather than complete only when
// combined with four other functions.
//
// If you add an interpolation to render.Network or render.Pflow, add its field
// here.
func (c *Config) validateShellSafe() error {
	for _, ifc := range c.Interfaces {
		// An absent device is validateInterfaces' error to report ("device is
		// required"), which says something more useful than a grammar
		// mismatch would.
		if ifc.Device == "" {
			continue
		}
		// render.Network: fwnetwork_have, ifconfig, sysctl, dhclient, echo.
		if err := validDeviceName(ifc.Device); err != nil {
			return fmt.Errorf("interface %s: device %q: %w", ifc.Name, ifc.Device, err)
		}
		// render.Network: route add default.
		if ifc.Gateway != "" && net.ParseIP(ifc.Gateway) == nil {
			return fmt.Errorf("interface %s: gateway %q is not an ip address", ifc.Name, ifc.Gateway)
		}
	}
	// render.Pflow interpolates only Flow.CollectorPort(), an int, and
	// render.Network's remaining interpolations (address, netmask, mtu) are
	// produced by net.ParseCIDR and strconv, not by the operator.
	return nil
}

// validateStrings sweeps every operator-settable string that a renderer
// interpolates into a generated config file. Renderers quote nothing and
// escape nothing by design (the files are line-oriented), so this is the
// boundary that keeps a config value from becoming a config directive.
func (c *Config) validateStrings() error {
	check := func(where, val string) error {
		if err := validConfigValue(val); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		return nil
	}
	fields := []struct{ where, val string }{
		{"system: hostname", c.System.Hostname},
		{"system: domain", c.System.Domain},
	}
	for _, d := range c.System.DNSServers {
		fields = append(fields, struct{ where, val string }{"system: dns server hostname", d.Hostname})
	}
	for _, n := range c.System.NTPServers {
		fields = append(fields, struct{ where, val string }{"system: ntp server", n})
	}
	for _, ifc := range c.Interfaces {
		fields = append(fields,
			struct{ where, val string }{"interface name", ifc.Name},
			struct{ where, val string }{"interface device", ifc.Device})
	}
	for _, s := range c.Services {
		fields = append(fields, struct{ where, val string }{"service name", s.Name})
	}
	for _, pf := range c.NAT.PortForwards {
		fields = append(fields, struct{ where, val string }{"port forward name", pf.Name})
	}
	for _, d := range c.DHCP {
		for _, l := range d.StaticLeases {
			fields = append(fields, struct{ where, val string }{"static lease hostname", l.Hostname})
		}
	}
	for _, o := range c.DNS.Overrides {
		fields = append(fields, struct{ where, val string }{"dns override host", o.Host})
	}
	for _, t := range c.WireGuard.Tunnels {
		fields = append(fields,
			struct{ where, val string }{"wireguard tunnel name", t.Name},
			struct{ where, val string }{"wireguard tunnel endpoint", t.EndpointHost})
		for _, p := range t.Peers {
			fields = append(fields,
				struct{ where, val string }{"wireguard peer name", p.Name},
				struct{ where, val string }{"wireguard peer endpoint", p.Endpoint},
				struct{ where, val string }{"wireguard peer allowed ips", p.AllowedIPs})
		}
	}
	fields = append(fields, struct{ where, val string }{"wireguard server endpoint", c.WireGuard.Server.EndpointHost})
	for _, cl := range c.WireGuard.Server.Clients {
		fields = append(fields, struct{ where, val string }{"wireguard client email", cl.Email})
	}
	for _, d := range c.Devices {
		fields = append(fields, struct{ where, val string }{"device name", d.Name})
	}
	for _, f := range fields {
		if err := check(f.where, f.val); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateInterfaces() error {
	devices := map[string]bool{}
	names := map[string]bool{}
	for _, ifc := range c.Interfaces {
		where := fmt.Sprintf("interface %s", ifc.Name)
		if ifc.Name == "" {
			return errors.New("interface: name is required")
		}
		// The name becomes a pf macro (macro() in render/pf.go maps it to
		// <name>_if), and a pf macro must start with a letter. A name that
		// breaks this rule makes every future apply fail at pfctl -nf, not
		// just the one that introduced it.
		if r := rune(ifc.Name[0]); !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return fmt.Errorf("%s: name must start with a letter", where)
		}
		if names[strings.ToLower(ifc.Name)] {
			return fmt.Errorf("%s: duplicate interface name", where)
		}
		names[strings.ToLower(ifc.Name)] = true
		if ifc.MTU != 0 && (ifc.MTU < 576 || ifc.MTU > 9216) {
			return fmt.Errorf("%s: mtu must be 576-9216", where)
		}
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
		if ifc.Gateway != "" {
			if net.ParseIP(ifc.Gateway) == nil {
				return fmt.Errorf("%s: gateway %q is not an ip address", where, ifc.Gateway)
			}
			if ifc.Role != "wan" {
				return fmt.Errorf("%s: only the wan interface carries a gateway", where)
			}
		}
		// A static wan with no next hop has no default route and cannot
		// reach anything off-link — reject it at the form rather than ship
		// a box that silently has no internet.
		if ifc.Role == "wan" && !ifc.DHCPClient && ifc.Gateway == "" {
			return fmt.Errorf("%s: a static wan needs a gateway", where)
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
		if err := validHostname(o.Host); err != nil {
			return fmt.Errorf("dns: override %q: %w", o.Host, err)
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

func (wg *WireGuard) validate(services map[string]Service) error {
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
	return wg.Server.validate(ports, services)
}

// validate checks the remote-access server. ports carries the listen ports
// already claimed by tunnels so the server cannot collide with them; services
// is the shared catalog clients grant access into.
func (s *WGServer) validate(ports map[int]bool, services map[string]Service) error {
	if !s.Enabled {
		return nil
	}
	if _, _, err := net.ParseCIDR(s.Address); err != nil {
		return fmt.Errorf("wireguard server: address must be CIDR: %w", err)
	}
	port := s.Port()
	if port < 1 || port > 65535 {
		return errors.New("wireguard server: listen port must be 1-65535")
	}
	if ports[port] {
		return fmt.Errorf("wireguard server: listen port %d already in use", port)
	}
	if !validWGKey(s.PrivateKey) {
		return errors.New("wireguard server: invalid private key")
	}
	ids := map[string]bool{}
	for _, cl := range s.Clients {
		if cl.ID == "" {
			return errors.New("wireguard client: missing id")
		}
		if ids[cl.ID] {
			return fmt.Errorf("wireguard client %q: duplicate id", cl.Email)
		}
		ids[cl.ID] = true
		if !strings.Contains(cl.Email, "@") {
			return fmt.Errorf("wireguard client %q: a valid email is required", cl.Email)
		}
		if _, _, err := net.ParseCIDR(cl.Address); err != nil {
			return fmt.Errorf("wireguard client %q: address must be CIDR: %w", cl.Email, err)
		}
		if !validWGKey(cl.PublicKey) {
			return fmt.Errorf("wireguard client %q: invalid public key", cl.Email)
		}
		if cl.PrivateKey != "" && !validWGKey(cl.PrivateKey) {
			return fmt.Errorf("wireguard client %q: invalid private key", cl.Email)
		}
		for _, id := range cl.ServiceIDs {
			if _, ok := services[id]; !ok {
				return fmt.Errorf("wireguard client %q: unknown service %q", cl.Email, id)
			}
		}
	}
	return nil
}

func (m *SMTP) validate() error {
	if m.Host == "" {
		return nil // relay not configured; email disabled
	}
	if m.From == "" {
		return errors.New("smtp: from address is required when a host is set")
	}
	if !strings.Contains(m.From, "@") {
		return fmt.Errorf("smtp: from %q is not an email address", m.From)
	}
	if m.Port != 0 && (m.Port < 1 || m.Port > 65535) {
		return errors.New("smtp: port must be 1-65535")
	}
	switch m.Security {
	case "", "starttls", "tls", "none":
	default:
		return fmt.Errorf("smtp: security must be starttls, tls, or none")
	}
	return nil
}

func (c *Config) validateVisibility() error {
	v := c.Visibility
	if v.HTTPPort != 0 && (v.HTTPPort < 1 || v.HTTPPort > 65535) {
		return fmt.Errorf("visibility: http port must be 1-65535")
	}
	known := map[string]bool{}
	for _, ifc := range c.Interfaces {
		known[ifc.Name] = true
	}
	seen := map[string]bool{}
	for _, name := range v.Interfaces {
		if !known[name] {
			return fmt.Errorf("visibility: unknown interface %q", name)
		}
		if seen[name] {
			return fmt.Errorf("visibility: interface %q listed twice", name)
		}
		seen[name] = true
	}
	return nil
}

func (c *Config) validateFlow() error {
	f := c.Flow
	if f.Port != 0 && (f.Port < 1 || f.Port > 65535) {
		return fmt.Errorf("flow: port must be 1-65535")
	}
	known := map[string]bool{}
	for _, ifc := range c.Interfaces {
		known[ifc.Name] = true
	}
	seen := map[string]bool{}
	for _, name := range f.Interfaces {
		if !known[name] {
			return fmt.Errorf("flow: unknown interface %q", name)
		}
		if seen[name] {
			return fmt.Errorf("flow: interface %q listed twice", name)
		}
		seen[name] = true
	}
	return nil
}

func (c *Config) validateUsers() error {
	// An appliance with no administrator cannot be administered, and the only
	// recovery is editing the config document by hand on the console. Refuse
	// the document rather than produce one.
	if len(c.Users) > 0 && c.Admins() == 0 {
		return errors.New("at least one account must have the admin role")
	}
	seen := map[string]bool{}
	for _, u := range c.Users {
		if u.Username == "" {
			return errors.New("user: username is required")
		}
		// The name flows into audit lines, the TOTP enrollment URL, and the
		// session and limiter map keys. Constrain it at the one place it
		// enters the system (docs/security-plan.md SEC-16).
		if !usernamePattern.MatchString(u.Username) {
			return fmt.Errorf("user %q: name must be 1-32 characters of letters, digits, dot, dash or underscore, starting with a letter or digit", u.Username)
		}
		if seen[u.Username] {
			return fmt.Errorf("user %q: duplicate username", u.Username)
		}
		seen[u.Username] = true
		// Parse the hash rather than sniffing its prefix. A config document
		// arrives wholesale from POST /system/restore, and a hash with absurd
		// parameters (m=16777216 is a 16 GiB allocation per login attempt) or a
		// malformed body is an account that can never be logged into. Rejecting
		// it here makes that a restore error instead of a silent lockout
		// (docs/security-plan.md SEC-4a).
		if _, _, _, _, _, err := auth.ParseHash(u.PasswordHash); err != nil {
			return fmt.Errorf("user %q: password hash: %w", u.Username, err)
		}
		if u.Role != "" {
			if _, ok := roleRank[u.Role]; !ok {
				return fmt.Errorf("user %q: unknown role %q", u.Username, u.Role)
			}
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
	byName := map[string]Interface{}
	for _, ifc := range c.Interfaces {
		byName[ifc.Name] = ifc
	}
	seen := map[string]bool{}
	for _, d := range c.DHCP {
		where := fmt.Sprintf("dhcp %q", d.Interface)
		ifc, ok := byName[d.Interface]
		if !ok {
			return fmt.Errorf("%s: unknown interface", where)
		}
		if ifc.Role == "wan" {
			return fmt.Errorf("%s: dhcp is not allowed on the wan interface", where)
		}
		if seen[d.Interface] {
			return fmt.Errorf("%s: duplicate dhcp server", where)
		}
		seen[d.Interface] = true
		if !d.Enabled {
			continue
		}
		if ifc.IPv4 == "" {
			return fmt.Errorf("%s: interface needs a static address", where)
		}
		_, ifcNet, err := net.ParseCIDR(ifc.IPv4)
		if err != nil {
			return fmt.Errorf("%s: interface address: %w", where, err)
		}
		start, end := net.ParseIP(d.RangeStart), net.ParseIP(d.RangeEnd)
		if start == nil || end == nil {
			return fmt.Errorf("%s: invalid pool range", where)
		}
		if !ifcNet.Contains(start) || !ifcNet.Contains(end) {
			return fmt.Errorf("%s: pool must be inside %s", where, ifcNet)
		}
		// Kea takes the pool as "start - end" and rejects an inverted range
		// at load time; catching it here keeps the error on the form field
		// instead of surfacing as a failed apply.
		if bytes.Compare(start.To16(), end.To16()) > 0 {
			return fmt.Errorf("%s: pool start must not be after pool end", where)
		}
		if d.LeaseSeconds < 60 {
			return fmt.Errorf("%s: lease must be at least 60 seconds", where)
		}
		macs, ips := map[string]bool{}, map[string]bool{}
		for i := range d.StaticLeases {
			l := &d.StaticLeases[i]
			// Normalize in place: net.ParseMAC also accepts the Cisco dotted
			// form (0102.0304.0506), which Kea's hw-address rejects — that
			// mismatch passes validation here and then fails the apply.
			mac, err := NormalizeMAC(l.MAC)
			if err != nil {
				return fmt.Errorf("%s: static lease %q: invalid mac", where, l.Hostname)
			}
			l.MAC = mac
			if macs[mac] {
				return fmt.Errorf("%s: static lease %q: duplicate mac %s", where, l.Hostname, l.MAC)
			}
			macs[mac] = true
			// The hostname is handed to Kea as the client's name and shows
			// up on the Devices page; give it a shape here rather than
			// discovering a malformed one in a lease file.
			if l.Hostname != "" {
				if err := validHostname(l.Hostname); err != nil {
					return fmt.Errorf("%s: static lease %s: hostname %q: %w", where, l.MAC, l.Hostname, err)
				}
			}
			if ip := net.ParseIP(l.IP); ip == nil || !ifcNet.Contains(ip) {
				return fmt.Errorf("%s: static lease %q: ip must be inside %s", where, l.Hostname, ifcNet)
			}
			if ips[l.IP] {
				return fmt.Errorf("%s: static lease %q: duplicate ip %s", where, l.Hostname, l.IP)
			}
			ips[l.IP] = true
		}
	}
	return nil
}

// validateServices checks the shared catalog and returns it as an id->Service
// map, which NAT and WireGuard validation use to resolve their references.
func (c *Config) validateServices() (map[string]Service, error) {
	byID := map[string]Service{}
	for _, svc := range c.Services {
		where := fmt.Sprintf("service %q", svc.Name)
		if svc.ID == "" {
			return nil, errors.New("service: missing id")
		}
		if _, dup := byID[svc.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate id %s", where, svc.ID)
		}
		if svc.Name == "" {
			return nil, errors.New("service: name is required")
		}
		if net.ParseIP(svc.IP) == nil {
			return nil, fmt.Errorf("%s: invalid ip %q", where, svc.IP)
		}
		if svc.Port < 1 || svc.Port > 65535 {
			return nil, fmt.Errorf("%s: port must be 1-65535", where)
		}
		switch svc.Proto {
		case "tcp", "udp", "tcp/udp":
		default:
			return nil, fmt.Errorf("%s: proto must be tcp, udp, or tcp/udp", where)
		}
		byID[svc.ID] = svc
	}
	return byID, nil
}

func (n *NAT) validate(services map[string]Service) error {
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
		svc, ok := services[pf.ServiceID]
		if !ok {
			return fmt.Errorf("%s: unknown service", where)
		}
		if pf.WANPort < 1 || pf.WANPort > 65535 {
			return fmt.Errorf("%s: wan port must be 1-65535", where)
		}
		// Expand tcp/udp so it collides with a single-protocol forward on the
		// same port: pf would load both rdr rules and silently use the first.
		for _, p := range protoSet(svc.Proto) {
			key := p + "/" + strconv.Itoa(pf.WANPort)
			if ports[key] {
				return fmt.Errorf("%s: wan port %d/%s already forwarded", where, pf.WANPort, p)
			}
			ports[key] = true
		}
	}
	return nil
}

// protoSet expands a config proto into the individual protocols it occupies.
func protoSet(p string) []string {
	if p == "tcp/udp" {
		return []string{"tcp", "udp"}
	}
	return []string{p}
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
	// loadErr records a validation failure of the on-disk document. Open
	// deliberately still succeeds: refusing to start would take the WebUI
	// down with the config, leaving no way to fix it short of SSH. The
	// invalid document is served read-only in effect, because Manager.Apply
	// re-validates and refuses to render it.
	loadErr error
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
		data = migrateLegacy(data)
		if err := json.Unmarshal(data, &s.cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		// A document that never went through Update (hand-edited, restored
		// by hand, or truncated by a power cut) can violate invariants the
		// renderers assume. Record it rather than fail: see loadErr.
		if err := s.cfg.Validate(); err != nil {
			s.loadErr = fmt.Errorf("%s is invalid: %w", path, err)
		}
	}
	return s, nil
}

// LoadError reports a validation failure of the config as read from disk, or
// nil when it was well-formed. It is cleared by the first successful Update.
func (s *Store) LoadError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

// migrateLegacy upgrades a pre-per-interface config in which "dhcp" was a
// single object into the current array form, binding the old settings to the
// lan interface. Without this, older on-disk configs fail to unmarshal (object
// vs array). Anything already in array form is returned unchanged.
func migrateLegacy(data []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return data
	}
	d, ok := raw["dhcp"]
	if !ok {
		return data
	}
	if t := bytes.TrimSpace(d); len(t) == 0 || t[0] != '{' {
		return data // already an array (or null)
	}
	lan := "LAN"
	if ifsRaw, ok := raw["interfaces"]; ok {
		var ifs []Interface
		if json.Unmarshal(ifsRaw, &ifs) == nil {
			for _, i := range ifs {
				if i.Role == "lan" {
					lan = i.Name
					break
				}
			}
		}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(d, &obj) != nil {
		return data
	}
	obj["interface"], _ = json.Marshal(lan)
	objBytes, _ := json.Marshal(obj)
	raw["dhcp"], _ = json.Marshal([]json.RawMessage{objBytes})
	out, err := json.Marshal(raw)
	if err != nil {
		return data
	}
	return out
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
	s.loadErr = nil // the document on disk is valid again by construction
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
	// Rename is atomic but says nothing about the data being on the platter.
	// Without this fsync a power cut moments after a save can leave a
	// zero-length fw.json — the appliance's whole source of truth — so pay
	// the sync on a file written only when an admin changes something.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	// Persist the directory entry too, so the rename itself survives.
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return nil // the data is written; a missing dir handle is not fatal
	}
	defer dir.Close()
	dir.Sync()
	return nil
}
