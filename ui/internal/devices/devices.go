// Package devices builds the live device table: who is on the network right
// now, joined with the durable naming the admin assigned. It answers the
// per-device view that plan.md's July roadmap calls the biggest gap versus
// Firewalla — turning IP-keyed flow data into named devices.
//
// The registry (config.Device, keyed by MAC) is the only durable state; it
// lives in the config document. Everything else here is derived at request time
// from three ephemeral sources and never persisted:
//
//   - the ARP and NDP neighbor tables (IP ↔ MAC, who is reachable now),
//   - DHCP leases (MAC ↔ hostname; static from config, dynamic from the lease
//     file), and
//   - the flow store's per-host byte totals (IP ↔ usage).
//
// The join key is the MAC: it survives DHCP churn and IP reassignment, and it
// is how a device keeps one identity across its v4 and v6 addresses. This is
// naming and observation only — not policy. Per docs/parental.md, policy is
// applied by network segment, not per-MAC, because MAC randomization makes
// MAC-as-policy fragile; identifying a device for display has no such problem.
package devices

import (
	"net/netip"
	"sort"
	"strings"

	"firewall/ui/internal/config"
	"firewall/ui/internal/flow"
)

// Neighbor is one IP↔MAC pair from the ARP or NDP table.
type Neighbor struct {
	IP  netip.Addr
	MAC string // normalized lower-case colon form
}

// Lease is one DHCP lease (static or dynamic) contributing a hostname and IP
// for a MAC.
type Lease struct {
	MAC      string
	IP       string
	Hostname string
}

// Device is one host as the live table sees it: identity, current addresses,
// how it was learned, and its usage over the query window.
type Device struct {
	MAC    string   `json:"mac"`
	Name   string   `json:"name"`   // registry name, else DHCP hostname, else ""
	IPs    []string `json:"ips"`    // current addresses (v4 and/or v6)
	Note   string   `json:"note"`   // registry note
	Online bool     `json:"online"` // present in the ARP/NDP table now
	Named  bool     `json:"named"`  // has a user-assigned registry entry
	Static bool     `json:"static"` // has a static DHCP reservation
	In     int64    `json:"in"`     // bytes received over the window
	Out    int64    `json:"out"`    // bytes sent over the window
	Pkts   int64    `json:"pkts"`
}

// Sources supplies the ephemeral inputs to Build. Fields are injectable so the
// join is unit-testable without touching the host; the default wiring
// (DefaultSources) runs arp/ndp and reads the lease file.
type Sources struct {
	Neighbors func() []Neighbor
	Leases    func() []Lease
}

// Build joins the registry, the live neighbor/lease sources, and per-host flow
// totals into the device table. hostTotals is keyed by IP string (from
// flow.Store.HostTotals); a nil map simply yields zero usage. The result is
// sorted online-first, then by total bytes descending, then MAC — the order the
// Devices page renders.
func Build(cfg config.Config, hostTotals map[string]flow.Talker, src Sources) []Device {
	byMAC := map[string]*Device{}
	get := func(mac string) *Device {
		d := byMAC[mac]
		if d == nil {
			d = &Device{MAC: mac}
			byMAC[mac] = d
		}
		return d
	}

	// Registry entries first, so a named-but-offline device still appears.
	for _, r := range cfg.Devices {
		d := get(r.MAC)
		d.Name = r.Name
		d.Note = r.Note
		d.Named = true
	}

	// DHCP hostnames (static reservations from config + dynamic leases). A
	// registry name always wins over a DHCP hostname; a static reservation
	// marks the device Static and seeds its IP if ARP hasn't seen it yet.
	staticMACs := staticLeaseMACs(cfg)
	if src.Leases != nil {
		for _, l := range src.Leases() {
			mac, err := config.NormalizeMAC(l.MAC)
			if err != nil {
				continue
			}
			d := get(mac)
			if staticMACs[mac] {
				d.Static = true
			}
			if !d.Named && d.Name == "" {
				d.Name = l.Hostname
			}
			if ip, err := netip.ParseAddr(strings.TrimSpace(l.IP)); err == nil {
				d.addIP(ip.String())
			}
		}
	}

	// Live neighbors: mark online, record the address, attach usage.
	if src.Neighbors != nil {
		for _, n := range src.Neighbors() {
			d := get(n.MAC)
			d.Online = true
			ip := n.IP.String()
			d.addIP(ip)
		}
	}

	// Sum flow usage across every IP each device currently holds.
	list := make([]Device, 0, len(byMAC))
	for _, d := range byMAC {
		for _, ip := range d.IPs {
			if t, ok := hostTotals[ip]; ok {
				d.In += t.In
				d.Out += t.Out
				d.Pkts += t.Pkts
			}
		}
		list = append(list, *d)
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].Online != list[j].Online {
			return list[i].Online // online first
		}
		bi, bj := list[i].In+list[i].Out, list[j].In+list[j].Out
		if bi != bj {
			return bi > bj // busier first
		}
		return list[i].MAC < list[j].MAC
	})
	return list
}

// addIP appends an address if not already present, keeping IPs unique and
// stable-ordered by insertion.
func (d *Device) addIP(ip string) {
	for _, existing := range d.IPs {
		if existing == ip {
			return
		}
	}
	d.IPs = append(d.IPs, ip)
}

// staticLeaseMACs is the set of MACs with a static DHCP reservation anywhere in
// the config, normalized for comparison.
func staticLeaseMACs(cfg config.Config) map[string]bool {
	out := map[string]bool{}
	for _, srv := range cfg.DHCP {
		for _, l := range srv.StaticLeases {
			if mac, err := config.NormalizeMAC(l.MAC); err == nil {
				out[mac] = true
			}
		}
	}
	return out
}

// staticLeasesFromConfig turns the config's static reservations into Leases, so
// the default source can merge them with dynamic leases uniformly.
func staticLeasesFromConfig(cfg config.Config) []Lease {
	var out []Lease
	for _, srv := range cfg.DHCP {
		for _, l := range srv.StaticLeases {
			out = append(out, Lease{MAC: l.MAC, IP: l.IP, Hostname: l.Hostname})
		}
	}
	return out
}
