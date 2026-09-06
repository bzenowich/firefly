package devices

import (
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"firewall/ui/internal/config"
)

// DefaultSources wires the live inputs for Build: the ARP and NDP neighbor
// tables via the system tools, and DHCP leases from config plus the dynamic
// lease files. Any source that fails or is absent (a dev box without arp/ndp, a
// box with no lease file) contributes nothing rather than erroring — the table
// degrades to whatever is available, down to registry-only.
func DefaultSources(cfg config.Config) Sources {
	return Sources{
		Neighbors: readNeighbors,
		Leases: func() []Lease {
			leases := staticLeasesFromConfig(cfg)
			return append(leases, readDynamicLeases()...)
		},
	}
}

// readNeighbors runs `arp -an` and `ndp -an` and merges their entries. Both
// tools exist on FreeBSD (the appliance) and Linux (dev); a missing tool or
// non-zero exit just yields no entries from that source.
func readNeighbors() []Neighbor {
	var out []Neighbor
	if b, err := exec.Command("arp", "-an").Output(); err == nil {
		out = append(out, parseARP(string(b))...)
	}
	if b, err := exec.Command("ndp", "-an").Output(); err == nil {
		out = append(out, parseNDP(string(b))...)
	}
	return out
}

// readDynamicLeases reads the Kea DHCPv4 and DHCPv6 lease CSVs if present. It is
// best-effort and location-dependent; absence yields no dynamic leases (static
// reservations from config still populate the table). Both files are read so a
// v6-only device — no ARP entry, no v4 lease — still contributes an identity;
// the two memfiles share a format, and Kea records the client's link-layer
// address in the v6 memfile's hwaddr column when it can see it, which is the
// only way a v6 lease can join the MAC-keyed table.
func readDynamicLeases() []Lease {
	leases := readKeaLeaseFile(keaLease4Paths)
	return append(leases, readKeaLeaseFile(keaLease6Paths)...)
}

// readKeaLeaseFile parses the first memfile in paths that exists.
func readKeaLeaseFile(paths []string) []Lease {
	for _, path := range paths {
		if b, err := os.ReadFile(path); err == nil {
			return parseKeaLeases(string(b), time.Now())
		}
	}
	return nil
}

// keaLease4Paths and keaLease6Paths are the usual Kea memfile locations; the
// first that exists wins.
var keaLease4Paths = []string{
	"/var/db/kea/kea-leases4.csv",
	"/var/lib/kea/kea-leases4.csv",
}

var keaLease6Paths = []string{
	"/var/db/kea/kea-leases6.csv",
	"/var/lib/kea/kea-leases6.csv",
}

// parseARP extracts IP↔MAC pairs from `arp -an` output. The relevant shape is
// shared across FreeBSD and Linux:
//
//	? (192.168.1.10) at 00:11:22:33:44:55 [ether] on em0 ...
//
// Lines without a parenthesized IP and a valid MAC (incomplete entries, the
// header, permanent-proxy rows) are skipped.
func parseARP(out string) []Neighbor {
	var ns []Neighbor
	for _, line := range strings.Split(out, "\n") {
		open := strings.IndexByte(line, '(')
		close := strings.IndexByte(line, ')')
		if open < 0 || close < open {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(line[open+1 : close]))
		if err != nil {
			continue
		}
		// The token after "at" is the MAC.
		fields := strings.Fields(line[close+1:])
		for i, f := range fields {
			if f == "at" && i+1 < len(fields) {
				if mac, err := config.NormalizeMAC(fields[i+1]); err == nil {
					ns = append(ns, Neighbor{IP: ip, MAC: mac})
				}
				break
			}
		}
	}
	return ns
}

// parseNDP extracts IPv6 neighbor↔MAC pairs from `ndp -an` (FreeBSD). Columns:
//
//	Neighbor              Linklayer Address  Netif Expire    S Flags
//	fe80::1%em0           00:11:22:33:44:55  em0   permanent R
//
// The first field is the address (with an optional %zone suffix stripped) and
// the second the MAC. Rows whose second field isn't a MAC (incomplete, header)
// are skipped.
func parseNDP(out string) []Neighbor {
	var ns []Neighbor
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr := fields[0]
		if i := strings.IndexByte(addr, '%'); i >= 0 {
			addr = addr[:i] // drop the zone id
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			continue
		}
		mac, err := config.NormalizeMAC(fields[1])
		if err != nil {
			continue
		}
		ns = append(ns, Neighbor{IP: ip, MAC: mac})
	}
	return ns
}

// parseKeaLeases parses a Kea DHCPv4 or DHCPv6 memfile CSV as of now. The header
// names the columns; we take address, hwaddr, hostname, and expire by name so
// column reordering (and the differing v4/v6 layouts) doesn't break the parse.
// Rows that no longer describe a live lease are dropped: a zero valid-lifetime
// (a release tombstone), an expire timestamp in the past, and — in the v6
// file — a delegated prefix. Honoring expire matters because Kea only rewrites
// the memfile when its cleanup (LFC) runs: without it an expired lease keeps
// attributing an IP — and every byte that IP moves — to a device that gave it
// up hours ago.
func parseKeaLeases(csv string, now time.Time) []Lease {
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) < 2 {
		return nil
	}
	col := map[string]int{}
	for i, name := range strings.Split(lines[0], ",") {
		col[strings.TrimSpace(name)] = i
	}
	addrIdx, ok1 := col["address"]
	macIdx, ok2 := col["hwaddr"]
	if !ok1 || !ok2 {
		return nil
	}
	nameIdx, hasName := col["hostname"]
	lifeIdx, hasLife := col["valid_lifetime"]
	expIdx, hasExp := col["expire"]
	typeIdx, hasType := col["lease_type"]
	nowUnix := now.Unix()

	// Later rows supersede earlier ones for the same address (the memfile is
	// append-only), so index by address and let the last write win.
	latest := map[string]Lease{}
	for _, line := range lines[1:] {
		f := strings.Split(line, ",")
		if addrIdx >= len(f) || macIdx >= len(f) {
			continue
		}
		// lease_type only exists in the v6 file, where Kea writes it as an int
		// (0 = IA_NA, 1 = IA_TA, 2 = IA_PD). Skip only the delegated prefix: it
		// is a route, not an address any host answers on. Testing for the one
		// known-bad value rather than "not 0" keeps an unexpected format from
		// silently discarding every v6 lease.
		if hasType && typeIdx < len(f) && strings.TrimSpace(f[typeIdx]) == "2" {
			continue
		}
		if hasLife && lifeIdx < len(f) && strings.TrimSpace(f[lifeIdx]) == "0" {
			delete(latest, f[addrIdx]) // released/expired: drop it
			continue
		}
		if hasExp && expIdx < len(f) && expiredAt(f[expIdx], nowUnix) {
			delete(latest, f[addrIdx]) // lease ran out; Kea just hasn't rewritten it
			continue
		}
		l := Lease{IP: strings.TrimSpace(f[addrIdx]), MAC: strings.TrimSpace(f[macIdx])}
		if hasName && nameIdx < len(f) {
			l.Hostname = strings.TrimSpace(f[nameIdx])
		}
		latest[l.IP] = l
	}
	out := make([]Lease, 0, len(latest))
	for _, l := range latest {
		out = append(out, l)
	}
	return out
}

// expiredAt reports whether a Kea expire cell (absolute unix seconds) is in the
// past. An unparseable or empty cell is treated as not expired: dropping a lease
// we merely failed to read would lose identity, which is worse than holding a
// stale one for a while.
func expiredAt(cell string, now int64) bool {
	exp, err := strconv.ParseInt(strings.TrimSpace(cell), 10, 64)
	if err != nil {
		return false
	}
	return exp <= now
}
