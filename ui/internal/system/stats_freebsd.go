package system

import (
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func collectPlatform(s *Stats) {
	// struct loadavg { fixpt_t ldavg[3]; long fscale; }: three uint32 fixed-
	// point samples, padding, then the scale divisor at offset 16 (amd64).
	if raw, err := unix.SysctlRaw("vm.loadavg"); err == nil && len(raw) >= 24 {
		if fscale := float64(binary.NativeEndian.Uint64(raw[16:])); fscale > 0 {
			s.Load1 = float64(binary.NativeEndian.Uint32(raw[0:])) / fscale
			s.Load5 = float64(binary.NativeEndian.Uint32(raw[4:])) / fscale
			s.Load15 = float64(binary.NativeEndian.Uint32(raw[8:])) / fscale
		}
	}
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		s.Uptime = time.Since(time.Unix(tv.Sec, tv.Usec*1000)).Truncate(time.Second)
	}
	if v, err := unix.SysctlUint64("hw.physmem"); err == nil {
		s.MemTotal = v
	}
	// "Available" the way top(1) frames it: free + inactive pages are
	// reclaimable without I/O.
	pageSize, err := unix.SysctlUint32("vm.stats.vm.v_page_size")
	if err != nil {
		return
	}
	var pages uint64
	for _, name := range []string{"vm.stats.vm.v_free_count", "vm.stats.vm.v_inactive_count"} {
		if v, err := unix.SysctlUint32(name); err == nil {
			pages += uint64(v)
		}
	}
	s.MemAvail = pages * uint64(pageSize)
}

// Offsets into the NET_RT_IFLIST dump on freebsd/amd64 (and arm64; both
// little-endian, same alignment). if_data is versioned via ifi_datalen, so
// the counter offsets are stable within a major release.
const (
	rtmIfInfo  = 0xe // RTM_IFINFO message type
	ifmIndex   = 12  // offsetof(struct if_msghdr, ifm_index)
	ifmData    = 16  // offsetof(struct if_msghdr, ifm_data)
	ifiDatalen = 6   // offsetof(struct if_data, ifi_datalen)
	ifiIbytes  = 64  // offsetof(struct if_data, ifi_ibytes)
	ifiObytes  = 72  // offsetof(struct if_data, ifi_obytes)
)

// ifCounters reads per-interface byte counters from the NET_RT_IFLIST
// routing sysctl (the getifaddrs data source, minus cgo). x/net/route does
// the raw-mib fetch — sysctlbyname cannot address the net.route subtree —
// but exposes no if_data, hence the manual walk.
func ifCounters() map[string][2]uint64 {
	out := map[string][2]uint64{}
	raw, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, 0)
	if err != nil {
		return out
	}
	names := map[int]string{}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			names[ifc.Index] = ifc.Name
		}
	}
	for len(raw) >= 4 {
		msglen := int(binary.NativeEndian.Uint16(raw[0:]))
		if msglen < 4 || msglen > len(raw) {
			break
		}
		msg := raw[:msglen]
		raw = raw[msglen:]
		if msg[3] != rtmIfInfo { // ifm_type
			continue
		}
		if len(msg) < ifmData+ifiObytes+8 {
			continue
		}
		data := msg[ifmData:]
		if int(binary.NativeEndian.Uint16(data[ifiDatalen:])) < ifiObytes+8 {
			continue
		}
		name, ok := names[int(binary.NativeEndian.Uint16(msg[ifmIndex:]))]
		if !ok {
			continue
		}
		out[name] = [2]uint64{
			binary.NativeEndian.Uint64(data[ifiIbytes:]),
			binary.NativeEndian.Uint64(data[ifiObytes:]),
		}
	}
	return out
}
