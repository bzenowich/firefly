// Package system collects host statistics for the dashboard. Linux paths are
// implemented so Phase 0 development works on any dev box; FreeBSD collection
// (sysctl vm.loadavg, hw.physmem, getifaddrs counters) is the deployment
// target and is stubbed until the image work starts.
package system

import (
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Stats struct {
	Hostname  string
	OS        string
	Uptime    time.Duration
	Load1     float64
	Load5     float64
	Load15    float64
	MemTotal  uint64 // bytes
	MemAvail  uint64 // bytes
	Ifaces    []IfStat
	Collected time.Time
}

type IfStat struct {
	Name    string
	Up      bool
	RxBytes uint64
	TxBytes uint64
}

func Collect() Stats {
	s := Stats{OS: runtime.GOOS, Collected: time.Now()}
	s.Hostname, _ = os.Hostname()

	switch runtime.GOOS {
	case "linux":
		collectLinux(&s)
	case "freebsd":
		// TODO: sysctl kern.boottime, vm.loadavg, hw.physmem,
		// vm.stats.vm.v_free_count; per-interface counters via getifaddrs.
	}

	counters := map[string][2]uint64{}
	if runtime.GOOS == "linux" {
		counters = linuxIfCounters()
	}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		c := counters[ifc.Name]
		s.Ifaces = append(s.Ifaces, IfStat{
			Name:    ifc.Name,
			Up:      ifc.Flags&net.FlagUp != 0,
			RxBytes: c[0],
			TxBytes: c[1],
		})
	}
	return s
}

func collectLinux(s *Stats) {
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(data))
		if len(f) >= 3 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
			s.Load5, _ = strconv.ParseFloat(f[1], 64)
			s.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(data)); len(f) > 0 {
			sec, _ := strconv.ParseFloat(f[0], 64)
			s.Uptime = time.Duration(sec) * time.Second
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			kb, _ := strconv.ParseUint(f[1], 10, 64)
			switch f[0] {
			case "MemTotal:":
				s.MemTotal = kb * 1024
			case "MemAvailable:":
				s.MemAvail = kb * 1024
			}
		}
	}
}

// linuxIfCounters parses /proc/net/dev into name -> [rx, tx] bytes.
func linuxIfCounters() map[string][2]uint64 {
	out := map[string][2]uint64{}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		out[strings.TrimSpace(name)] = [2]uint64{rx, tx}
	}
	return out
}
