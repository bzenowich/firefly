// Package system collects host statistics for the dashboard. Linux paths
// exist so Phase 0 development works on any dev box; FreeBSD is the
// deployment target (plan.md §6). Platform code lives in stats_GOOS.go.
package system

import (
	"net"
	"os"
	"runtime"
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
	collectPlatform(&s)

	counters := ifCounters()
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
