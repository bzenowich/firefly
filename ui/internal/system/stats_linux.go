package system

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func collectPlatform(s *Stats) {
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

// ifCounters parses /proc/net/dev into name -> [rx, tx] bytes.
func ifCounters() map[string][2]uint64 {
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
