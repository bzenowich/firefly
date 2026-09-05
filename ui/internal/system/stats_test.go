package system

import (
	"net"
	"runtime"
	"testing"
)

// TestCollect sanity-checks live collection on supported platforms; run it
// on the FreeBSD VM (go test -c with GOOS=freebsd) as well as the dev box.
func TestCollect(t *testing.T) {
	s := Collect()
	if s.Hostname == "" {
		t.Error("no hostname")
	}
	if s.OS != runtime.GOOS {
		t.Errorf("OS = %q", s.OS)
	}
	switch runtime.GOOS {
	case "linux", "freebsd":
		if s.Uptime <= 0 {
			t.Errorf("Uptime = %v", s.Uptime)
		}
		if s.MemTotal == 0 {
			t.Error("MemTotal = 0")
		}
		if s.MemAvail == 0 || s.MemAvail > s.MemTotal {
			t.Errorf("MemAvail = %d (total %d)", s.MemAvail, s.MemTotal)
		}
		if s.Load1 < 0 || s.Load15 < 0 {
			t.Errorf("load = %v %v %v", s.Load1, s.Load5, s.Load15)
		}
	}
	// At least one non-loopback interface with traffic on any test host.
	var traffic bool
	for _, ifc := range s.Ifaces {
		if ifc.RxBytes > 0 || ifc.TxBytes > 0 {
			traffic = true
		}
	}
	if len(s.Ifaces) == 0 {
		// A network namespace with only lo (containers, some CI) has nothing
		// for Collect to report, which is not a failure of Collect. Only skip
		// once the host really has no non-loopback interface — if it has one
		// and Collect missed it, that is the bug this test is here to catch.
		if !hasNonLoopback(t) {
			t.Skip("host has no non-loopback interface")
		}
		t.Error("no interfaces")
	} else if !traffic {
		t.Error("no interface counters collected")
	}
}

func hasNonLoopback(t *testing.T) bool {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback == 0 {
			return true
		}
	}
	return false
}
