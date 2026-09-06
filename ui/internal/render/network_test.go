package render

import (
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

func TestNetworkDefault(t *testing.T) {
	out, err := Network(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# PROVIDE: fwnetwork",
		"# BEFORE: pf", // addressing must land before pf resolves :network macros
		// A device the config names but this board does not have is skipped,
		// not fatal: one image boots on boards with different port counts.
		"fwnetwork_have 'igc0'",
		// Offloads off everywhere by default.
		"ifconfig 'igc1' -tso -lro -txcsum -rxcsum -txcsum6 -rxcsum6",
		"sysctl 'dev.igc.1.eee_control=0'",
		// Static LAN address, guarded so an unrelated apply does not bounce it.
		"ifconfig 'igc1' inet 192.168.1.1/24 alias",
		"grep -q 'inet 192.168.1.1 netmask 0xffffff00'",
		// DHCP WAN is only kicked when it has no address.
		"service dhclient onestart 'igc0'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// No gateway configured (the default WAN is a DHCP client), so no default
	// route is installed — the lease carries it.
	if strings.Contains(out, "route -q add default") {
		t.Errorf("installed a default route for a dhcp wan:\n%s", out)
	}
}

func TestNetworkStaticWANGateway(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces[0].DHCPClient = false
	cfg.Interfaces[0].IPv4 = "203.0.113.2/24"
	cfg.Interfaces[0].Gateway = "203.0.113.1"
	out, err := Network(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ifconfig 'igc0' inet 203.0.113.2/24 alias",
		"route -q add default '203.0.113.1'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "service dhclient onestart 'igc0'") {
		t.Errorf("ran dhclient on a statically addressed wan:\n%s", out)
	}
}

func TestNetworkHardwareOffloadOptIn(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces[2].HardwareOffload = true
	cfg.Interfaces[2].MTU = 9000
	out, err := Network(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ifconfig 'igc2' tso lro txcsum rxcsum txcsum6 rxcsum6") {
		t.Errorf("opt-in offloads not rendered:\n%s", out)
	}
	if !strings.Contains(out, "ifconfig 'igc2' mtu 9000") {
		t.Errorf("mtu not rendered:\n%s", out)
	}
	// The other ports keep the safe default.
	if !strings.Contains(out, "ifconfig 'igc1' -tso -lro") {
		t.Errorf("offloads left on for a port that did not opt in:\n%s", out)
	}
}

func TestSplitDevice(t *testing.T) {
	cases := []struct {
		dev, driver, unit string
		ok                bool
	}{
		{"igc0", "igc", "0", true},
		{"vtnet10", "vtnet", "10", true},
		{"wgsrv", "", "", false}, // no unit suffix
		{"", "", "", false},
	}
	for _, c := range cases {
		d, u, ok := splitDevice(c.dev)
		if d != c.driver || u != c.unit || ok != c.ok {
			t.Errorf("splitDevice(%q) = %q,%q,%v; want %q,%q,%v",
				c.dev, d, u, ok, c.driver, c.unit, c.ok)
		}
	}
}

func TestHexMask(t *testing.T) {
	for _, c := range []struct{ cidr, want string }{
		{"192.168.1.1/24", "0xffffff00"},
		{"10.0.0.1/8", "0xff000000"},
		{"172.16.0.1/30", "0xfffffffc"},
	} {
		cfg := config.Default()
		cfg.Interfaces[1].IPv4 = c.cidr
		out, err := Network(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "netmask "+c.want) {
			t.Errorf("%s: want netmask %s in:\n%s", c.cidr, c.want, out)
		}
	}
}
