package render

import (
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

func TestUnboundDefault(t *testing.T) {
	out, err := Unbound(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "default.unbound.conf", out)
	if strings.Contains(out, AdblockInclude) {
		t.Error("adblock include rendered while disabled")
	}
}

func TestUnboundFull(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces[2].IPv4 = "10.0.2.1/24" // OPT1 configured
	cfg.DNS.Adblock = config.Adblock{
		Enabled: true,
		Lists:   []string{"https://example.org/hosts.txt"},
	}
	cfg.DNS.Overrides = []config.HostOverride{
		{Host: "nas.lan", IP: "192.168.1.5"},
	}
	out, err := Unbound(cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "full.unbound.conf", out)

	for _, want := range []string{
		"interface: 10.0.2.1",
		"access-control: 10.0.2.0/24 allow",
		`local-data: "nas.lan. IN A 192.168.1.5"`,
		"include: " + AdblockInclude,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestUnboundNeedsInternalAddress(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.Enabled = false // LAN without address is otherwise invalid
	cfg.Interfaces[1].IPv4 = ""
	if _, err := Unbound(cfg); err == nil {
		t.Fatal("want error without internal addresses")
	}
}
