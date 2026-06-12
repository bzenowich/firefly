package render

import (
	"encoding/json"
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

func TestKeaDefault(t *testing.T) {
	out, err := KeaDHCP4(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "default.kea-dhcp4.conf", out)
	if !json.Valid([]byte(out)) {
		t.Error("output is not valid JSON")
	}
}

func TestKeaStaticLeases(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.StaticLeases = []config.StaticLease{
		{MAC: "00:0d:b9:51:ab:cd", IP: "192.168.1.5", Hostname: "nas"},
		{MAC: "00:0d:b9:51:ab:ce", IP: "192.168.1.6", Hostname: "printer"},
	}
	out, err := KeaDHCP4(cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "leases.kea-dhcp4.conf", out)
	for _, want := range []string{"00:0d:b9:51:ab:cd", "192.168.1.6", "printer"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestKeaNeedsStaticLAN(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces[1].IPv4 = ""
	cfg.Interfaces[1].DHCPClient = true
	if _, err := KeaDHCP4(cfg); err == nil {
		t.Fatal("want error for LAN without static address")
	}
}
