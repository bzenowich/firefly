package render

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name string, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s (run with -update to accept):\n%s", path, got)
	}
}

func TestPFDefault(t *testing.T) {
	out, err := PF(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "default.pf.conf", out)
}

func TestPFFull(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces[2].IPv4 = "10.0.2.1/24" // OPT1 configured
	cfg.NAT.PortForwards = []config.PortForward{
		{ID: "a1", Name: "web", Proto: "tcp", WANPort: 443, DestIP: "192.168.1.10", DestPort: 443, Enabled: true},
		{ID: "b2", Name: "game", Proto: "tcp/udp", WANPort: 27015, DestIP: "192.168.1.20", DestPort: 27015, Enabled: true},
		{ID: "c3", Name: "old", Proto: "tcp", WANPort: 8080, DestIP: "192.168.1.30", DestPort: 80, Enabled: false},
	}
	cfg.WireGuard = config.WireGuard{
		Enabled: true,
		Tunnels: []config.WGTunnel{
			{Name: "road-warrior", Address: "10.6.0.1/24", ListenPort: 51820},
			{Name: "site-b", Address: "10.7.0.1/24", ListenPort: 51821},
		},
	}
	out, err := PF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "full.pf.conf", out)

	// Disabled forwards must not leak into the ruleset.
	if strings.Contains(out, "8080") || strings.Contains(out, "192.168.1.30") {
		t.Error("disabled forward rendered")
	}
}

func TestPFNoWAN(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = nil
	if _, err := PF(cfg); err == nil {
		t.Fatal("want error without wan interface")
	}
}
