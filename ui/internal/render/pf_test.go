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
	cfg.Services = []config.Service{
		{ID: "svc-web", Name: "web", IP: "192.168.1.10", Port: 443, Proto: "tcp"},
		{ID: "svc-game", Name: "game", IP: "192.168.1.20", Port: 27015, Proto: "tcp/udp"},
		{ID: "svc-old", Name: "old", IP: "192.168.1.30", Port: 80, Proto: "tcp"},
	}
	cfg.NAT.PortForwards = []config.PortForward{
		{ID: "a1", Name: "web", ServiceID: "svc-web", WANPort: 443, Enabled: true},
		{ID: "b2", Name: "game", ServiceID: "svc-game", WANPort: 27015, Enabled: true},
		{ID: "c3", Name: "old", ServiceID: "svc-old", WANPort: 8080, Enabled: false},
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
