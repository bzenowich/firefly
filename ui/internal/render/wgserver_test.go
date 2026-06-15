package render

import (
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

// serverConfig is a valid config with the remote-access server enabled, one
// service, and one client granted that service.
func serverConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.WireGuard = config.WireGuard{
		Enabled: true,
		Server: config.WGServer{
			Enabled:      true,
			Address:      "10.9.0.1/24",
			ListenPort:   51820,
			EndpointHost: "vpn.example.com",
			PrivateKey:   testKey(9),
			Services: []config.WGService{
				{ID: "s1", Name: "NAS", IP: "192.168.1.10", Port: 443, Proto: "tcp"},
				{ID: "s2", Name: "DNS", IP: "192.168.1.1", Port: 53, Proto: "tcp/udp"},
			},
			Clients: []config.WGClient{
				{ID: "c1", Email: "a@example.com", Address: "10.9.0.2/32",
					PublicKey: testKey(10), PrivateKey: testKey(11), ServiceIDs: []string{"s1"}},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fixture must be valid: %v", err)
	}
	return cfg
}

func TestWGServerFileRendered(t *testing.T) {
	files, err := WireGuard(serverConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	// No tunnels here, so the only file is the server's, with a fixed name.
	if len(files) != 1 || files[0].Name != "wgsrv.conf" {
		t.Fatalf("want one wgsrv.conf, got %+v", files)
	}
	for _, want := range []string{"ListenPort = 51820", "# Client: a@example.com", "AllowedIPs = 10.9.0.2/32"} {
		if !strings.Contains(files[0].Content, want) {
			t.Errorf("server file missing %q:\n%s", want, files[0].Content)
		}
	}
}

func TestWGServerDisabledNoFile(t *testing.T) {
	cfg := serverConfig(t)
	cfg.WireGuard.Server.Enabled = false
	files, err := WireGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("disabled server must emit no file, got %+v", files)
	}
}

func TestPFServerRules(t *testing.T) {
	out, err := PF(serverConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"port 51820 keep state", // wan pinhole for the listen port
		"block in on wgsrv all", // default deny on the VPN interface
		"pass in on wgsrv inet proto tcp from 10.9.0.2 to 192.168.1.10 port 443 keep state", // the one grant
	} {
		if !strings.Contains(out, want) {
			t.Errorf("pf missing %q:\n%s", want, out)
		}
	}
	// The ungranted service must not produce a pass rule.
	if strings.Contains(out, "192.168.1.1 port 53") {
		t.Errorf("ungranted service leaked into pf:\n%s", out)
	}
}

func TestWGServerClientConfig(t *testing.T) {
	cfg := serverConfig(t)
	conf, err := WGServerClient(cfg, cfg.WireGuard.Server.Clients[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address = 10.9.0.2/32",
		"DNS = 192.168.1.1", // gateway as resolver
		"Endpoint = vpn.example.com:51820",
		"192.168.1.0/24", // split-tunnel LAN net
		"10.9.0.0/24",    // plus the VPN subnet
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("client config missing %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "AllowedIPs = 0.0.0.0/0") {
		t.Errorf("remote-access client should be split-tunnel, not full:\n%s", conf)
	}
}
