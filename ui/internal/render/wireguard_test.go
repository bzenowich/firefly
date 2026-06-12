package render

import (
	"encoding/base64"
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

// Fixed test keys: base64 of 32 deterministic bytes, so golden files are
// stable. Not real keys.
func testKey(fill byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func wgConfig() config.Config {
	cfg := config.Default()
	cfg.WireGuard = config.WireGuard{
		Enabled: true,
		Tunnels: []config.WGTunnel{
			{
				Name: "road-warrior", Address: "10.6.0.1/24", ListenPort: 51820,
				PrivateKey: testKey(1),
				Peers: []config.WGPeer{
					{Name: "phone", PublicKey: testKey(2), AllowedIPs: "10.6.0.2/32", Keepalive: 25},
					{Name: "laptop", PublicKey: testKey(3), AllowedIPs: "10.6.0.3/32"},
				},
			},
			{
				Name: "site-b", Address: "10.7.0.1/30", ListenPort: 51821,
				PrivateKey: testKey(4),
				Peers: []config.WGPeer{
					{Name: "office", PublicKey: testKey(5),
						AllowedIPs: "10.7.0.2/32, 192.168.2.0/24",
						Endpoint:   "b.example.org:51821"},
				},
			},
		},
	}
	return cfg
}

func TestWireGuard(t *testing.T) {
	cfg := wgConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fixture must be valid: %v", err)
	}
	files, err := WireGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("want 2 files, got %d", len(files))
	}
	if files[0].Name != "wg0.conf" || files[1].Name != "wg1.conf" {
		t.Fatalf("device naming: %s, %s", files[0].Name, files[1].Name)
	}
	golden(t, "wg0.conf", files[0].Content)
	golden(t, "wg1.conf", files[1].Content)

	// Optional fields only render when set.
	if strings.Contains(files[0].Content, "Endpoint") {
		t.Error("wg0: endpoint rendered without value")
	}
	if strings.Contains(files[1].Content, "PersistentKeepalive") {
		t.Error("wg1: keepalive rendered without value")
	}
}

func TestWireGuardEmpty(t *testing.T) {
	files, err := WireGuard(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("want no files, got %d", len(files))
	}
}
