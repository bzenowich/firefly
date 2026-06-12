package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewWGKeypair(t *testing.T) {
	priv, pub, err := NewWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{priv, pub} {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != 32 {
			t.Fatalf("key %q: not base64 32 bytes", k)
		}
	}
	derived, err := WGPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if derived != pub {
		t.Fatalf("derived public %s != generated %s", derived, pub)
	}
}

func TestValidateWireGuard(t *testing.T) {
	priv, pub, err := NewWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	valid := func() WireGuard {
		return WireGuard{
			Enabled: true,
			Tunnels: []WGTunnel{{
				Name: "t1", Address: "10.6.0.1/24", ListenPort: 51820, PrivateKey: priv,
				Peers: []WGPeer{{Name: "p1", PublicKey: pub, AllowedIPs: "10.6.0.2/32"}},
			}},
		}
	}

	cases := []struct {
		name    string
		mutate  func(*WireGuard)
		wantErr string
	}{
		{"valid", func(wg *WireGuard) {}, ""},
		{"disabled skips checks", func(wg *WireGuard) {
			wg.Enabled = false
			wg.Tunnels[0].PrivateKey = "garbage"
		}, ""},
		{"missing name", func(wg *WireGuard) { wg.Tunnels[0].Name = "" }, "name is required"},
		{"bad address", func(wg *WireGuard) { wg.Tunnels[0].Address = "10.6.0.1" }, "must be CIDR"},
		{"bad port", func(wg *WireGuard) { wg.Tunnels[0].ListenPort = 0 }, "listen port"},
		{"bad private key", func(wg *WireGuard) { wg.Tunnels[0].PrivateKey = "xxx" }, "invalid private key"},
		{"bad peer key", func(wg *WireGuard) { wg.Tunnels[0].Peers[0].PublicKey = "xxx" }, "invalid public key"},
		{"missing allowed ips", func(wg *WireGuard) { wg.Tunnels[0].Peers[0].AllowedIPs = "" }, "allowed ips required"},
		{"bad allowed ips entry", func(wg *WireGuard) { wg.Tunnels[0].Peers[0].AllowedIPs = "10.6.0.2/32, junk" }, "allowed ips"},
		{"duplicate listen port", func(wg *WireGuard) {
			dup := wg.Tunnels[0]
			dup.Name = "t2"
			wg.Tunnels = append(wg.Tunnels, dup)
		}, "already in use"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.WireGuard = valid()
			tc.mutate(&cfg.WireGuard)
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
