package server

import (
	"net/url"
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

func TestWireGuardTunnelAndPeerCRUD(t *testing.T) {
	c, store := newTestServer(t)

	if loc := c.post(t, "/wireguard/settings", url.Values{"enabled": {"on"}}); loc.Query().Get("err") != "" {
		t.Fatalf("settings: %s", loc.Query().Get("err"))
	}

	tun := url.Values{
		"name": {"wg0"}, "address": {"10.8.0.1/24"},
		"listen_port": {"51820"}, "endpoint_host": {"vpn.example.com"},
	}
	if loc := c.post(t, "/wireguard/tunnels", tun); loc.Query().Get("err") != "" {
		t.Fatalf("tunnel create: %s", loc.Query().Get("err"))
	}
	got := store.Get().WireGuard.Tunnels
	if len(got) != 1 || got[0].PrivateKey == "" {
		t.Fatalf("tunnel missing or no generated key: %+v", got)
	}
	if loc := c.post(t, "/wireguard/tunnels", tun); loc.Query().Get("err") == "" {
		t.Fatal("duplicate tunnel name accepted")
	}

	// Peer with no public key: keypair generated, config + QR served.
	peer := url.Values{"name": {"phone"}, "allowed_ips": {"10.8.0.2/32"}}
	if loc := c.post(t, "/wireguard/tunnels/wg0/peers", peer); loc.Query().Get("err") != "" {
		t.Fatalf("peer create: %s", loc.Query().Get("err"))
	}
	p := store.Get().WireGuard.Tunnels[0].Peers[0]
	if p.PrivateKey == "" || p.PublicKey == "" {
		t.Fatalf("peer keypair not generated: %+v", p)
	}

	w := c.get(t, "/wireguard/tunnels/wg0/peers/phone/config")
	if w.Code != 200 {
		t.Fatalf("peer config: status %d: %s", w.Code, w.Body.String())
	}
	for _, want := range []string{
		"PrivateKey = " + p.PrivateKey,
		"Address = 10.8.0.2/32",
		"Endpoint = vpn.example.com:51820",
	} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("client config missing %q:\n%s", want, w.Body.String())
		}
	}
	if w = c.get(t, "/wireguard/tunnels/wg0/peers/phone/qr.png"); w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("qr: status %d type %s", w.Code, w.Header().Get("Content-Type"))
	}

	// Peer with a supplied public key has no stored private key, hence no config.
	_, pub, err := newPeerKey()
	if err != nil {
		t.Fatal(err)
	}
	peer2 := url.Values{"name": {"laptop"}, "allowed_ips": {"10.8.0.3/32"}, "public_key": {pub}}
	if loc := c.post(t, "/wireguard/tunnels/wg0/peers", peer2); loc.Query().Get("err") != "" {
		t.Fatalf("peer2 create: %s", loc.Query().Get("err"))
	}
	if w = c.get(t, "/wireguard/tunnels/wg0/peers/laptop/config"); w.Code != 404 {
		t.Fatalf("config for external-key peer: want 404, got %d", w.Code)
	}

	if loc := c.post(t, "/wireguard/tunnels/wg0/peers/phone/delete", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("peer delete: %s", loc.Query().Get("err"))
	}
	if loc := c.post(t, "/wireguard/tunnels/wg0/delete", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("tunnel delete: %s", loc.Query().Get("err"))
	}
	if len(store.Get().WireGuard.Tunnels) != 0 {
		t.Fatal("tunnel not deleted")
	}
}

// newPeerKey wraps config.NewWGKeypair for tests.
func newPeerKey() (private, public string, err error) {
	return config.NewWGKeypair()
}
