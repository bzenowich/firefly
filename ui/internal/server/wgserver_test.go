package server

import (
	"net/url"
	"strings"
	"testing"
)

func TestWGServerClientFlow(t *testing.T) {
	c, store := newTestServer(t)

	// Master WireGuard switch + server enable (key generated, default subnet).
	if loc := c.post(t, "/wireguard/settings", url.Values{"enabled": {"on"}}); loc.Query().Get("err") != "" {
		t.Fatalf("wg enable: %s", loc.Query().Get("err"))
	}
	srvForm := url.Values{"enabled": {"on"}, "address": {"10.9.0.1/24"}, "listen_port": {"51820"}}
	if loc := c.post(t, "/wireguard/server", srvForm); loc.Query().Get("err") != "" {
		t.Fatalf("server enable: %s", loc.Query().Get("err"))
	}
	if store.Get().WireGuard.Server.PrivateKey == "" {
		t.Fatal("server key not generated on enable")
	}

	// A service to grant.
	svc := url.Values{"name": {"NAS"}, "ip": {"192.168.1.10"}, "port": {"443"}, "proto": {"tcp"}}
	if loc := c.post(t, "/wireguard/server/services", svc); loc.Query().Get("err") != "" {
		t.Fatalf("service create: %s", loc.Query().Get("err"))
	}
	svcID := store.Get().WireGuard.Server.Services[0].ID

	// Add a client granted that service: keypair generated, IP auto-assigned.
	cl := url.Values{"email": {"user@example.com"}, "service_ids": {svcID}}
	if loc := c.post(t, "/wireguard/server/clients", cl); loc.Query().Get("err") != "" {
		t.Fatalf("client create: %s", loc.Query().Get("err"))
	}
	clients := store.Get().WireGuard.Server.Clients
	if len(clients) != 1 {
		t.Fatalf("want 1 client, got %d", len(clients))
	}
	got := clients[0]
	if got.PrivateKey == "" || got.PublicKey == "" {
		t.Fatalf("client keypair not generated: %+v", got)
	}
	if got.Address != "10.9.0.2/32" {
		t.Fatalf("want first free addr 10.9.0.2/32, got %s", got.Address)
	}
	if len(got.ServiceIDs) != 1 || got.ServiceIDs[0] != svcID {
		t.Fatalf("grant not stored: %+v", got.ServiceIDs)
	}

	// A second client must get the next free address.
	if loc := c.post(t, "/wireguard/server/clients", url.Values{"email": {"two@example.com"}}); loc.Query().Get("err") != "" {
		t.Fatalf("client2 create: %s", loc.Query().Get("err"))
	}
	if addr := store.Get().WireGuard.Server.Clients[1].Address; addr != "10.9.0.3/32" {
		t.Fatalf("want 10.9.0.3/32 for second client, got %s", addr)
	}

	// Config download works and carries the client's private key + filename.
	w := c.get(t, "/wireguard/server/clients/"+got.ID+"/config")
	if w.Code != 200 {
		t.Fatalf("client config: status %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PrivateKey = "+got.PrivateKey) {
		t.Errorf("config missing client key:\n%s", w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "vpn-user.conf") {
		t.Errorf("download filename: %q", cd)
	}
	if w = c.get(t, "/wireguard/server/clients/"+got.ID+"/qr.png"); w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("qr: status %d type %s", w.Code, w.Header().Get("Content-Type"))
	}

	// Updating grants replaces the set.
	if loc := c.post(t, "/wireguard/server/clients/"+got.ID, url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("grant update: %s", loc.Query().Get("err"))
	}
	if len(store.Get().WireGuard.Server.Clients[0].ServiceIDs) != 0 {
		t.Fatal("grant not cleared on update")
	}

	// Deleting the service prunes any dangling grant (re-grant first).
	c.post(t, "/wireguard/server/clients/"+got.ID, url.Values{"service_ids": {svcID}})
	if loc := c.post(t, "/wireguard/server/services/"+svcID+"/delete", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("service delete: %s", loc.Query().Get("err"))
	}
	if len(store.Get().WireGuard.Server.Clients[0].ServiceIDs) != 0 {
		t.Fatal("dangling grant not pruned on service delete")
	}

	// Email without a relay configured is a no-op success, not an error.
	if loc := c.post(t, "/wireguard/server/clients/"+got.ID+"/email", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("email without relay should be a no-op: %s", loc.Query().Get("err"))
	}

	// Delete a client.
	if loc := c.post(t, "/wireguard/server/clients/"+got.ID+"/delete", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("client delete: %s", loc.Query().Get("err"))
	}
	if len(store.Get().WireGuard.Server.Clients) != 1 {
		t.Fatalf("want 1 client after delete, got %d", len(store.Get().WireGuard.Server.Clients))
	}
}

func TestWGClientRequiresEnabledServer(t *testing.T) {
	c, _ := newTestServer(t)
	c.post(t, "/wireguard/settings", url.Values{"enabled": {"on"}})
	// Server not enabled yet.
	loc := c.post(t, "/wireguard/server/clients", url.Values{"email": {"x@example.com"}})
	if loc.Query().Get("err") == "" {
		t.Fatal("adding a client with the server disabled should fail")
	}
}

func TestSMTPSettings(t *testing.T) {
	c, store := newTestServer(t)
	form := url.Values{
		"host": {"smtp.example.com"}, "port": {"587"},
		"from": {"fw@example.com"}, "security": {"starttls"},
		"username": {"u"}, "password": {"p"},
	}
	if loc := c.post(t, "/wireguard/smtp", form); loc.Query().Get("err") != "" {
		t.Fatalf("smtp save: %s", loc.Query().Get("err"))
	}
	m := store.Get().SMTP
	if !m.Enabled() || m.Host != "smtp.example.com" || m.EffectivePort() != 587 {
		t.Fatalf("smtp not stored: %+v", m)
	}
	// A host without a from address is rejected by validation.
	if loc := c.post(t, "/wireguard/smtp", url.Values{"host": {"x"}}); loc.Query().Get("err") == "" {
		t.Fatal("smtp host without from should fail validation")
	}
}
