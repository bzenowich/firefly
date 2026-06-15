package server

import (
	"net/http"
	"net/url"
	"testing"
)

func TestVisibilitySettings(t *testing.T) {
	c, store := newTestServer(t)

	// Enable, custom port, monitor only LAN.
	form := url.Values{"enabled": {"on"}, "http_port": {"3001"}, "interfaces": {"LAN"}}
	if loc := c.post(t, "/visibility/settings", form); loc.Query().Get("err") != "" {
		t.Fatalf("settings: %s", loc.Query().Get("err"))
	}
	v := store.Get().Visibility
	if !v.Enabled || v.Port() != 3001 {
		t.Fatalf("enabled/port not stored: %+v", v)
	}
	if len(v.Interfaces) != 1 || v.Interfaces[0] != "LAN" {
		t.Fatalf("interface subset not stored: %+v", v.Interfaces)
	}

	// Checking every interface collapses back to the empty (all) default.
	all := url.Values{"enabled": {"on"}, "interfaces": {"WAN", "LAN", "OPT1"}}
	c.post(t, "/visibility/settings", all)
	if got := store.Get().Visibility.Interfaces; got != nil {
		t.Fatalf("all-checked should store nil, got %+v", got)
	}

	// Unknown interface is rejected by config validation, leaving state intact.
	bad := url.Values{"enabled": {"on"}, "interfaces": {"NOPE"}}
	if loc := c.post(t, "/visibility/settings", bad); loc.Query().Get("err") == "" {
		t.Fatal("unknown interface accepted")
	}

	// Non-numeric port is rejected.
	if loc := c.post(t, "/visibility/settings", url.Values{"http_port": {"x"}}); loc.Query().Get("err") == "" {
		t.Fatal("non-numeric port accepted")
	}
}

func TestVisibilityProxyDisabled(t *testing.T) {
	c, _ := newTestServer(t)
	// Visibility off by default: the proxy refuses rather than dialing ntopng.
	w := c.get(t, "/visibility/app/")
	if w.Code != http.StatusForbidden {
		t.Fatalf("disabled proxy: status %d", w.Code)
	}
}

func TestVisibilityProxyUnavailable(t *testing.T) {
	c, _ := newTestServer(t)
	c.post(t, "/visibility/settings", url.Values{"enabled": {"on"}})
	// Enabled but no ntopng listening: friendly 503, not a raw 502.
	w := c.get(t, "/visibility/app/")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable proxy: status %d, body %s", w.Code, w.Body.String())
	}
}
