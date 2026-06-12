package server

import (
	"net/url"
	"testing"
)

func TestDNSBlocklistsAndOverrides(t *testing.T) {
	c, store := newTestServer(t)

	if loc := c.post(t, "/dns/settings", url.Values{"enabled": {"on"}, "adblock": {"on"}}); loc.Query().Get("err") != "" {
		t.Fatalf("settings: %s", loc.Query().Get("err"))
	}
	if !store.Get().DNS.Adblock.Enabled {
		t.Fatal("adblock not enabled")
	}

	list := "https://example.com/hosts.txt"
	if loc := c.post(t, "/dns/blocklists", url.Values{"url": {list}}); loc.Query().Get("err") != "" {
		t.Fatalf("blocklist add: %s", loc.Query().Get("err"))
	}
	if loc := c.post(t, "/dns/blocklists", url.Values{"url": {list}}); loc.Query().Get("err") == "" {
		t.Fatal("duplicate blocklist accepted")
	}
	if loc := c.post(t, "/dns/blocklists", url.Values{"url": {"ftp://nope"}}); loc.Query().Get("err") == "" {
		t.Fatal("non-http blocklist accepted")
	}
	if loc := c.post(t, "/dns/blocklists/delete", url.Values{"url": {list}}); loc.Query().Get("err") != "" {
		t.Fatalf("blocklist delete: %s", loc.Query().Get("err"))
	}
	if len(store.Get().DNS.Adblock.Lists) != 0 {
		t.Fatal("blocklist not deleted")
	}

	o := url.Values{"host": {"nas.lan"}, "ip": {"192.168.1.20"}}
	if loc := c.post(t, "/dns/overrides", o); loc.Query().Get("err") != "" {
		t.Fatalf("override create: %s", loc.Query().Get("err"))
	}
	if loc := c.post(t, "/dns/overrides", o); loc.Query().Get("err") == "" {
		t.Fatal("duplicate override accepted")
	}
	o.Set("ip", "192.168.1.21")
	if loc := c.post(t, "/dns/overrides/nas.lan", o); loc.Query().Get("err") != "" {
		t.Fatalf("override update: %s", loc.Query().Get("err"))
	}
	got := store.Get().DNS.Overrides
	if len(got) != 1 || got[0].IP != "192.168.1.21" {
		t.Fatalf("override after update: %+v", got)
	}
	if loc := c.post(t, "/dns/overrides/nas.lan/delete", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("override delete: %s", loc.Query().Get("err"))
	}
	if len(store.Get().DNS.Overrides) != 0 {
		t.Fatal("override not deleted")
	}
}
