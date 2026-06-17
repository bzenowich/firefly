package server

import (
	"net/url"
	"testing"
)

func TestDHCPSettingsAndLeases(t *testing.T) {
	c, store := newTestServer(t)

	loc := c.post(t, "/dhcp/LAN/settings", url.Values{
		"enabled":       {"on"},
		"range_start":   {"192.168.1.50"},
		"range_end":     {"192.168.1.99"},
		"lease_seconds": {"3600"},
	})
	if loc.Query().Get("err") != "" {
		t.Fatalf("settings: %s", loc.Query().Get("err"))
	}
	d := store.Get().DHCPFor("LAN")
	if d.RangeStart != "192.168.1.50" || d.LeaseSeconds != 3600 {
		t.Fatalf("settings not stored: %+v", d)
	}

	// Pool outside the LAN subnet must be rejected and leave config untouched.
	loc = c.post(t, "/dhcp/LAN/settings", url.Values{
		"enabled":       {"on"},
		"range_start":   {"10.9.9.1"},
		"range_end":     {"10.9.9.9"},
		"lease_seconds": {"3600"},
	})
	if loc.Query().Get("err") == "" {
		t.Fatal("out-of-subnet pool accepted")
	}
	if store.Get().DHCPFor("LAN").RangeStart != "192.168.1.50" {
		t.Fatal("rejected update mutated config")
	}

	lease := url.Values{"mac": {"aa:bb:cc:dd:ee:ff"}, "ip": {"192.168.1.10"}, "hostname": {"printer"}}
	if loc = c.post(t, "/dhcp/LAN/leases", lease); loc.Query().Get("err") != "" {
		t.Fatalf("lease create: %s", loc.Query().Get("err"))
	}
	// Duplicate MAC rejected.
	lease.Set("ip", "192.168.1.11")
	if loc = c.post(t, "/dhcp/LAN/leases", lease); loc.Query().Get("err") == "" {
		t.Fatal("duplicate mac accepted")
	}

	lease.Set("hostname", "scanner")
	if loc = c.post(t, "/dhcp/LAN/leases/aa:bb:cc:dd:ee:ff", lease); loc.Query().Get("err") != "" {
		t.Fatalf("lease update: %s", loc.Query().Get("err"))
	}
	got := store.Get().DHCPFor("LAN").StaticLeases
	if len(got) != 1 || got[0].Hostname != "scanner" || got[0].IP != "192.168.1.11" {
		t.Fatalf("lease after update: %+v", got)
	}

	if loc = c.post(t, "/dhcp/LAN/leases/aa:bb:cc:dd:ee:ff/delete", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("lease delete: %s", loc.Query().Get("err"))
	}
	if len(store.Get().DHCPFor("LAN").StaticLeases) != 0 {
		t.Fatal("lease not deleted")
	}
}
