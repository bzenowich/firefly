package cert

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The certificate is generated at first boot from the hostname and LAN address
// of the moment. Changing either on the UI used to leave the stored identity
// naming the old one, so the browser warned on every visit — and an admin
// trained to click through a warning on their own firewall will click through a
// real one (docs/security-plan.md SEC-17).
func TestRegeneratesWhenIdentityChanges(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	if _, err := Ensure(certPath, keyPath, "firewall", []net.IP{net.ParseIP("192.168.1.1")}); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	// Same identity: must reuse, so a restart does not invalidate the browser
	// exception the admin already accepted.
	if _, err := Ensure(certPath, keyPath, "firewall", []net.IP{net.ParseIP("192.168.1.1")}); err != nil {
		t.Fatal(err)
	}
	same, _ := os.ReadFile(certPath)
	if string(same) != string(first) {
		t.Error("regenerated for an unchanged identity; the browser exception would break on every restart")
	}

	for _, tc := range []struct {
		name     string
		hostname string
		ips      []net.IP
	}{
		{"hostname changed", "gateway", []net.IP{net.ParseIP("192.168.1.1")}},
		{"lan address changed", "firewall", []net.IP{net.ParseIP("10.0.0.1")}},
		{"address added", "firewall", []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}},
	} {
		if err := os.WriteFile(certPath, first, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Ensure(certPath, keyPath, tc.hostname, tc.ips); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, _ := os.ReadFile(certPath)
		if string(got) == string(first) {
			t.Errorf("%s: certificate not regenerated", tc.name)
		}
	}
}

// A corrupt or unreadable certificate must regenerate rather than fail the
// daemon: refusing to start would take the whole UI down over a cosmetic file.
func TestRegeneratesFromDamage(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	ips := []net.IP{net.ParseIP("192.168.1.1")}

	if _, err := Ensure(certPath, keyPath, "firewall", ips); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(certPath, keyPath, "firewall", ips); err != nil {
		t.Fatalf("damaged certificate was not recovered: %v", err)
	}
	if stale, why := isStale(certPath, "firewall", ips); stale {
		t.Errorf("still stale after regeneration: %s", why)
	}
}
