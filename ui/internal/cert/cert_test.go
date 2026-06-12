package cert

import (
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
)

func TestEnsureGeneratesAndReuses(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")

	c1, err := Ensure(certPath, keyPath, "firewall", []net.IP{net.ParseIP("192.168.1.1")})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "firewall" || len(leaf.DNSNames) != 1 {
		t.Errorf("subject: %+v dns: %v", leaf.Subject, leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("ip sans: %v", leaf.IPAddresses)
	}

	// Second call must load the same cert, not regenerate.
	c2, err := Ensure(certPath, keyPath, "firewall", nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := x509.ParseCertificate(c2.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Error("certificate was regenerated on second Ensure")
	}
}
