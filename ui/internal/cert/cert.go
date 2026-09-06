// Package cert provides the appliance's self-signed TLS identity: generated
// once at first boot, reused afterwards. A real CA cannot vouch for a LAN
// address, so self-signed is the steady state, not a stopgap (plan.md §7).
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"os"
	"slices"
	"time"
)

// Ensure loads the certificate at certPath/keyPath, generating a new
// self-signed one when either file is missing — or when the appliance's
// identity has moved out from under the one on disk.
//
// The second case is why this is not just a file-exists check. The certificate
// is generated at first boot from the hostname and LAN address of the moment;
// change either on the Interfaces or System page and the stored certificate
// still names the old one. The browser then warns on every visit, and an admin
// who has been trained to click through a certificate warning on their own
// firewall is an admin who will click through a real one
// (docs/security-plan.md SEC-17).
func Ensure(certPath, keyPath, hostname string, ips []net.IP) (tls.Certificate, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	missing := errors.Is(certErr, fs.ErrNotExist) || errors.Is(keyErr, fs.ErrNotExist)

	if !missing {
		if stale, why := isStale(certPath, hostname, ips); stale {
			log.Printf("cert: regenerating the TLS identity: %s", why)
			missing = true
		}
	}
	if missing {
		if err := generate(certPath, keyPath, hostname, ips); err != nil {
			return tls.Certificate{}, fmt.Errorf("generate certificate: %w", err)
		}
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// isStale reports whether the stored certificate no longer covers the
// appliance's current identity, and why.
//
// Only additions matter: a certificate that names more than it needs to is
// harmless, one that names less produces a warning. An unreadable or unparseable
// file counts as stale — regenerating is the recovery, and refusing to start
// would take the UI down over a cosmetic problem.
func isStale(certPath, hostname string, ips []net.IP) (bool, string) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return true, "certificate is unreadable"
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return true, "certificate is not valid PEM"
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, "certificate does not parse"
	}
	if time.Now().After(c.NotAfter) {
		return true, "certificate has expired"
	}
	if hostname != "" && !slices.Contains(c.DNSNames, hostname) {
		return true, fmt.Sprintf("hostname %q is not in the certificate", hostname)
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(c.IPAddresses, func(have net.IP) bool { return have.Equal(ip) }) {
			return true, fmt.Sprintf("address %s is not in the certificate", ip)
		}
	}
	return false, ""
}

func generate(certPath, keyPath, hostname string, ips []net.IP) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour), // tolerate clock skew at first boot
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
