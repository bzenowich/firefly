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
	"math/big"
	"net"
	"os"
	"time"
)

// Ensure loads the certificate at certPath/keyPath, generating a new
// self-signed one first when either file is missing.
func Ensure(certPath, keyPath, hostname string, ips []net.IP) (tls.Certificate, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if errors.Is(certErr, fs.ErrNotExist) || errors.Is(keyErr, fs.ErrNotExist) {
		if err := generate(certPath, keyPath, hostname, ips); err != nil {
			return tls.Certificate{}, fmt.Errorf("generate certificate: %w", err)
		}
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
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
