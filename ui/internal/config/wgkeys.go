package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

// WireGuard keys are X25519: 32 bytes, base64. crypto/ecdh covers this with
// no external dependency; wg itself clamps private keys on use.

// NewWGKeypair generates a WireGuard keypair.
func NewWGKeypair() (private, public string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// WGPublicKey derives the public key from a base64 private key, for showing
// the tunnel's public key in the UI without storing it separately.
func WGPublicKey(private string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// validWGKey reports whether s is a base64-encoded 32-byte key.
func validWGKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}
