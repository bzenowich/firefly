package config

import (
	"bytes"
	"strings"
	"testing"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	c := Default()
	c.SMTP = SMTP{Host: "smtp.example.com", From: "fw@example.com", Password: "the-relay-password"}
	c.WireGuard.Server.PrivateKey = "aVeryPrivateKeyIndeed="
	return c
}

func TestExportPlaintextIsStillJSON(t *testing.T) {
	c := testConfig(t)
	out, err := Export(c, "")
	if err != nil {
		t.Fatal(err)
	}
	if IsEncryptedExport(out) {
		t.Error("an empty passphrase produced an encrypted file")
	}
	got, err := Import(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.SMTP.Password != c.SMTP.Password {
		t.Error("plaintext round trip lost data")
	}
}

// The point of the feature: the file on disk must not contain the secrets.
func TestEncryptedExportLeaksNothing(t *testing.T) {
	c := testConfig(t)
	out, err := Export(c, "a sufficiently long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedExport(out) {
		t.Fatal("export is not marked encrypted")
	}
	for _, secret := range []string{
		c.SMTP.Password,
		c.WireGuard.Server.PrivateKey,
		"smtp.example.com",
		"password_hash",
	} {
		if bytes.Contains(out, []byte(secret)) {
			t.Errorf("the encrypted export contains %q in the clear", secret)
		}
	}
}

func TestEncryptedRoundTrip(t *testing.T) {
	c := testConfig(t)
	const pass = "a sufficiently long passphrase"
	out, err := Export(c, pass)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Import(out, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got.SMTP.Password != c.SMTP.Password ||
		got.WireGuard.Server.PrivateKey != c.WireGuard.Server.PrivateKey ||
		got.System.Hostname != c.System.Hostname {
		t.Error("round trip lost data")
	}
}

func TestImportRejectsWrongPassphraseAndTampering(t *testing.T) {
	out, err := Export(testConfig(t), "a sufficiently long passphrase")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Import(out, "the wrong passphrase entirely"); err == nil {
		t.Error("a wrong passphrase decrypted the backup")
	}
	if _, err := Import(out, ""); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("an encrypted backup with no passphrase: %v", err)
	}

	// Flipping a ciphertext byte must fail authentication, not produce garbage.
	tampered := append([]byte{}, out...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := Import(tampered, "a sufficiently long passphrase"); err == nil {
		t.Error("a tampered backup was accepted")
	}

	// The header is authenticated too: editing the KDF cost must not let a
	// file be opened more cheaply than it was written.
	hdrEdit := append([]byte{}, out...)
	hdrEdit[len(exportMagic)+3] = 1 // time = 1 instead of exportTime
	if _, err := Import(hdrEdit, "a sufficiently long passphrase"); err == nil {
		t.Error("an edited key-derivation header was accepted")
	}
}

// A crafted header must not turn a restore into a memory-exhaustion bomb — the
// same lesson as the login hash (SEC-4c).
func TestImportBoundsKeyDerivationParameters(t *testing.T) {
	out, err := Export(testConfig(t), "a sufficiently long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	bomb := append([]byte{}, out...)
	// memory = 0xFFFFFFFF KiB
	for i := range 4 {
		bomb[len(exportMagic)+4+i] = 0xff
	}
	_, err = Import(bomb, "a sufficiently long passphrase")
	if err == nil || !strings.Contains(err.Error(), "unreasonable") {
		t.Errorf("absurd KDF parameters were honored: %v", err)
	}
}

func TestExportRejectsShortPassphrase(t *testing.T) {
	if _, err := Export(testConfig(t), "short"); err == nil {
		t.Error("a short passphrase was accepted")
	}
}
