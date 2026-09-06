package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Passphrase-wrapped config export (docs/security-plan.md S4).
//
// The backup is the entire appliance: argon2id password hashes, WireGuard
// private keys, TOTP seeds, the SMTP relay password. As a plain .json it is a
// file that ends up in a Downloads folder, an email to oneself, a cloud sync —
// and anyone who reads it has the firewall.
//
// Encrypting it is not a substitute for handling it carefully; it is what makes
// careless handling survivable. The plaintext export stays available, because
// an operator restoring on a box they cannot type a passphrase into needs it,
// and because a format nobody can read without this program is its own kind of
// hazard.

// exportMagic identifies the format and its version. A restore that reads this
// knows to ask for a passphrase rather than failing with a JSON parse error
// pointing at a binary blob.
var exportMagic = [8]byte{'F', 'W', 'B', 'A', 'K', 'U', 'P', 1}

// Argon2id parameters for the export.
//
// Deliberately heavier than the login hash: a login runs on every attempt and
// must stay responsive, while this runs once per backup and once per restore.
// The cost is what stands between a stolen file and an offline dictionary
// attack, and an extra second is nothing against that.
const (
	exportTime    = 3
	exportMemory  = 256 * 1024 // KiB
	exportThreads = 4
	exportSaltLen = 16
	exportKeyLen  = 32
)

// minPassphrase is short enough not to be an obstacle and long enough that the
// argon2 cost above is doing work rather than compensating.
const minPassphrase = 12

// Export serialises the config and, with a passphrase, encrypts it. An empty
// passphrase returns indented JSON — the existing plaintext backup.
func Export(c Config, passphrase string) ([]byte, error) {
	plain, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	if passphrase == "" {
		return append(plain, '\n'), nil
	}
	if len(passphrase) < minPassphrase {
		return nil, fmt.Errorf("passphrase must be at least %d characters", minPassphrase)
	}

	salt := make([]byte, exportSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := exportAEAD(passphrase, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// The header is authenticated as additional data, so a file whose
	// parameters have been edited fails to open rather than being decrypted
	// with the attacker's cheaper cost.
	hdr := exportHeader(salt)
	out := append([]byte{}, hdr...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, hdr), nil
}

// Import reads an exported document, decrypting it when it is encrypted.
func Import(data []byte, passphrase string) (Config, error) {
	if !IsEncryptedExport(data) {
		var c Config
		dec := json.NewDecoder(bytes.NewReader(data))
		// Unknown fields are an error: it is how "you uploaded the wrong JSON
		// file" is caught before the document reaches Validate and produces a
		// confusing complaint about a missing interface.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return Config{}, fmt.Errorf("not a valid backup: %w", err)
		}
		return c, nil
	}
	if passphrase == "" {
		return Config{}, errors.New("this backup is encrypted: enter its passphrase")
	}

	hdrLen := len(exportMagic) + 4*3 + exportSaltLen
	if len(data) < hdrLen {
		return Config{}, errors.New("backup is truncated")
	}
	hdr := data[:hdrLen]
	salt := hdr[len(exportMagic)+4*3:]

	aead, err := exportAEADFromHeader(passphrase, hdr, salt)
	if err != nil {
		return Config{}, err
	}
	rest := data[hdrLen:]
	if len(rest) < aead.NonceSize() {
		return Config{}, errors.New("backup is truncated")
	}
	nonce, box := rest[:aead.NonceSize()], rest[aead.NonceSize():]

	plain, err := aead.Open(nil, nonce, box, hdr)
	if err != nil {
		// One message for a wrong passphrase and for a corrupted file: which
		// it was is not something the holder of the file should learn from us.
		return Config{}, errors.New("could not decrypt the backup: wrong passphrase, or the file is damaged")
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("backup decrypted but is not valid: %w", err)
	}
	return c, nil
}

// IsEncryptedExport reports whether data is a passphrase-wrapped export.
func IsEncryptedExport(data []byte) bool {
	return len(data) >= len(exportMagic) &&
		subtle.ConstantTimeCompare(data[:len(exportMagic)], exportMagic[:]) == 1
}

// exportHeader is magic, the KDF parameters, and the salt. Parameters travel
// with the file so that raising them later does not orphan old backups.
func exportHeader(salt []byte) []byte {
	hdr := make([]byte, 0, len(exportMagic)+4*3+len(salt))
	hdr = append(hdr, exportMagic[:]...)
	hdr = binary.BigEndian.AppendUint32(hdr, exportTime)
	hdr = binary.BigEndian.AppendUint32(hdr, exportMemory)
	hdr = binary.BigEndian.AppendUint32(hdr, exportThreads)
	return append(hdr, salt...)
}

func exportAEAD(passphrase string, salt []byte) (cipher.AEAD, error) {
	return newAEAD(argon2.IDKey([]byte(passphrase), salt, exportTime, exportMemory, exportThreads, exportKeyLen))
}

// exportAEADFromHeader derives the key using the parameters the file carries,
// bounded so a crafted header cannot turn a restore into a memory-exhaustion
// bomb — the same lesson as the login hash (SEC-4c).
func exportAEADFromHeader(passphrase string, hdr, salt []byte) (cipher.AEAD, error) {
	off := len(exportMagic)
	t := binary.BigEndian.Uint32(hdr[off:])
	m := binary.BigEndian.Uint32(hdr[off+4:])
	p := binary.BigEndian.Uint32(hdr[off+8:])
	if t == 0 || t > 16 || m == 0 || m > 4*exportMemory || p == 0 || p > 16 {
		return nil, fmt.Errorf("backup asks for unreasonable key-derivation parameters (t=%d m=%d p=%d)", t, m, p)
	}
	return newAEAD(argon2.IDKey([]byte(passphrase), salt, t, m, uint8(p), exportKeyLen))
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
