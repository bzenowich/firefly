package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP per RFC 6238: SHA-1, 30-second step, 6 digits — the parameters every
// authenticator app ships with.

const totpStep = 30 * time.Second

// b32 is the unpadded uppercase alphabet authenticator apps expect.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 160-bit base32 secret.
func NewTOTPSecret() string {
	var buf [20]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return b32.EncodeToString(buf[:])
}

// TOTPURL renders the otpauth:// URL that enrollment QR codes encode.
func TOTPURL(secret, user, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.PathEscape(issuer), url.PathEscape(user), secret, url.QueryEscape(issuer))
}

// CurrentTOTP returns the code for the current time step — what an in-sync
// authenticator app shows right now. Used by tests and enrollment checks.
func CurrentTOTP(secret string) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	return totpCode(key, time.Now()), nil
}

// VerifyTOTP checks a 6-digit code against the secret, accepting one step of
// clock skew either side.
func VerifyTOTP(secret, code string) bool {
	_, ok := VerifyTOTPStep(secret, code)
	return ok
}

// VerifyTOTPStep is VerifyTOTP plus the time step the code matched. The ±1 step
// skew window means one code stays valid for up to 90 seconds, so a login path
// that must not accept the same code twice records the returned step and
// refuses anything not strictly newer (design-review §4.6).
func VerifyTOTPStep(secret, code string) (int64, bool) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	code = strings.TrimSpace(code)
	now := time.Now()
	var step int64
	ok := false
	for skew := -1; skew <= 1; skew++ {
		t := now.Add(time.Duration(skew) * totpStep)
		want := totpCode(key, t)
		// Check every window — no early exit — so timing stays uniform.
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			step, ok = stepNumber(t), true
		}
	}
	return step, ok
}

// stepNumber is the RFC 6238 counter value for t: the number of whole steps
// since the Unix epoch.
func stepNumber(t time.Time) int64 {
	return t.Unix() / int64(totpStep/time.Second)
}

func totpCode(key []byte, t time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(stepNumber(t)))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	v := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}
