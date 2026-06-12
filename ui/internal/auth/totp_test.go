package auth

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238Vector(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 rows, truncated to 6 digits.
	key := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1234567890, "005924"},
		{20000000000, "353130"},
	}
	for _, tc := range cases {
		if got := totpCode(key, time.Unix(tc.unix, 0)); got != tc.want {
			t.Errorf("t=%d: got %s want %s", tc.unix, got, tc.want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := NewTOTPSecret()
	key, err := b32.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(secret, totpCode(key, time.Now())) {
		t.Error("current code rejected")
	}
	if !VerifyTOTP(secret, totpCode(key, time.Now().Add(-totpStep))) {
		t.Error("previous-step code rejected")
	}
	if VerifyTOTP(secret, totpCode(key, time.Now().Add(3*totpStep))) {
		t.Error("far-future code accepted")
	}
	if VerifyTOTP(secret, "000000") && VerifyTOTP(secret, "123456") {
		t.Error("arbitrary codes accepted")
	}
	if VerifyTOTP("not base32!!", "123456") {
		t.Error("bad secret accepted")
	}
}

func TestTOTPURL(t *testing.T) {
	u := TOTPURL("ABC234", "admin", "firewall")
	for _, want := range []string{"otpauth://totp/firewall:admin", "secret=ABC234", "issuer=firewall"} {
		if !strings.Contains(u, want) {
			t.Errorf("url %q missing %q", u, want)
		}
	}
}
