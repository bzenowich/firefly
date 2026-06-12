package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashVerify(t *testing.T) {
	hash := HashPassword("hunter22")
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash format: %s", hash)
	}
	if !VerifyPassword(hash, "hunter22") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(hash, "hunter23") {
		t.Error("wrong password accepted")
	}
	// Two hashes of the same password differ (random salt).
	if hash == HashPassword("hunter22") {
		t.Error("salt not random")
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	for _, hash := range []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=65536,t=1,p=4$c2FsdA$aGFzaA",   // wrong variant
		"$argon2id$v=18$m=65536,t=1,p=4$c2FsdA$aGFzaA",  // wrong version
		"$argon2id$v=19$m=banana,t=1,p=4$c2FsdA$aGFzaA", // bad params
		"$argon2id$v=19$m=65536,t=1,p=4$!!!$aGFzaA",     // bad salt b64
		"$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$",        // empty key
	} {
		if VerifyPassword(hash, "x") {
			t.Errorf("malformed hash accepted: %q", hash)
		}
	}
}

func TestSessions(t *testing.T) {
	s := NewSessions(time.Hour)
	tok := s.Create("admin")
	if user, ok := s.Get(tok); !ok || user != "admin" {
		t.Fatalf("Get = %q, %v", user, ok)
	}
	if _, ok := s.Get("bogus"); ok {
		t.Error("bogus token accepted")
	}
	s.Delete(tok)
	if _, ok := s.Get(tok); ok {
		t.Error("deleted session still valid")
	}
}

func TestSessionExpiry(t *testing.T) {
	s := NewSessions(time.Millisecond)
	tok := s.Create("admin")
	time.Sleep(5 * time.Millisecond)
	if _, ok := s.Get(tok); ok {
		t.Error("expired session still valid")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, time.Hour)
	if !l.Allow("ip") {
		t.Fatal("fresh key blocked")
	}
	for range 3 {
		l.Fail("ip")
	}
	if l.Allow("ip") {
		t.Error("key allowed after max failures")
	}
	if !l.Allow("other") {
		t.Error("unrelated key blocked")
	}
	l.Reset("ip")
	if !l.Allow("ip") {
		t.Error("key still blocked after reset")
	}
}

func TestLimiterWindowExpiry(t *testing.T) {
	l := NewLimiter(1, time.Millisecond)
	l.Fail("ip")
	time.Sleep(5 * time.Millisecond)
	if !l.Allow("ip") {
		t.Error("failures outlived window")
	}
}
