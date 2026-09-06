package auth

import (
	"fmt"
	"testing"
	"time"
)

// The username bucket must slow an attacker without ever locking out the
// account's owner. A hard cap there lets any LAN device deny the admin access
// to their own firewall (docs/security-plan.md SEC-12).
func TestUsernameBucketDelaysRatherThanLocking(t *testing.T) {
	l := NewLimiter(5, 15*time.Minute)
	key := "user:admin"

	if d := l.Delay(key); d != 0 {
		t.Errorf("delay %v before any failure", d)
	}
	for range 5 {
		l.Fail(key)
	}
	// At the cap: still no delay, and crucially still allowed.
	if d := l.Delay(key); d != time.Second {
		t.Errorf("delay at the cap = %v, want 1s", d)
	}

	// Past the cap the cost escalates...
	var last time.Duration
	for i := range 10 {
		l.Fail(key)
		d := l.Delay(key)
		if d < last {
			t.Errorf("delay went down at failure %d: %v after %v", i, d, last)
		}
		last = d
	}
	if last != maxDelay {
		t.Errorf("delay settled at %v, want the %v cap", last, maxDelay)
	}

	// Delay never signals refusal, whatever the count: it returns a duration,
	// and the caller waits it out. The complementary property — that the login
	// handler asks Delay rather than Allow for the username bucket, so the
	// account's owner can never be locked out — is a property of the caller,
	// and is asserted in server.TestLoginRateLimitPerUsername.
	for range 100 {
		l.Fail(key)
	}
	if d := l.Delay(key); d != maxDelay {
		t.Errorf("delay under sustained failure = %v, want the %v cap", d, maxDelay)
	}
}

// The map is keyed by attacker-supplied usernames, so a spray must not grow it
// without bound.
func TestMapIsBounded(t *testing.T) {
	l := NewLimiter(5, time.Hour)
	for i := range maxKeys * 2 {
		l.Fail(fmt.Sprintf("user:sprayed-%d", i))
	}
	if got := len(l.m); got > maxKeys {
		t.Errorf("map holds %d keys, over the %d bound", got, maxKeys)
	}
}

// Eviction must drop the coldest key, so a spray of one-shot usernames cannot
// flush out the entry tracking a real attack.
func TestEvictionKeepsTheHotKey(t *testing.T) {
	now := time.Now()
	l := NewLimiter(5, time.Hour)
	l.now = func() time.Time { return now }

	hot := "user:admin"
	l.Fail(hot)

	for i := range maxKeys * 2 {
		now = now.Add(time.Millisecond)
		if i%50 == 0 {
			l.Delay(hot) // the real attack keeps touching this key
		}
		l.Fail(fmt.Sprintf("user:sprayed-%d", i))
	}
	if _, ok := l.m[hot]; !ok {
		t.Error("a username spray evicted the entry tracking the account under attack")
	}
}
