package auth

import (
	"testing"
	"time"
)

// The absolute lifetime is the point of SEC-11: the dashboard polls every two
// seconds, so the idle timer alone made an open tab an immortal session — and a
// cookie stolen from a laptop that is never closed never expired.
func TestAbsoluteLifetimeIsNotExtendedByActivity(t *testing.T) {
	now := time.Now()
	s := NewSessions(time.Hour, 2*time.Hour)
	s.now = func() time.Time { return now }

	created := now
	tok := s.Create("admin", "192.0.2.1")

	// Poll continuously for longer than the absolute lifetime, always well
	// inside the idle window — exactly what an open dashboard tab does.
	for range 200 {
		now = now.Add(time.Minute)
		if _, ok := s.Get(tok); !ok {
			if age := now.Sub(created); age < 2*time.Hour {
				t.Fatalf("session died after %v, before its absolute lifetime", age)
			}
			return // expired at the absolute deadline, as intended
		}
	}
	t.Fatal("session survived past its absolute lifetime under continuous activity")
}

func TestIdleTimeoutStillApplies(t *testing.T) {
	now := time.Now()
	s := NewSessions(time.Hour, 24*time.Hour)
	s.now = func() time.Time { return now }
	tok := s.Create("admin", "192.0.2.1")

	now = now.Add(30 * time.Minute)
	if _, ok := s.Get(tok); !ok {
		t.Fatal("session expired inside the idle window")
	}
	now = now.Add(90 * time.Minute) // idle past the TTL
	if _, ok := s.Get(tok); ok {
		t.Error("idle session survived its TTL")
	}
}

// The inventory must never print a live credential into a page.
func TestInventoryExposesNoToken(t *testing.T) {
	s := NewSessions(time.Hour, 24*time.Hour)
	tok := s.Create("admin", "192.0.2.7")
	other := s.Create("bob", "192.0.2.8")

	list := s.List(tok)
	if len(list) != 2 {
		t.Fatalf("listed %d sessions, want 2", len(list))
	}
	var current int
	for _, e := range list {
		if e.ID == tok || e.ID == other {
			t.Error("inventory exposed a session token as its id")
		}
		if len(e.ID) < 8 {
			t.Errorf("session id %q is too short to be unguessable", e.ID)
		}
		if e.Current {
			current++
		}
	}
	if current != 1 {
		t.Errorf("%d sessions marked current, want exactly 1", current)
	}
	if list[0].From == "" {
		t.Error("inventory records no source address, so an admin cannot tell sessions apart")
	}
}

func TestRevokeByIDAndOthers(t *testing.T) {
	s := NewSessions(time.Hour, 24*time.Hour)
	mine := s.Create("admin", "192.0.2.1")
	theirs := s.Create("admin", "192.0.2.2")
	bob := s.Create("bob", "192.0.2.3")

	var theirID string
	for _, e := range s.List(mine) {
		if !e.Current && e.User == "admin" {
			theirID = e.ID
		}
	}
	if !s.DeleteID(theirID) {
		t.Fatal("DeleteID did not find the session")
	}
	if _, ok := s.Get(theirs); ok {
		t.Error("revoked session still works")
	}
	if _, ok := s.Get(mine); !ok {
		t.Error("revoking one session killed another")
	}

	// Sign out everywhere else must keep the session it was invoked from —
	// otherwise the admin fixing a stolen cookie logs themselves out too.
	again := s.Create("admin", "192.0.2.4")
	if n := s.DeleteOthers("admin", mine); n != 1 {
		t.Errorf("DeleteOthers dropped %d, want 1", n)
	}
	if _, ok := s.Get(mine); !ok {
		t.Error("DeleteOthers logged out the caller's own session")
	}
	if _, ok := s.Get(again); ok {
		t.Error("DeleteOthers left another session of the same user alive")
	}
	if _, ok := s.Get(bob); !ok {
		t.Error("DeleteOthers touched a different user's session")
	}
}

func TestElevationWindow(t *testing.T) {
	now := time.Now()
	s := NewSessions(time.Hour, 24*time.Hour)
	s.now = func() time.Time { return now }
	tok := s.Create("admin", "192.0.2.1")

	if s.Elevated(tok) {
		t.Error("a fresh session is elevated; re-auth would be meaningless")
	}
	s.Elevate(tok, 5*time.Minute)
	if !s.Elevated(tok) {
		t.Error("Elevate did not take")
	}
	now = now.Add(6 * time.Minute)
	if s.Elevated(tok) {
		t.Error("elevation outlived its window")
	}

	s.Elevate(tok, 5*time.Minute)
	s.DropElevation(tok)
	if s.Elevated(tok) {
		t.Error("DropElevation did not end the window")
	}
}
