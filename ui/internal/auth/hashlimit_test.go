package auth

import (
	"strings"
	"testing"
	"time"
)

// TestVerifyPasswordIsSlotGated proves the property that matters: a
// verification cannot start while every slot is held, so peak argon2 memory is
// a constant (slots x argonMemory) no matter how hard /login is driven
// (docs/security-plan.md SEC-4a).
func TestVerifyPasswordIsSlotGated(t *testing.T) {
	hash := HashPassword("correct horse")

	// Occupy every slot, so a gated VerifyPassword cannot proceed.
	n := cap(hashSlots)
	for i := 0; i < n; i++ {
		hashSlots <- struct{}{}
	}

	done := make(chan bool, 1)
	go func() { done <- VerifyPassword(hash, "correct horse") }()

	select {
	case <-done:
		t.Fatal("VerifyPassword ran with every hash slot held; it is not gated")
	case <-time.After(250 * time.Millisecond):
	}

	// Free one slot; it must now complete (and still be correct).
	<-hashSlots
	select {
	case ok := <-done:
		if !ok {
			t.Error("VerifyPassword returned false for the right password")
		}
	case <-time.After(hashWait):
		t.Fatal("VerifyPassword never completed after a slot was freed")
	}

	for i := 0; i < n-1; i++ {
		<-hashSlots
	}
	if len(hashSlots) != 0 {
		t.Errorf("%d slots leaked", len(hashSlots))
	}
}

func TestHashConcurrencyBounded(t *testing.T) {
	if got := cap(hashSlots); got < 1 || got > 4 {
		t.Errorf("hash slot cap is %d, want 1-4", got)
	}
}

// A hash is not always ours: POST /system/restore accepts a whole config
// document and validateUsers only checks the "$argon2id$" prefix. A crafted
// memory parameter must be refused, not honored.
func TestVerifyPasswordRejectsAbsurdParameters(t *testing.T) {
	real := HashPassword("secret")
	parts := strings.Split(real, "$")
	for _, params := range []string{
		"m=16777216,t=1,p=4", // 16 GiB
		"m=0,t=1,p=4",
		"m=65536,t=0,p=4",
		"m=65536,t=99,p=4",
		"m=65536,t=1,p=0",
	} {
		parts[3] = params
		if VerifyPassword(strings.Join(parts, "$"), "secret") {
			t.Errorf("accepted hash with parameters %q", params)
		}
	}
	// The genuine article still verifies.
	if !VerifyPassword(real, "secret") {
		t.Error("rejected a valid hash")
	}
}
