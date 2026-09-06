package main

import (
	"os"
	"os/user"
	"testing"
)

// A drop to a nonexistent account must fail loudly. The caller treats every
// error here as fatal, because a root packet parser is not an acceptable
// degraded mode — so a silent failure is the dangerous outcome, not a noisy one.
func TestDropPrivilegeUnknownAccount(t *testing.T) {
	if _, err := dropPrivilege("no-such-account-hopefully"); err == nil {
		t.Fatal("dropPrivilege accepted an account that does not exist")
	}
}

// Dropping to the account we already are is a no-op, not an error. The
// syscalls all require privilege we do not have in that case — even setgroups
// with an identical list is refused — so without the short-circuit this would
// be a fatal "operation not permitted" for a process that is already exactly
// where it should be.
func TestDropPrivilegeToSelf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: dropping to root proves nothing about the drop")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	name, err := dropPrivilege(u.Username)
	if err != nil {
		t.Fatalf("dropPrivilege(%q): %v", u.Username, err)
	}
	if name != u.Username {
		t.Errorf("reported %q, want %q", name, u.Username)
	}
}

// verifyDropped is what stands between a half-completed drop and a process that
// looks unprivileged while still being able to climb back. Check it rejects a
// uid that does not match reality.
func TestVerifyDroppedCatchesAMismatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	self := os.Getuid()
	if err := verifyDropped(self, os.Getgid()); err != nil {
		t.Errorf("verifyDropped rejected the truth: %v", err)
	}
	// A uid we are definitely not.
	if err := verifyDropped(self+1, os.Getgid()); err == nil {
		t.Error("verifyDropped accepted a uid the process does not have")
	}
	if err := verifyDropped(self, os.Getgid()+1); err == nil {
		t.Error("verifyDropped accepted a gid the process does not have")
	}
}

// The account's supplementary groups must survive the drop: on the appliance
// the bpf grant is carried by group membership (_fwdbpf), so a drop that
// cleared the groups would leave the classifier unable to capture anything.
//
// A real drop needs root. Unprivileged, this asserts the property that is
// checkable here — the no-op path leaves the process's groups exactly as they
// were, rather than clearing them on its way through. The genuine drop is
// checked on the box (docs/hw-bringup.md §8a).
func TestDropKeepsSupplementaryGroups(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dropPrivilege(u.Username); err != nil {
		t.Fatal(err)
	}
	after, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("group set changed: %v -> %v", before, after)
	}
	have := map[int]bool{}
	for _, g := range after {
		have[g] = true
	}
	for _, g := range before {
		if !have[g] {
			t.Errorf("group %d was dropped; the bpf grant travels this way", g)
		}
	}
}
