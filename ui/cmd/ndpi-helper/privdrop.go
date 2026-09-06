package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

// dropPrivilege irreversibly drops to the named account.
//
// This process links libpcap and libnDPI — tens of thousands of lines of C
// protocol dissectors — and points them at raw frames off the WAN. It is the
// highest-value remote code execution target on the appliance
// (docs/security-plan.md SEC-2a), and it needs root for exactly one thing:
// opening /dev/bpf*. Once the capture handles and the label socket are open it
// needs no privilege at all, so it gives it up.
//
// Order matters and is not negotiable: supplementary groups, then the real and
// effective gid, then the uid. Dropping the uid first would make every later
// call fail, leaving the process running with the groups it meant to shed —
// the classic half-drop.
//
// The bpf grant comes from group membership (devfs.rules, docs/security-plan.md
// §3.3), so the target account keeps whatever supplementary groups it is a
// member of; it simply is not root.
func dropPrivilege(name string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("account %q: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return "", fmt.Errorf("account %q: unusable uid %q", name, u.Uid)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return "", fmt.Errorf("account %q: unusable gid %q", name, u.Gid)
	}

	// Already the target account: nothing to drop, and nothing to prove. The
	// syscalls below all require privilege we do not have in that case — even
	// setgroups with the identical group list is refused — so attempting them
	// would turn "already correct" into a fatal error. This is the path taken
	// when a supervisor other than our rc.d script starts us directly as the
	// service account.
	if os.Getuid() == uid && os.Geteuid() == uid {
		return u.Username, nil
	}

	gidStrs, err := u.GroupIds()
	if err != nil {
		return "", fmt.Errorf("account %q: reading groups: %w", name, err)
	}
	groups := make([]int, 0, len(gidStrs))
	for _, s := range gidStrs {
		g, err := strconv.Atoi(s)
		if err != nil {
			return "", fmt.Errorf("account %q: unusable group %q", name, s)
		}
		groups = append(groups, g)
	}

	if err := unix.Setgroups(groups); err != nil {
		return "", fmt.Errorf("setgroups: %w", err)
	}
	if err := unix.Setgid(gid); err != nil {
		return "", fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := unix.Setuid(uid); err != nil {
		return "", fmt.Errorf("setuid(%d): %w", uid, err)
	}

	if err := verifyDropped(uid, gid); err != nil {
		return "", err
	}
	return u.Username, nil
}

// verifyDropped confirms the drop actually took and cannot be undone.
//
// Checking is not paranoia. A setuid that silently fails, or one that leaves a
// saved-set-uid of 0 behind, produces a process that looks unprivileged and is
// not — and this particular process is the one parsing hostile packets. If any
// of this is wrong the caller exits: a root packet parser is not an acceptable
// degraded mode.
func verifyDropped(uid, gid int) error {
	if got := unix.Getuid(); got != uid {
		return fmt.Errorf("uid is %d after setuid(%d)", got, uid)
	}
	if got := unix.Geteuid(); got != uid {
		return fmt.Errorf("effective uid is %d after setuid(%d)", got, uid)
	}
	if got := unix.Getgid(); got != gid {
		return fmt.Errorf("gid is %d after setgid(%d)", got, gid)
	}
	if uid == 0 {
		return nil // asked to run as root; nothing was dropped and nothing to prove
	}
	// The saved-set-uid is the one that does not show up in getuid/geteuid. If
	// it were still 0 the process could climb back, so prove it cannot by
	// trying: this must fail.
	if err := unix.Setuid(0); err == nil {
		return fmt.Errorf("regained uid 0 after dropping to %d: the drop is not irreversible", uid)
	}
	return nil
}
