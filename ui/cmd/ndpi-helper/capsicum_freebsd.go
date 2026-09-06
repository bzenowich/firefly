//go:build freebsd

package main

import "golang.org/x/sys/unix"

// enterCapabilityMode puts this process into Capsicum capability mode
// (docs/security-plan.md SEC-2a).
//
// After cap_enter(2) the process keeps the descriptors it already holds and
// loses the global namespace entirely: no open(2) by path, no connect(2) by
// path, no new sockets. For a process whose whole remaining job is reading
// frames from already-open bpf devices and writing labels to an already-open
// socket, that is close to the ideal sandbox — and this process links libnDPI,
// tens of thousands of lines of C dissectors aimed at hostile traffic, which is
// the most likely thing on the appliance to be exploitable.
//
// It is opt-in rather than default because two things about it can only be
// established on real hardware: whether libnDPI opens any file after
// initialisation (custom category and risk lists are a documented feature, and
// a build that uses them would fault), and whether the Go runtime does. Both
// would appear as the classifier dying rather than as a visible error, so the
// flag defaults off until someone has watched it run.
func enterCapabilityMode() error { return unix.CapEnter() }

// capsicumSupported reports whether this build can enter capability mode.
const capsicumSupported = true
