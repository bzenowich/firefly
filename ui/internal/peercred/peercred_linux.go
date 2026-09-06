//go:build linux

package peercred

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// UID returns the uid of the process on the other end of a unix socket.
// Linux spells this SO_PEERCRED; like FreeBSD's LOCAL_PEERCRED the kernel
// supplies the values, so they cannot be forged by the peer.
//
// The appliance is FreeBSD; this exists so the privileged boundary can be run
// and tested on a dev box rather than only on hardware.
func UID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	return cred.Uid, nil
}
