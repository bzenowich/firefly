//go:build freebsd

package peercred

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// UID returns the uid of the process on the other end of a unix socket.
//
// FreeBSD answers this with LOCAL_PEERCRED, which fills a struct xucred with
// the credentials the peer had when it called connect(2). The kernel supplies
// them, so a peer cannot claim someone else's uid.
//
// This is the appliance's real implementation; the Linux one exists so the
// boundary is exercisable on a dev box.
func UID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		cred    *unix.Xucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, fmt.Errorf("LOCAL_PEERCRED: %w", credErr)
	}
	return cred.Uid, nil
}
