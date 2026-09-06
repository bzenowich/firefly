//go:build !freebsd && !linux

package peercred

import (
	"errors"
	"net"
)

// UID has no implementation on this platform. The helper treats that as
// fatal rather than as "skip the check": a privileged service that cannot
// identify its caller must not accept one.
func UID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are not available on this platform")
}
