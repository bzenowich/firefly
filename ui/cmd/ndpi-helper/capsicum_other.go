//go:build !freebsd

package main

import "errors"

// enterCapabilityMode is FreeBSD-only. Elsewhere -capsicum is refused rather
// than silently ignored: a flag that claims to sandbox and does nothing is
// worse than no flag.
func enterCapabilityMode() error {
	return errors.New("capability mode is a FreeBSD facility")
}

const capsicumSupported = false
