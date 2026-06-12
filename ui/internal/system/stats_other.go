//go:build !linux && !freebsd

package system

// Unsupported dev platforms still get hostname and interface up/down from
// the portable path in Collect.

func collectPlatform(*Stats) {}

func ifCounters() map[string][2]uint64 { return nil }
