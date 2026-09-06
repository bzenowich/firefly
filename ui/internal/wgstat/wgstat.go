// Package wgstat reads live WireGuard peer state from the kernel.
//
// It is a privileged read: wg(8) queries the interface through an ioctl that
// the kernel restricts to root, so on a split appliance this runs in fwd-helper
// and the answer comes back over the boundary (docs/security-plan.md §3.1).
// The web daemon only formats it.
package wgstat

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// timeout bounds the query. It is a local ioctl; if it has not answered in
// three seconds something is wrong and a stale "never" is better than a page
// that will not render.
const timeout = 3 * time.Second

// Peers returns each peer's last handshake time on dev, keyed by public key.
//
// Peers with no handshake yet are omitted rather than reported as the unix
// epoch, so the caller can render "never" without a sentinel.
func Peers(dev string) (map[string]time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "wg", "show", dev, "latest-handshakes").Output()
	if err != nil {
		return nil, err
	}
	return parse(string(out)), nil
}

// parse reads the two-column "<public key>\t<unix seconds>" output.
func parse(out string) map[string]time.Time {
	peers := map[string]time.Time{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		secs, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || secs == 0 {
			continue // 0 means the peer has never completed a handshake
		}
		peers[fields[0]] = time.Unix(secs, 0)
	}
	return peers
}
