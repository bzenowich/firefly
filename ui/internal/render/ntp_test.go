package render

import (
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

func TestNTPDefault(t *testing.T) {
	out, err := NTP(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"driftfile /var/db/ntpd.drift",
		"restrict default limited kod nomodify notrap noquery nopeer",
		"server pool.ntp.org iburst",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestNTPNoServersServesNothing(t *testing.T) {
	cfg := config.Default()
	cfg.System.NTPServers = nil
	out, err := NTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The restrict posture stays (it costs nothing and is the safe default),
	// but nothing is synced against and apply stops the daemon.
	if strings.Contains(out, "\nserver ") {
		t.Errorf("rendered a time source with none configured:\n%s", out)
	}
	if !strings.Contains(out, "restrict default") {
		t.Errorf("dropped the restrict posture:\n%s", out)
	}
}
