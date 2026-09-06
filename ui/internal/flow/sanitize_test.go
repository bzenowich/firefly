package flow

import (
	"strings"
	"testing"
)

// App labels are derived from attacker-controlled bytes: nDPI reads them out of
// a TLS SNI or an HTTP Host header. They then travel to the admin's browser and
// into the flow database (docs/security-plan.md SEC-13).
func TestSanitizeApp(t *testing.T) {
	for _, ok := range []string{
		"TLS.Netflix", "QUIC", "BitTorrent", "HTTP", "TLS.GoogleServices",
		"unknown-1", "app_name", "a/b", "SIP+TLS",
	} {
		if got := SanitizeApp(ok); got != ok {
			t.Errorf("SanitizeApp(%q) = %q, want it kept", ok, got)
		}
	}

	for _, bad := range []string{
		"",
		"<script>alert(1)</script>",
		`" onload="x`,
		"a\nb",
		"a\x00b",
		"app name", // a space is not part of a protocol name
		"café",     // non-ASCII
		strings.Repeat("a", maxAppLen+1),
	} {
		if got := SanitizeApp(bad); got != "" {
			t.Errorf("SanitizeApp(%q) = %q, want it rejected", bad, got)
		}
	}
}

// The stream reader is the one place every label enters the system, so it is
// where the constraint has to hold.
func TestReadLabelsDropsHostileApps(t *testing.T) {
	stream := strings.Join([]string{
		`{"src":"192.0.2.1","dst":"192.0.2.2","sport":1,"dport":2,"proto":6,"app":"TLS.Netflix"}`,
		`{"src":"192.0.2.1","dst":"192.0.2.3","sport":1,"dport":2,"proto":6,"app":"<img src=x onerror=alert(1)>"}`,
		`{"src":"192.0.2.1","dst":"192.0.2.4","sport":1,"dport":2,"proto":6,"app":"QUIC"}`,
	}, "\n")

	var got []string
	if err := ReadLabels(strings.NewReader(stream), func(l Label) error {
		got = append(got, l.App)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"TLS.Netflix", "QUIC"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("label %d = %q, want %q", i, got[i], want[i])
		}
	}
}
