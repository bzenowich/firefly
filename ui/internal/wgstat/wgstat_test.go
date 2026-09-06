package wgstat

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	const out = "" +
		"abc123=\t1757000000\n" +
		"def456=\t0\n" + // never handshaked
		"ghi789=\tnotanumber\n" + // junk
		"short\n" + // malformed
		"jkl012=\t1757000100\n"

	peers := parse(out)
	if len(peers) != 2 {
		t.Fatalf("parsed %d peers, want 2: %v", len(peers), peers)
	}
	if got := peers["abc123="]; !got.Equal(time.Unix(1757000000, 0)) {
		t.Errorf("abc123= = %v", got)
	}
	if _, ok := peers["def456="]; ok {
		t.Error("a peer that never handshaked should be omitted, not reported as the epoch")
	}
	for _, junk := range []string{"ghi789=", "short"} {
		if _, ok := peers[junk]; ok {
			t.Errorf("malformed line produced a peer: %q", junk)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	if got := parse(""); len(got) != 0 {
		t.Errorf("empty output produced %v", got)
	}
}
