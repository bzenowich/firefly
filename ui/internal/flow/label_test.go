package flow

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestLabelNDJSONRoundTrip(t *testing.T) {
	in := Label{
		Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("1.1.1.1"),
		SPort: 51000, DPort: 443, Proto: 6, App: "TLS.Netflix",
	}
	var buf bytes.Buffer
	if err := WriteLabel(&buf, in); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("NDJSON line not newline-terminated")
	}
	var got []Label
	if err := ReadLabels(&buf, func(l Label) error { got = append(got, l); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != in {
		t.Fatalf("round trip: got %+v, want %+v", got, in)
	}
}

func TestReadLabelsSkipsMalformed(t *testing.T) {
	stream := `{"src":"10.0.0.5","dst":"1.1.1.1","sport":51000,"dport":443,"proto":6,"app":"TLS"}
not json
{"src":"10.0.0.6","dst":"8.8.8.8","sport":33000,"dport":53,"proto":17,"app":"DNS"}
`
	var got []Label
	if err := ReadLabels(strings.NewReader(stream), func(l Label) error { got = append(got, l); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d labels, want 2 (malformed line skipped)", len(got))
	}
	if got[0].App != "TLS" || got[1].App != "DNS" {
		t.Errorf("apps: %q, %q", got[0].App, got[1].App)
	}
}

func TestNormKeyDirectionAgnostic(t *testing.T) {
	a := netip.MustParseAddr("10.0.0.5")
	b := netip.MustParseAddr("1.1.1.1")
	// Forward and reverse of the same conversation share a key.
	fwd := normKey(a, 51000, b, 443, 6)
	rev := normKey(b, 443, a, 51000, 6)
	if fwd != rev {
		t.Errorf("forward %v != reverse %v", fwd, rev)
	}
	// A different proto is a different flow.
	if normKey(a, 51000, b, 443, 17) == fwd {
		t.Error("proto not part of key")
	}
	// A different port is a different flow.
	if normKey(a, 51001, b, 443, 6) == fwd {
		t.Error("port not part of key")
	}
}
