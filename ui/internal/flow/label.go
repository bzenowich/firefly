package flow

import (
	"bufio"
	"encoding/json"
	"io"
	"net/netip"
)

// Label is one app-layer enrichment record: the nDPI verdict for a flow,
// streamed from the ndpi-helper to the collector over a unix socket as NDJSON
// (docs/ndpi-helper-design.md §3). The helper sends the flow in whatever
// direction it observed; the collector normalizes the 5-tuple on its end, so
// direction here is not significant. App is opaque — whatever string nDPI
// produced (e.g. "TLS.Netflix", "QUIC", "BitTorrent").
type Label struct {
	Src   netip.Addr `json:"src"`
	Dst   netip.Addr `json:"dst"`
	SPort uint16     `json:"sport"`
	DPort uint16     `json:"dport"`
	Proto uint8      `json:"proto"`
	App   string     `json:"app"`
}

// key is the direction-normalized 5-tuple used to join a Label to a pflow flow
// (design §4). A conversation and its reverse share one key, so the two
// endpoints are ordered canonically with the smaller first.
type key struct {
	proto uint8
	a, b  netip.AddrPort // a <= b
}

// normKey builds the normalized join key from a 5-tuple in either direction.
func normKey(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, proto uint8) key {
	ep1 := netip.AddrPortFrom(src, sport)
	ep2 := netip.AddrPortFrom(dst, dport)
	if comparePort(ep2, ep1) < 0 {
		ep1, ep2 = ep2, ep1
	}
	return key{proto: proto, a: ep1, b: ep2}
}

// key returns the Label's normalized join key.
func (l Label) key() key {
	return normKey(l.Src, l.SPort, l.Dst, l.DPort, l.Proto)
}

// comparePort orders two endpoints: by address first, then port. netip.Addr's
// own Compare gives a stable total order across v4/v6.
func comparePort(x, y netip.AddrPort) int {
	if c := x.Addr().Compare(y.Addr()); c != 0 {
		return c
	}
	switch {
	case x.Port() < y.Port():
		return -1
	case x.Port() > y.Port():
		return 1
	default:
		return 0
	}
}

// WriteLabel encodes a Label as one NDJSON line. Used by the helper's sink.
func WriteLabel(w io.Writer, l Label) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// maxAppLen bounds an app label. nDPI's longest real verdicts are well inside
// this ("TLS.GoogleServices" is 18); anything longer is not a protocol name.
const maxAppLen = 64

// SanitizeApp constrains an app label to what a protocol name can be, returning
// "" for anything else.
//
// The label is derived from attacker-controlled bytes: nDPI reads it out of a
// TLS SNI or an HTTP Host header, which is to say out of whatever the remote
// end chose to send. It then travels to the admin's browser and into the flow
// database. Constraining it at ingest means every consumer downstream — the
// Visibility page's JavaScript, a future export, a log line — is handling a
// protocol name rather than a hostile string, and none of them has to remember
// that (docs/security-plan.md SEC-13).
//
// Rejecting rather than escaping is deliberate: an app label that needs
// escaping is not an app label.
func SanitizeApp(app string) string {
	if app == "" || len(app) > maxAppLen {
		return ""
	}
	for _, r := range app {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '+' || r == '/':
		default:
			return ""
		}
	}
	return app
}

// ReadLabels decodes an NDJSON Label stream, calling fn for each record until
// the reader ends or fn returns an error. Malformed lines are skipped so one
// bad record never tears down the stream; a fatal read error is returned.
func ReadLabels(r io.Reader, fn func(Label) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var l Label
		if err := json.Unmarshal(line, &l); err != nil {
			continue // skip malformed line
		}
		// Sanitize here rather than at each consumer: this is the one place
		// every label enters the system.
		if l.App = SanitizeApp(l.App); l.App == "" {
			continue
		}
		if err := fn(l); err != nil {
			return err
		}
	}
	return sc.Err()
}
