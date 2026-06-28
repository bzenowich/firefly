//go:build !ndpi

package main

// The stub classifier ships when the binary is built without the `ndpi` tag. It
// labels flows by well-known port — enough to exercise the whole pipeline on a
// dev box and on appliances where libnDPI is not installed, without any C
// dependency. The real port of nDPI (classifier_ndpi.go) replaces it under
// `-tags ndpi` and yields true app identification from payload.

// portApp maps a well-known service port to a coarse app label. The service is
// whichever endpoint owns the lower port, so the engine checks the smaller of
// the two ports first.
var portApp = map[uint16]string{
	22:    "SSH",
	53:    "DNS",
	67:    "DHCP",
	80:    "HTTP",
	123:   "NTP",
	143:   "IMAP",
	443:   "TLS",
	465:   "SMTPS",
	587:   "SMTP",
	853:   "DoT",
	993:   "IMAPS",
	3478:  "STUN",
	5353:  "mDNS",
	51820: "WireGuard",
}

type stubClassifier struct{}

func newClassifier() Classifier { return stubClassifier{} }

// Classify is one-shot: a port lookup needs no payload, so it returns a final
// verdict on the first packet. An unknown port yields an empty label (the
// engine emits nothing) so the flow log isn't polluted with guesses.
func (stubClassifier) Classify(_ *FlowState, p Packet) (string, bool) {
	lo, hi := p.SPort, p.DPort
	if hi < lo {
		lo, hi = hi, lo
	}
	if app, ok := portApp[lo]; ok {
		return app, true
	}
	if app, ok := portApp[hi]; ok {
		return app, true
	}
	return "", true
}
