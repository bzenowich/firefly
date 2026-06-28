package main

import (
	"net/netip"
	"testing"
	"time"

	"firewall/ui/internal/flow"
)

// recordSink captures emitted labels for assertions.
type recordSink struct{ labels []flow.Label }

func (r *recordSink) Emit(l flow.Label) error { r.labels = append(r.labels, l); return nil }

func pkt(src string, sport uint16, dst string, dport uint16, proto uint8) Packet {
	return Packet{
		Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
		SPort: sport, DPort: dport, Proto: proto,
	}
}

func TestEngineEmitsOnePerFlow(t *testing.T) {
	sink := &recordSink{}
	eng := NewEngine(newChanSource(0), stubClassifier{}, sink)

	// Three packets of the same TLS flow: exactly one label, no re-emit.
	for i := 0; i < 3; i++ {
		eng.handle(pkt("10.0.0.5", 51000, "1.1.1.1", 443, 6))
	}
	if len(sink.labels) != 1 {
		t.Fatalf("emitted %d labels, want 1", len(sink.labels))
	}
	if sink.labels[0].App != "TLS" {
		t.Errorf("app = %q, want TLS", sink.labels[0].App)
	}
}

func TestEngineUnknownPortNoEmit(t *testing.T) {
	sink := &recordSink{}
	eng := NewEngine(newChanSource(0), stubClassifier{}, sink)
	eng.handle(pkt("10.0.0.5", 50000, "10.0.0.9", 49999, 6)) // no well-known port
	if len(sink.labels) != 0 {
		t.Fatalf("unknown flow emitted %d labels, want 0", len(sink.labels))
	}
}

func TestEngineEvictsIdle(t *testing.T) {
	sink := &recordSink{}
	eng := NewEngine(newChanSource(0), stubClassifier{}, sink)
	now := time.Now()
	eng.now = func() time.Time { return now }

	eng.handle(pkt("10.0.0.5", 51000, "1.1.1.1", 443, 6))
	if len(eng.flows) != 1 {
		t.Fatalf("flow table size %d, want 1", len(eng.flows))
	}
	// Advance past idleTTL and evict.
	now = now.Add(idleTTL + time.Second)
	eng.evictIdle()
	if len(eng.flows) != 0 {
		t.Errorf("flow table size %d after evict, want 0", len(eng.flows))
	}
}

// countingClassifier never decides, to exercise the maxClassifyPkts cap.
type countingClassifier struct{}

func (countingClassifier) Classify(*FlowState, Packet) (string, bool) { return "", false }

func TestEngineCapsClassification(t *testing.T) {
	sink := &recordSink{}
	eng := NewEngine(newChanSource(0), countingClassifier{}, sink)
	for i := 0; i < maxClassifyPkts+5; i++ {
		eng.handle(pkt("10.0.0.5", 51000, "1.1.1.1", 443, 6))
	}
	fe := eng.flows[keyOf(pkt("10.0.0.5", 51000, "1.1.1.1", 443, 6))]
	if !fe.done {
		t.Error("flow not marked done after hitting the packet cap")
	}
	if fe.state.Pkts != maxClassifyPkts {
		t.Errorf("inspected %d packets, want cap %d", fe.state.Pkts, maxClassifyPkts)
	}
}
