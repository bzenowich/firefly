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

	// Three packets of the same TLS flow: exactly one label — re-emit only
	// happens after labelRefresh, not per packet.
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

func TestEngineRefreshesLongFlows(t *testing.T) {
	sink := &recordSink{}
	eng := NewEngine(newChanSource(0), stubClassifier{}, sink)
	now := time.Now()
	eng.now = func() time.Time { return now }

	// Verdict on the first packet, then a long-lived flow: each packet past
	// labelRefresh re-emits so the collector cache stays warm until pflow
	// exports at state teardown; packets inside the window do not.
	eng.handle(pkt("10.0.0.5", 51000, "1.1.1.1", 443, 6))
	now = now.Add(labelRefresh / 2)
	eng.handle(pkt("10.0.0.5", 51000, "1.1.1.1", 443, 6))
	if len(sink.labels) != 1 {
		t.Fatalf("emitted %d labels inside the refresh window, want 1", len(sink.labels))
	}
	now = now.Add(labelRefresh)
	eng.handle(pkt("10.0.0.5", 51000, "1.1.1.1", 443, 6))
	if len(sink.labels) != 2 {
		t.Fatalf("emitted %d labels after refresh interval, want 2", len(sink.labels))
	}
	if sink.labels[1].App != "TLS" {
		t.Errorf("refreshed app = %q, want TLS", sink.labels[1].App)
	}

	// An unlabeled flow (classified-unknown) never re-emits.
	eng.handle(pkt("10.0.0.5", 50000, "10.0.0.9", 49999, 6))
	now = now.Add(labelRefresh * 2)
	eng.handle(pkt("10.0.0.5", 50000, "10.0.0.9", 49999, 6))
	if len(sink.labels) != 2 {
		t.Fatalf("unknown flow re-emitted: %d labels, want 2", len(sink.labels))
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
func (countingClassifier) Release(*FlowState)                         {}

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

func TestEngineCapsFlowTable(t *testing.T) {
	sink := &recordSink{}
	eng := NewEngine(newChanSource(0), stubClassifier{}, sink)
	now := time.Now()
	eng.now = func() time.Time { return now }
	eng.maxFlows = 2 // maxFlows itself is 100k; the behavior is what matters

	tracked := pkt("10.0.0.5", 51000, "1.1.1.1", 443, 6)
	eng.handle(tracked)
	eng.handle(pkt("10.0.0.5", 51001, "1.1.1.1", 443, 6))
	// A third flow arrives with the table full and nothing idle enough to
	// reclaim: it is refused, not tracked.
	eng.handle(pkt("10.0.0.5", 51002, "1.1.1.1", 443, 6))
	if len(eng.flows) != 2 {
		t.Fatalf("flow table size %d, want 2 (capped)", len(eng.flows))
	}
	if eng.refused != 1 {
		t.Errorf("refused = %d, want 1", eng.refused)
	}

	// Packets for a flow already tracked keep working while the table is full:
	// this one is past labelRefresh, so it re-emits.
	before := len(sink.labels)
	now = now.Add(labelRefresh + time.Second)
	eng.handle(tracked)
	if len(sink.labels) != before+1 {
		t.Errorf("tracked flow emitted %d labels, want %d", len(sink.labels), before+1)
	}

	// Once an entry goes quiet past pressureIdle, the pressure sweep reclaims
	// it and a new flow is admitted again.
	now = now.Add(pressureIdle + time.Second)
	eng.handle(pkt("10.0.0.9", 40000, "1.1.1.1", 443, 6))
	if _, ok := eng.flows[keyOf(pkt("10.0.0.9", 40000, "1.1.1.1", 443, 6))]; !ok {
		t.Error("new flow not admitted after idle entries were reclaimed")
	}
}
