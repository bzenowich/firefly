package main

import (
	"context"
	"net/netip"
	"time"

	"firewall/ui/internal/flow"
)

// maxClassifyPkts caps how many packets the engine feeds a flow before giving
// up: nDPI almost always decides within the flow head, and an undecided flow
// past this is treated as classified-unknown so its state can be dropped.
const maxClassifyPkts = 12

// idleTTL bounds how long a flow's state is kept after its last packet, so the
// state table can't grow without bound on a busy box.
const idleTTL = 2 * time.Minute

// flowKey is the engine's direction-normalized flow identity, mirroring the
// collector's join key so a flow the helper labels matches the same flow pflow
// exports. Kept local to avoid coupling the helper to the collector's internals.
type flowKey struct {
	proto uint8
	a, b  netip.AddrPort
}

func keyOf(p Packet) flowKey {
	x := netip.AddrPortFrom(p.Src, p.SPort)
	y := netip.AddrPortFrom(p.Dst, p.DPort)
	if less(y, x) {
		x, y = y, x
	}
	return flowKey{proto: p.Proto, a: x, b: y}
}

func less(x, y netip.AddrPort) bool {
	if c := x.Addr().Compare(y.Addr()); c != 0 {
		return c < 0
	}
	return x.Port() < y.Port()
}

// Sink receives the app labels the engine produces. The production sink streams
// them as NDJSON to the collector socket; tests use a recording sink.
type Sink interface {
	Emit(flow.Label) error
}

type flowEntry struct {
	state    FlowState
	done     bool
	lastSeen time.Time
}

// Engine drives classification: it groups packets into flows, feeds each flow's
// packets to the Classifier until a verdict, emits one Label per flow on the
// verdict, and stops inspecting that flow. Idle flow state is evicted on a
// timer. Single-goroutine — no locking on the flow table.
type Engine struct {
	src   Source
	cls   Classifier
	sink  Sink
	flows map[flowKey]*flowEntry
	now   func() time.Time // injectable clock for tests
}

func NewEngine(src Source, cls Classifier, sink Sink) *Engine {
	return &Engine{
		src:   src,
		cls:   cls,
		sink:  sink,
		flows: map[flowKey]*flowEntry{},
		now:   time.Now,
	}
}

// Run consumes packets until the source is exhausted or ctx is cancelled,
// evicting idle flow state periodically.
func (e *Engine) Run(ctx context.Context) error {
	evict := time.NewTicker(idleTTL)
	defer evict.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case p, ok := <-e.src.Packets():
			if !ok {
				return nil
			}
			e.handle(p)
		case <-evict.C:
			e.evictIdle()
		}
	}
}

// handle routes one packet to its flow and advances classification.
func (e *Engine) handle(p Packet) {
	k := keyOf(p)
	fe := e.flows[k]
	if fe == nil {
		fe = &flowEntry{}
		e.flows[k] = fe
	}
	fe.lastSeen = e.now()
	if fe.done {
		return // already classified; ignore the rest of the flow
	}
	fe.state.Pkts++
	app, done := e.cls.Classify(&fe.state, p)
	if !done && fe.state.Pkts < maxClassifyPkts {
		return
	}
	// Verdict reached, or the cap hit: stop inspecting this flow.
	fe.done = true
	if app != "" {
		_ = e.sink.Emit(flow.Label{
			Src: p.Src, Dst: p.Dst, SPort: p.SPort, DPort: p.DPort,
			Proto: p.Proto, App: app,
		})
	}
}

// evictIdle drops flow state untouched for longer than idleTTL.
func (e *Engine) evictIdle() {
	cutoff := e.now().Add(-idleTTL)
	for k, fe := range e.flows {
		if fe.lastSeen.Before(cutoff) {
			delete(e.flows, k)
		}
	}
}
