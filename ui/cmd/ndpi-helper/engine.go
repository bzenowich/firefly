package main

import (
	"context"
	"log"
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

// labelRefresh re-emits a classified flow's label while the flow stays active.
// pflow(4) exports a flow only at pf state teardown, so a long-lived flow (an
// hours-long video stream — exactly the flow the app label matters for) would
// otherwise outlive the collector's label cache TTL and insert unlabeled. Must
// stay comfortably below flow.labelTTL (5 min).
const labelRefresh = 2 * time.Minute

// maxFlows hard-caps concurrently tracked flows. Under -tags ndpi every tracked
// flow holds a C ndpi_flow_struct — ~1–2 KB that Go's GC neither sees nor
// reclaims, freed only by Release — plus ~100 B of Go map entry, so 100k flows
// is roughly the 0.3 GB plan.md §8.5 budgets for this process. Without a cap the
// table is bounded only by idleTTL: a SYN/UDP port scan or a P2P swarm creates
// tens of thousands of new tuples per second that never reach a verdict (one
// packet, no reply), so two minutes of that is millions of live C allocations
// and an OOM the Go heap profile can't even explain.
const maxFlows = 100_000

// pressureIdle is the idle cutoff applied when the table is full: entries quiet
// this long are reclaimed early to make room, well before the relaxed idleTTL
// they would otherwise get. Long enough that an ordinary flow between packets
// (TLS handshake round trips, a keepalive gap) is never sacrificed.
const pressureIdle = 10 * time.Second

// reclaimInterval throttles the pressure sweep, so a table pinned at maxFlows
// costs one O(maxFlows) scan per interval rather than one per packet.
const reclaimInterval = time.Second

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
	app      string // the verdict, kept for periodic re-emit on long flows
	lastSeen time.Time
	lastEmit time.Time
}

// Engine drives classification: it groups packets into flows, feeds each flow's
// packets to the Classifier until a verdict, emits one Label per flow on the
// verdict, and stops inspecting that flow. Idle flow state is evicted on a
// timer, and the table is hard-capped at maxFlows. Single-goroutine — no locking
// on the flow table.
type Engine struct {
	src   Source
	cls   Classifier
	sink  Sink
	flows map[flowKey]*flowEntry
	now   func() time.Time // injectable clock for tests

	maxFlows    int       // table cap; maxFlows, lowered by tests
	lastReclaim time.Time // last pressure sweep, throttled by reclaimInterval
	refused     uint64    // new flows dropped because the table was full
}

func NewEngine(src Source, cls Classifier, sink Sink) *Engine {
	return &Engine{
		src:      src,
		cls:      cls,
		sink:     sink,
		flows:    map[flowKey]*flowEntry{},
		now:      time.Now,
		maxFlows: maxFlows,
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
			e.reportRefused()
		}
	}
}

// handle routes one packet to its flow and advances classification. A packet
// for an already-tracked flow is always processed; only a packet that would
// create a new flow can be refused, and only when the table is full.
func (e *Engine) handle(p Packet) {
	k := keyOf(p)
	now := e.now()
	fe := e.flows[k]
	if fe == nil {
		if !e.admit(now) {
			return
		}
		fe = &flowEntry{}
		e.flows[k] = fe
	}
	fe.lastSeen = now
	if fe.done {
		// Already classified. Refresh the collector's cache entry while the
		// flow stays active, so the label survives until pflow's export at
		// state teardown (see labelRefresh).
		if fe.app != "" && now.Sub(fe.lastEmit) >= labelRefresh {
			fe.lastEmit = now
			e.emit(p, fe.app)
		}
		return
	}
	fe.state.Pkts++
	app, done := e.cls.Classify(&fe.state, p)
	if !done && fe.state.Pkts < maxClassifyPkts {
		return
	}
	// Verdict reached, or the cap hit: stop inspecting this flow.
	fe.done = true
	if app != "" {
		fe.app = app
		fe.lastEmit = now
		e.emit(p, app)
	}
	// The flow won't be fed again; free any classifier resources now rather
	// than waiting for eviction (a done flow can linger idleTTL otherwise).
	e.cls.Release(&fe.state)
}

func (e *Engine) emit(p Packet, app string) {
	_ = e.sink.Emit(flow.Label{
		Src: p.Src, Dst: p.Dst, SPort: p.SPort, DPort: p.DPort,
		Proto: p.Proto, App: app,
	})
}

// admit decides whether a new flow may be tracked. Below the cap it always can.
// At the cap the engine first tries to make room by reclaiming the entries idle
// past pressureIdle (at most once per reclaimInterval, so this stays cheap under
// a scan flood); if that frees nothing the new flow is refused. Refusing costs
// one unlabeled flow — the alternative, an unbounded table of C flow handles, is
// an OOM that takes the appliance down.
func (e *Engine) admit(now time.Time) bool {
	if len(e.flows) < e.maxFlows {
		return true
	}
	if now.Sub(e.lastReclaim) >= reclaimInterval {
		e.lastReclaim = now
		e.evictBefore(now.Add(-pressureIdle))
		if len(e.flows) < e.maxFlows {
			return true
		}
	}
	e.refused++
	return false
}

// reportRefused logs (and clears) the refused-flow count, so a table sitting at
// its cap is visible in the log rather than showing up only as missing labels.
func (e *Engine) reportRefused() {
	if e.refused == 0 {
		return
	}
	log.Printf("flow table full at %d flows: refused %d new flows since the last sweep",
		len(e.flows), e.refused)
	e.refused = 0
}

// evictIdle drops flow state untouched for longer than idleTTL.
func (e *Engine) evictIdle() { e.evictBefore(e.now().Add(-idleTTL)) }

// evictBefore drops every flow whose last packet predates cutoff. Releasing is
// the point: under -tags ndpi that is where the flow's C ndpi_flow_struct is
// freed, so every path that forgets a flow must come through here. Release is
// idempotent, so a flow already freed at its verdict is safely a no-op; an
// undecided flow (a 1-packet scan probe, say) is freed for the first time.
func (e *Engine) evictBefore(cutoff time.Time) {
	for k, fe := range e.flows {
		if fe.lastSeen.Before(cutoff) {
			e.cls.Release(&fe.state)
			delete(e.flows, k)
		}
	}
}
