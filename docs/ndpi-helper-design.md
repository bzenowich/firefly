# nDPI Helper — App-Layer Enrichment (design)

Phase 2 of `docs/visibility-design.md`: add application labels (Netflix, QUIC,
BitTorrent, …) onto the baseline flow records. `pflow(4)` supplies byte/packet
counts but never sees payload, so it cannot name applications. A separate helper
process performs deep-packet inspection on the first few packets of each flow,
reaches a verdict, and streams `{5-tuple → app}` enrichment to the in-process
collector, which stamps the label onto matching flows.

This document specifies the wire protocol, the flow join, the collector-side
data flow, and the helper's internals. It builds on the Phase 1 store, which
already ships the `app` column, the `app_roll` table, and the "Top apps" query
path — all empty until this lands, by design, so no migration is needed.

## 1. Why a separate process (hard constraint)

`libnDPI` is **LGPL**. `plan.md` §8 forbids LGPL/GPL code in the `fwd` binary.
cgo-linking nDPI into `fwd` would link LGPL into the Go binary, so the helper is
its own binary that links `libnDPI` **dynamically**. `fwd` stays pure Go and
GPL-clean. This is the *only* reason for the split: the collector itself remains
in-process. The boundary is a process boundary plus a dynamic link, never cgo
inside `fwd`.

## 2. Architecture

```
                       first ~5–10 pkts/flow
   capture device ──▶ ndpi-helper ──▶ libnDPI verdict
   (libpcap)            │  flow-state table
                        │  {5-tuple → app}, NDJSON
                        ▼
                  unix socket (/var/run/fw-ndpi.sock)
                        │
   pflow ──IPFIX──▶ flow Collector ──stamp app──▶ flows.db
                    + LabelCache         (join on normalized 5-tuple)
```

- The **helper** is the only component that touches packets, and only the flow
  head: it inspects each flow until nDPI reaches a verdict (typically within
  5–10 packets — TLS SNI, HTTP Host, QUIC, protocol fingerprint), then stops
  inspecting that flow. It does **no byte accounting** — counting bytes in
  userland is the line-rate cost `pflow` exists to avoid.
- The **collector** (Phase 1, in `fwd`) listens on a unix socket for label
  records, holds them in a short-TTL cache, and stamps the app onto pflow flows
  as they are inserted. `fwd` spawns and supervises the helper.

## 3. Wire protocol (helper → collector)

Transport: a **unix stream socket**. The collector listens; the helper connects
and streams, reconnecting with backoff if the socket drops. Localhost-only,
filesystem-permissioned (0600, owned by the service user) — the enrichment never
leaves the box and needs no auth beyond file permissions.

Framing: **newline-delimited JSON** (NDJSON), one label record per line.
Debuggable (`nc -U` + read), trivial to parse, matches the codebase's pragmatic
style. One record is emitted per flow when nDPI reaches its verdict:

```json
{"src":"10.0.0.5","dst":"1.1.1.1","sport":51000,"dport":443,"proto":6,"app":"TLS.Netflix"}
```

| Field | Type | Meaning |
|---|---|---|
| `src`,`dst` | string | IPs as the helper saw them (its capture direction) |
| `sport`,`dport` | uint16 | transport ports |
| `proto` | uint8 | IP protocol number |
| `app` | string | nDPI label, e.g. `TLS.Netflix`, `QUIC`, `BitTorrent` |

The helper sends the flow in whatever direction it observed first; the collector
normalizes (below), so direction does not matter. `app` is opaque to the
collector — whatever string nDPI produces is stored and displayed verbatim.

## 4. The join (direction-normalized 5-tuple)

A conversation and its reverse are the same flow and share one app label, but
`pflow` may export either direction and the helper may have seen either first.
So the join key is a **direction-normalized 5-tuple**: the two endpoints
`(ip, port)` are ordered canonically and the smaller is placed first.

```
key = (proto, min(endpointA, endpointB), max(endpointA, endpointB))
```

Both the cache (keyed by this) and the SQL backfill (which matches both the
as-seen and the swapped tuple) use this normalization, so a pflow flow finds its
label regardless of which side initiated or which side the helper saw first.

`ifindex` is **not** part of the key in v1. Matching pflow's ingress ifindex to a
pcap helper's capture device is unreliable (design-doc open question), and the
5-tuple is unique enough on a single box within the short cache window. ifindex
stays available on the raw flow for display.

## 5. Collector-side data flow

The collector gains a `LabelCache` and a unix-socket listener. Two paths set the
app, covering both orderings of the inherent race between a flow's IPFIX export
and its classification:

1. **Stamp at insert (primary).** nDPI classifies at flow *start*; `pflow`
   exports at flow *expiry* (state teardown / active timeout). So the label
   almost always arrives **before** the pflow flow. On `Collector.ingest`, each
   record's normalized key is looked up in the cache and the app stamped before
   `store.Insert`. This is the common path and the one that feeds `app_roll`
   correctly (the rollup reads app from raw, and insert precedes rollup).

2. **Backfill on label (backstop).** If a flow was inserted with `app = NULL`
   before its label arrived, the incoming label triggers a bounded
   `UPDATE flows SET app=? WHERE app IS NULL AND <key matches either direction>
   AND ts > <raw window>`. This corrects the **flow-log** view.

   *Known limitation:* a flow already folded into the rollups (past the rollup
   watermark) with `app = NULL` will be corrected in the raw log but not
   retroactively added to `app_roll` for that bucket. Because path 1 is the
   overwhelmingly common case, `app_roll` is correct in practice; the backstop
   exists for the flow log, and this gap is accepted for v1 rather than carrying
   a second app-only watermark.

Cache entries carry an insertion time and are evicted after a short TTL (a few
minutes — well past the gap between classification and export). The cache is
bounded by TTL, not count; flow rates on a home/SMB box keep it small.

The TTL alone cannot cover **long-lived flows**: `pflow(4)` exports only at pf
state teardown, so an hours-long stream — exactly the flow whose app label
matters most — would outlive any sane TTL. The helper closes this gap by
**re-emitting** a classified flow's label while the flow stays active (every
`labelRefresh`, below the cache TTL), keeping the cache entry warm until the
export finally arrives.

## 6. Helper internals (`cmd/ndpi-helper`)

```
 Source ──pkt meta──▶ Engine ──verdict──▶ Sink (NDJSON over unix socket)
 (libpcap)            flow-state table
                      Classifier (libnDPI)
```

Three seams, each an interface so the LGPL/C parts are isolated and the engine
is testable in pure Go:

- **`Source`** yields packet metadata (`{5-tuple, ifindex, payload, dir}`). The
  real source is **libpcap** behind a build tag (`//go:build pcap`, cgo); a
  channel-fed source drives unit tests.
- **`Classifier`** maps a flow + its accumulated packets to `(app, done)`. The
  real impl links **libnDPI** behind `//go:build ndpi` (cgo, dynamic). A
  **stub** (`//go:build !ndpi`) classifies by well-known port (443→`TLS`,
  53→`DNS`, 51820→`WireGuard`, …) so the binary builds and the whole pipeline is
  exercisable without the C library present.
- **`Sink`** writes `flow.Label` records as NDJSON to the collector socket, with
  connect/reconnect-with-backoff.

The **Engine** owns the flow-state table: `map[normKey]*flowState{pkts, ndpi,
done}`. For each packet it routes to the flow's state, feeds the Classifier
until `done` (verdict reached or a max-packet cap hit), emits one `Label` on
verdict, and stops inspecting that flow. Later packets of a labeled flow only
re-emit the stored label on the `labelRefresh` interval (§5 — long-lived flows
must outlast the collector's cache TTL); the classifier is never fed again.
Idle flows are evicted on a timer so the table is bounded.

The wire types (`flow.Label`, the NDJSON reader/writer, and the normalized key)
live in `internal/flow` as **pure Go** and are imported by the helper. Sharing
the protocol type does not contaminate licensing: `libnDPI` is linked only into
the helper binary; `internal/flow` and `fwd` carry no C.

## 7. Supervision & packaging

- **Supervision.** `fwd` starts the helper when `Flow.Enabled`, passing the
  socket path and capture devices, and restarts it with backoff if it exits —
  the same in-process-supervisor shape the logs collector uses, gated to FreeBSD
  (the appliance). On a dev box `fwd` does not spawn it; the collector's socket
  listener still runs, so a fake helper (or the stub binary) can drive the
  pipeline for testing.
- **Packaging.** The helper is built in the **OS image pipeline** as a base
  package (baseline tier — it ships always-on, unlike the opt-in ntopng power
  tier), linking `libnDPI` **dynamically, never static**, to keep the LGPL
  boundary at the dynamic-link line.

## 8. Build phasing

1. **Wire protocol + collector enrichment** (pure Go, testable now): `flow.Label`
   + normalized key + NDJSON codec; `LabelCache`; the socket listener;
   stamp-at-insert; the backfill UPDATE; store method + tests.
2. **Helper engine** (pure Go, testable now): `Source`/`Classifier`/`Sink`
   interfaces, the stub classifier, the flow-state engine, the NDJSON sink, and
   `main` wiring; engine tests with an injected source and a fake socket.
3. **Real capture + nDPI** (built only in the OS pipeline): `source_pcap.go` and
   `classifier_ndpi.go` behind build tags, linking libpcap and libnDPI.
4. **Supervision**: `fwd` spawns/supervises the helper on the appliance.

Phases 1, 2, and 4 build and are verified on the dev box with the stub
classifier; phase 3 is the only C dependency and is exercised in the image
build.

## 9. Testing

- **Codec / key:** round-trip `Label` NDJSON; normalized key equates a flow and
  its reverse, separates different flows.
- **Enrichment:** label-before-insert stamps app at insert (and into `app_roll`
  via rollup); label-after-insert backfills the raw flow log; non-matching
  labels leave flows `NULL`.
- **Engine:** an injected source of synthetic packets yields exactly one `Label`
  per flow at the verdict, stops inspecting afterward, and evicts idle flows.
- **End-to-end (dev box):** a fake helper emits NDJSON to the collector socket;
  a pflow flow on the same 5-tuple comes out app-labeled via `/api/flows`.

## 10. Cross-references

- `docs/visibility-design.md` — the baseline pipeline this enriches (esp. §3
  components, §6 phasing, §7 open questions on capture source and ifindex)
- `plan.md` §8 — the Go/C build-vs-integrate split and the LGPL rule
- `plan.md` §8.5 — the AI assist layer consumes the app-labeled flows
