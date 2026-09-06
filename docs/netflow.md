# Native traffic visibility — replacing ntopng

> ## ⛔ SUPERSEDED — historical, not the design of record
>
> **The design of record is [`visibility-design.md`](./visibility-design.md).**
> That pipeline is **built and shipping**: kernel `pflow(4)` → Go IPFIX collector →
> SQLite → the native Flows UI, with app labels from a separate `cmd/ndpi-helper`
> process. Cite that doc, not this one.
>
> Two things this document asserts are **no longer true**, and they are exactly the
> assertions that would mislead:
>
> - **"cgo-free" is not a hard constraint.** It was, and the reasoning below (§2, §2.1,
>   §5) is why we tried to hold it. What actually resolved it is that the constraint
>   only ever needed to hold for **`fwd`** — and it still does: `fwd` is pure Go
>   (`modernc.org/sqlite`) and `deploy.sh` cross-compiles it with a plain
>   `GOOS=freebsd go build`. The C dependency lives in a **separate binary**, where the
>   LGPL boundary plan.md §8 demands already forced it to live. So we ship full libnDPI
>   (5.0) over libpcap in `cmd/ndpi-helper`, built natively with `-tags "pcap ndpi"`,
>   and the "DPI-lite, pure Go" tier below was never built. The real cost is a build/
>   deploy path for that one binary, not a compromised product.
> - **"No code yet" is stale.** Written before any of it existed; the baseline landed
>   in 2026-06 and the real capture + nDPI 5.0 classifier on 2026-07-15.
>
> **What is still worth reading here:** §1 (the ntopng feature inventory — still the
> best checklist of what a mature visibility app does, and the yardstick for the native
> UI), §2.2 (geo/ASN database licensing for a *sold* product — undecided and still
> live), and §3 (the render/transport catalogue — its "server-computed SVG swapped by
> htmx, canvas only where frame-rate matters, htmx and xterm are the only vendored JS"
> house style is *current* and correct). Read §4's tiers as history.

Status: **superseded design exploration**, retained for the inventory and the
rationale trail. This doc inventories what ntopng does and sketches how we'd build the
equivalent natively in the existing Go + htmx single binary (plan.md §7, §8).

## Why native

ntopng works (verified live, see `os/vm/`) but its dependency chain is heavy:
ntopng itself is 41 MB, yet it drags in python311 (202 MB), boost-libs
(180 MB), glib (105 MB), perl, icu, pango/harfbuzz/fonts — **~650 MB** for an
appliance whose whole point is a lean, single-binary, no-runtime-deps design.
It also needs Redis as a live store and runs its own web server we have to
reverse-proxy behind our auth. Building visibility into `fwd` keeps the
single-binary promise, removes the second credential surface, and lets the UI
match the rest of the product instead of an embedded iframe.

Two hard constraints any native plan must respect:

1. **cgo-free.** `fwd` is pure Go today (`modernc.org/sqlite`, no cgo), so
   `deploy.sh` cross-compiles from Linux with a plain `GOOS=freebsd go build`.
   Anything pulling C libraries (libpcap, libnDPI) breaks that and is a real
   cost — call it out explicitly wherever it appears below.
2. **No JS chart libraries.** The Traffic page draws with hand-rolled 2D
   canvas; the only vendored JS is htmx and xterm. Streaming today is htmx
   polling (`hx-trigger="every Ns"`), not SSE/WebSocket. Native viz should hold
   that line: prefer **server-rendered SVG swapped by htmx**, with a little
   canvas where high frame-rate matters.

---

## 1. ntopng feature inventory

What ntopng offers, grouped. Tiering note: C = Community (free), P = Pro/
Enterprise (paid). We only need to clone Community-class features.

### 1.1 Flow & traffic monitoring
- Real-time **active flows** table: 5-tuple, L4 proto, L7 app, bytes/packets
  each direction, duration, current throughput, flow state. (C)
- Per-interface live throughput, packet rate, drops. (C)
- **Historical flows** with drill-down and filtering; needs a flow store
  (ClickHouse / nIndex in recent versions; MySQL older). (C, store extra)
- Traffic by L4 protocol (TCP/UDP/ICMP), by port, by direction. (C)

### 1.2 Deep packet inspection (nDPI)
- L7 **application/protocol identification**, 500+ protocols. (C)
- **Encrypted Traffic Analysis**: TLS SNI + certificate inspection, JA3/JA4
  client/server fingerprints, QUIC/HTTP2 detection. (C)
- **Flow risk** scoring: ~50 nDPI risks (self-signed/expired cert, DGA-looking
  domain, suspicious user-agent, cleartext creds, etc.). (C)

### 1.3 Hosts
- Top talkers / host list with sortable traffic columns. (C)
- **Host detail**: per-host apps, peers, ports, L4 breakdown, throughput over
  time, score. (C)
- Local vs remote classification (from configured local networks). (C)
- **Device fingerprinting / OS detection** (DHCP fingerprint, HTTP UA, TCP). (C)
- **Host pools**: group hosts into logical sets with their own stats/policy. (C)

### 1.4 Network grouping
- Per-subnet/network stats. (C)
- VLAN stats. (C)
- **Autonomous System (AS)** breakdown. (C)
- **Country / geo** breakdown. (C)

### 1.5 Visualizations (the streamed-data UI — expanded in §3)
- **Dashboard**: top talkers, top apps, traffic gauges, recent alerts. (C)
- **Sankey** diagram of talkers (who↔who). (C)
- Timeseries **charts** (RRD default; InfluxDB/Prometheus optional). (C)
- **Sparklines** inline on tables. (C)
- **Geo map**: remote hosts plotted on a world map. (C)
- **Protocol/application breakdown**: pie/donut/treemap. (C)
- **Flows page**: live, filterable flow table. (C)
- **Service / periodic maps**: host-relationship graphs. (P-ish)
- **Traffic report**: per host/app/network over a time range. (C)

### 1.6 Alerting
- Behavioral **checks** and thresholds on flows/hosts/interfaces. (C)
- Alert **endpoints**: email, Slack, Discord, Telegram, webhook, syslog,
  Microsoft Teams. (C, some P)
- SNMP trap reception. (P)

### 1.7 Active monitoring
- Continuous **probes** to targets: ICMP RTT, HTTP, throughput, with timeseries
  and alerts. (C)

### 1.8 SNMP
- Poll switches/routers for interface counters, errors, topology; map devices. (P)

### 1.9 Network discovery
- ARP scan, mDNS/SSDP/Bonjour, SNMP, DHCP fingerprint → device inventory. (C)

### 1.10 Flow collection (ingest from other gear)
- **NetFlow v5/v9, IPFIX, sFlow** collected via nProbe (separate binary) over
  ZMQ. ntopng itself doesn't parse NetFlow; nProbe does. (C+nProbe)

### 1.11 Storage / timeseries backends
- Redis for live state. (C)
- RRD (default) or InfluxDB/Prometheus for timeseries. (C)
- ClickHouse/nIndex for historical flow records. (C)

### 1.12 Data export & extensibility
- **REST API** (v1/v2). (C)
- **Lua scripting** engine + user scripts/plugins. (C)
- Export to MQTT, Kafka, Elasticsearch, syslog. (P)

### 1.13 Traffic recording & forensics
- n2disk integration for continuous PCAP-to-disk; download the PCAP of a
  selected flow. (P)

### 1.14 Security / threat intel
- Flow-risk-based scoring, host blacklists, threat-intel/blocklist feeds,
  alerting on hits. (C, feeds vary)

### 1.15 Operational
- Multi-user, RBAC, multi-tenant interface views. (P)
- Scheduled PDF reports. (P)

**Triage for our product (suggested, not final):** the must-haves are §1.1
flows, §1.2 nDPI app naming + TLS SNI, §1.3 hosts/top talkers, §1.4 geo/AS,
§1.5 the live dashboards, and a lean §1.6 alerting. SNMP, active monitoring,
n2disk, multi-tenant, Kafka, and scheduled reports are out of scope for v1.

---

## 2. Where the data comes from (native sources)

Native visibility is mostly a data-acquisition problem; the rendering is the
easy half. Sources, cheapest-first:

| Source | Gives us | cgo? | Capture? | Notes |
|---|---|---|---|---|
| **`pf` state table** (`DIOCGETSTATES` ioctl, or parse `pfctl -ss`) | Every routed flow: 5-tuple, dir, byte/pkt counters, age, state | No | No | We **are** the gateway — pf already tracks north-south + inter-segment. Free, always-on, zero packet handling. The backbone of Tier 0. |
| **pflog** (already collected, plan.md logs) | Blocked/passed packets, rule hits | No | (pcap on pflog0) | Already in the log ring; reuse for "denied" views. |
| **Unbound query log** | DNS name ↔ IP mapping, top domains | No | No | Turns raw IPs into names; drives "top domains" and host labels. |
| **DHCP leases (Kea)** | MAC ↔ IP ↔ hostname, vendor | No | No | Device inventory + fingerprint seed. |
| **BPF capture** (open `/dev/bpf*`, set filter via `golang.org/x/net/bpf`) | Raw packets for L7 inspection | **No (doable pure-Go)** | Yes | Pure-Go BPF read is feasible on FreeBSD without libpcap. Needed only for DPI beyond port-guessing. Sample, don't capture everything. |
| **gopacket + libpcap** | Same, easier API | **Yes (libpcap)** | Yes | Breaks cgo-free cross-compile. Avoid unless the pure-Go BPF path proves too painful. |
| **NetFlow/IPFIX/sFlow ingest** (`netsampler/goflow2`, pure Go) | Flows from a downstream managed switch (east-west) | No | No | plan.md §8 "bring a managed switch" path. cgo-free. |
| **libnDPI via cgo** | Full 500+ protocol DPI, JA3/JA4, risks | **Yes** | (on captured pkts) | The crown jewel of ntopng. ~10 MB lib, but it's C → breaks cgo-free. See §2.1. |
| **GeoLite2 / DB-IP mmdb** (`oschwald/maxminddb-golang`, pure Go) | Country, city, ASN for remote IPs | No | No | Geo + AS views. DB is ~10–70 MB; licensing note in §2.2. |

### 2.1 The DPI question (the one real fork in the road)

App-layer naming is what makes ntopng feel magical. Three native options:

- **DPI-lite, pure Go (recommended start).** Most traffic today is TLS, and the
  **SNI** in the ClientHello is cleartext; HTTP/1.1 has `Host`; QUIC exposes
  SNI; DNS gives names directly. A few hundred lines of pure-Go parsers over a
  *sampled* BPF stream identify the bulk of real-world apps by hostname, plus
  JA3/JA4 fingerprints are computable from the ClientHello with no library.
  cgo-free, tiny, covers ~the cases users care about ("what is talking to
  facebook / a sketchy domain").
- **Port + heuristic map.** Zero capture: classify pf-state flows by well-known
  port. Crude (everything-over-443 is "TLS"), but free and a fine Tier 0.
- **libnDPI via cgo.** Full fidelity, 500+ protocols, risk engine. The cost is
  giving up the pure-Go cross-compile (`deploy.sh` would need a FreeBSD
  toolchain or on-box build) and adding a C dependency to audit. Reserve for
  a later tier if DPI-lite proves insufficient.

### 2.2 Geo/ASN data

MaxMind GeoLite2 needs a (free) account + EULA and periodic redistribution
rules; **DB-IP Lite** or **IPinfo Lite** are CC-licensed alternatives that ship
cleaner for a sold product. All read by the same pure-Go `maxminddb` reader.
Ship the Country+ASN DBs (~20 MB total) by default; City is optional.

---

## 3. Streamed-data visualizations — native approaches

For each ntopng visualization: the data behind it, and how to render + stream it
natively. Default rendering strategy is **server-computed SVG emitted by a Go
template and swapped by htmx** — no client charting lib, works with JS off for
the static frame, and the server already owns the data. Use **canvas** only for
smooth high-rate line charts (the existing Traffic page already does this), and
add **SSE** only where polling is too coarse (the live flow tail).

### 3.1 Transport choices
| Transport | Use for | Status |
|---|---|---|
| **htmx poll** (`hx-trigger="every 2s"`) | tables, top-N, gauges, summaries | already the house style |
| **SSE** (raw `EventSource` or htmx SSE ext) | live flow tail, per-second counters | not yet used; one goroutine push, natural fit |
| **WebSocket** | — | reserved (shell only); overkill for one-way data |

### 3.2 Per-visualization plan

| ntopng viz | Data source | Native render | Stream |
|---|---|---|---|
| **Throughput line/area chart** | traffic SQLite (exists) | 2D canvas (exists) | poll |
| **Inline sparklines** (per host/app row) | rolling per-key SQLite buckets | server-rendered inline `<svg>` polyline | poll |
| **Top talkers / top apps tables** | pf states aggregated by host/app | htmx partial table, sortable | poll 2–5s |
| **Protocol / app breakdown** (donut/treemap) | flow bytes grouped by L7/port | **server SVG**: Go computes arc/rect geometry, emits `<svg>` | poll |
| **Live flows table** | pf state diff + DPI labels | htmx table, or **SSE** append rows | SSE preferred |
| **Sankey (who↔who / host↔app)** | aggregated src→dst byte pairs | **server SVG**: Go lays out nodes/links, emits paths (no d3) | poll |
| **Geo map** (remote endpoints) | mmdb lookup per remote IP | **server SVG**: static world map + bubbles sized by bytes at lat/long | poll |
| **AS / country bars** | mmdb ASN/country grouping | server SVG bar chart | poll |
| **Host detail timeseries** | per-host SQLite series | canvas (reuse Traffic draw) | poll |
| **Host-relationship / service map** | flow adjacency matrix | **server SVG** chord or arc diagram; force-directed only if we ever vendor a tiny lib | poll |
| **Flow-risk / alerts feed** | DPI risks + threshold checks | htmx list partial (like Logs) | poll/SSE |
| **DNS top domains** | unbound query log | htmx table | poll |
| **Activity heatmap** (host × hour) | bucketed SQLite counts | server SVG grid of `<rect>` | poll |

The recurring pattern: **Go aggregates from pf-states / SQLite / mmdb, then
emits an `<svg>` (or a JSON blob for the one canvas chart) and htmx swaps the
fragment.** This keeps every new view inside the existing no-JS-dep, server-
rendered model and reuses the apply/config/auth plumbing already built.

### 3.3 Storage shape

Extend the existing `traffic` SQLite store (or a sibling DB) with:
- a **live in-memory flow table** rebuilt each poll from pf states (no disk);
- **rolled-up timeseries** per dimension (host, app, country, AS) into SQLite
  ring buffers, same pattern as the current per-interface throughput sampler;
- optional **flow-record archive** (sampled) for historical drill-down — the
  one place we might later want a columnar store, but SQLite covers v1.

---

## 4. Suggested build phases (decide scope later)

1. **Tier 0 — pf-state visibility, cgo-free, no capture.** Flows, top talkers,
   per-host/app/port breakdowns, geo/AS via mmdb, throughput timeseries. Port-
   based app guess. Server-SVG dashboards + live flow table. This alone beats
   most prosumer firewalls and ships with zero new system deps.
2. **Tier 1 — DPI-lite, pure Go.** Sampled BPF read → TLS SNI / HTTP Host / QUIC
   / DNS extraction + JA3/JA4. Real app names and basic flow risks. Still
   cgo-free.
3. **Tier 2 — ingest + alerts.** goflow2 NetFlow/IPFIX/sFlow from a managed
   switch (east-west, plan.md §8); threshold/behavioral alerts to email/ntfy/
   webhook (ties into the open §13 alerting question).
4. **Tier 3 (optional) — full nDPI via cgo.** Only if DPI-lite is proven
   insufficient; accept the cross-compile cost.

---

## 5. Open questions

- **cgo line in the sand:** is keeping pure-Go cross-compile worth shipping
  DPI-lite instead of full nDPI? (Lean: yes, start pure-Go.)
- **Capture method:** pure-Go `/dev/bpf` reader vs. biting the libpcap/cgo
  bullet — prototype the pure-Go path early to confirm it's not a tar pit.
- **Geo DB licensing** for a *sold* product: GeoLite2 EULA vs DB-IP/IPinfo Lite.
- **Sampling rate** for the DPI capture (full line-rate inspection on a 2.5G
  box is not the goal; 1-in-N sampling for naming is fine).
- **SSE adoption:** introduce it for the live flow tail, or stay all-polling for
  one transport everywhere?
- **How much history** to keep, and whether the flow archive ever justifies a
  columnar store beyond SQLite.
- Relationship to the existing **Traffic** page (plan.md §7): does this absorb
  it, or stay a separate "Visibility" deep-dive as today?
```
