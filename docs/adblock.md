# Ad blocking — how pfBlockerNG does it, and our equivalent

Status: design + partial build. The config and resolver wiring exist today
(`config.Adblock`, `render.Unbound` emits `include: /var/db/fwd/adblock.conf`);
the **fetch/compile job that fills that file is not built yet**. This doc studies
how pfBlockerNG-devel (the de-facto pfSense ad blocker) actually works, then maps
each piece onto Luciola's Go + Unbound + `pf` stack (`../plan.md` §7).

> **Scope.** pfBlockerNG does two largely separate jobs: **DNSBL** (DNS-based
> domain blocking — the ad/tracker blocker) and **IP blocking** (pf table feeds
> from GeoIP/threat lists). This doc is about the **DNSBL** half, which is what
> "ad blocking" means. The IP-feed half maps to a future `pf`-table feature and
> is noted at the end, not detailed.

---

## 1. How pfBlockerNG-devel blocks ads (DNSBL)

pfBlockerNG layers on top of pfSense's **Unbound** resolver. The pipeline:

**a. Feeds.** The admin subscribes to *DNSBL feeds* — URLs of blocklists in
various formats (hosts files like StevenBlack, domain lists, AdBlock-Plus cosmetic
syntax, EasyList). Feeds are organized into **groups** and tagged with an action
and an update schedule (via cron).

**b. Download + normalize.** On a schedule, pfBlockerNG fetches each feed,
deduplicates, and **normalizes wildly different formats into a flat domain list**.
It parses:
- `hosts` format (`0.0.0.0 ads.example.com`) — strip the IP, keep the domain.
- raw domain lists.
- AdBlock Plus syntax (`||ads.example.com^`) — extract the domain.
- It discards comments, invalid lines, and (importantly) entries that would block
  too much.

**c. Allowlist + suppression.** Before compiling, it applies a **whitelist** and a
**TLD/suppression** pass so a single bad feed entry can't blackhole something
essential. It also de-duplicates across all feeds so the same domain isn't
compiled twice.

**d. Compile into Unbound.** Historically pfBlockerNG wrote per-domain
`local-zone`/`local-data` lines. The modern, fast path uses Unbound's
**`local-zone` with a single redirect/`always_nxdomain` per domain**, loaded via a
generated include file, plus an Unbound **python module** (`unbound_pi.py`) option
for live, per-client behaviour and logging. The two response modes that matter:
- **NXDOMAIN / "Unbound" mode** — the resolver answers "no such name." Cleanest;
  the client just fails to connect. No web server needed.
- **DNSBL VIP / "null-block" mode** — resolve the blocked name to a local
  *virtual IP* (e.g. `10.10.10.1`) where pfBlockerNG runs a tiny web server that
  returns a 1×1 pixel or a block page, so HTTP requests get a clean empty reply
  instead of a timeout. This is the "DNSBL Webserver/VIP" feature.

**e. Reload, don't restart.** It reloads Unbound's local data (ideally without a
full restart) so blocking takes effect with minimal resolver downtime. A botched
feed must not take DNS down — validation gates the reload.

**f. Report.** A python/unbound hook logs every blocked query (client IP, blocked
domain, which feed matched) into a DNSBL log, surfaced as reports/top-blocked
dashboards and per-client stats.

**Key design properties to copy:**
- **Format normalization** — accept hosts/domain/ABP feeds, emit one canonical
  domain set.
- **Dedup + allowlist + suppression** before compile — robustness over raw size.
- **Compiled include file**, resolver-native, reloaded atomically.
- **NXDOMAIN as the default response mode**; VIP/pixel as an option.
- **Per-query block logging** for reports.
- **Scheduled auto-update** with validation gating the swap.

**Things we deliberately won't copy:**
- The **AdBlock-Plus cosmetic/element-hiding rules** (CSS `##.banner`) — those are
  browser-extension territory, meaningless at the DNS layer. We parse ABP feeds
  only to *extract blockable domains*, ignoring cosmetic rules.
- The **per-feed PHP/cron sprawl** and a second web server by default — heavy and
  not single-binary-friendly.

---

## 2. Mapping to Luciola

Luciola already has the resolver wiring; what's missing is the **compiler job**.
Today:

```
config.Adblock{ Enabled bool; Lists []string }      // ../ui/internal/config/config.go
render.Unbound() -> "include: /var/db/fwd/adblock.conf"  // when Adblock.Enabled
const AdblockInclude = "/var/db/fwd/adblock.conf"   // ../ui/internal/render/unbound.go
```

So the resolver is already told to `include` a compiled file. We need to **build
the thing that writes it**, mirroring pfBlockerNG's pipeline but as pure Go in
`fwd` (no PHP, no cron daemon, no second web server). Proposed component:
`internal/adblock` — a fetch→normalize→dedup→compile→validate→reload job.

### 2.1 The compile pipeline (Go)

| pfBlockerNG step | Luciola equivalent |
|---|---|
| Feeds + groups | `config.Adblock.Lists` (URLs) → grow to typed feeds w/ name+category+enabled |
| Scheduled download | `fwd` scheduler goroutine + HTTP GET with ETag/Last-Modified caching |
| Format normalize | Go parser: hosts / domain-list / ABP-domain → canonical FQDN set |
| Allowlist + suppression | `config` allowlist + a built-in suppression list (never-block) |
| Dedup across feeds | one `map[string]struct{}` across all enabled feeds |
| Compile to Unbound | write `local-zone:` lines to `AdblockInclude` |
| Validate before reload | `unbound-checkconf` on a temp config, then swap |
| Reload | `unbound-control reload`/`local_zones` (no full restart) |
| Block logging/reports | Unbound query logging or a response-IP sink → SQLite (traffic pipeline) |

### 2.2 Response mode

Default to **NXDOMAIN** — it's the cleanest, needs no extra service, and fits the
single-binary promise. Emit per domain:

```
local-zone: "ads.example.com." always_nxdomain
```

(`always_nxdomain` is purpose-built for exactly this and is cheaper than
`redirect` + `local-data`.) Generating millions of `local-zone` lines is fine —
Unbound loads them from the include; this is the same approach pfBlockerNG's fast
path uses.

Offer **null/pixel mode** later as an option for the people who want HTTP ad slots
to collapse cleanly instead of hang: resolve blocked names to a Luciola-served
sinkhole IP where `fwd` returns a 1×1 / 204. Lower priority — NXDOMAIN covers the
common case and avoids standing up a sink listener.

### 2.3 Where the work runs

The fetch/compile is **runtime, network-bound, and must not block config apply** —
exactly why the existing comment says "the fetch/compile job is separate from
rendering." So:
- `render.Unbound` stays pure/deterministic (just the `include` line) — unchanged.
- `internal/adblock` runs as a scheduled background job in `fwd`, writes
  `AdblockInclude`, then triggers an Unbound reload. A config apply that toggles
  adblock on/off only rewrites `unbound.conf`; the blocklist data refreshes on its
  own timer (and on-demand via a "Refresh now" button).

### 2.4 Categorized feeds + UI

Grow `Adblock.Lists []string` (bare URLs) into typed feeds so the DNS page can
present categories with per-list stats — the same UX direction as `parental.md`:

```go
type Feed struct {
    Name     string // "StevenBlack hosts"
    URL      string
    Category string // ads | tracking | malware | adult | ...
    Enabled  bool
}
```

Per-feed metadata to display: source URL, category, license, entry count,
last-refresh time, last-status (ok / fetch-failed / using-cached). Curate a
default set of well-known feeds (StevenBlack, OISD, Hagezi, AdGuard) shipped
disabled-by-default or with a sane "ads + tracking" baseline on.

### 2.5 Allowlist, suppression, and safety

Copy pfBlockerNG's robustness instincts — a blocklist that breaks DNS is worse
than no blocklist:

- **User allowlist** in config — domains never blocked even if a feed lists them
  (e.g. a CDN the family depends on). Allowlist wins over any feed.
- **Built-in suppression list** — domains we refuse to compile no matter what
  (the resolver root, the appliance's own domain, common essential infra,
  `*.in-addr.arpa`, telemetry that breaks OSes like `*.apple.com` captive checks).
  Guards against a poisoned or over-broad feed.
- **Sanity gate** — if a feed parses to suspiciously few entries, an empty body,
  or a fetch error, **keep the previous compiled file** and flag the feed as
  failed in the UI rather than shrinking/blanking the blocklist.
- **Validate before swap** — `unbound-checkconf` the include; only
  `unbound-control reload` if it passes. Never leave DNS down on a bad refresh.
- **DNSSEC interaction** — `always_nxdomain` returns an unsigned NXDOMAIN. For
  the appliance's own validating resolver that's fine (locally authoritative
  local-zones aren't DNSSEC-validated), but document it; it's a known pfBlockerNG
  footgun when people expect signed responses.

### 2.6 Reporting

Per-query block logging is what makes an ad blocker *feel* like it's working and
lets users fix false positives. Options, cheapest first:
- **Unbound response-ip / query logging** parsed into the existing SQLite ring
  buffer → a "top blocked domains / blocks per client" panel on the Traffic or
  DNS page.
- Later: an Unbound python module (à la pfBlockerNG's `unbound_pi.py`) for
  richer per-client attribution — but that adds a python dependency we'd rather
  avoid given the cgo-free / lean-binary stance (`netflow.md`); prefer log
  parsing unless attribution demands the module.

---

## 3. Per-network scope (ties into parental.md)

pfBlockerNG DNSBL is largely **global** (all clients get the same blocklist),
with per-client behaviour bolted on via the python module. Luciola should instead
scope blocklists **per network view** using Unbound views (see `parental.md` §6):
the kids segment gets `ads + tracking + adult`, the trusted segment gets
`ads + tracking`, guest gets a stricter set. Same compiled-include mechanism,
emitted inside per-view blocks. This is a cleaner architecture than pfBlockerNG's
global-plus-python model and reuses machinery we're already designing for
parental controls.

---

## 4. What we're *not* building (the IP-feed half)

pfBlockerNG's other half feeds **pf tables** from IP/GeoIP/threat lists
(`pfctl -t blocklist -T add …`) to drop traffic at L3 regardless of DNS. That's a
separate future feature — a `pf`-table manager fed by IP reputation / GeoIP feeds
(maps onto plan.md §8 visibility + the geo-blocking idea in `parental.md`). Worth
building eventually for threat-IP and country blocking, but it is **not** ad
blocking and is out of scope here. Keep the two pipelines separate, exactly as
pfBlockerNG does (DNSBL vs IP), so a DNS feed failure can't affect pf and vice
versa.

---

## 5. Build order

| Step | Deliverable |
|---|---|
| 1 | `internal/adblock`: fetch (ETag-cached) → normalize (hosts/domain/ABP) → dedup → compile `always_nxdomain` → `AdblockInclude` |
| 2 | Validate (`unbound-checkconf`) + `unbound-control reload`; sanity gate keeps last-good file |
| 3 | Scheduler + "Refresh now"; per-feed status/entry-count surfaced in the DNS page |
| 4 | Typed categorized feeds + curated defaults + user allowlist + suppression list |
| 5 | Block logging → SQLite → top-blocked / per-client report panel |
| 6 | Per-view scoping (shared with `parental.md`); optional null/pixel sink mode |

Steps 1–2 turn the *already-wired* `include` into a working ad blocker; the rest
is robustness, UX, and reporting — the parts that separate a real product from a
cron job piping a hosts file into a resolver.

---

*Stack references: `../ui/internal/config/config.go` (`Adblock`),
`../ui/internal/render/unbound.go` (`AdblockInclude`, the `include` wiring).
Related: `./parental.md` (per-view blocklists, categorized feeds),
`./netflow.md` (cgo-free / lean-binary constraints, SQLite reporting),
`./firewalla.md` (competitive context for blocking + reporting UX).*
