# Design review — 2026-09-04

Full-project review ahead of hardware arrival: an **N150 mini PC, 16 GB RAM,
256 GB NVMe, 4× i226** — i.e. the plan.md §10 Phase 0 COTS box. Method: full
read of plan.md (working tree), all docs, os/vm scripts, and the entire `ui/`
tree (config/render/apply, server/auth/web, flow/devices/ndpi-helper), plus
external verification of the load-bearing hardware facts. Findings carry
file:line references; severities are relative to the Phase 0 goal (working
appliance on this box), not the eventual sellable product.

---

## 1. Verdict

**The box you ordered is the right box.** It is exactly the §10 Phase 0
target, 16 GB matches the §8.5 "everything on" budget (~10–12 GB), 256 GB
clears the ~70 GB disk budget, and the i226 NICs use the same `igc(4)` driver
and even the same default device names (`igc0..igc2`) the shipped
`config.Default()` already assumes — on real hardware the default config maps
*better* than it does in the VM.

**But "proceed quickly" is currently blocked by four software gaps**, all
fixable before the box arrives:

1. **The engine doesn't manage interface addressing at all** (§3.1) — on
   hardware, nothing writes `ifconfig_igcX` lines, so the first apply can't
   even validate and UI address edits can never truly take effect. The VM
   only works because `provision.sh` hand-aliases the LAN IP.
2. **There is no hardware provisioning path** (§2.2) — all setup knowledge
   (rcvars, packages, seed pf.conf, offload flags) lives in a QEMU
   serial-console script that cannot run against a physical box.
3. **`ndpi-helper` is never built for or shipped to FreeBSD** (§5.1) — the
   app-label half of the visibility pipeline, the product differentiator, is
   dead code on the deployment target today.
4. **`fwpflow_enable` is set nowhere**, and apply uses `service X restart`
   which fails when the rcvar is off (§3.2) — flow export dies on every
   reboot and first-apply fails on a stock install.

Beyond the bring-up path, the review found real engine bugs (WireGuard
site-to-site renders but pf drops all tunnel traffic; VPN clients get a DNS
server that refuses them; rollback has three distinct failure modes), a
security posture that is fine for a bench box but not for a LAN with other
people on it (everything runs as root, the web shell is a root shell, no
CSRF), and a docs layer that has drifted from both the code and itself.

---

## 2. Hardware readiness — the N150 box

### 2.1 What already works in your favor

- **Default NIC mapping matches.** `config.Default()` maps WAN→igc0,
  LAN→igc1 (192.168.1.1/24), OPT1→igc2 (`ui/internal/config/config.go:471`).
  Unlike the VM, no device remap is needed — the seed `fw.json` can be the
  actual default.
- **`fwd` cross-compiles cleanly.** The SQLite driver is `modernc.org/sqlite`
  (pure Go), so the existing `GOOS=freebsd go build` in `os/vm/deploy.sh`
  works for hardware too. The cgo problem is confined to `ndpi-helper`.
- **libnDPI is packaged.** FreeBSD's `net/ndpi` currently ships a 5.0
  snapshot (`ndpi-5.0.d20251224`), matching what `classifier_ndpi.go` was
  written against. `pkg install ndpi` covers the runtime dep.
- **igc(4) EEE is disabled by default** in FreeBSD, addressing plan.md risk
  #4's intent — but see §2.4 for pinning it and for the i226 ASPM issue.
- **16 GB / 256 GB sizing is validated** — the docs agent confirmed the
  Intel ARK 16 GB platform-ceiling claim, and the plan's RAM/disk arithmetic
  checks out.

### 2.2 Gap: no install/provision path for physical hardware

Everything in `os/` is `os/vm/`: a cloud-init qcow2 plus
`provision.sh`/`serial_expect.py` driving a QEMU serial socket. None of it
can touch a physical box, and the knowledge embedded in it (offload flags,
rcvars, package set, seed pf.conf, ntopng_flags workaround, LAN alias) exists
nowhere in a hardware-consumable form. The §6 image pipeline (poudriere +
mkimg) is future work and shouldn't gate bring-up.

**Recommendation:** extract a target-agnostic `os/provision-appliance.sh`
(run over SSH on any freshly installed FreeBSD 15.x, VM or hardware, taking
device names as parameters) plus a short `docs/hw-bringup.md`. The VM script
then becomes a thin wrapper, killing the acknowledged hand-drift between
`provision.sh`'s inline JSON and `config.Default()` (`provision.sh:21`).

### 2.3 Gap: the 4th NIC

The config model allows any number of `opt` interfaces (validation pins
exactly one wan + one lan only, `config.go:504`), so `OPT2 → igc3` in a
hand-edited fw.json validates today. But the UI cannot add an interface —
the only route is `POST /interfaces/{name}/address` (edit device/addressing
of the fixed three, `ui/internal/server/server.go:194,612`), and
`Default()` maps three. On the 4-port box, igc3 is dead metal without a
hand edit.

Short term: seed fw.json with an OPT2 entry. Product decision to log: COTS
firewall boxes in this class are 4-port; if the custom board stays 3-port,
the software should still handle N ports as a first-class case (it nearly
does — this is a UI affordance, not an engine change).

### 2.4 Gap: igc-specific NIC settings are unmanaged

Nothing in `ui/` or `os/` renders per-NIC settings; the VM script disables
offloads on vtnet0 only (`provision.sh:55`). For the i226 box:

- **Offloads:** disable `tso`/`lro` (and consider csum) on all routed and
  captured ports — LRO is wrong for a router's forwarding path and hands
  the pcap-based ndpi-helper merged mega-segments that break dissection
  (snaplen is 1600, `source_pcap.go:116`). This belongs in the interface
  render alongside addressing (§3.1), not in a provisioning script.
- **EEE:** default-off in igc, but pin `dev.igc.X.eee_control=0` explicitly
  (plan risk #4 says "disable by default" — make it deliberate, not
  incidental).
- **ASPM:** i226 has a known RX-stall issue with ASPM L1.2 (freebsd-src
  PR #2318); check whether the fix is in the 15.1 kernel and keep
  `hw.igc.disable_aspm=1` in the back pocket if links stall under load.
- **Port→device order:** which physical jack is igc0 depends on the vendor's
  lane wiring — verify with `ifconfig` + cable before trusting the WAN/LAN
  seed mapping.

### 2.5 Smaller bring-up notes

- **Console:** these mini PCs have no DB9; install via HDMI + USB keyboard,
  enable sshd immediately, and treat serial-console-first as a custom-board
  goal, not a Phase 0 constraint.
- **Installer:** use the 15.1 memstick image with guided ZFS-on-root — that
  gives `bectl` boot environments, matching the product design and letting
  you exercise the BE update/rollback story on real hardware early.
- **Subnet collision:** the seed LAN is 192.168.1.1/24. If the home LAN the
  WAN port plugs into is also 192.168.1.0/24, routing breaks confusingly.
  Pick a distinct test subnet (e.g. 192.168.77.0/24) in the seed.
- **Dashboard temperature:** plan.md §7 promises CPU/RAM/**temp**;
  `internal/system/stats_freebsd.go` reads load/mem/uptime only. On the
  N150 this needs `coretemp(4)` loaded and `dev.cpu.N.temperature` read.
  Minor, but it's the first thing you'll look at during thermal soak.
- **VM ≠ hardware deltas to expect:** stock install has no cloud-init user,
  and base `local_unbound` may hold port 53 (nothing detects/disables it —
  `render/unbound.go` relies on the port's compiled-in defaults). *Correction:
  an earlier draft of this section claimed `os/vm/provision.sh` was missing
  `redis`; it installs and enables it. The real gap is that apply never checked
  for redis — see §3.7 — which is what was fixed.*

### 2.6 Suggested pre-arrival order of work

1. Interface addressing + NIC flags render (§3.1, §2.4) — the one real
   engine feature missing for hardware.
2. `os/provision-appliance.sh` + `docs/hw-bringup.md` (§2.2), including all
   rcvars (`fwpflow_enable` included) and the 4th-interface seed.
3. ndpi-helper build/deploy path (§5.1) — build natively in the VM
   (`pkg install go ndpi`), scp to target; record the nDPI version pin.
4. Apply-path fixes: rcvar-aware service handling, rollback mode bug,
   `wireguard_interfaces` (§3.2, §3.3).
5. The 5-minute VM verifications in §7 (they'll all recur on hardware).

Day one with the box is then: install FreeBSD → run provision script →
`deploy.sh` fwd + helper → create admin → Apply → confirm flows and app
labels on real traffic.

---

## 3. Config engine, render, apply (fwd core)

### 3.1 HIGH — interface addressing is config the engine claims but doesn't own

No renderer writes `ifconfig_*`/rc.conf addressing. Consequences: (a) on a
stock box the first apply can't validate — `$lan_if:network` in the pf macro
layer (`render/pf.go:62`) expands against *live* interface addresses; (b)
changing the LAN IP in the UI renders unbound/kea for an address the NIC
doesn't have, so the reload fails and apply rolls back, every time. The VM
sidesteps this with a hand-alias (`provision.sh:57`). Fix: render an rc.conf
fragment (or `sysrc` plan steps) for interface addressing + offload/EEE
flags, applied before service reloads.

### 3.2 HIGH — service enablement only exists in the VM script

`apply/plan.go` reloads via `service X restart`, which **fails when the
rcvar is off**; all `*_enable=YES` lines live only in `provision.sh:60`. And
`fwpflow_enable=YES` is set nowhere at all — `plan.go:118` says boot
persistence "is the image's job", but no image sets it, so **flow export
silently dies on every reboot** (VM included). Fix: apply sets rcvars it
depends on (or uses `onerestart` plus explicit rcvar management for boot).

### 3.3 HIGH — WireGuard site-to-site ships dead

- pf renders WAN pinholes for listen ports but **no pass rules on the wg
  tunnel interfaces** (`render/pf.go:79,102-110`, acknowledged in a TODO):
  peers handshake, then every decapsulated packet is dropped. With the
  generated client's `AllowedIPs = 0.0.0.0/0` (`wgclient.go:140`) this
  blackholes the peer's whole internet.
- `service wireguard restart` manages nothing because
  `wireguard_interfaces` is never set (`apply/plan.go:93`,
  `provision.sh:60`): apply reports success, zero tunnels exist. Deleting a
  tunnel removes the conf before teardown, so the old interface + keys stay
  live until reboot (`manager.go:372-384`).
- Road-warrior DNS is broken: clients are told `DNS = <LAN IP>`
  (`wgclient.go:166`) but pf default-denies wgsrv except explicit grants
  (`pf.go:135`) and unbound's ACL allows only internal interface subnets,
  not the VPN subnet (`unbound.go:165-169`). Every connected client has
  dead name resolution — and this is the flagship remote-management path
  (plan §7).

### 3.4 MED — dead config: DoT upstreams, NTP, timezone

`System.DNSServers` documents DNS-over-TLS upstreams (`config.go:216`) but
`render/unbound.go` emits no `forward-zone`/`forward-tls-upstream`; NTP
servers and timezone render to nothing. The System page accepts and stores
settings that change nothing — worse than absent, because it lies.

### 3.5 MED — rollback has three failure modes

1. **Mode bug:** rollback restores every file as 0600
   (`apply/manager.go:432-441`), but the pflow rc script is installed 0755;
   after any rollback `service fwpflow` fails, and it never self-heals
   because the next apply diffs content, not mode (`manager.go:359`).
2. **First-apply rollback is partial and self-breaking:** files that didn't
   pre-exist roll back to deletion, then the reload replay aborts at the
   first failure (`pfctl -f` on the deleted pf.conf), leaving services half
   old/half new (`manager.go:429-451`); timer-driven rollback errors are
   discarded unlogged (`manager.go:400`).
3. **In-memory only, and the document isn't reverted:** backups live in a
   RAM map (`manager.go:285`) — a crash/power-cut inside the 60 s window
   (exactly when a bad ruleset cut you off) makes the bad files permanent.
   Independently, fw.json keeps the bad settings after rollback, and
   nothing marks "running ≠ saved" — the next Apply re-applies what was
   just rolled back.

Also design-level: `pfctl -f` doesn't flush states created under a bad
ruleset — if rollback is a security boundary, flush states on rollback.

### 3.6 MED — string injection into root-owned rendered configs

Validation blocks space/tab in a few fields but never newline/quote.
Hostname/domain → unbound `local-data:` lines (`unbound.go:183-187`, Kea
`dhcp.go:95`); forward/service names and WG names/emails → pf.conf and
wg .conf comments (`pf.go:73,96`, `wireguard.go:34,42`); a `\n` breaks out
of a comment and wg-quick executes `PostUp` as root. Admin-only today (see
§4.1 — every UI user is effectively root anyway), but it destroys the trust
boundary the planned root helper depends on. One shared "single printable
line, no quotes" validator on every renderer-bound string closes it.

### 3.7 Other engine findings (abbreviated)

- Interface **Name** uniqueness/format never validated → duplicate/empty/
  digit-leading names produce broken pf macros; `pfctl -nf` then rejects
  *every* apply until renamed (`config.go:597-624`, `pf.go:160-171`).
- `Store.Open` doesn't run `Validate()` (`config.go:993`) — hand-edited
  fw.json bypasses invariants renderers assume.
- DHCP: no `RangeStart <= RangeEnd` check; Kea subnet IDs are positional so
  reordering orphans leases; `net.ParseMAC` accepts Cisco dot-form that
  Kea rejects (`dhcp.go:70-106`).
- Port-forward dup detection conflates `tcp` vs `tcp/udp` (`config.go:965`).
- pflow script assumes the exporter it creates is `pflow0`
  (`render/pflow.go:299`) — racy if anything else made one.
- Enabling adblock before the (unbuilt, §6) compile job has run makes
  `unbound-checkconf` fail on the missing include → whole apply rejected
  (`unbound.go:193`).
- `ntopng.go:210` claims "Redis-less community mode" — no such mode exists;
  works in the VM only because provision.sh installs+enables redis. Apply
  never checks redis, so enabling Visibility without it = opaque rollback.
- No fsync before rename in atomic-write paths (`config.go:1108`,
  `apply/system.go:176`) — power cut can persist a zero-length fw.json.
- Apply mutex is held up to 2 min/command while every page render calls
  `Pending()` → UI (including the Confirm button!) freezes during slow
  applies (`manager.go:299`, `server.go:415`).

---

## 4. Security (server/auth/web)

Current posture is bench-appropriate, not LAN-appropriate. Ordered by what
an attacker on the LAN would chain:

### 4.1 HIGH — everything is root; the plan's privilege model is unimplemented

plan.md §7 promises non-root fwd + a narrow root helper. No helper, no
privilege drop, no rc user exists anywhere; deploy runs `/root/fwd` as root
and the daemon execs `pfctl`/`service`/`tcpdump` directly
(`apply/system.go:95`, `logs/collect.go:25`). The full HTTP/template/
websocket/SQLite/proxy surface is in the root process. This is fine for the
bench box behind your own LAN, but should be tracked as unimplemented-plan,
and §3.6/§4.2 both get much worse until it lands.

### 4.2 HIGH — the web shell is a root shell by default

`Shell.User: ""` means "current user" = root (`config.go:172`,
`shell.go:203`), and the UI toggle can't set a user. One stolen session
cookie = root PTY. Default the shell to an unprivileged user and make root
opt-in with friction.

### 4.3 HIGH (verify) — global HTTP timeouts likely kill the shell and long proxies

`ReadTimeout: 10s / WriteTimeout: 30s` on the single `http.Server`
(`cmd/fwd/main.go:136`); `x/net/websocket` hijacks the conn and never clears
the armed deadlines, so shell sessions should die ~10–30 s in, and long
ntopng proxy responses truncate. Unit tests can't catch this (httptest sets
no server timeouts). **5-minute VM check**; fix is clearing deadlines
post-hijack or per-route timeouts. Related verify: the spawned `/bin/sh -l`
(`shell.go:193`) — confirm FreeBSD `sh` accepts `-l` (likely fine, but it's
exactly the passes-on-Linux class; one SSH command settles it).

### 4.4 MED — no CSRF tokens; SameSite=Lax is the only line

~40 state-changing POSTs rely solely on the Lax cookie
(`server.go:254-263`), and side-effecting GETs
(`/system/dns/test?address=…`) are reachable via top-level navigation →
CSRF-triggered probing *from* the firewall (`probe.go:314`). htmx makes
synchronizer tokens cheap (`hx-headers`). Also: creating an admin user
requires no current-password confirmation (`system.go:202`).

### 4.5 MED — session lifecycle gaps

Deleting a user or changing a password revokes nothing
(`system.go:217-250`); dashboard polls every 2 s and each poll extends the
12 h idle TTL, so open tabs are immortal (`session.go:329-342`). Add a
per-user session sweep on delete/password-change.

### 4.6 MED — login flow leaks + limiter bypass

Distinct "invalid password" vs "invalid TOTP" errors confirm passwords;
limiter is per-IP so an IPv6 /64 gives unlimited tries; TOTP codes are
replayable within the ±1 step window (`server.go:285-363`, `totp.go:419`).
Uniform error + per-username lockout + /64 bucketing.

### 4.7 MED — mail

STARTTLS is opportunistic: a stripped EHLO capability → WG client config
**with private key** sent in cleartext (`mail/mail.go:169`); make
`starttls` mean mandatory. The SMTP password is echoed into the System page
HTML value attribute (`system.html:151`) — use leave-blank-to-keep.

### 4.8 LOW (selected)

First-boot `POST /setup` is LAN-race-to-own (console-printed setup token
someday); `totpPending` never cleared; one unescaped `innerHTML` sink on
the traffic page (kernel-sourced data today, `traffic.html:125`); HTTP→HTTPS
redirect echoes client Host.

**Solid (verified fine):** argon2id params + constant-time compare + dummy-
hash timing defense; 256-bit random opaque sessions, HttpOnly/Secure, new
token on login; shell gating (origin check, session cap, idle watchdog,
audit ring); no path-traversal auth bypass; fully parameterized SQL
everywhere; html/template autoescaping; atomic 0600 config writes; staged
validate-before-install apply pipeline; localhost-only ntopng behind the
authenticated proxy; X25519 keygen.

---

## 5. Flow pipeline (pflow → collector → SQLite; ndpi-helper; devices)

### 5.1 HIGH — ndpi-helper never reaches the target

Nothing builds it for FreeBSD: `deploy.sh` builds only `fwd`; the OS image
pipeline both design docs defer to doesn't exist; the VM provision installs
neither `ndpi` nor a Go toolchain. So `superviseHelper` fails `LookPath`
and silently disables app labels (`cmd/fwd/main.go:190`) — the entire
enrichment layer (capture, classifier, label join) is dead on target.
Cross-compiling cgo to FreeBSD needs a sysroot nothing provides; the
realistic path is native build in the VM (`pkg install go ndpi`,
`go build -tags "pcap ndpi"`) + scp, automated in deploy. Also pin the nDPI
version expectation (`classifier_ndpi.go:389` targets the 5.0 API; the
port is a moving snapshot and nDPI breaks API across majors).

### 5.2 HIGH — engine flow table is unbounded (scan → OOM)

Eviction is TTL-only on a 2-minute ticker with no count cap
(`engine.go:70-74,164`); under `ndpi` tags each new tuple holds a ~1–2 KB C
`ndpi_flow_struct` until verdict or eviction, and 1-packet scan flows never
reach a verdict. A SYN/UDP scan or P2P swarm at tens of k new tuples/sec →
multi-GB C heap invisible to Go GC → OOM. plan.md budgets "~0.3 GB (100k
flows)" but nothing enforces 100k. Add a hard cap on tracked flows plus
pressure-based eviction. (Same TTL-only pattern, lower stakes, in
`LabelCache`, `enrich.go:26`.)

### 5.3 HIGH — rollup watermark drops same-second flows permanently

Rollup folds `ts > watermark` and sets watermark to `MAX(ts)` of folded
rows at 1 s granularity (`store.go:230-239`); records inserted later within
that same second are below the watermark forever — a systematic silent
undercount concentrated in bursty periods. Fold up to `now-1s` instead.

### 5.4 MED — accounting semantics

- Volume series sums `inb+outb` over all hosts = every flow counted twice
  (`store.go:420`, pinned by a test); halve or present as directional.
- Flows are stamped with collector arrival time, not the flowStart/End
  IEs pflow exports (`ipfix.go`, `collector.go:395`) — an hour-long
  transfer lands in one minute-bucket at teardown, misdating rollups.
- `host_roll` minute rows are kept 32 days but never queried past 24 h;
  with every remote IP a "host", that's millions of dead rows slowing
  every upsert (`store.go:241-260`). Trim minute width at ~2 days.

### 5.5 MED — enrichment join questions to settle on real traffic

- **NAT:** the helper captures on all monitored devices; a NATed flow is
  seen pre-NAT on LAN and post-NAT on WAN — which tuple pflow exports for
  a NATed pf state decides whether per-device app attribution works at
  all. Neither design doc addresses it. Verify on the VM/box; may argue
  for LAN-side-only capture.
- **Backfill cost:** every label re-emit (every 2 min per long-lived flow)
  triggers an `UPDATE` that scans the raw window via the ts index only
  (`store.go:167`, `enrich.go:124`) — hundreds of thousands of row visits
  on the single writer under load, and the label path is synchronous on
  the socket read loop, so a slow SQLite stalls the *classifier engine*
  (no write deadline in `Emit`, `sink.go:44`). Skip refresh re-backfills
  + add a partial index + decouple with a queue.
- Capture BPF is "ip or ip6" — full line-rate copy to userland at 2.5GbE
  (~200 kpps) for an engine that inspects 12 packets/flow, and
  `pcap_stats` is never read so kernel drops are invisible
  (`source_pcap.go:121`). Cheap now: bigger BPF buffer + drop-counter
  logging; later: smarter pre-filter.
- Partial-open crash: if the Nth device fails to open, handles with live
  capture goroutines get `pcap_close`d → cgo use-after-free segfault +
  3 s restart loop (`source_pcap.go:147-160`).

### 5.6 Devices layer: built but unwired

`internal/devices` (registry, ARP/NDP/lease join) is imported by nothing —
no route, no template, no per-device page, despite commit 75e497f claiming
a "live table". Kea lease parsing ignores the `expire` column (stale
attribution until LFC rewrite) and reads IPv4 leases only.

**Solid (verified fine):** IPFIX/v9 decoder (templates, reduced-size
counters, enterprise skip, bounds checks); parameterized SQL + single-writer
WAL discipline; join-key canonicalization identical on both sides; NDJSON
codec + reconnect; VLAN/QinQ + DLT handling; engine single-goroutine design;
clean shutdown paths, no goroutine leaks.

---

## 6. Documentation consistency

The repo has been idle since 2026-07-15; several docs describe a pre-July
world, and the uncommitted plan.md edits aren't fully propagated:

- **plan.md self-contradictions:** §10 Phase 0 still says "ntopng integrated
  on-box" as baseline vs §8's tiering (baseline = Go + kernel + helper, no
  ntopng/Redis); §8 still says "the 8 GB box" post-16 GB decision; §13 still
  lists the $199/$249–299 pricing question §9 now answers ($329–379 →
  $279), and still asks the eMMC question §2 decided.
- **docs/firewalla.md** is stale on four decisions: 8 GB RAM, 32 GB eMMC,
  C1110 embedded SKU, $249–299 pricing.
- **docs/netflow.md** is superseded (declares cgo-free a hard constraint;
  the shipped architecture is the cgo helper) but carries no banner, and
  three docs still cite it as the design of record — visibility-design.md
  is the actual one.
- **docs/visibility-design.md** still calls the pcap/nDPI capture "the one
  piece outstanding"; it landed 2026-07-15 (9f0c47a). The two *real*
  residuals go unrecorded: the soak-test load spike "under investigation"
  and the pflow-ifindex question (visibility-design §2 also still says the
  join is "5-tuple + ifindex"; code and helper doc say 5-tuple only).
- **Stale mechanism claims:** plan §7 says ttyd (reality: in-process
  xterm.js/WebSocket/pty — better, and materially different for security),
  uPlot (reality: hand-rolled canvas; only htmx+xterm are vendored), SSE
  logs (reality: htmx polling).
- **July plan honest status:** P1 capture done (same-day); P2 device
  identity half-done (backend only, unwired); P3 block-from-flow, P4
  adblock job, P5 alerting, P6 QoS, P7 IPv6 — not started.
- Externally verified: N150 16 GB ARK ceiling ✓; all BOM/RAM/disk
  arithmetic ✓. One overstatement: §2's "DDR5 does not rescue this" ignores
  commercialized 32 Gb DDR5 dies — moot (platform caps at 16 GB), but don't
  let that sentence justify anything later.

---

## 7. Dev environment & process

- **Uncommitted work:** plan.md's 16 GB/BOM/pricing rewrite is sitting in
  the working tree, and `sandbox.conf` is untracked despite its own header
  saying "it belongs to the project, so commit it". Commit both (propagate
  the §6 doc fixes into the same change).
- **The sandbox can't build the project.** `sandbox.conf`'s DNS allowlist
  has `#golang.org` commented out, and go.mod requires Go 1.25 while the
  host go is 1.22 → the toolchain auto-download is proxy-filtered and
  `go build`/`go test`/`go vet` all fail inside the box. Uncomment
  `golang.org` (the anchored pattern covers `proxy.golang.org`, which also
  serves module downloads). This review had to be static because of it.
- **Five-minute VM verifications queued** (all recur on hardware): web
  shell survives >30 s (§4.3); `sh -l` on FreeBSD (§4.3); pflow NAT tuple
  (§5.5); per-rule `keep state (pflow)` grammar on stock 15.1 (the one
  generated-syntax choice not independently confirmable from source — the
  pf goldens + live `pfctl -nf` gate make a mismatch loud, and ec8bc62
  claims live verification, so low risk); base `local_unbound` port-53
  conflict on a stock install (§2.5).

---

## 8. Plan-level observations

- **Pricing decision is open and load-bearing.** §9 now shows the 16 GB/
  NVMe sizing broke the launch range; $329–379 → $279 is proposed but
  undecided, and §13/firewalla.md still carry the old numbers. Decide and
  propagate — marketing positioning (vs Firewalla Purple at its price
  point) hangs off it.
- **3-port vs 4-port.** The COTS world (and your bench box) is 4-port; the
  custom board is 3-port by §2. The software should treat port count as
  data (it nearly does); the *hardware* question — whether the sellable
  board grows a 4th lane (budget has 3 spare) — deserves a §13 entry
  rather than silence.
- **The security roadmap needs a phase.** The plan promises the privilege
  split (§7) and hardening (§6) but no phase owns "make the daemon safe to
  expose beyond the bench": root helper, CSRF, session revocation, shell
  user. Suggest folding a "hardening pass" milestone into Phase 0's exit
  criteria — it's cheaper before more surface accretes.
- **Idle-since-July risk.** plan_july.md's triad (device identity →
  block-from-flow → alerts) is the right competitive read and is at ~0.5
  of 3 with seven weeks of no commits. Hardware arriving is the natural
  restart; the §2.6 list above is sequenced so bring-up work and the triad
  don't block each other (device identity's missing UI page is pure
  software, fine to interleave).

---

## Appendix: finding counts by severity

| Area | High | Med | Low |
|---|---|---|---|
| Hardware readiness (§2) | 3 | 3 | 3 |
| Engine (§3) | 3 | 5 | 7 |
| Security (§4) | 3 | 4 | 4+ |
| Flow pipeline (§5) | 3 | 4 | 3 |
| Docs (§6) | 4 | 3 | 3 |

Highest-leverage week of work before the box arrives: §2.6 items 1–4.

---

# Status update — 2026-09-04 (same day)

The findings above were worked through in one pass. **Nothing here has been
compiled, vetted, or tested** — the sandbox this was done in has no Go
toolchain and no module cache (`proxy.golang.org` was blocked; §7 records the
`sandbox.conf` fix, which takes effect on the next launch). Every change was
syntax-checked with `gofmt -e` and `sh -n`, and cross-checked statically for
unused imports, duplicate declarations, template action balance, and signature
agreement across the packages that were edited in parallel. Treat the first
`go build && go test ./...` as the real gate.

## Fixed

**Hardware readiness (§2)**
- `os/provision-appliance.sh` — target-agnostic provisioning over SSH: packages
  (including `ca_root_nss`, now required for DoT), fwd's rc.d script, a seed
  `pf.conf`, and a seed config **generated from the NICs the box actually has**,
  so the 4th port is populated on arrival rather than hand-edited.
- `os/rc.d/fwd` — fwd had no service script at all; it was started by hand.
- `os/build-ndpi-helper.sh` — builds the cgo helper *on the target* and installs
  it, closing §5.1. `os/vm/deploy.sh` now installs fwd to `/usr/local/sbin` and
  says plainly that it does not build the helper.
- `docs/hw-bringup.md` — day-one guide, including the port-mapping step that has
  no VM equivalent and the on-box verification list from §7.

**Engine (§3)**
- **§3.1 interface addressing** — new `render/network.go` emits an `fwnetwork`
  rc.d script owning addressing, offload/EEE/MTU tuning, and the default route.
  It is ordered ahead of pf in the apply plan, is idempotent, only re-addresses
  when the address actually differs (so an unrelated apply never drops the
  admin's session), and skips a configured device the board does not have.
  `Interface` gained `Gateway`, `HardwareOffload`, and `MTU`; a static WAN with
  no gateway is now a validation error instead of a box with no route.
- **§3.2 rcvars** — `enableAndRun`/`disableAndStop` replace bare
  `service X restart`, which fails when the rcvar is off; `fwpflow_enable` and
  friends are now set by apply, so services survive a reboot. pf's reload also
  sets `pf_enable`/`pflog_enable`, starts `pflog`, and runs `pfctl -e`.
- **§3.3 WireGuard** — pf now emits pass rules on the tunnel interfaces (the
  feature previously handshook and dropped every packet); `wireguard_interfaces`
  is derived from the rendered files, so a restart actually manages something;
  VPN clients can reach the resolver they are handed (pf rule + unbound ACL for
  the tunnel subnet).
- **§3.4 dead config** — DoT upstreams render a `forward-zone` with
  `tls-cert-bundle`, and mixed TLS/plaintext upstreams are rejected rather than
  silently sending some queries in the clear. NTP renders (`render/ntp.go`).
  *Timezone is still not rendered — see Remaining.*
- **§3.5 rollback** — backups carry their mode, so restoring no longer strips
  the executable bit off the generated rc.d scripts (a failure that never
  healed, because the next apply compares content, not mode); rollback reloads
  are best-effort instead of aborting at the first failure; timer-driven
  rollback failures are logged instead of discarded; `Pending()` no longer
  blocks behind a running apply, so the Confirm button renders during one.
- **§3.6 injection** — one central `validateStrings` sweep over every
  operator-settable string that reaches a renderer; newlines, quotes,
  backslashes and control characters are rejected at the form.
- **§3.7** — interface name uniqueness and pf-macro-safety; `Store.Open`
  validates and records `LoadError` (without refusing to start, which would
  take the UI down with the config) while `Manager.Apply` refuses to render an
  invalid document; DHCP pool ordering and MAC canonicalization; port-forward
  `tcp` vs `tcp/udp` overlap; the pflow exporter id is read back instead of
  assumed to be `pflow0`; ntopng checks for redis with a clear message; fsync
  before rename on the config document; an empty adblock include is created so
  enabling adblock cannot brick every apply.

**Security (§4)** — websocket/proxy deadlines cleared per-handler and HTTP/2
pinned off (`x/net/websocket` hijacks unconditionally, so h2 would have broken
the shell outright); the web shell defaults to an unprivileged account and
fails loudly on an unknown user instead of falling back to root; CSRF tokens on
all 51 authenticated POST forms plus an htmx header, with the two pre-session
forms exempt by construction and an Origin fallback for the ntopng proxy;
side-effecting GETs moved to POST; sessions revoked on user delete and password
change; uniform login error, per-username limiter, IPv6 `/64` bucketing, TOTP
replay rejection; mandatory STARTTLS; SMTP password no longer echoed into the
page.

**Flow pipeline (§5)** — the classifier's flow table is capped with pressure
eviction (a port scan could previously OOM the box through GC-invisible C
memory); the rollup watermark can no longer strand same-second flows; volume
double-counting fixed and minute-width rollup rows trimmed at 2 days; label
backfill only runs when the label is news, behind a bounded queue with a write
deadline, so slow SQLite can no longer stall the classifier; pcap drop counters
logged; the partial-open cgo use-after-free fixed; Kea lease expiry honored and
v6 leases read.

**Devices (§5.6)** — the registry that nothing imported is now a page.

**Docs (§6)** — plan.md's internal contradictions (ntopng baseline, "the 8 GB
box", pricing, eMMC) resolved; `firewalla.md` brought up to date on four stale
decisions; `netflow.md` banner'd as superseded and its citations repointed;
`visibility-design.md` marked done where done and given its three real
residuals; `plan_july.md` given a dated status.

## Remaining, deliberately

- **fwd still runs as root (§4.1).** The privilege split plan.md §7 promises is
  architectural, not a patch. It is now written into plan.md §10 as a Phase 0
  exit criterion.
- **Rollback still does not revert the config document (§3.5).** Files roll
  back; `fw.json` keeps the rejected settings and nothing marks "running ≠
  saved", so the next Apply re-applies it. Backups also remain in memory, so a
  crash inside the 60 s window makes the bad files permanent. Both need a
  Manager↔Store contract that touches the constructor and the server.
- **Timezone is still dead config (§3.4).** The model stores UTC offsets
  (`UTC+05:30`), which do not map onto zoneinfo — `Etc/GMT±N` is whole-hours and
  sign-inverted. The fix is to store IANA names, which is a model change.
- **The UI still cannot add or remove an interface (§2.3).** Provisioning seeds
  all four ports, so the box is usable; the Interfaces page still edits only the
  existing set.
- **Absolute session lifetime (§4.5)**, current-password confirmation for admin
  creation (§4.4), the `/setup` LAN race and the HTTP→HTTPS `Host` echo (§4.8),
  dashboard temperature (§2.5), and flow bucketing by `flowStart`/`flowEnd`
  (§5.4c, documented in the code with why it is not a safe local change).
- **Everything in §7's on-box list** is unchanged in status: it is verification,
  not code, and `docs/hw-bringup.md` §8 now carries it.
