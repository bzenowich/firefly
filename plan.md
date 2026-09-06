# Luciola — Project Plan

**Pyroptics** (company) · **Luciola** (product). A spiritual successor to the PC Engines
APU2: an open, fanless, serial-console-first 3-port firewall appliance with coreboot
firmware, a FreeBSD-based OS, and a purpose-built WebUI. Goal: a sellable product with
published design files. Branding rationale + positioning in `docs/marketing.md`.

## 1. Decisions made

| Area | Decision | Rationale |
|------|----------|-----------|
| SoC | **Value SKU:** Intel Processor N150 (Twin Lake / ADL-N) | 4 Gracemont cores @ 3.6 GHz, 6 W base TDP, 9 PCIe 3.0 lanes, AES-NI/VAES, public Intel FSP enables coreboot, strong FreeBSD support, best $/perf for a 3-port box |
| SoC | **Embedded SKU:** Intel Atom x7425E (Alder Lake-N embedded) | Same ADL-N silicon as N150 — **true drop-in on the same board** (same FCBGA, DDR4/DDR5 + In-Band ECC, 9 PCIe 3.0 lanes, same proven coreboot path). Adds **Intel IoT ~10–15-yr availability** + industrial temp grade for the long-support tier. 12 W (thermal worst case). One PCB, one firmware image. q100 price opaque — confirm before locking |
| NICs | 3× Intel i226-IT (2.5GbE) | Industrial temp, one PCIe 3.0 lane each, mature FreeBSD `igc(4)` driver, auto-negotiates down to 1000baseT |
| WebUI | Go + htmx, single static binary | No runtime deps, trivial FreeBSD cross-compile, server-rendered with live updates, small attack surface, maintainable solo |
| Goal | Sellable product | Plan includes certification, manufacturing, and supply-chain sections |

**SoC SKU strategy — two-tier, one board, all ADL-N Gracemont:**

- **Value SKU — Intel Processor N150** (Twin Lake, 4× Gracemont @ 3.6 GHz, 6 W base,
  9 PCIe 3.0 lanes). Current silicon (Q1 2025), cheapest, highest clock, lowest thermal,
  best-supported coreboot path (ADL-N / Dasharo / Nissa). **N100** is the drop-in
  fallback (3.4 GHz, ~same price) if N150 stock lags. Memory: soldered DDR4 with In-Band
  ECC only.
- **Embedded SKU — Intel Atom x7425E** (Alder Lake-N embedded, Q1 2023). *Same ADL-N
  silicon* as N150 and a **true drop-in on the same PCB** — same FCBGA package, same
  DDR4/DDR5 + In-Band ECC, same 9 PCIe 3.0 lanes, same coreboot image. What it buys over
  N150: **Intel IoT long-life availability (~10–15 yr)** and **industrial temperature
  grade** — the supply-continuity + spec story for a sellable, long-supported appliance
  (directly addresses §9 supply and risk #3). Costs vs N150: ~12 W (the §5 thermal worst
  case), opaque embedded pricing (higher than N150's ~$45), and a slightly lower 3.4 GHz
  turbo (irrelevant for I/O-bound routing). Higher-end future option in the same family:
  Atom x7835RE "Amston Lake" (8 cores) if a premium SKU ever wants more compute.

**Why one board, not two.** N150 and x7425E share package, memory interface, lane count,
and firmware, so a single PCB layout carries both — stuff N150 for the value SKU, x7425E
for the embedded SKU. No second board, no second coreboot bring-up, no second SI review.
This is the embedded-tier story the plan originally chased with the **Atom C1110**
(Arizona Beach), now demoted — see below.

**C1110 demoted to research-pending-FSP (was the embedded SKU).** C1110 offered real
LPDDR5-5200 ECC + PCIe Gen4 and is proven in the Netgate 4200 (3.2 Gbps IPsec), but a
2026-06-24 coreboot-feasibility review found: **no coreboot port exists** (zero refs in
the coreboot tree/gerrit; Netgate ships closed AMI BIOS) and — the fatal item — **no
evidence of a public Intel FSP** for Arizona Beach (absent from coreboot vendorcode,
unlike Denverton-NS / Snow Ridge of the same era; ~75% confidence it is NDA-gated).
Without a public FSP a coreboot port is *impossible*, not merely hard — this fails the
open-firmware pillar. C1110 also needed its own PCB (different package, LPDDR5) and a
from-scratch firmware bring-up. It stays parked unless a direct query to the **Intel FSP
Program Office** confirms a public FSP; the LPDDR5-ECC/Gen4 advantages don't matter at
3× 2.5GbE anyway. Confirm distributor stock (Mouser/Arrow) before locking any SKU.

## 2. Hardware specification (target)

- **SoC:** two-tier on **one board**, all ADL-N 4× Gracemont — **N150** (value, 6 W,
  DDR4, drop-in N100 fallback) and **Atom x7425E** (embedded, 12 W, ~10–15-yr life +
  industrial temp; true drop-in on the same PCB). See §1 for the full SKU strategy;
  C1110 is demoted (no public coreboot FSP — §1, risk #7).
- **Memory:** **16 GB** soldered DDR4-3200 (single channel, **8× x16 chips,
  dual-rank**). In-Band ECC enabled where the SKU/firmware supports it. Soldered like
  the APU2 — no SODIMM to work loose, better vibration/thermal profile.
  - **Why 8 devices, not 4 — this is a layout decision, not a BOM decision.** DDR4 x16
    dies top out at **16 Gb (2 GB)**; 32 Gb DDR4 was never commercialized. So 4× x16 =
    8 GB is the hard ceiling for a *single rank*, and 16 GB requires a second rank
    (8 devices). DDR5 doesn't change the answer here: 24 Gb and 32 Gb dies do exist
    (32 Gb is commercialized), so 4× x16 DDR5 could in principle reach 16 GB — but
    ADL-N caps at 16 GB total anyway, x16 DDR5 at those densities is a thin,
    price-premium supply line, and the SKU we route for is DDR4. **Treat this as
    moot, not as an argument** — it must never be the reason a later decision goes
    one way. LPDDR5 would fit 16 GB in one or two packages but means a different,
    stricter memory-down layout. **Route for 8 devices or 8 GB is permanent
    for the life of the product.** Board area, clamshell/side-by-side placement,
    two-rank fly-by routing, and an extra SI pass are the price.
  - **One RAM config, stuffed on every unit.** 8 GB (one rank, 4 devices depopulated)
    is a legal option on the same PCB, but the cost is not the ~$13 of DRAM — it is a
    **second memory-down SPD blob in coreboot, a board-ID strap to select it, and a
    second memory-training validation pass**. We already carry two SoC SKUs; a RAM axis
    makes four variants for a solo-run product. Killing the axis is worth more than the
    BOM delta. Revisit only if the value-SKU price proves sacred (§9).
  - **16 GB is the platform ceiling**, not a compromise: Intel ARK lists max memory =
    16 GB for both N150 and x7425E.
  - **In-Band ECC costs capacity and bandwidth.** IBECC stores its check bits in the
    same DRAM — budget roughly an eighth of the protected range, plus a read-bandwidth
    penalty, so plan on **~14 GB usable of 16** with IBECC on. Measure at bring-up.
    Single-channel DDR4-3200 (~25.6 GB/s) is already the platform's tightest resource.
  - **Budget (see §8.5 for the full table):** baseline image ≈ 4 GB resident
    (kernel + capped ZFS ARC + Unbound/blocklists + fwd + nDPI helper); everything on
    (+ Suricata + ntopng/Redis + LLM) ≈ 10–12 GB. **8 GB = baseline plus one power-tier
    feature; 16 GB = everything at once.**
- **Storage:**
  - M.2 2280 M-key, PCIe 3.0 x2 NVMe — **primary, 256 GB standard fit**. 128 GB is a
    dead market segment (low volume, often the same price as 256 GB), and the
    full-featured budget below lands near 70 GB with ZFS headroom, so 256 GB is the
    honest floor with room for retention growth.
  - Optional **16 GB eMMC** on board — **recovery/rescue image only, not primary.**
    32 GB cannot carry the full-featured appliance (see the budget below); as a
    failsafe that survives a botched update or a dead NVMe, 16 GB is plenty.
    **Bring-up risk:** ADL-N has an eMMC 5.1 controller, but FreeBSD's `sdhci`/`mmcsd`
    path on Intel PCI SDHCI is far less exercised than NVMe — validate early or the
    recovery path is theoretical.
  - **Disk budget (§8 retention model):** base + packages 3–4 GB; 3–5 boot environments
    6–15 GB unique; flow DB (1 h raw + minute/hour rollups, ~1 yr) 1–5 GB; bounded log
    ring ≤2 GB; bounded Suricata `eve.json` ring 5–10 GB; ntopng + Redis 1–5 GB; LLM
    model(s) 3–8 GB; swap + kernel minidump 4–8 GB. **Subtotal ~25–57 GB; ~70 GB with
    ZFS kept under 80% full.**
  - **Endurance is a non-issue; power-loss is the real risk.** At ~500 MB/day of flow +
    log writes even a 100 TBW drive lasts decades. What kills appliance SSDs is being
    yanked from the wall mid-write — pick a controller with decent power-loss handling,
    not the cheapest DRAM-less QLC part on the BOM.
  - **Per-dataset quotas protect the BE rollback.** Boot environments are the headline
    feature (§6) and BE creation fails on a full pool, so a runaway `eve.json` would
    take the rollback guarantee with it. Separate quota'd datasets for `/var/log`, the
    flow DB, and `/conf`; `recordsize=16k` on the SQLite datasets, `atime=off`, `lz4`
    (2–4× on log/flow text, so effective capacity beats raw).
- **Networking:** 3× i226-IT, each on one PCIe 3.0 lane; 3× RJ45 with integrated
  magnetics, side-by-side front panel like APU2
- **Expansion:** M.2 2230 E-key (PCIe x1 + USB 2.0) for optional Wi-Fi/BT —
  *not populated in v1* (avoids FCC intentional-radiator / CE RED certification)
- **Console:** DB9 RS232 (115200 8N1, the APU tradition) **plus** USB-C console
  (CP2102N/FT231X bridge) — both wired to the same SoC UART via a mux or to two UARTs
- **USB:** 2× USB 3.x Type-A front panel
- **Misc I/O:** power button, reset, 3 front-panel LEDs (GPIO), SPI flash header for
  external programmer recovery (flashrom + CH341A/clip), TPM 2.0 (SPI, e.g. SLB9672) — optional fit
- **Power:** 12 V DC barrel jack (center positive, APU-compatible), ~18 W budget
  (N150 6 W base + NICs + storage; headroom for cTDP-up), buck regulators for SoC
  rails. No PoE in v1 (adds cost/cert complexity; possible v2 option).
- **PCIe lane budget (9 lanes available):** 3 NICs (3) + M.2 M-key (2) + M.2 E-key (1) = 6 used, 3 spare
- **Firmware flash:** 32 MB SPI NOR (W25Q256-class) — ADL-N IFWI (descriptor + CSE/ME
  region + coreboot + payload) does not fit in 16 MB

## 3. Firmware (coreboot)

- **Base:** upstream coreboot; Alder Lake-N is already supported (Google "Nissa"
  boards, Protectli/Dasharo VP24xx series prove the path)
- **Silicon init:** Intel FSP (publicly released binary for ADL-N). Full platform
  design collateral (PDG, schematics review) requires an Intel CNDA — sign up via
  Intel Partner Alliance early.
- **CSE/ME:** required blob; investigate "ME disable" HAP bit / Dasharo-style
  slimming. Document exactly which blobs ship and why.
- **Payload:** EDK2 UefiPayloadPkg (FreeBSD boots UEFI cleanly) with full serial
  console redirection. Evaluate SeaBIOS as secondary for legacy tooling.
- **Features to replicate from APU2 firmware:**
  - Serial console everything — setup menu, boot output, no video required
  - Boot-order persistence (sortbootorder equivalent — UEFI variables cover this)
  - iPXE network boot option
  - Memtest payload in flash
  - `flashrom` internal reflash from the running OS, with signed release images
- **Partner option:** 3mdeb (Dasharo) maintained PC Engines coreboot releases and
  ships coreboot on ADL-N today — strong candidate for contract bring-up or audit.

## 4. PCB design (KiCad)

- **Tool:** KiCad 9+ (diff pairs, length tuning, and DDR fanout are all workable now)
- **Stackup:** 8-layer, controlled impedance, via-in-pad under the FCBGA. This is the
  hard part of the whole project: DDR4 fly-by routing and PCIe diff pairs.
- **De-risk path (strongly recommended):** before full custom layout, do a
  **carrier-board phase** using an off-the-shelf SMARC or COM Express Mini module with
  an ADL-N SoC. The carrier (NICs, power, console, M.2) is a 4-layer board a solo
  designer can finish in weeks. It validates the schematic-level design, the case, the
  thermal solution, and all software — then the custom single-board version replaces
  the module at leisure. Many "module → custom board" products never need step two.
- **Board outline:** target the APU enclosure footprint class (~152 × 152 mm or
  smaller) so case design stays simple
- **Design reviews:** budget for at least one external SI/PI review of the DDR and
  PCIe routing before fab (cheap insurance vs. a $5k respin)
- **Prototyping:** 2 proto spins assumed. 5 boards per spin, assembled (JLCPCB/PCBWay
  advanced assembly or a domestic quick-turn shop for the BGA work).

## 5. Thermal & case

- **Concept:** APU2-style — fanless, case is the heatsink
- **Path:** SoC die → thermal gap pad → milled aluminum heat-spreader boss on the
  case base plate (3–4 mm) → folded/anodized aluminum shell (1.5 mm)
- N150 base is 6 W — same ballpark as the GX-412TC, so fanless is well within reach.
  Boost/cTDP-up can pull ~15–25 W in short bursts: validate with a worst-case soak
  test (all ports saturated + WireGuard) at 40 °C ambient; add base-plate fins or pin
  cTDP if needed. (The x7425E embedded SKU runs 12 W and is the thermal worst case to design the heat-spreader against.)
- **CAD:** case modeled in FreeCAD/OnShape from the KiCad STEP export; DXF flat
  patterns for the sheet-metal shop
- Front panel: 3× RJ45, 2× USB-A, USB-C console, DB9, power LED / activity LEDs.
  Rear: 12 V jack. Wall-mount tabs.

## 6. Operating system

- **Base:** FreeBSD **15.x-RELEASE**, custom-built image — *not* a pfSense fork;
  clean-room product with its own identity. (15.x is required for native
  `pflow(4)`: Netgate upstreamed it into the pf tree in `main`, so it ships in
  15.x but is **absent from all 14.x** — it backs the §8 baseline visibility
  exporter. 14.x dev boxes fall back to `ng_netflow`. See
  docs/visibility-design.md §7.)
- **Filesystem:** ZFS with **boot environments** (`bectl`) — every system update is a
  new BE, one-command rollback, the killer feature for an appliance
- **Image build:** poudriere for packages + a reproducible `mkimg`-based image
  pipeline in CI; signed release artifacts
- **Core services:**
  | Function | Component | Notes |
  |---|---|---|
  | Firewall/NAT | `pf` | pf.conf generated from declarative config |
  | DHCP | Kea (or dnsmasq DHCP-only) | ISC dhcpd is EOL |
  | DNS + Adblock | Unbound | blocklists compiled to `local-zone` data, auto-refresh |
  | VPN | WireGuard `wg(4)` | in-kernel since FreeBSD 14 |
  | Logging | syslogd + `pflog` | parsed into SQLite ring buffer for the UI |
  | Time | ntpd / chrony | |
- **Hardening:** minimal package set, no compiler/ports on the appliance, `pf`
  default-deny, WebUI on LAN only by default, SSH key-only

## 7. WebUI

- **Architecture:** one Go binary = HTTPS server + REST/JSON API + server-rendered
  htmx UI + config engine. Runs as a non-root service; privileged operations go
  through a tiny separate root helper with a narrow internal API (apply pf.conf,
  restart service, read counters).
- **Mobile-first, first-class (lesson from Firewalla):** the UI is a **responsive PWA
  served by the same binary** — installable (home-screen icon, standalone display),
  one mobile-first responsive layout (single-column reflow, bottom nav, large touch
  targets; dashboard cards and the canvas traffic graphs reflow to narrow).
  **No native app**
  (would mean two codebases + app-store review — solo-killing) and **no cloud relay**
  (would break the no-cloud pillar). Remote phone management goes over the **WireGuard
  tunnel** we already ship — the QR-code WG onboarding below *is* the phone setup flow.
  The honest tradeoff vs Firewalla's cloud app: you must be on the VPN to manage away
  from home — framed as a feature (no one else can reach your box either).
- **Config model (the core idea):** a single declarative config file
  (`/conf/config.json`, versioned, with history) is the source of truth. The engine
  renders it into `pf.conf`, Unbound/Kea/WireGuard configs, validates (`pfctl -nf`),
  applies atomically, and auto-rolls-back if the admin doesn't confirm within 60 s
  (prevents lock-out — the classic remote-firewall footgun).
- **Pages (matching current feature list):**
  - **Dashboard** — WAN status/IP, per-interface throughput sparklines, CPU/RAM/temp, service health, BE/version info
  - **Services** — shared catalog of network destinations (name + host IP + port + proto), defined once and referenced by both NAT port forwards and WireGuard access grants, so a host's address lives in one place. Deleting a service is refused while a port forward references it
  - **NAT** — port forwards (each references a **service** for its destination), outbound NAT, 1:1
  - **DHCP** — pools, static leases, active lease table
  - **DNS** — Unbound settings, local overrides, **Adblock** blocklist management with per-list enable + stats
  - **WireGuard** — site-to-site tunnels + peers, **and a wan-bound remote-access ("road warrior") server**: per-client keypair generation, auto-assigned tunnel IP, QR code + downloadable config, emailed config (via the System-page SMTP relay), and last-session time from `wg show`. Each client is **default-deny** and granted explicit access to **services** from the shared catalog via a searchable per-client access page (scales to ~100 services); grants are enforced in pf on the server interface. Clients get split-tunnel configs with the appliance gateway as DNS
  - **Logs** — live firewall log (pflog tail), system log, filterable. Refreshed by
    **htmx polling** (`hx-trigger="every 5s"`) — one transport for every live view;
    SSE stays unused until a view genuinely needs sub-poll latency
  - **Traffic Graph** — counters sampled to SQLite, drawn with **hand-rolled 2D
    canvas** (no charting library); live + historical (day/week/month). The only
    vendored JS in the whole UI is htmx and xterm — that is a deliberate line, not
    an accident: every chart dep is a supply-chain item on a security appliance
  - **Shell** — web terminal **in-process**: xterm.js in the browser over a Go
    WebSocket bridged to a `creack/pty` PTY by `fwd` itself — *not* ttyd or any
    reverse-proxied second daemon. That matters for the security story: there is no
    second listener, no second credential surface, and no process outside our auth
    gate; the session inherits the fwd session cookie and is additionally gated by
    an Origin check, a concurrent-session cap, an idle watchdog, and an audit ring
    (`docs/shell.md`). **Off by default**, big warning; SSH remains the recommended
    path — and the shell must run as an unprivileged user before this is safe to
    expose beyond a bench LAN (see the §10 Phase 0 hardening exit criterion)
  - **System** — updates (BE-based), config backup/restore (single file!), users, certificates, **outbound SMTP relay** (shared email facility: WireGuard client configs today, status/alerts later), reboot/halt
- **Auth:** local users, bcrypt/argon2, session cookies, optional TOTP, login
  rate-limiting. **Passkeys/WebAuthn** for biometric phone login (no password) —
  on-brand and best-in-class mobile UX; TOTP is the fallback.
- **Updates:** UI checks a signed release feed; update = fetch image, create BE, apply, reboot, auto-rollback on failed health check

## 8. Network visibility & traffic analysis

Deep traffic visibility is a deliberate differentiator — most consumer/prosumer
firewalls show north-south bandwidth and little else. The honest constraint: **a
gateway only sees traffic it routes.** North-south (host↔internet) is free; east-west
(host↔host) only becomes visible if it is forced through the box. Full east-west
visibility therefore requires owning the L2 edge (switch + AP), not just the gateway.
Set customer expectations accordingly and tier the feature to the gear they run.

**Visualizer:** ntopng on the appliance (FreeBSD package), with nDPI for app-layer
identification. Two ingestion modes: the box exports NetFlow/IPFIX from its own
interfaces (north-south + inter-segment, zero extra hardware), and optionally ingests
sFlow/NetFlow from a downstream managed switch or does packet capture on a mirror
port. This complements the lightweight built-in Traffic Graph page (§7) — ntopng is
the power-user deep-dive; the native UI is the always-on summary.

**Approaches considered (what each sees / what it costs):**

| Approach | Sees | Requires | Verdict |
|---|---|---|---|
| NetFlow/IPFIX from our own interfaces | North-south + inter-segment | Nothing — built in | **Baseline, ship it** |
| Trust-tier segmentation (WiFi/IoT/guest on port 3, own subnet) | Inter-segment east-west, + policy | Just our 3rd port | **Default win, no extra gear** |
| 802.1Q VLANs on LAN port (router-on-stick) | Full wired east-west if hosts segmented | Customer managed switch | **Power-user opt-in** |
| SPAN/port-mirror → ntopng capture | Everything wired, incl. same-subnet | Managed switch w/ mirror + spare cycles | Opt-in; mirror bandwidth cost |
| sFlow/NetFlow from managed switch | Sampled wired flows | Managed switch | Light; trends not forensics |
| AP client-isolation + TDLS-prohibit | WiFi east-west forced to gateway | **We control the AP config** | Opt-in; needs an AP we *spec/recommend*, not bundle (§13) |
| ARP/NDP spoofing (self-insert MITM) | Same-subnet east-west on flat LAN | Dumb switch only | **Rejected** — see below |

**WiFi is a special blind spot.** Same-AP, same-subnet stations are bridged by the AP
locally (intra-BSS forwarding) and never hit the uplink. **TDLS** (Tunneled Direct
Link Setup) is worse — stations talk radio-direct, the AP isn't even in path; only
radio capture (monitor mode, correct channel, decrypted, PMF permitting) could see it,
which we will not build. The non-radio fix is AP config: set the **TDLS-Prohibited**
bit and enable **client/AP isolation**, forcing station traffic up to the gateway.
Both only work if **we control the AP config** — an argument for *speccing/recommending*
a known-good AP rather than "bring your own" (but not *manufacturing* one; see §13 on
why we don't bundle hardware).

**ARP/NDP poisoning is explicitly rejected as an architecture.** Drop-in boxes that
*aren't* the gateway (Cujo, Fingbox) ARP-poison to insert themselves into the path. We
*are* the gateway, so we already route north-south and gain nothing for it. As a
flat-LAN east-west hack it is: (1) indistinguishable from an MITM attack — trips
customers' IDS/AV and looks malicious for a product we sell; (2) fragile — races the
real gateway, broken by any static ARP entry, constant re-poison churn; (3) IPv4-only
— IPv6 needs separate NDP + RA spoofing (with RA-Guard/SEND defenses to fight); (4) a
single-box bottleneck and a liability when it glitches. At most a loudly-warned,
IPv4-only "flat-LAN inspect mode" for customers who refuse a managed switch — never
the default path. Honest segmentation beats forged frames.

**Net positioning:** baseline NetFlow + nDPI north-south works on any topology with
zero config; the port-3 trust tier delivers real east-west visibility on a dumb switch;
full east-west (wired VLANs, WiFi isolation) is gated on owning the L2 edge and is
positioned as a "bring a managed switch / use a recommended AP" integration — not a
hardware bundle (§13), and not promised on arbitrary gear.

**Build vs. integrate — the Go/C split.** Guiding principle: **Go owns the control
plane; the C engines own the data plane.** Line-rate packet matching in a GC'd language
is the wrong tool, and the protocol/signature corpora (nDPI, Suricata rules) are
constantly-moving targets that would be madness to re-author. So the engines run as
**separate processes** and Go orchestrates them and parses their output (JSON / flow
records) — never statically linked in, never reimplemented:

| Component | What it is | Reimplement in Go? | Dependency if not |
|---|---|---|---|
| NetFlow/IPFIX **collector** | Parse flow records off UDP → SQLite | **Yes — easy, drops a dep** (goflow2 = reference) | — |
| NetFlow/IPFIX **export** | Generate flow records from traffic | **No** — stays in the packet path | kernel `pflow(4)` (FreeBSD base, reads the pf state table, zero userland) or softflowd |
| **nDPI** | 300+ protocol DPI dissectors (C lib) | **No, never** — years of work, perpetual protocol churn | `libnDPI` (LGPL) |
| **Suricata** | IDS/IPS engine, SIMD + Hyperscan, multi-thread | **No** — hyper-optimized line-rate matcher + whole rule ecosystem | `suricata` (GPLv2) + ruleset feed (ET Open free / ET Pro paid) + Hyperscan (Intel x86 — our SoC, good) + libpcap/netmap |
| **ntopng** | Full traffic-monitor *app* (C++), own UI + DB | **No** (it's a whole app) — and **demote it** (below) | `ntopng` (GPLv3) + **Redis (mandatory backing store)** + nDPI + libpcap |

**Go therefore implements:** the **IPFIX collector** (flow records → SQLite); **alert
ingestion** (Suricata `eve.json` → SQLite ring buffer → UI + the §8.5 LLM feed);
**config generation** for every engine (`suricata.yaml`, ntopng cfg, `pflow` setup) via
the same declarative engine as pf/unbound (§7); the **Traffic Graph + flow UI**
(server-rendered htmx + hand-rolled canvas, no chart dep — §7); and **engine
supervision** (start/stop/health). Go does **not** implement nDPI
dissectors, the Suricata engine, ntopng's forensic app, or packet-path flow export.

**Two gotchas that drive the tiering.** (1) **Redis** — ntopng *requires* it, a second
always-on service (~1–1.5 GB with ntopng, §8.5) that must be installed and running or
enabling Visibility fails at apply time. Even at the §2 16 GB sizing that is real
budget, and it competes head-on with the §8.5 LLM's ~3 GB — which is precisely why the
pair is the opt-in power tier and not the baseline. (2)
**Licensing** — Suricata GPLv2, ntopng GPLv3, nDPI LGPL are all fine as **separate
processes/packages** (mere aggregation, exactly as we already ship pf/unbound), but
**none may be static-linked into the Go binary**; in particular keep nDPI behind a
**separate helper process**, not cgo, to avoid pulling LGPL into the binary.

**Tiering (resolves where each engine lives):**

- **Baseline — ships in the base image, Go + kernel where possible.** Kernel `pflow(4)`
  export → **Go IPFIX collector** → SQLite → our UI. App-layer identification (which §8
  promises at baseline) comes from a **small nDPI helper process** that links `libnDPI`,
  classifies flows, and emits enriched records to the Go collector over a socket — this
  keeps app-ID baseline **without dragging in ntopng or Redis.** Base appliance =
  Go binary + kernel + one tiny nDPI helper: no Redis, no GPLv3 app, no IDS overhead.
- **Power tier — optional packages, off by default.** **ntopng + Redis** for the deep
  forensic deep-dive (the power-user role §8 already describes). **Suricata** for
  IDS/IPS — this is the detector stack the §8.5 LLM triage layer consumes; it is *not*
  in the base image and must be opted into.

## 8.5 AI assist layer (Phase 0.5) — local LLM for triage, explanation & NL interface

A small on-box LLM is a **human-facing layer on top of** the §8 visibility stack, never
a packet inspector. The architecture is deliberately split-brain: **dumb-fast detectors
do security at line rate; a slow-smart LLM does the human interface.** Optional,
off by default, fully local — it fits the no-cloud pillar and is a real prosumer
differentiator (a firewall that *explains itself*).

**The hard constraint — physics, not engineering.** A gateway sees millions of
packets/sec and gigabits/sec; a 2 B-param model on these cores does ~5–15 tokens/sec —
a 6+ order-of-magnitude gap. The LLM therefore **never touches the fast path**: no
inline DPI, no per-packet IDS, no malware byte-scanning. That work stays with the right
tools — the baseline nDPI flow path plus the opt-in power-tier detectors of §8:

| Job | Tool | Speed |
|---|---|---|
| Signature IDS/IPS | Suricata (FreeBSD pkg) | line-rate |
| App-layer DPI / flow classify | nDPI + ntopng (§8) | line-rate |
| Malware byte signatures | YARA (on flagged artifacts only) | fast |
| Flow anomaly detection | **small classical ML** (gradient-boost / isolation-forest on NetFlow features) — KB-size model, µs inference, *not* an LLM | line-rate |

The LLM consumes only the **low-volume, already-flagged output** of those detectors,
on-demand or in batch (seconds-to-minutes latency is fine).

**What the LLM does (all async, human-facing):**

- **Alert triage & summarize** — cluster/rank an overnight Suricata+ntopng alert pile
  into plain English: *"3 LAN hosts beaconing to one C2; likely a single infection on
  .14."*
- **Explain alerts** — translate cryptic signature IDs into what/why/risk for a
  non-expert. Big UX win for a sellable product.
- **NL query over flow data** — *"what did the TV talk to yesterday?"* → structured
  query over the ntopng/flow DB, results rendered in the existing UI.
- **Config assistant** — natural language → a proposed `/conf/config.json` change,
  validated through the normal engine (`pfctl -nf`, 60 s auto-rollback — §7). LLM only
  *drafts*; the deterministic engine remains the source of truth and the safety gate.
- **Incident report draft** — correlate flagged events into a readable writeup for
  export/email.

**Hardware budget (the gating reality).** CPU-only — no GPU, no usable NPU. Gracemont
has AVX2 + AVX-VNNI, which helps int8/Q4 inference via `llama.cpp`, but the box is
RAM- and thermal-bound:

- **Model:** target **Gemma 3n E2B** (≈2 B effective params; Q4 ≈ 2–3 GB resident).
  Alternates if quality is short: Qwen2.5-3B-Instruct, Phi-3.5-mini. Evaluate on *real*
  alert data before committing — 2 B models are weak at multi-step correlation.
- **Runtime:** `llama.cpp` (FreeBSD-buildable, single static-ish binary, no Python),
  loaded lazily; unload after idle to reclaim RAM.
- **RAM: 16 GB is a hardware prerequisite for this layer, not an option.** The model
  wants 2–3 GB resident, and it is the *last* claimant on the box:

  | Consumer | Resident |
  |---|---|
  | FreeBSD kernel + base services | ~0.5 GB |
  | ZFS ARC (capped — must be capped) | 2 GB |
  | pf states (200k) | ~0.06 GB |
  | Unbound + adblock local-zone (1M entries) | 0.5–1 GB |
  | fwd (Go) + SQLite page cache | ~0.3 GB |
  | `ndpi-helper` (100k tracked flows) | ~0.3 GB |
  | **Baseline subtotal** | **~4 GB** |
  | + Suricata w/ ET Open | 2–3 GB |
  | + ntopng + Redis | 1–1.5 GB |
  | + Gemma 3n E2B Q4 + KV cache | ~3 GB |
  | **Everything on** | **~10–12 GB** |

  On 8 GB you get the baseline plus *one* power-tier feature; the LLM plus Suricata
  plus ntopng does not fit. §2 therefore routes for 16 GB and stuffs it on every unit.
  Note the phasing trap: **Phase 0.5 lands before any PCB work (§10)**, so the LLM
  question is answered before layout — but only if the board was already routed for
  8 DRAM devices, because that decision cannot be revisited later (§2). Never swap a
  model to NVMe — latency death.
- **Contention & thermal:** inference pegs all 4 cores and blows the 6 W fanless budget,
  so it is **burst-only**: hard-capped to 1–2 threads, `nice`/`rctl`-limited, and gated
  to run only when WAN is idle or on explicit user request. **Routing/NAT must never be
  starved by the assistant** — this is a hard invariant, not a tuning goal.

**Why not let the LLM detect?** It hallucinates, it's six orders of magnitude too slow,
and it has no ground truth on raw bytes. Detection is line-rate pattern-matching — a
solved problem for the tools above. The LLM's value is *interpretation*, not detection.

**Implementation boundary (per the §8 Go/C split).** The assist layer is **all Go**: it
consumes the artifacts the detectors already produce — Suricata `eve.json` and the flow
SQLite — and adds the LLM glue (prompt assembly, `llama.cpp` invocation, NL-query →
structured-query translation, draft-config generation through the §7 engine). It does
**not** parse packets or embed any detector; richer alerts simply require the §8
power-tier (Suricata) to be opted in.

**Phasing.** Strictly software, and gated behind the detectors that feed it: the
**baseline nDPI flow path** covers NL flow queries out of the box, while **alert triage
and explanation require the §8 power tier (Suricata) opted in**. Ships as an **optional,
off-by-default** feature so the base appliance carries no LLM cost or attack surface.
Positioned as **Phase 0.5** — after the visibility baseline, before any firmware/PCB work.

**Open questions for this layer:** (1) bundle a model in the image (size, license,
update cadence) vs. an opt-in download? (2) is E2B good enough, or does the floor model
have to be 3 B? (§2 now routes 16 GB on every unit, so this is a quality
question, not a hardware one.) (3) does the config-assistant write path stay
*draft-only* forever (safest) or ever auto-apply behind confirmation? Lean draft-only.

## 9. Certification, manufacturing, supply (sellable product)

- **Regulatory (no radio in v1 keeps this sane):**
  - FCC Part 15 Subpart B unintentional radiator — SDoC after accredited-lab testing
  - CE: EMC Directive (EN 55032/55035) + Safety EN 62368-1 + RoHS/REACH
  - Budget: ~$2–5k EMC pre-scan during Phase 4, ~$10–20k full compliance suite
  - Powered by an already-certified external 12 V adapter (don't build a PSU)
- **Manufacturing:**
  - Pilot: 50–100 units at a quick-turn CM with X-ray BGA inspection
  - Production test jig: serial-console provisioning script flashes coreboot +
    OS image, runs port/LED/USB loopback tests, burns serial number + MAC range
    (buy a MAC OUI block or a range from a registrar)
- **Supply chain:** all long-life parts (Intel embedded SKUs carry ~10-year
  availability; i226-IT likewise). Second-source every commodity part in the BOM.
  Lock the SoC SKU only after confirming distributor stock at Mouser/Arrow.
- **BOM target & reality:** stretch goal is **sub-$200 retail** at a ~$70 BOM (beat
  the APU2's old $150-assembled price). Honest math says $70 is not reachable for a
  custom x86 SBC — the SoC + 3 NICs + RAM alone are ~$75–95 at the §2 sizing.
  Realistic numbers:

  | Part | qty 100 | qty 1000 |
  |------|---------|----------|
  | N150 SoC | $45 | $35 |
  | 3× i226-IT | $16 | $13 |
  | 16 GB DDR4 (soldered, 8× x16 dual-rank) | $34 | $27 |
  | 256 GB M.2 NVMe | $22 | $17 |
  | 16 GB eMMC (recovery image) | $7 | $4 |
  | 8-layer PCB + BGA assembly (8 DRAM devices) | $48 | $28 |
  | Case (folded aluminum) | $25 | $18 |
  | Connectors / power / misc | $28 | $18 |
  | **Total BOM** | **~$225** | **~$160** |

  So **$200 retail only works at scale and with thin margin**; it is not achievable
  at a pilot run. **⚠ The §2 memory/storage sizing moved this table** (8→16 GB DDR4,
  256 GB NVMe standard, eMMC demoted to a recovery image, 8 DRAM devices to assemble):
  BOM went ~$187→~$225 at qty 100 and ~$129→~$160 at qty 1000. **That breaks the
  $249 end of the launch range** — $249 retail on a $225 BOM is a loss once cert, test,
  and support are amortized, and the **$199 qty-1000 SKU is gone** at a $160 BOM.
  Positioning needs a decision: **$329–379 at launch** drifting to **$279 at qty 1000+**,
  or an explicit 8 GB / eMMC-only value SKU that accepts the second coreboot memory
  config §2 rules out. Levers to cut BOM: 8 GB single-rank (costs a second SPD blob and
  training pass — §2), eMMC over NVMe, DDR4 over DDR5, N100 over N150, volume on
  PCB/assembly (the single biggest swing). Don't chase $70.
- **Open hardware stance:** publish schematics, KiCad sources, coreboot config, and
  OS/UI source after pilot ships. Open design + sold-assembled is exactly the PC
  Engines model.

## 10. Phases & milestones

| Phase | Deliverable | Duration (solo, est.) |
|-------|-------------|----------------------|
| **0 — Software first** | Full OS image + WebUI running on a COTS ADL-N / i226 box (e.g. a Protectli VP24xx or CWWK N100 unit). All 9 UI feature areas working, **as a mobile-first responsive PWA** (passkey login, WG-tunnel remote access — §7). **Network visibility baseline (§8 tiering):** kernel `pflow(4)` → Go IPFIX collector → SQLite → the native Flows UI, with the separate nDPI helper supplying app labels — no ntopng, no Redis in the base image; ntopng + Redis are the opt-in power tier and only need to *install and enable cleanly*, not ship on. **Exit criterion — hardening pass:** the §7 privilege model actually implemented (non-root `fwd` + narrow root helper, shell defaulted to an unprivileged user), CSRF tokens on state-changing requests, and session revocation on user-delete/password-change. Cheaper now than after more surface accretes, and it is what separates "works on my bench LAN" from "safe on a LAN with other people on it". This is the product's value; hardware can lag. | 3–4 months |
| **0.5 — AI assist (optional)** | Off-by-default local LLM assist layer on top of the Phase 0 detector stack (Suricata + nDPI/ntopng): alert triage/summarize, alert explanation, NL flow queries, draft-only config assistant. `llama.cpp` + a 2–3 B model, burst-only, routing never starved. Requires the 16 GB board (§2, §8.5). **Software only — see §8.5.** | 1–2 months |
| **1 — Firmware** | coreboot + EDK2 payload booting the Phase 0 image on reference ADL-N hardware (Dasharo-supported box ideal), serial console end-to-end | 1–2 months |
| **2 — Carrier board** | SMARC/COMe-Mini carrier in KiCad: NICs, power, console, M.2. 5 protos assembled, OS + coreboot running on own hardware | 3 months |
| **3 — Case & thermal** | Folded-aluminum enclosure, thermal soak validation at 40 °C ambient | 1–2 months (overlaps 2) |
| **4 — Custom SBC (optional but the real goal)** | Full single-board layout replacing the module; 2 spins; external SI review; EMC pre-scan on rev B | 4–6 months |
| **5 — Productize** | Compliance testing, pilot run 50–100, test jig, docs site, store, launch | 3 months |

Total: roughly 12–18 months solo; Phases 0/1 are pure software and prove the project
before any PCB money is spent.

## 11. Repository layout

```
firewall/
├── plan.md          # this file
├── ui/              # Go WebUI + config engine
├── os/              # FreeBSD image build (poudriere, mkimg, CI)
├── fw/              # coreboot configs, build scripts, blobs policy
├── hw/
│   ├── carrier/     # Phase 2 KiCad project
│   └── sbc/         # Phase 4 KiCad project
├── case/            # FreeCAD models, DXF flat patterns
└── docs/            # design notes (visibility, nDPI helper, adblock, parental,
                     #   shell, competitive analysis, marketing). No user manual
                     #   yet — that's a Phase 5 deliverable
```

## 12. Top risks

1. **DDR4/PCIe layout complexity** (Phase 4) — mitigated by carrier-board phase,
   external SI review, and budgeting two spins
2. **Intel blob dependency** (FSP + CSE) — unavoidable on modern x86; mitigate by
   documenting precisely, tracking Dasharo's ME-slimming work; fully blob-free is a
   non-goal for v1
3. **Solo bus-factor** — the very problem that ended PC Engines; mitigate with open
   design files from day one and a contractor relationship (3mdeb) for firmware
4. **i226 quirks** — i225 had IPG/EEE errata; i226 is far better but disable EEE by
   default in the driver config and validate 2.5G interop early
5. **Thermal at 12 W fanless** — validate in Phase 3; cTDP-down to 6 W is the escape
   hatch
6. **Certification failure on rev B** — pre-scan early, keep a respin in the budget
7. **Embedded-SKU supply continuity** — *resolved by SKU choice.* The embedded tier is
   now **x7425E**, same ADL-N coreboot path as N150, so no firmware risk. C1110 was
   demoted after a 2026-06-24 review found no coreboot port and no public Intel FSP for
   Arizona Beach (likely NDA-gated → open firmware impossible). C1110 only revives if the
   Intel FSP Program Office confirms a public FSP. Residual item: x7425E is **design-in
   only** — not stocked at Mouser/Digi-Key/Arrow/Avnet (confirmed 2026-06-24); Intel RCP
   is **$58 @ 1k** (MM# 99C822), ~$13 over the N150 line. Qty-100 pricing comes through
   the **Intel IoT design-in channel / CM**, not catalog distribution — open that account
   early (ties to the §3 Intel Partner Alliance signup).

## 13. Open questions

- ~~Product/OS name and branding~~ **DECIDED:** Company **Pyroptics** (fire + optics =
  protection + visibility), product **Luciola** (firefly genus, "little light"; keeps the
  glowing-firefly logo + "Security you own"). `pyroptics.com` owned; product nests at
  `pyroptics.com/luciola`. Replaced "Lampyr" — phonetically identical to **Lampyre**
  (lampyre.io, an active OSINT/cyber tool, same field). `lampyr.org` owned but now a
  spare/redirect. Still TODO: **formal TM clearance** on both names, classes 9 + 42 +
  hardware (have counsel weigh the Gateron "Luciola" keyboard-switch line — different
  goods, likely fine). See `docs/marketing.md`.
- ~~SoC tiers: N150 value vs C1110 embedded~~ **DECIDED:** two-tier on one board,
  **N150** value + **x7425E** embedded (both ADL-N, x7425E drops onto the N150 PCB).
  **C1110 demoted** — 2026-06-24 review found no coreboot port and no public Intel FSP
  for Arizona Beach (§1, risk #7). Remaining: x7425E is **design-in only** (not at
  Mouser/Digi-Key/Arrow/Avnet, confirmed 2026-06-24; Intel RCP $58 @ 1k, MM# 99C822) —
  get qty-100 pricing via the **Intel IoT design-in channel / CM**, not catalog. Optional:
  a direct query to the Intel FSP Program Office to settle the C1110 FSP question with
  certainty (currently ~75% NDA-gated).
- **Retail price point — the old $199/$249–299 range is dead; pick the replacement.**
  The §2 sizing (16 GB dual-rank, 256 GB NVMe standard, 8 DRAM devices to assemble)
  moved the BOM to **~$225 @ qty 100 / ~$160 @ qty 1000** (§9 table), and $249 retail
  on a $225 BOM is a loss once cert, test, and support amortize. §9's proposal is
  **$329–379 at launch drifting to $279 at qty 1000+**; the only alternative that
  keeps a sub-$250 SKU is an explicit 8 GB / eMMC-only value variant, which costs the
  second coreboot memory config §2 deliberately killed. **Still open, and it is the
  load-bearing one** — it sets the whole position against the Purple at ~$319 and
  every number in `docs/firewalla.md` and `docs/marketing.md` follows from it.
- **3-port vs 4-port on the sellable board.** §2 routes 3× i226-IT with **3 spare
  PCIe lanes** — a 4th NIC is affordable in lanes, but costs a lane, a jack, ~$5 of
  BOM, and front-panel width. Every COTS box in this class (and the Phase 0 bench
  box) is 4-port, so 3 ports reads as a spec deficit on a comparison grid even when
  the trust-tier argument (§8) only needs three. Software is already close to
  port-count-agnostic — the config model takes N `opt` interfaces; only the UI's
  add-an-interface affordance is missing — so this is purely a hardware/positioning
  call, not an engine one. Decide before the Phase 2 carrier layout.
- SMARC vs COM Express Mini for the Phase 2 module (pick by module vendor's ADL-N
  offering and long-life commitment — Kontron, Advantech, congatec all ship ADL-N SMARC)
- IPv6 scope for v1 UI (DHCPv6-PD, RA — recommend yes, table stakes in 2026)
- ~~eMMC: worth the BOM cost vs. NVMe-only?~~ **DECIDED (§2):** yes, but only as a
  **16 GB recovery/rescue image** — never primary. NVMe is the primary and 256 GB is
  the standard fit; 32 GB eMMC can't carry the full-featured appliance, while 16 GB
  is plenty for a failsafe that survives a botched update or a dead NVMe, at $7/$4
  on the §9 BOM. Residual is a *bring-up* risk, not a decision: FreeBSD's
  `sdhci`/`mmcsd` path on Intel PCI SDHCI is far less exercised than NVMe — validate
  early or the recovery path is theoretical, and drop the part if it doesn't work.
- TPM: populate by default (measured boot story) or leave as option?
- **Off-VPN push/alerting without a cloud.** Web Push needs a push service = cloud,
  which the no-cloud pillar forbids (§7). In-app alerts work fine for a phone on the
  WireGuard tunnel, but how do we notify the admin of an event (WAN down, intrusion,
  failed update) when they're *not* on the VPN? Candidates: user-configured email/SMTP,
  a self-hosted ntfy the customer points at, or a webhook to their own service. Lean:
  ship email + optional ntfy/webhook, never an us-operated cloud. Decide which for v1.
  **Progress:** a user-configured **SMTP relay** now exists (config + `internal/mail`,
  first consumer: emailing WireGuard client configs) — the email leg of this is built;
  ntfy/webhook still open.
- **AP / managed-switch bundling — lean NO (gateway-only).** Full east-west visibility
  needs owning the L2 edge (§8), which tempts bundling a switch + AP — but that rebuilds
  UniFi's ecosystem, the exact scope trap we reject (`docs/marketing.md`, "The scope
  trap"). Default stance: ship the gateway alone, be the **brain box** that integrates
  with the customer's switch/AP via open standards (NetFlow/IPFIX, sFlow, 802.1Q).
  Baseline north-south + nDPI ships free; deeper east-west is "bring a managed switch /
  use your own AP," never "buy ours." Open sub-questions if ever revisited: (1) spec a
  *recommended/validated* switch + AP (compatibility list, no inventory) as a middle
  path? (2) does WiFi east-west matter enough to justify speccing an AP we can set
  TDLS-prohibit + client-isolation on? Lean: recommend, don't manufacture.
