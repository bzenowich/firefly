# Luciola — Project Plan

**Pyroptics** (company) · **Luciola** (product). A spiritual successor to the PC Engines
APU2: an open, fanless, serial-console-first 3-port firewall appliance with coreboot
firmware, a FreeBSD-based OS, and a purpose-built WebUI. Goal: a sellable product with
published design files. Branding rationale + positioning in `docs/marketing.md`.

## 1. Decisions made

| Area | Decision | Rationale |
|------|----------|-----------|
| SoC | **Value SKU:** Intel Processor N150 (Twin Lake / ADL-N) | 4 Gracemont cores @ 3.6 GHz, 6 W base TDP, 9 PCIe 3.0 lanes, AES-NI/VAES, public Intel FSP enables coreboot, strong FreeBSD support, best $/perf for a 3-port box |
| SoC | **Embedded SKU:** Intel Atom C1110 (Arizona Beach) | Same 4× Gracemont cores, but networking-grade: ~10-yr embedded availability, **real LPDDR5 ECC**, PCIe **Gen4** (~20 lanes), 13 W. Proven in the Netgate 4200 (C1110 + 4× i226, 3.2 Gbps IPsec). **Separate board** — not pin-compatible with N150 (different package, LPDDR5). coreboot support **unverified** — gating risk |
| NICs | 3× Intel i226-IT (2.5GbE) | Industrial temp, one PCIe 3.0 lane each, mature FreeBSD `igc(4)` driver, auto-negotiates down to 1000baseT |
| WebUI | Go + htmx, single static binary | No runtime deps, trivial FreeBSD cross-compile, server-rendered with live updates, small attack surface, maintainable solo |
| Goal | Sellable product | Plan includes certification, manufacturing, and supply-chain sections |

**SoC SKU strategy — two-tier, both Gracemont:**

- **Value SKU — Intel Processor N150** (Twin Lake, 4× Gracemont @ 3.6 GHz, 6 W base,
  9 PCIe 3.0 lanes). Current silicon (Q1 2025), cheapest, highest clock, best-supported
  coreboot path (ADL-N / Dasharo / Nissa). **N100** is the drop-in fallback (3.4 GHz,
  ~same price) if N150 stock lags. Memory: soldered DDR4 with In-Band ECC only.
- **Embedded SKU — Intel Atom C1110** (Arizona Beach, Q2 2022). *Same Gracemont cores*
  as N150 but purpose-built for networking: ~10-yr embedded availability, **real
  LPDDR5-5200 ECC**, **PCIe Gen4** (1×16+4 or 2×8+4, ~20 lanes), 13 W, VAES crypto
  (no QAT). Lower base clock (2.1 GHz) — irrelevant for I/O-bound firewall work; the
  Netgate 4200 (C1110 + 4× i226-IT) does 3.2 Gbps IPsec on pfSense, validating this
  exact architecture. **Not a drop-in for the N150 board** (different package, LPDDR5
  vs DDR4) — it needs its own PCB layout.

**Two gating unknowns to confirm before committing C1110:** (1) does a **coreboot port
exist** for Arizona Beach? Netgate ships its own BIOS, so this may be a from-scratch
bring-up — a serious risk to the open-firmware pillar. (2) **C1110 price at qty 100**
(embedded pricing, no public figure). If coreboot is a dead end, the embedded path
falls back to the **Atom x7425E** (true drop-in for the N150 ADL-N board, In-Band ECC,
12 W) instead. Higher-end future option: Atom x7000RE "Amston Lake" (up to 8 cores).
Confirm distributor stock (Mouser/Arrow) before locking any SKU.

## 2. Hardware specification (target)

- **SoC:** two-tier, both 4× Gracemont — **N150** (value, 6 W, DDR4, drop-in N100
  fallback) and **Atom C1110** (embedded, 13 W, LPDDR5 ECC, Gen4; separate board).
  See §1 for the full SKU strategy and the C1110 coreboot/price gating items.
- **Memory:** 8 GB soldered DDR4-3200 (single channel, 4× x16 chips). In-Band ECC
  enabled where the SKU/firmware supports it. Soldered like the APU2 — no SODIMM to
  work loose, better vibration/thermal profile.
- **Storage:**
  - M.2 2280 M-key, PCIe 3.0 x2 NVMe (primary)
  - Optional 32 GB eMMC on board (low-cost SKU / recovery image)
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
  cTDP if needed. (The x7425E embedded alternate runs 12 W and is the thermal worst case.)
- **CAD:** case modeled in FreeCAD/OnShape from the KiCad STEP export; DXF flat
  patterns for the sheet-metal shop
- Front panel: 3× RJ45, 2× USB-A, USB-C console, DB9, power LED / activity LEDs.
  Rear: 12 V jack. Wall-mount tabs.

## 6. Operating system

- **Base:** FreeBSD 14.x-RELEASE (track 15.x by ship time), custom-built image —
  *not* a pfSense fork; clean-room product with its own identity
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
  targets; dashboard sparklines + uPlot graphs reflow to narrow). **No native app**
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
  - **NAT** — port forwards, outbound NAT, 1:1
  - **DHCP** — pools, static leases, active lease table
  - **DNS** — Unbound settings, local overrides, **Adblock** blocklist management with per-list enable + stats
  - **WireGuard** — site-to-site tunnels + peers, **and a wan-bound remote-access ("road warrior") server**: per-client keypair generation, auto-assigned tunnel IP, QR code + downloadable config, emailed config (via SMTP relay), and last-session time from `wg show`. Each client is **default-deny** and granted explicit access to a catalog of network **services** (host+port+proto), enforced in pf on the server interface. Clients get split-tunnel configs with the appliance gateway as DNS
  - **Logs** — live firewall log (pflog tail via SSE/htmx), system log, filterable
  - **Traffic Graph** — counters sampled to SQLite, rendered with uPlot (one small JS dep); live + historical (day/week/month)
  - **Shell** — web terminal via ttyd reverse-proxied behind auth, **off by default**, big warning; SSH remains the recommended path
  - **System** — updates (BE-based), config backup/restore (single file!), users, certificates, reboot/halt
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
  custom x86 SBC — the SoC + 3 NICs + RAM alone are ~$60–75. Realistic numbers:

  | Part | qty 100 | qty 1000 |
  |------|---------|----------|
  | N150 SoC | $45 | $35 |
  | 3× i226-IT | $16 | $13 |
  | 8 GB DDR4 (soldered) | $18 | $14 |
  | 32 GB eMMC (NVMe optional) | $10 | $6 |
  | 8-layer PCB + BGA assembly | $45 | $25 |
  | Case (folded aluminum) | $25 | $18 |
  | Connectors / power / misc | $28 | $18 |
  | **Total BOM** | **~$187** | **~$129** |

  So **$200 retail only works at scale and with thin margin**; it is not achievable
  at a pilot run. Realistic positioning: **$249–299 retail** at launch (qty 100,
  covers cert amortization + test + support), drifting toward a **$199 SKU at qty
  1000+** with eMMC and DDR4. Levers to cut BOM: eMMC over NVMe, DDR4 over DDR5,
  N100 over N150, volume on PCB/assembly (the single biggest swing). Don't chase $70.
- **Open hardware stance:** publish schematics, KiCad sources, coreboot config, and
  OS/UI source after pilot ships. Open design + sold-assembled is exactly the PC
  Engines model.

## 10. Phases & milestones

| Phase | Deliverable | Duration (solo, est.) |
|-------|-------------|----------------------|
| **0 — Software first** | Full OS image + WebUI running on a COTS ADL-N / i226 box (e.g. a Protectli VP24xx or CWWK N100 unit). All 9 UI feature areas working, **as a mobile-first responsive PWA** (passkey login, WG-tunnel remote access — §7). **Network visibility baseline:** NetFlow/IPFIX + nDPI with ntopng integrated on-box (§8). This is the product's value; hardware can lag. | 3–4 months |
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
└── docs/            # user manual, build guides
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
7. **C1110 coreboot bring-up** (embedded SKU only) — Arizona Beach has no proven
   coreboot port; Netgate ships closed BIOS. Confirm feasibility before committing the
   embedded board; **x7425E is the drop-in fallback** if it's a dead end. Does not
   affect the N150 value SKU (ADL-N coreboot is solid).

## 13. Open questions

- ~~Product/OS name and branding~~ **DECIDED:** Company **Pyroptics** (fire + optics =
  protection + visibility), product **Luciola** (firefly genus, "little light"; keeps the
  glowing-firefly logo + "Security you own"). `pyroptics.com` owned; product nests at
  `pyroptics.com/luciola`. Replaced "Lampyr" — phonetically identical to **Lampyre**
  (lampyre.io, an active OSINT/cyber tool, same field). `lampyr.org` owned but now a
  spare/redirect. Still TODO: **formal TM clearance** on both names, classes 9 + 42 +
  hardware (have counsel weigh the Gateron "Luciola" keyboard-switch line — different
  goods, likely fine). See `docs/marketing.md`.
- SoC tiers: **N150** value vs **C1110** embedded (both Gracemont). Two blockers on
  C1110 before it's real — **(1) coreboot port for Arizona Beach exists?** (may be
  from-scratch; risks the open-firmware pillar) and **(2) qty-100 price?** If coreboot
  is a dead end, fall back to **x7425E** (drop-in for the N150 board). Confirm
  distributor stock before locking.
- Retail price point: $199 stretch (needs qty 1000+) vs $249–299 realistic at launch
- SMARC vs COM Express Mini for the Phase 2 module (pick by module vendor's ADL-N
  offering and long-life commitment — Kontron, Advantech, congatec all ship ADL-N SMARC)
- IPv6 scope for v1 UI (DHCPv6-PD, RA — recommend yes, table stakes in 2026)
- eMMC: worth the BOM cost vs. NVMe-only?
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
