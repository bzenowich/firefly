# Open Firewall Appliance — Project Plan

A spiritual successor to the PC Engines APU2: an open, fanless, serial-console-first
3-port firewall appliance with coreboot firmware, a FreeBSD-based OS, and a purpose-built
WebUI. Goal: a sellable product with published design files.

## 1. Decisions made

| Area | Decision | Rationale |
|------|----------|-----------|
| SoC | Intel Atom x7000E series (Alder Lake-N embedded) | Long-life embedded availability into the 2030s, ~6–12 W TDP, AES-NI + SHA extensions, public Intel FSP enables coreboot, strong FreeBSD support |
| NICs | 3× Intel i226-IT (2.5GbE) | Industrial temp, one PCIe 3.0 lane each, mature FreeBSD `igc(4)` driver, auto-negotiates down to 1000baseT |
| WebUI | Go + htmx, single static binary | No runtime deps, trivial FreeBSD cross-compile, server-rendered with live updates, small attack surface, maintainable solo |
| Goal | Sellable product | Plan includes certification, manufacturing, and supply-chain sections |

**SoC SKU note:** the exact part needs confirmation against Intel's embedded roadmap at
design start. Primary candidate: **Atom x7425E** (4 cores, 12 W, Alder Lake-N embedded).
Alternates: x7211E (2-core, low-cost SKU) and the Atom x7000RE "Amston Lake" series
(up to 8 cores, In-Band ECC support) for a higher-end variant. All share the same
ballout/platform, so one PCB can serve multiple SKUs.

## 2. Hardware specification (target)

- **SoC:** Intel Atom x7425E, 4× Gracemont cores, 12 W TDP, fanless
- **Memory:** 8 GB soldered DDR4-3200 (single channel, 4× x16 chips). In-Band ECC
  enabled if the chosen SKU supports it. Soldered like the APU2 — no SODIMM to work
  loose, better vibration/thermal profile.
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
- **Power:** 12 V DC barrel jack (center positive, APU-compatible), ~25 W budget,
  buck regulators for SoC rails. No PoE in v1 (adds cost/cert complexity; possible v2 option).
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
- 12 W TDP is ~double the GX-412TC's 6 W: validate with a worst-case soak test
  (all ports saturated + WireGuard) at 40 °C ambient; add base-plate fins if needed,
  or run the 6 W cTDP-down config as a fallback
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
  - **WireGuard** — tunnels, peers, QR code generation for mobile clients, handshake status
  - **Logs** — live firewall log (pflog tail via SSE/htmx), system log, filterable
  - **Traffic Graph** — counters sampled to SQLite, rendered with uPlot (one small JS dep); live + historical (day/week/month)
  - **Shell** — web terminal via ttyd reverse-proxied behind auth, **off by default**, big warning; SSH remains the recommended path
  - **System** — updates (BE-based), config backup/restore (single file!), users, certificates, reboot/halt
- **Auth:** local users, bcrypt/argon2, session cookies, optional TOTP, login rate-limiting
- **Updates:** UI checks a signed release feed; update = fetch image, create BE, apply, reboot, auto-rollback on failed health check

## 8. Certification, manufacturing, supply (sellable product)

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
- **Rough BOM target:** $150–190 at qty 100 (SoC ~$45–60, NICs ~$18, DDR4 ~$18,
  PCB+assembly ~$45, case ~$25, connectors/power/misc ~$30). Suggests a
  $329–399 retail with margin for cert amortization — APU2 pricing is not
  reachable in 2026 and shouldn't be the target.
- **Open hardware stance:** publish schematics, KiCad sources, coreboot config, and
  OS/UI source after pilot ships. Open design + sold-assembled is exactly the PC
  Engines model.

## 9. Phases & milestones

| Phase | Deliverable | Duration (solo, est.) |
|-------|-------------|----------------------|
| **0 — Software first** | Full OS image + WebUI running on a COTS ADL-N / i226 box (e.g. a Protectli VP24xx or CWWK N100 unit). All 9 UI feature areas working. This is the product's value; hardware can lag. | 3–4 months |
| **1 — Firmware** | coreboot + EDK2 payload booting the Phase 0 image on reference ADL-N hardware (Dasharo-supported box ideal), serial console end-to-end | 1–2 months |
| **2 — Carrier board** | SMARC/COMe-Mini carrier in KiCad: NICs, power, console, M.2. 5 protos assembled, OS + coreboot running on own hardware | 3 months |
| **3 — Case & thermal** | Folded-aluminum enclosure, thermal soak validation at 40 °C ambient | 1–2 months (overlaps 2) |
| **4 — Custom SBC (optional but the real goal)** | Full single-board layout replacing the module; 2 spins; external SI review; EMC pre-scan on rev B | 4–6 months |
| **5 — Productize** | Compliance testing, pilot run 50–100, test jig, docs site, store, launch | 3 months |

Total: roughly 12–18 months solo; Phases 0/1 are pure software and prove the project
before any PCB money is spent.

## 10. Repository layout

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

## 11. Top risks

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

## 12. Open questions

- Product/OS name and branding
- Confirm exact SoC SKU against current Intel embedded roadmap + distributor stock
- SMARC vs COM Express Mini for the Phase 2 module (pick by module vendor's ADL-N
  offering and long-life commitment — Kontron, Advantech, congatec all ship ADL-N SMARC)
- IPv6 scope for v1 UI (DHCPv6-PD, RA — recommend yes, table stakes in 2026)
- eMMC: worth the BOM cost vs. NVMe-only?
- TPM: populate by default (measured boot story) or leave as option?
