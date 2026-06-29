# Luciola vs Firewalla Purple — feature comparison

A head-to-head between **Luciola** (this project — see `../plan.md`) and the
**Firewalla Purple**, the closest prosumer competitor in price and positioning.
The Purple is the relevant SKU: gigabit-class, ~$319 retail, sits between the
1Gbps Gold and the 500 Mbps Purple SE.

The two products make opposite bets. Firewalla is an **ARM appliance driven by a
cloud-connected mobile app**, optimized for zero-config consumer onboarding and
deep out-of-the-box traffic intelligence. Luciola is an **open x86 appliance with
a self-hosted web UI and no cloud**, optimized for ownership, transparency, and
prosumer/SMB routing. Where Firewalla is ahead today is called out honestly.

> **Maturity caveat.** Firewalla is a shipping product with years of polish, a
> threat-intel pipeline, and a large install base. Luciola is in Phase 0
> (software). This table compares the *target* Luciola design against
> *shipping* Firewalla. Columns marked **(planned)** are not built yet.

## At a glance

| | Luciola | Firewalla Purple |
|---|---|---|
| **Bet** | Ownership + transparency, no cloud | Convenience + intelligence via cloud |
| **Platform** | Intel x86 (N150), FreeBSD + `pf` | 6-core ARM, custom Linux |
| **RAM / storage** | 8 GB / NVMe | 2 GB / 16 GB eMMC |
| **Ports / speed** | 3× 2.5GbE | 2× 1GbE |
| **Management** | Self-hosted web UI + PWA | Mobile app only |
| **Cloud / account** | None required | Required |
| **Openness** | Open HW + firmware + source | Closed |
| **Config model** | Declarative file, atomic apply + 60 s auto-rollback | App/cloud state |
| **OS updates** | ZFS boot environments (rollback) | OTA app push |
| **Policy engine** | Service-catalog grants (no per-device rules yet) | Mature per-device rules + schedules |
| **DPI / categories** | nDPI (planned) | Out-of-box app/category ID |
| **Threat intel** | List-based only | Cloud-fed Active Protect (IDS-style) |
| **QoS** | None yet | Smart Queue (bufferbloat) |
| **Alerts** | Email/ntfy, on-VPN (no cloud push) | Rich push alarms |
| **VPN** | WireGuard (server + S2S) | WireGuard + OpenVPN, + VPN client |
| **Price** | $249–299 target | ~$319 |
| **Status** | Phase 0 (software) | Shipping, mature |
| **Best for** | Prosumers/homelab/SMB who run their own gateway | Families/consumers wanting easy strong security |

*Detail and sourcing for every row is in the sections below.*

## Hardware

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| CPU | Intel N150 (4× Gracemont x86-64, 3.6 GHz) / Atom C1110 embedded SKU | 6-core ARM (4× Cortex-A53 + 2× Cortex-A73) |
| Architecture | x86-64 | ARMv8 (aarch64) |
| RAM | 8 GB DDR4 (In-Band ECC where supported) | 2 GB DDR4 |
| Storage | M.2 NVMe (+ optional 32 GB eMMC) | 16 GB eMMC |
| Network ports | **3× 2.5GbE** (i226-IT) | 2× 1GbE |
| Inspection throughput | Multi-Gbps target (x86 + pf, validate in Phase 0) | ~1 Gbps |
| Onboard WiFi | None in v1 (M.2 E-key unpopulated; AP is "bring your own") | 2×2 802.11ac, **short-range** (setup/backup only, not a real AP) |
| Bluetooth | None | BT 5.0 (used for app onboarding) |
| Console | DB9 RS232 + USB-C serial | None (app-only) |
| Cooling | Fanless (case = heatsink) | Fanless |
| Power | 12 V barrel, ~18 W | USB-C, ~low single-digit W |
| Size | ~APU2 class (~152 mm) | Palm-size, smaller |
| Expansion | M.2 M-key + E-key, spare PCIe lanes | None |
| TPM / measured boot | Optional TPM 2.0 fit | None |

**Read:** Luciola wins on raw compute, RAM, port count (3× vs 2×), and link speed
(2.5G vs 1G). Firewalla wins on size, idle power, and bundling a (weak) radio +
Bluetooth for setup.

## Firmware & openness

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| Boot firmware | **coreboot** + EDK2 payload (planned) | Vendor U-Boot (closed) |
| Open schematics / PCB | **Yes** — KiCad sources published after pilot | No |
| Open OS / UI source | **Yes** (planned) | No (app + backend closed) |
| Blob policy | Documented (Intel FSP + CSE only); ME-slimming tracked | Undisclosed |
| Serial recovery / reflash | flashrom + external programmer header | No |
| Right-to-repair posture | Core design pillar | Sealed appliance |

**Read:** This is Luciola's clearest structural advantage. Firewalla is a closed
appliance; Luciola is open hardware + open firmware + open source by design.

## Operating system & network stack

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| Base OS | FreeBSD 15.x (custom image, not a fork) | Custom Linux (Ubuntu-derived) |
| Firewall engine | `pf` (declarative config → `pf.conf`) | iptables/nftables + custom userland |
| Update model | **ZFS boot environments** — one-command rollback | OTA app-pushed updates |
| Config as data | Single declarative `config.json`, versioned, with history | App/cloud-stored config |
| Atomic apply + auto-rollback | **Yes** — 60 s confirm or revert (anti-lockout) | N/A (cloud-mediated) |
| Backup / restore | Single config file | Cloud backup (account-tied) |
| Routing modes | Router (gateway) | Router, **Bridge**, **DHCP (monitor)**, Simple — flexible drop-in |

**Read:** Luciola's BE rollback + declarative config + anti-lockout is a stronger
*operational* story for a real router. Firewalla's bridge/DHCP modes make it
easier to drop into an existing network without re-architecting — a genuine
Firewalla convenience Luciola does not match (Luciola is the gateway, period).

## Management UX

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| Primary interface | **Self-hosted web UI** (Go + htmx), responsive **PWA** | **Native mobile app** (iOS/Android) only — no web UI |
| Cloud dependency | **None** — no relay, no account | **Yes** — app talks via Firewalla cloud relay |
| Remote management | Over the WireGuard tunnel you already run | Anywhere via cloud (more convenient) |
| Account required | No | Yes (app account) |
| Desktop management | Yes (browser) | No (mobile app only) |
| Auth | Local users, argon2/bcrypt, TOTP, **passkeys/WebAuthn** | App-account auth |
| Web terminal / shell | Optional ttyd behind auth (off by default) | None (SSH via support) |
| Offline operation | Fully functional with zero internet | Degraded without cloud |

**Read:** The core philosophical split. Firewalla's cloud app is **more
convenient** — manage from anywhere, no VPN needed, polished mobile flows.
Luciola trades that convenience for **no cloud, no account, no third party in the
path**: remote management requires being on your own WireGuard tunnel. Honest
framing — "no one else can reach your box either."

## Firewall, NAT & services

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| Stateful firewall | `pf` default-deny | Yes |
| Port forwarding | Yes (references shared service catalog) | Yes |
| Outbound / 1:1 NAT | Yes | Yes (NAT) |
| DHCP server | Kea / dnsmasq, static leases, lease table | Yes |
| Local DNS | Unbound, local overrides | Yes |
| Network segmentation / VLANs | 802.1Q, trust-tier 3rd port (planned) | VLAN + segment support |
| IPv6 | DHCPv6-PD / RA (planned for v1) | Yes |
| Per-device / per-group policy | Service-catalog grants (per WG client today) | **Per-device rules, groups, schedules** (mature) |

**Read:** Firewalla's per-device policy engine (rules per host/group, time
schedules, "pause internet for this kid's tablet") is more mature and
consumer-friendly today. Luciola's model is service-catalog-centric and
prosumer-oriented; per-device parental-style policy is thinner.

## VPN

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| WireGuard server | **Yes** — road-warrior, per-client keys, QR + emailed config | Yes |
| WireGuard site-to-site | Yes | Yes |
| OpenVPN | No (WireGuard-only by design) | Yes |
| VPN client (egress) | Planned | Yes (route devices out via VPN) |
| Per-client access control | **Default-deny + explicit service grants**, enforced in pf | Group-based |
| Onboarding | QR code + emailed config (SMTP relay) | App-driven |
| Kernel WireGuard | Yes (`wg(4)`, in-kernel FreeBSD 14) | Yes |

**Read:** Comparable. Luciola's WG access-grant model (default-deny, per-client
service grants in pf) is a tighter security posture; Firewalla adds OpenVPN and a
polished VPN-client (route-out) feature Luciola hasn't built.

## DNS, ad-block & threat intelligence

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| Ad / tracker blocking | Unbound blocklists, per-list enable + stats | Yes (ad block, family filter) |
| DoH / DoT | DoH planned | **DoH upstream** |
| Threat-intel feeds | Not built (own blocklists only) | **Active Protect cloud feed** — IDS-style blocking |
| Reputation / IoC blocking | No | Yes (cloud-fed) |
| Parental controls | Service-grant / segment approach | **Mature** (categories, schedules, social/gaming) |

**Read:** Firewalla is clearly ahead here. Its cloud-fed threat intelligence
("Active Protect") and category/parental controls are a major selling point and a
direct consequence of the cloud model Luciola rejects. Luciola does
list-based blocking only; matching curated threat-intel without a cloud is an
open problem (self-hosted feeds / ntfy-style).

## Traffic visibility & analytics

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| Per-interface throughput | Dashboard sparklines + uPlot history | Real-time + history |
| Flow logging | NetFlow/IPFIX from own interfaces (planned) | Built-in flow capture |
| Deep packet inspection / app-ID | nDPI via ntopng, or native (design in `netflow.md`) | **DPI app/category ID** (mature, out-of-box) |
| East-west (host↔host) visibility | Only what it routes; honest topology tiering (§8) | Same gateway limitation; bridge mode helps |
| Per-device usage breakdown | Planned | **Yes — strong, polished** |
| Historical analytics | SQLite + uPlot, day/week/month | Cloud-assisted history |
| Alarms / anomaly alerts | Email/ntfy (planned, no cloud push) | **Rich push alarms** (via cloud) |

**Read:** Firewalla's out-of-box flow + DPI + per-device analytics with push
alarms is its headline feature and is more mature. Luciola's plan (NetFlow + nDPI
+ optional ntopng) can reach parity on *visibility* but the **no-cloud push**
constraint makes off-VPN alerting genuinely harder (an open question in plan.md
§13).

## Software capabilities — deep dive

The tables above compare features feature-by-feature. This section goes deeper
into *how each project's software actually works*, because the two are built on
opposite architectures and the differences matter more than a checkbox grid shows.

Luciola status below reflects what is **actually built** in the Go binary today
(`../ui/`): pages for dashboard, interfaces/DHCP, services, NAT, DNS, WireGuard
(+ per-client access), traffic, visibility, logs, shell, and system. Items still
on the roadmap are marked **(planned)**.

### Firewalla — the rule engine

Firewalla's software centre of gravity is its **policy/rule engine**, exposed
entirely through the mobile app. A rule has four elements — **action, target,
device, schedule** — and the power is in the breadth of *target* types:

- **Applications** — app-level identity from DPI (e.g. "TikTok", "Steam"),
  not just IP/port.
- **Categories** — curated content buckets (gaming, adult/porn, video,
  social, shopping, VPN/proxy) maintained cloud-side.
- **Target Lists** — reusable named sets of domains (exact or all-subdomains)
  and IPs (exact or range), used as building blocks across rules and QoS. The
  community shares and subscribes to these.
- **Regions / Geo-IP** — block or allow whole countries (inbound and outbound).
- **Network flows** — block by IP / domain / port from a seen flow.
- **Internet / Local Network** — coarse on/off and segment isolation.

Rules attach to a **device, a device group, a network, or all devices**, with
optional **schedules** ("no gaming 9pm–7am", "pause this tablet"). Blocks can be
created **directly from an alarm or a flow** — one tap from "this device hit a
malicious domain" to a standing block. This closed-loop *observe → one-tap
enforce* flow is Firewalla's signature UX and is genuinely mature.

Supporting software:

- **Active Protect** — cloud-fed IDS-style blocking of malicious IPs/domains,
  plus newer advanced threat filtering (lookalike / Punycode domain detection).
- **Smart Queue (QoS)** — fq_codel-based bufferbloat control with per-device /
  per-group / per-target priority (Low / Default / High) to protect video calls.
- **Flows** — continuous flow capture with per-device, per-app, per-category
  attribution; tap any flow to diagnose which rule matched or to allow/block it.
- **Alarms** — push notifications for new devices, abnormal upload, port scans,
  malicious-site access, etc., each actionable.
- **Network assessment** — open-port detection, basic vulnerability checks,
  new-device alarms.
- **DDNS**, **DoH upstream**, **VPN client route-out** (send selected devices
  out through a commercial VPN), **VPN server** (WireGuard + OpenVPN).
- **MSP portal** — a separate web console for managing many Firewalla boxes (this
  is the *only* web UI Firewalla offers, and it's for fleet operators, not the
  per-box admin).

The architectural cost: **all of this rides on the cloud + mobile app.**
Category lists, threat intel, push alarms, app updates, and remote access are
cloud-mediated. There is no local web UI for a single box and no documented
declarative config you own as a file. You configure by tapping in an app that
talks to Firewalla's relay.

### Luciola — the config engine

Luciola's software centre of gravity is the opposite: a **single declarative
config** (`/conf/config.json`, versioned with history) that is the source of
truth, plus an **apply engine** that renders it to native configs, validates,
applies atomically, and auto-rolls-back. This is built today:

- **Render → validate → apply → confirm/rollback.** Editing config produces a
  pending plan; the engine renders `pf.conf` / Unbound / Kea / WireGuard, runs
  `pfctl -nf` to validate, applies atomically, then requires the admin to
  **confirm within 60 s or it auto-reverts** — the anti-lockout that a remote
  firewall lives or dies by. Routes: `POST /system/apply`,
  `/system/apply/confirm`, `/system/apply/rollback`. Firewalla has no equivalent
  user-facing concept because the app/cloud mediates state.
- **Service catalog** — network destinations (name + host + port + proto)
  defined **once** and referenced by both NAT forwards and WireGuard access
  grants, so a host's address lives in one place; deletion is refused while
  referenced. This is a deliberately different model from Firewalla's
  per-device rules: Luciola is **destination/service-centric**, Firewalla is
  **device/policy-centric**.
- **WireGuard access grants** — every road-warrior client is **default-deny** and
  granted explicit access to catalog services via a per-client access page
  (`/wireguard/server/clients/{id}/access`), enforced in `pf` on the server
  interface. Per-client keypair + auto IP + QR + downloadable + emailed config
  (via the SMTP relay) all built.
- **NAT** — port forwards (each references a service), toggle, outbound; built.
- **DHCP** — per-interface pools + static leases + lease table; built.
- **DNS / Adblock** — Unbound settings, local overrides, blocklist management
  with per-list enable; built. (DoH upstream **planned**.)
- **Traffic + Visibility** — throughput history (SQLite + hand-rolled
  canvas/uPlot) built; deeper NetFlow/IPFIX + nDPI flow attribution is the
  `netflow.md` design track **(planned)**.
- **Logs** — live `pflog` tail + system log, filterable; built.
- **System** — BE-based updates, single-file backup/restore, local users,
  argon2 + TOTP (passkeys **planned**), certificates, **SMTP relay**, reboot;
  built. Optional **web shell** (ttyd-style) behind auth, off by default.

The architectural cost (and the point): **none of this touches a cloud.** There
are no curated category lists, no cloud threat-intel feed, no push service, and
**no per-device policy/QoS engine** — those are Firewalla strengths Luciola does
not match today. What Luciola offers instead is config you can read, diff,
version, back up as one file, and roll back deterministically, served by a web
UI that works with zero internet.

### Where each is genuinely stronger (software only)

| Capability | Stronger | Why |
|---|---|---|
| Per-device / per-group policy + schedules | **Firewalla** | Mature rule engine; Luciola has no device-policy model yet |
| App / category identification | **Firewalla** | DPI + cloud-curated categories out of the box |
| Threat intelligence / IDS-style blocking | **Firewalla** | Cloud-fed Active Protect; Luciola is list-based only |
| QoS / bufferbloat | **Firewalla** | Smart Queue shipping; Luciola has none yet |
| Push alarms / actionable alerts | **Firewalla** | Cloud push; Luciola is constrained to email/ntfy (no cloud) |
| Reusable target lists | **Firewalla** | Shared community lists; Luciola's catalog is local-only |
| Declarative config you own | **Luciola** | One versioned file; Firewalla config lives in the app/cloud |
| Atomic apply + auto-rollback | **Luciola** | 60 s confirm-or-revert; no Firewalla equivalent |
| System update rollback | **Luciola** | ZFS boot environments vs OTA app push |
| Default-deny VPN access grants | **Luciola** | Per-client service grants enforced in pf |
| Web UI for a single box | **Luciola** | Firewalla single-box is app-only (web = MSP fleet portal) |
| Offline / no-account operation | **Luciola** | Fully functional with no internet, no account |
| Right-to-audit the software | **Luciola** | Open source; Firewalla backend is closed |

**Net (software):** Firewalla is the more capable *application* today — its rule
engine, DPI categories, threat intel, QoS, and alarm UX are real, mature, and
hard to match without a cloud. Luciola is the more capable *system* — owned
declarative config, deterministic apply/rollback at both the config and OS
layer, no cloud, and an auditable open codebase. Closing the policy/DPI/alerting
gap *without* adopting a cloud is the explicit hard problem Luciola is signing up
for (plan.md §8, §13).

## Commercial & support

| Feature | Luciola | Firewalla Purple |
|---|---|---|
| Price (retail) | $249–299 launch → ~$199 at scale (target) | ~$319 |
| Subscription | None | None for core; optional features cloud-tied |
| Availability | Pre-product (Phase 0) | Shipping, mature |
| Hardware longevity | ~10-yr embedded SoC + i226; second-sourced BOM | Consumer lifecycle |
| Support model | Self-serve + open community (planned) | Vendor support + large community |
| Vendor lock-in | None (open everything) | App + cloud account |

## Summary

**Choose Luciola when** you want: ownership and openness (open HW/FW/SW), no
cloud and no account, a real web UI, more compute/RAM, 3× 2.5GbE ports, x86
flexibility, ZFS rollback, and a serial console. It targets prosumers, homelabs,
and small business who run their own gateway.

**Choose Firewalla Purple when** you want: a polished consumer mobile app,
manage-from-anywhere convenience, out-of-the-box DPI + per-device analytics +
threat-intel + parental controls, easy bridge-mode drop-in, and a shipping
product you can buy today. It targets families and consumers who want strong
security without running infrastructure.

**The honest one-liner:** Firewalla sells *convenience and intelligence via the
cloud*; Luciola sells *ownership and transparency without one*. They are not the
same product — Luciola's bet is that a meaningful slice of buyers will trade the
cloud app for owning the whole stack.

---

*Sources: Firewalla Purple specs from* [firewalla.com](https://firewalla.com/products/firewalla-purple)
*,* [TechRadar](https://www.techradar.com/reviews/firewalla-purple)
*,* [Tech Advisor](https://www.techadvisor.com/article/1964915/firewalla-purple-review.html)*.
Firewalla software capabilities from Firewalla docs:*
[Rules](https://help.firewalla.com/hc/en-us/articles/360008521833-Manage-Rules)*,*
[Target Lists](https://help.firewalla.com/hc/en-us/articles/1500005941962-Firewalla-Feature-Target-Lists)*,*
[Smart Queue](https://help.firewalla.com/hc/en-us/articles/360056976594-Firewalla-Feature-Smart-Queue)*,*
[Network Flows](https://help.firewalla.com/hc/en-us/articles/24739086338323-Firewalla-Feature-Network-Flows)*.
Luciola details from* `../plan.md`*, software status from* `../ui/`*.*
