# July 2026 plan — closing the Firewalla gap

Status snapshot and prioritized next steps, written 2026-07-01. Context:
`../plan.md` (master plan), `firewalla.md` (competitive analysis vs Firewalla
Purple / Purple SE), `visibility-design.md` (baseline flow pipeline).

**Everything below is the 2026-07-01 snapshot and is left as written.** For where
the seven priorities actually stand, see **Status update — 2026-09-04** near the
end of this document.

## Where the project stands

**Phase 0 (software) is ~80% done.** Built and working:

- Config engine: declarative `config.json` → render → validate → atomic apply
  with 60 s confirm-or-rollback
- All UI pages: Dashboard, Interfaces, Services, NAT, DHCP, DNS/Adblock,
  WireGuard (server + per-client default-deny access grants, QR/email
  onboarding), Traffic, Visibility, Logs, Shell, System
- Auth (argon2id + TOTP), HTTPS with self-signed cert, SMTP relay, backup/
  restore, responsive phone/tablet PWA layout
- Visibility baseline Phases 1–2: `pflow(4)` → Go IPFIX collector → SQLite →
  native Flows UI; nDPI helper process with stub classifier; ntopng reframed
  as the opt-in power tier
- OS target locked to FreeBSD 15.x (native `pflow(4)`); QEMU VM provisioning
  seeds NIC mapping + LAN alias

**Competitive read (vs Firewalla Purple SE + app).** Luciola wins the *system*
layer: owned declarative config, deterministic apply/rollback at config and OS
(ZFS BE) level, no cloud, no account, open everything, more hardware. Firewalla
wins the *application* layer: per-device analytics, mature rule engine with
one-tap flow→block, rich push alarms, cloud-curated categories/threat intel,
Smart Queue QoS. The three app strengths that make Firewalla sticky — **per-device
view, observe→enforce loop, actionable alarms** — are the gaps that matter most,
and all three fit the no-cloud architecture.

## Priorities, in order

### 1. Finish the nDPI helper real capture

The one outstanding baseline piece (`visibility-design.md` §6): `source_pcap.go`
(libpcap capture) and `classifier_ndpi.go` (libnDPI classification) behind
`//go:build pcap` / `ndpi` tags, built only in the OS image, libnDPI linked
dynamically (LGPL boundary — never into fwd). Then an end-to-end soak on the
FreeBSD 15 VM, which also settles the open question of whether the `pflow(4)`
IPFIX template carries ifindex. This completes the visibility baseline — the
product's differentiator.

### 2. Device identity layer

The biggest structural gap vs the Firewalla app. Flows are keyed by IP today;
Firewalla's headline feature is *per-device* usage. Build a device registry:

- Sources: DHCP leases + ARP/NDP tables + user-assigned names/icons in config
- Join flows on device, not raw IP; per-device usage page
- Handle MAC randomization per `parental.md`: private MACs are stable per-SSID,
  so lease-keyed identity still works within a network

This is the prerequisite for parental zones, per-device pages, new-device
alerts, and per-device QoS — build it before any of those.

### 3. Observe→enforce loop (block from flow)

Firewalla's signature UX: tap a flow → standing block. Cheap for Luciola
because the engine already exists: add "block this host/domain/app" actions to
the Flows view that draft a declarative config change and go through the normal
apply/confirm/rollback path. High leverage, small surface.

### 4. Adblock fetch/compile job

`config.Adblock` and the Unbound `include:` wiring exist; the job that fetches
feeds, normalizes formats (hosts files, domain lists), dedupes, and compiles
`adblock.conf` is not built (`adblock.md`). Scheduled refresh + per-list enable
+ block stats from Unbound logs. Small, closes a shipping gap on an
already-promised feature.

### 5. Alerting (resolve plan.md §13 open question)

Firewalla's push alarms are a major app draw; Luciola's answer must stay
cloud-free. Ship:

- An event bus: WAN down, new device joined, failed update, apply rolled back,
  blocklist hit spike
- Delivery: email (SMTP relay already built) + user-pointed ntfy and/or webhook
  — never an us-operated push service
- First alarm: **new-device detection** from DHCP lease events — easy win,
  consumer favorite, feeds directly off priority 2's registry

### 6. QoS / bufferbloat ("Smart Queue" answer)

Firewalla's Smart Queue sells. FreeBSD pf supports `dnpipe` → dummynet with
fq_codel (since 14.x). v1: one toggle per WAN with up/down bandwidth settings.
Per-device priority tiers come later, once the device registry (priority 2)
exists.

### 7. IPv6 (DHCPv6-PD, RA)

Table stakes in 2026 (`plan.md` §13); Firewalla has it. Needed before launch
but less urgent than 1–5.

## Status update — 2026-09-04

Where the seven priorities actually stand, two months on. The honest headline:
**the triad is at ~0.5 of 3, and nothing has been committed since 2026-07-15.**
Hardware arriving (an N150 / 16 GB / 256 GB / 4× i226 COTS box — `../plan.md` §10
Phase 0) is the natural restart, and bring-up work interleaves cleanly with the
triad because the triad is pure software.

| # | Priority | State |
|---|---|---|
| 1 | nDPI helper real capture | **Done** — landed 2026-07-15 (`9f0c47a`), same day it was written down. Residuals below. |
| 2 | Device identity layer | **Half done** — registry built (`75e497f`), UI landing now. |
| 3 | Observe→enforce (block from flow) | Not started. |
| 4 | Adblock fetch/compile job | Not started. |
| 5 | Alerting | Not started. |
| 6 | QoS / bufferbloat | Not started. |
| 7 | IPv6 (DHCPv6-PD, RA) | Not started. |

**1 — done, with three residuals that belong to bring-up, not to the build.**
`source_pcap.go` (libpcap, BPF-filtered, per-device), `parse.go`, and
`classifier_ndpi.go` on the nDPI 5.0 API all shipped behind the `pcap` / `ndpi`
tags, and the VM soak showed flows labelled end-to-end with TLS confirmed. What is
*not* settled, and is now recorded in `visibility-design.md` §7: whether the
`pflow(4)` IPFIX template carries **ifindex** at all (the question this priority was
supposed to answer and didn't); **whether pflow exports pre- or post-NAT tuples**,
which decides whether per-device app attribution is even possible and therefore
gates priority 2's payoff; and the **load spike** the longer soak showed, still
unexplained. All three are empirical and want the real box. One thing this priority
assumed but never delivered: the helper is built for no target — nothing in the
image or deploy path compiles it for FreeBSD, so on the appliance today app labels
silently do not exist. That is the first bring-up task, not a design question.

**2 — registry built, UI landing now.** `internal/devices` exists: a MAC-keyed
registry joining ARP/NDP tables and Kea leases, per the July design. It has been
sitting unwired — no route, no template, no per-device page — so flows are still
keyed by raw IP and none of the things this priority unblocks (per-device pages,
parental zones, new-device alerts, per-device QoS) can be built on it yet. That is
being closed now; treat priority 2 as **in flight, not finished**, and note that
"finished" means *flows joined on device*, not merely a device table rendering.
Two known gaps in the registry itself when the UI lands on it: lease parsing ignores
the `expire` column (stale attribution until Kea's LFC rewrite) and reads IPv4
leases only.

**3–7 — not started, and the ordering still looks right.** Nothing here has been
invalidated by the last two months. 3 remains the cheapest high-leverage item on the
list *once 2 lands* (the apply/confirm/rollback engine it needs already exists), and
5's first alarm still falls straight out of 2's registry. The one thing worth
re-weighing against `../plan.md` §10's Phase 0 exit criterion: a **hardening pass**
(non-root `fwd` + root helper, CSRF, session revocation, unprivileged shell user)
now competes with this list for the same solo hours, and it gets more expensive the
more surface 3–7 add. Sequence it before or alongside 3, not after 7.

## Deferred (deliberately)

- **Phase 0.5 LLM assist** — gated on a mature detector stack; revisit after
  the visibility baseline + alerting land
- **Suricata power tier** — opt-in IDS; after baseline is solid
- **Passkeys/WebAuthn**, **VPN client route-out** — nice-to-haves, not
  parity-critical
- **Phase 1 firmware (coreboot)** — wait until software parity items 1–5 land;
  software is the product value, hardware can lag (`plan.md` §10)

## One-line strategy

The baseline lets the user *see* traffic; the next quarter is about letting
them *act* on it — device identity, block-from-flow, and alerts. That triad is
what makes the Firewalla app sticky, and all three fit Luciola's no-cloud
architecture.
