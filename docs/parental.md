# Parental controls — design notes

Status: design exploration. No code yet. This sketches how Luciola would
implement parental controls for children's devices on top of the existing stack
(`pf`, Unbound, Kea/dnsmasq, per-network segmentation — see `../plan.md` §7, §8),
and confronts the three things that actually break naive implementations:
**MAC randomization, DNS-over-HTTPS, and the honest limits of a gateway.**

> **Framing.** A gateway can only police traffic that crosses it. Everything
> here is best-effort defense-in-depth, not a guarantee. A determined teenager
> with cellular data, a neighbour's Wi-Fi, or a personal VPN is out of scope by
> physics. Parental controls are a *speed bump and a visibility layer*, and they
> work best paired with on-device controls (Screen Time, Family Link). Say this
> to the customer plainly — overpromising here is how competitors lose trust.

---

## 1. The core decision: filter by network, not by device

The instinct is "pin a policy to my kid's iPad by its MAC address." **Don't build
it that way.** MAC-as-identity is fragile (next section) and per-device rule
engines are exactly the heavy, cloud-shaped feature Luciola is light on
(`firewalla.md`). Instead, lean on what Luciola already does well: **network
segmentation** (plan.md §8, the trust-tier 3rd port / VLAN model).

**Model: a "Kids" network is a policy zone.**

- Put children's devices on their own segment — a dedicated SSID bridged to a
  VLAN, or the physical 3rd port's subnet. Anything on that segment inherits the
  kid policy automatically, regardless of MAC, regardless of how many devices.
- Policy attaches to the **interface/subnet**, which `pf` and Unbound already key
  on natively. No per-device table to maintain, no identity to spoof.
- Optionally several tiers: `kids-young` (walled garden), `kids-teen` (block
  categories + schedule), `guest`, `trusted`.

This sidesteps the entire MAC-randomization problem and maps cleanly onto
Luciola's "policy zone" architecture. **Per-device rules become an optional
refinement *within* a zone, not the foundation.** Recommend this as the primary
design.

The catch worth stating: assigning a device to the kids SSID is a one-time act of
control (you set up the child's device, you pick its Wi-Fi). That's a reasonable
assumption for *young* children. For teens who can switch SSIDs, network
assignment must be enforced at the Wi-Fi layer (per-device PSK / RADIUS mapping
the device to the kid VLAN), which means controlling the AP config — the same
"we spec/recommend an AP" boundary from plan.md §8/§13.

---

## 2. MAC address randomization

**The problem.** iOS/iPadOS (14+) and Android (10+) default to a *private
(randomized) MAC* per SSID. Identifying a device by hardware MAC is therefore
unreliable, and static DHCP leases keyed on MAC can break.

**What's actually true (and useful):**

- The private MAC is **stable per-SSID**. Apple/Android generate one random MAC
  *for that network* and reuse it on every reconnect. So once you've seen a
  device on your kids SSID, its (private) MAC is stable there — a static lease
  and per-device rule will *hold* until the user manually toggles the setting or
  forgets/rejoins the network.
- iOS 18 added periodic rotation of the private MAC, but **only while the device
  is not associated** to the network; the associated/known-network MAC stays put.
  Practically: a device that lives on your home Wi-Fi keeps its address.
- So MAC randomization degrades device identity from "permanent" to "stable but
  resettable." Fine for a coarse zone model; shaky as the *sole* hook for a
  per-child rule.

**How Luciola handles it (in priority order):**

1. **Don't depend on it — use the network-zone model (§1).** A device on the kids
   VLAN gets the kids policy whatever its MAC says.
2. **Identity at join time, not by MAC.** Where per-device pinning is wanted,
   bind identity at the Wi-Fi layer: a **per-device PSK** (a.k.a. private PSK /
   iPSK) or **802.1X/RADIUS** that maps a credential → the kid VLAN. The device's
   MAC becomes irrelevant; the *credential* is the identity. Requires AP support
   (recommended-AP boundary, §1).
3. **Tell the parent to disable private MAC on the child's device.** Legitimate —
   it's *your* child's *your* device on *your* network. The UI should surface a
   one-line "for reliable per-device limits, set this device's Wi-Fi to use its
   real address" with platform steps. Then a normal static lease works.
4. **DHCP fingerprinting as a soft signal, never a control.** Option-55
   parameter-request-list, hostname, and DHCP vendor class can *suggest* device
   type for the dashboard ("looks like an iPad"), but treat it as advisory — easy
   to spoof, never the basis for enforcement.

**UI consequence:** the device list shows a "private address" badge and warns
that per-device limits on that device can be reset by toggling Wi-Fi settings;
nudge toward the zone model or a fixed address.

---

## 3. DNS over HTTPS / DoT / encrypted DNS

This is the feature that quietly defeats most DNS-based parental filtering, so it
gets the most attention. If the child's browser or OS resolves names via DoH to
`1.1.1.1` or Google, **your Unbound never sees the query and your blocklists do
nothing.**

Luciola's answer is **lock the kids segment to our resolver and block the escape
hatches**, in layers:

**A. Force all plaintext DNS to our resolver.**
- `pf` redirect (rdr/nat) on the kids interface: any UDP/TCP `:53` to any
  destination is transparently redirected to the local Unbound. A device hard-
  coded to `8.8.8.8` still lands on us.
- Then **default-deny egress** on the kids segment for DNS: drop outbound `:53`
  to anything except the gateway (belt-and-suspenders with the redirect).

**B. Kill DoT.** Block outbound TCP/UDP **`:853`** entirely on the kids segment.
DoT uses a dedicated port, so this is clean and complete.

**C. Suppress DoH where the client cooperates.**
- **Firefox canary:** return `NXDOMAIN` for `use-application-dns.net`. Firefox
  treats that as "network says don't auto-enable DoH" and falls back to system
  DNS. (Only Firefox honors it; still worth doing.)

**D. Block known DoH endpoints (the real work).** DoH rides ordinary `:443`, so
you can't block it by port. Maintain a **DoH-resolver blocklist** — the curated
public lists of known DoH server hostnames *and* IPs (Cloudflare, Google, Quad9,
NextDNS, AdGuard, etc.). Enforce both ways:
- Unbound: `local-zone` the DoH hostnames to refused/NXDOMAIN.
- `pf`: drop the DoH resolver **IP** ranges from the kids segment, so a client
  with a hard-coded DoH IP (no DNS needed) still fails and **falls back to Do53**,
  which we capture in (A). Lists need periodic refresh (same auto-update
  machinery as the ad blocklists).

**E. Block iCloud Private Relay.** Apple's Private Relay tunnels DNS *and*
traffic over QUIC to Apple, bypassing everything. Apple documents the fix: block
its hostnames (`mask.icloud.com`, `mask-h2.icloud.com`) at the resolver and/or
the relay traffic — return NXDOMAIN and Private Relay disables itself for that
network. Do this on the kids segment by default.

**F. Optionally blunt QUIC / HTTP-3.** QUIC (UDP `:443`) hides SNI and carries
DoH well. Blocking outbound **UDP `:443`** on the kids segment forces browsers to
fall back to HTTP/2 over TCP, where at least the TLS **SNI** is visible to flow
inspection. Trade-off: a small latency/feature hit on some apps; make it a toggle.

**The wall we can't climb without TLS interception: ECH.** Encrypted Client Hello
encrypts the SNI too, so even the TCP-443 fallback stops revealing the hostname.
ECH adoption is growing. Our honest options are (1) block endpoints/IPs as above,
(2) for the strictest tier, block QUIC and rely on IP/category lists, or (3) TLS
interception with a installed root CA — **which Luciola will not ship** (it breaks
cert pinning, is a security liability, and is the opposite of the trust posture we
sell). Document this limit; don't paper over it.

**Net for DNS:** on the kids segment we (1) redirect/force Do53 to Unbound,
(2) block DoT `:853`, (3) NXDOMAIN the Firefox canary, (4) blocklist DoH
endpoints by host *and* IP, (5) kill Private Relay, (6) optionally block QUIC.
That captures the overwhelming majority of consumer devices. The residue (ECH,
unknown private DoH servers, VPNs) is acknowledged, not hidden.

---

## 4. Importing age-appropriate lists

Yes — this is largely a packaging problem, and Luciola's Unbound `local-zone`
pipeline (already used for ad-block, plan.md §7) is the right substrate.

**Categorized domain blocklists (the workhorse).** Several maintained,
free-to-use, *categorized* lists compile straight to Unbound data:

- **Hagezi** — actively maintained, has dedicated category lists (adult/porn,
  gambling, dating, fake/scam, plus a "Pro" base). Clean, well-sized.
- **StevenBlack hosts** — composite variants that include porn / gambling /
  social add-ons.
- **University of Toulouse (UT1) "blacklists"** — the classic *category* corpus
  (adult, gambling, dating, drugs, violence, redirector, etc.), long used by
  SquidGuard/e2guardian. Big and granular; good for category toggles.
- **OISD**, **URLhaus**, **AdGuard** category feeds for trackers/malware.

These ship as named, toggleable categories in the DNS page ("Adult," "Gambling,"
"Social media," "Gaming," "Violence") with per-list enable + auto-refresh —
exactly the existing blocklist UX, just categorized and scoped *per network view*
(§6).

**Filtering DNS upstreams (the easy mode).** Instead of (or alongside) local
lists, point the kids view's Unbound at a family-filtering resolver:

- **CleanBrowsing** (Family / Adult tiers), **OpenDNS FamilyShield**
  (`208.67.222.123`), **Cloudflare for Families** (`1.1.1.3` blocks malware +
  adult), **AdGuard Family DNS**, **Quad9**.
- Trade-off to flag honestly: this delegates filtering to a third party and sends
  the kids' DNS to them — a *cloud dependency the customer opts into*, like the
  SMTP relay. It is the *user's* chosen upstream, not an us-operated cloud, so it
  doesn't violate the no-cloud pillar — but the UI must say where queries go.
  Offer it as a one-click alternative to self-hosted lists; let the privacy-
  conscious parent run lists locally instead.

**SafeSearch enforcement (cheap and high-value).** Force the big engines into
safe mode via Unbound `local-data` CNAMEs — no list maintenance:
- Google → `forcesafesearch.google.com`
- Bing → `strict.bing.com`
- DuckDuckGo → `safe.duckduckgo.com`
- YouTube → `restrict.youtube.com` (strict) or `restrictmoderate.youtube.com`
Ship these as a single "Enforce SafeSearch" toggle on the kids view.

**Allowlist / walled-garden mode (for young kids).** The strictest tier: Unbound
default-deny for the view, allow only an explicit set of domains (PBS Kids, Khan
Academy, school portals…). **Caveat that bites:** modern sites pull assets from
many CDN/3rd-party domains, so a naive allowlist breaks pages. A usable
walled garden needs curated allow-bundles (the site *plus* its CDN/asset
domains). Ship a few starter bundles; warn that allowlisting is high-maintenance.

**Format & pipeline.** All of the above are domain or hosts-format text →
compiled to Unbound `local-zone`/`local-data`, refreshed on a timer, validated
before reload (same machinery as ad-block). Per-list metadata: name, category,
source URL, license, entry count, last-refresh, enabled-per-view.

---

## 5. Time, schedules, and quotas

DNS/IP filtering decides *what*; parents also want *when*.

- **Bedtime / schedule windows.** Render time-windowed `pf` rules and/or swap the
  kids Unbound view, driven by a scheduler in `fwd` that re-renders and reloads on
  a cron-like timetable. `pf` has no native time-of-day match, so the engine must
  reload anchors on schedule (cheap; `pfctl` anchor swap). "No internet for the
  Kids network 21:00–07:00" = drop-all egress rule loaded in that window, with a
  carve-out for nothing (or for alarm-clock/homework allowlist).
- **Per-device pause ("dinner button").** A one-tap "pause internet" that loads a
  block rule for a device/zone — straightforward, and a beloved Firewalla
  feature worth matching.
- **Time *quotas* (e.g. 2 h/day) are harder.** They need session accounting (bytes
  or connection-time per device) feeding a state machine that flips a block rule
  when the budget is spent. Feasible with the shipped flow-accounting pipeline
  (`visibility-design.md`: `pflow(4)` → collector → SQLite rollups) as the meter —
  once flows are keyed by *device* and not raw IP — but it's a real feature, not a
  config toggle.
  Scope it as a later tier; honest about the lift.

---

## 6. Per-network Unbound views

To serve *different* blocklists/SafeSearch/upstreams to the kids segment vs the
trusted segment from one resolver, use **Unbound views** (or tagged ACLs, or a
second resolver instance) keyed on source subnet. Each network zone → a view with
its own `local-zone` set, SafeSearch toggle, and upstream. This is the mechanism
that makes "policy per network" (§1) real on the DNS side, and it reuses the one
Unbound we already run. The config engine renders the views from the declarative
config like everything else.

---

## 7. Visibility, transparency, and the block page

- **What got blocked.** Parents want to see attempts, not just silence. Feed
  blocked-query and blocked-flow events (pflog + Unbound logging) into the
  existing logs/traffic pipeline, surfaced as a per-zone "blocked activity" view.
  This is also how a parent tunes false positives.
- **The block page problem.** For plaintext **HTTP** you can redirect a blocked
  request to a friendly "this site is blocked" page. For **HTTPS** (i.e. almost
  everything) you *can't* — without TLS interception the browser just shows a
  connection/cert error. So a blocked HTTPS site looks "broken," not "blocked."
  Set expectations: optional HTTP block-page, but most blocks present as a failed
  load. (NXDOMAIN from the resolver is the cleanest failure mode.)
- **Alerts.** "Child's device attempted blocked category / tried to reach a DoH
  server / hit the bedtime wall" → the same email/ntfy alerting track as other
  events (no-cloud push constraint applies, plan.md §13).

---

## 8. The honest limits (put these in the UI)

State the bypass vectors plainly; a parent who trusts a leaky filter is worse off
than one who knows the gaps:

1. **Cellular / mobile data** — a phone with a SIM never touches your network.
   Out of scope; handle with on-device controls.
2. **Other networks** — neighbour Wi-Fi, school, a friend's hotspot. Out of scope.
3. **Personal VPN / Tor** — tunnels everything past your filtering. Mitigate by
   blocking known VPN endpoint lists + Tor on the kids segment, blocking the
   common easy ones; a custom WireGuard endpoint on an arbitrary UDP port is
   effectively unblockable without breaking the network. Acknowledge it.
4. **ECH** — encrypted SNI removes the last cleartext hostname signal (§3). We do
   not do TLS interception, so the strict tier falls back to IP/category lists.
5. **Shared/family devices** — network identity is per-device, not per-person; a
   family iPad can't distinguish parent from child by network alone. On-device
   profiles handle the per-person split.
6. **Determined teenagers** — factory resets, second devices, MAC/SSID toggling.
   Network controls are a speed bump, not a cage.

**Therefore position parental controls as a layer, not a solution:** great at
"keep casual adult content and trackers off the kids' tablets and enforce
bedtime," weak against an adversarial, technical teen. Pair with Screen Time /
Family Link and an honest conversation. That honesty is on-brand and is exactly
where always-overpromising competitors are vulnerable.

---

## 9. Suggested build order

| Tier | Capability | Lift |
|---|---|---|
| **0 — foundation** | Kids network zone (VLAN/SSID + subnet), per-network Unbound view | Reuses segmentation + Unbound |
| **1 — DNS filtering** | Category blocklists (Hagezi/UT1) + SafeSearch CNAMEs, per-view toggles | Reuses ad-block pipeline |
| **2 — DNS lockdown** | Force Do53 to Unbound, block `:853`, DoH endpoint host+IP blocklist, Private Relay block, Firefox canary | `pf` redirect + curated lists |
| **3 — schedules** | Bedtime windows, one-tap pause (scheduled `pf` anchor reloads) | `fwd` scheduler |
| **4 — visibility** | Per-zone blocked-activity view, alerts (email/ntfy) | Reuses logs + alerting |
| **5 — advanced (later)** | Time quotas, walled-garden allowlists, per-device PSK identity, VPN-endpoint blocking, optional QUIC block | New accounting + AP integration |

Tiers 0–2 deliver the bulk of real-world value and ride almost entirely on
machinery Luciola already has (segmentation, Unbound `local-zone`, `pf` redirect,
list auto-refresh). Tiers 3–5 are genuine new features; sequence them by demand.

---

*Stack references: `../plan.md` §7 (Unbound, pf, WebUI), §8 (segmentation /
trust-tier port), §13 (no-cloud alerting). Visibility/accounting substrate:
`./visibility-design.md` (the design of record — `./netflow.md` is superseded).
Competitive context: `./firewalla.md`.*
