# Marketing & Positioning

## Brand architecture

- **Pyroptics** — the *company*. *Pyro* (fire → firewall/protection) + *optics*
  (light/vision → visibility into your network). Carries the techy, credible mission
  framing. Domain `pyroptics.com` owned. Fallback spelling **Pyroptix** if ever needed.
- **Luciola** — the *product*. Firefly genus, "little light." Keeps the magic/wonder,
  the glowing-firefly logo, and the "light you own, off-grid, no cloud" story. Nests at
  `pyroptics.com/luciola`.
- **Model:** classic maker→product split — Netgate→pfSense, Ubiquiti→UniFi,
  PC Engines→APU, Framework→Laptop.
- **Naming history:** earlier candidate "Lampyr" was dropped — phonetically identical to
  **Lampyre** (`lampyre.io`), an active OSINT/cyber-intel tool in the same field (high
  likelihood-of-confusion). "Luci" was dropped too — collides with **LuCI**, OpenWrt's
  firewall web UI, and **LUCI** (registered US mark, hardware/software). `lampyr.org` is
  owned but now just a spare/redirect.
- **Open TODO:** **formal TM clearance** on *both* names (classes 9 + 42 + hardware).
  Knockout scans are clean in-field; have counsel weigh the Gateron "Luciola"
  keyboard-switch line (different goods, likely fine) and the pyro/pyrotechnics space.

## Positioning statement

> For technically-minded people who take security and privacy seriously —
> prosumers, homelabbers, and small professional practices — **Luciola** is an
> open, self-hosted firewall appliance that makes powerful network security simple
> to run and easy to trust. Unlike ISP routers and subscription boxes like Firewalla
> or Eero Plus, **Luciola** charges no monthly fee, never phones home, and runs
> firmware and software you can read, verify, and own.

## Taglines

**Primary candidate:**
- **Security you own.**

**Alternates (by angle):**
- *Ownership / no-subscription:* "Your network. Your rules. No subscription."
- *Openness / trust:* "A firewall you can actually trust — because you can read it."
- *KISS / simplicity:* "Powerful security, made simple. No monthly fee, ever."
- *Privacy:* "No cloud. No catch. No one watching but you."
- *Identity:* "Self-hosted security for people who read the source."

## Brand / visual identity

The firefly is a **beetle** (order Coleoptera), and that fact is a gift — it gives the
brand a three-layer metaphor that all maps to the product:

| Firefly trait | Biology | Brand meaning |
|---|---|---|
| **Elytra** (hardened wing covers) | beetles fold a literal armored shield over the soft wings/abdomen at rest, lift it to fly | **the shield / the firewall** — protection |
| **Bioluminescence** | makes its own cold light | **visibility** — see your whole network (value pillar #3) |
| **Off-grid light** | self-powered, no external source | **you own it** — no cloud, no subscription |

So Luciola carries the *protective* story on its own (elytra = shield), which complements
Pyroptics (fire + optics). Light **and** armor in one creature.

### Mascot: two faces from one animal

- **Adult firefly** — glowing, friendly, magic. The *approachable* face: consumer-facing
  pages, "make your network safe," KISS messaging. Likely the primary logo.
- **Armored larva** — flattened, segmented, plated, trilobite-like. The *tough/serious*
  face: security-credibility, packaging, dark-mode aesthetic, a possible "Pro" SKU mark.
- Optional mapping to the **two-tier product**: adult = friendly base SKU; armored larva
  = embedded / Pro SKU. Same animal, two personalities.

### Accuracy guardrail (for copy)

The dramatic "**trilobite beetle**" (Platerodrilus) is a *cousin* — a net-winged beetle
(Lycidae), **not** a firefly. Real firefly (lampyrid) larvae *are* flattened and plated,
so write *"firefly larvae resemble armored trilobites"* (true). Do **not** claim the
firefly larva *is* the trilobite beetle (false) — an entomologist customer will catch it.

---

## The core insight

Do **not** sell to the mass consumer. Against the ISP-router incumbent (free at the
margin) and the entertainment budget (a $300 game console), a $300 security box always
loses. The mass market does not value security it cannot see, and the threats are too
abstract to motivate the spend.

The product's real buyer was the founder's own description: skilled IT, security- and
privacy-conscious, KISS-minded, running a network for a company and a home. **Build the
thing you wish you could buy, and sell it to the thousands of people like you** — not to
the millions who are the wrong fit. PC Engines, Protectli, Netgate, and Firewalla all
built real businesses on exactly this niche.

## Why the obvious pitches fail

- **"Save $20/mo vs your ISP" — false and self-defeating.** The appliance is not a modem
  and not a wifi AP; the customer still needs both, so the ISP rental does not go away.
  A claim that unravels under scrutiny is poison for a *security* brand, where trust is
  the entire product. Do not use it.
- **"Keep your kids safe online" — commoditized.** Network DNS filtering is free
  (Pi-hole) or ~$20/yr (NextDNS); Apple/Google give on-device screen-time away. Fine as a
  *secondary* benefit; never the headline.
- **The game-console comparison is correct — for the wrong buyer.** A family choosing
  between this and a PS5 picks the PS5. That just confirms the family is not the customer.

## Lesson from AppleTV

AppleTV charges $150 for "the same as a $50 Roku" and wins on brand, trust, privacy
reputation, and polish. For a security device the **trust premium** is the most real
premium there is. Copy that posture; do not dismiss it.

## Target segments (in priority order)

1. **Prosumers / homelabbers / privacy-and-security-minded technical users** — the core
   ICP. Currently overpay (Firewalla, UDM) or self-host with hassle (pfSense/OPNsense on
   a DIY box).
2. **SOHO / small professional practices** (doctors, lawyers, accountants, small shops) —
   compliance pressure (HIPAA/PCI), no IT staff, *business* budget where $300–500 is a
   rounding error. Higher margin, less price-sensitive, they renew and refer. Possibly the
   better-margin beachhead.

## Value pillars (priority order)

1. **No subscription, no cloud, you own it.** "Your security never phones home, no
   monthly fee ever." KISS made concrete; clean differentiator vs Firewalla/Eero Plus/Circle.
2. **Open and verifiable — the moat.** Open firmware (coreboot), open-source UI, published
   design. *"A security box you don't have to trust blindly — you can read every line."*
   No mass-market competitor can credibly claim this; security people distrust black boxes.
3. **Visibility + network-wide ad/tracker blocking — the gateway benefit.** The one thing
   buyers *feel daily*: faster pages, no ads on every device (incl. the smart TV), "see
   every device and every connection." Lead the demo with this; abstract "security" does
   not sell, a dashboard that shows the creepy stuff does.
4. **Simple by default.** Secure out of the box, clean UI when wanted. KISS as a feature.
   Includes a **phone-first experience** — an installable PWA with app-grade mobile UX —
   matching Firewalla's app convenience *without* a cloud: you reach it on your LAN or
   over your own WireGuard VPN, never through our servers (see `plan.md` §7).

## Competitive frame

| Competitor | They sell on | We counter with |
|---|---|---|
| ISP router | free, already there | real security + visibility, you own it |
| Firewalla Gold/Purple ($300–500) | easy powerful security, slick phone app, no sub | + open/verifiable, + no cloud *at all* — same app-grade mobile UX (installable PWA) without their cloud relay; you reach it over your own VPN |
| Ubiquiti Dream Machine | ecosystem, slick UI | open firmware, no account/cloud lock-in |
| Netgate / pfSense | SMB credibility | simpler UX, open hardware, friendlier |
| Protectli (bare box) | DIY, cheap | turnkey OS+UI, supported, certified |
| NextDNS / Pi-hole | cheap/free filtering | full firewall + appliance + support |

## The scope trap: don't rebuild UniFi

Chasing **full network visibility** quietly drags the product toward Ubiquiti's shape.
True east-west (host-to-host) visibility requires owning the L2 edge — the switch *and*
the AP, not just the gateway (see `plan.md` §8 for the physics). Follow that to its end
and you're building a *product line*: gateway + switch + AP + controller. That is UniFi.
And on that ground we lose every axis that matters — volume, price, polish, support
headcount. A solo shop reborn as a worse, pricier UniFi is a dead end.

**The discipline: be the brain box, not the ecosystem.** Build one excellent 3-port
gateway and integrate with *whatever* switch/AP the customer already runs, via open
standards (NetFlow/IPFIX, sFlow, 802.1Q). Concede ecosystem breadth on purpose:

- **Baseline visibility ships free** on any topology — north-south flows + nDPI + ad/
  tracker blocking. This is value pillar #3, and it works with a dumb switch.
- **Deeper east-west is an integration, not a SKU.** "Bring a managed switch / use your
  own AP and we'll speak its flow data" — never "buy our switch." We don't build the
  switch or the AP. One box, not a catalog.

**The real competitor is Firewalla, not UniFi.** Single box, deep visibility, prosumer,
app-driven — that's the silhouette we share. Firewalla is closed, cloud-tied, ARM, their
stack; we are open, x86, self-hosted UI, no cloud. UniFi and the UDM are an *ecosystem*
play we deliberately decline to join. Naming the right rival keeps scope honest.

**Corollary on price:** we cannot win on cost (low volume, no employees) and must not
try. Charge *more*, openly — open hardware + no-cloud + 10-year longevity is the premium,
the same posture as Framework or System76. The buyer who wants ownership pays for it; the
buyer who wants the cheapest box was never the customer (see "The core insight").

## The honest test

Would a skilled-IT, KISS-minded, security-conscious person buy this over a UDM or a
Firewalla? If the **open + own-it + no-subscription + simple** combination makes them say
yes, that is the wedge — and there are enough such people to build a business.
