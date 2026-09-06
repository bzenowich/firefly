# docs/

**Design notes and rationale**, not end-user documentation — there is no user
manual yet; that is a Phase 5 deliverable (`../plan.md` §10). These are the
working documents behind the decisions in `../plan.md`, written to record *why*
as much as *what*.

| Doc | What it is |
|---|---|
| `hw-bringup.md` | **Start here for real hardware** — installing, provisioning and verifying Luciola on a COTS x86 box |
| `design-review.md` | Full-project review (2026-09-04) ahead of hardware arrival, with a status update on what has been fixed |
| `visibility-design.md` | **Design of record** for the baseline flow pipeline: `pflow(4)` → Go IPFIX collector → SQLite → native Flows UI |
| `ndpi-helper-design.md` | The out-of-process libnDPI helper and the label join |
| `netflow.md` | **Superseded** — the earlier cgo-free native-visibility exploration; kept for its ntopng feature inventory and rationale trail |
| `adblock.md` | Blocklist fetch/normalize/compile design (the Unbound `include` is wired; the job is not built) |
| `parental.md` | Per-network views, categorized feeds, time policy |
| `shell.md` | The in-process web terminal: xterm.js → WebSocket → PTY, and its gating |
| `firewalla.md` | Competitive analysis vs Firewalla Purple |
| `marketing.md` | Branding, naming, positioning |
| `plan_july.md` | July 2026 prioritized roadmap + a dated status update |
