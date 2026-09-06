# Security plan — 2026-09-05

Follow-on to `docs/design-review.md` §4. That review's security pass was written
from the outside in (what an attacker on the LAN would chain) and its fixes
landed in `1406893`/`ccfe11f`: CSRF tokens, session revocation, uniform login
errors, TOTP replay defense, mandatory STARTTLS, a non-root default for the web
shell. What it explicitly *deferred* was the one thing that changes the shape of
every other finding — **the privilege model**.

This plan closes that, re-examines CSRF now that tokens exist, and records a
second, deeper pass over the code looking specifically for the ways a
compromise *escalates* rather than the ways it *starts*. That second pass found
one verified root command injection reachable from an ordinary UI form, and a
pre-auth resource-exhaustion pair, neither of which appears in the design
review.

The standard this is written against is not "fine on my bench LAN". It is: **a
box someone else's family sits behind, on a LAN full of devices we do not
control, where the firewall is the last thing standing.**

---

## 1. Threat model

Naming the adversaries first, because half the findings below are only findings
relative to one of them.

| # | Adversary | Position | What they must not get |
|---|---|---|---|
| T1 | Internet | WAN side, unauthenticated | Anything. No inbound path exists except port forwards and the WG listener. |
| T2 | Hostile LAN device | An IoT bulb, a TV, a compromised laptop — on the trusted LAN | The admin UI, SSH, a login oracle, a way to exhaust the box |
| T3 | Curious LAN user | A housemate/kid with a browser, no credentials | First-boot ownership, the login form, the setup form |
| T4 | Stolen session | Attacker holds one valid `fw_session` cookie (XSS, an unlocked laptop, a shoulder-surf) | Persistence: new accounts, disabled 2FA, a root shell |
| T5 | Malicious traffic | Packets crossing the box, seen by nDPI/pflog/DHCP/DNS | Code execution in a parser, stored XSS in the admin UI |
| T6 | Compromised low-privilege component | `unbound`, `kea`, `ntopng`, the web-shell PTY, a bug in `fwd` | Root, the config document, the WireGuard keys |
| T7 | Rogue admin / social engineering | Valid credentials | *Nothing today* — admin is total. Roles are a later concern, noted but not solved here. |

**T6 is the adversary this plan is mostly about.** Today it does not exist as a
distinct level: everything already *is* root, so "a bug in fwd" and "root on the
appliance" are the same sentence. The privilege model is what creates the level
in the first place; everything else here is making sure it cannot be stepped
over once it exists.

---

## 2. Findings

Severity is relative to the standard in the header, not to the bench box. Each
finding carries the fix that Part 3 sequences.

### SEC-1 — CRITICAL — Root command injection via an interface device name

**Verified.** `config.validateStrings` (`config.go:668`) rejects newlines,
quotes, backslashes and control characters, because it was designed for the
*quoting* contexts renderers put strings in (pf comments, unbound `local-data`,
wg keys — design-review §3.6). `render.Network` is a *shell* context, and it
interpolates `Interface.Device` unquoted into a script installed at
`/usr/local/etc/rc.d/fwnetwork` mode 0755 and executed as root by `service(8)`
at every apply and every boot (`network.go:87`, `:99`, `:123`, `:138`).

`validateInterfaces` (`config.go:730`) checks the device is non-empty and
unique. It never checks its shape. `;`, `` ` ``, `$()`, `&`, `|` and spaces all
pass.

Reproduced against the current tree — setting the LAN device to
`igc1; touch /tmp/pwned` passes `Validate()` and renders:

```sh
	if fwnetwork_have igc1; touch /tmp/pwned; then
```

and, separately, into pf.conf as `lan_if = "igc1; touch /tmp/pwned"`.

Reachable from `POST /interfaces/{name}/address` (`server.go:768` — the form
value is `TrimSpace`d and stored) and from `POST /system/restore`.

Today the caller is already an authenticated admin, and an authenticated admin
already has root by other means, so the *present-day* impact is limited. That
is exactly why it is CRITICAL rather than informational: **it is the escape
hatch that would silently defeat the entire privilege split in Part 3.** A
helper that accepts rendered file content, or that renders from a config
document containing this value, hands root back the moment it runs.

**Fix.**
1. Charset-validate every value that reaches a shell context:
   `Interface.Device` must match `^[a-z][a-z0-9]*[0-9](\.[0-9]+)?$` (FreeBSD
   driver+unit, optional VLAN). Same treatment for anything else that lands in
   a generated `rc.d` script.
2. Add a `shellQuote` helper in `render/` and use it at every interpolation
   site in `network.go` and `pflow.go` — belt and braces, because rule 1 is one
   forgotten field away from failing.
3. Add a `validateShellSafe` sweep parallel to `validateStrings`, listing every
   field that reaches a script, so a new field cannot quietly skip it.
4. A golden test that feeds metacharacter payloads through `Validate()` →
   `Network()` → and asserts rejection at the validator, not just absence in
   the output.

### SEC-2 — HIGH — Everything runs as root

`plan.md` §7 promises a non-root `fwd` plus a narrow root helper. Neither
exists. `os/rc.d/fwd` has no `fwd_user`; the daemon execs `pfctl`, `service`,
`sysrc`, `tcpdump`, `sh -c` directly (`apply/system.go:104`,
`apply/plan.go:153`, `logs/collect.go:42`) and spawns the web-shell PTY itself.
The full HTTP + `html/template` + WebSocket + SQLite + reverse-proxy + IPFIX-
parsing surface sits in the root process. Any memory-safety or logic bug
anywhere in that surface is immediately root.

Note what is *not* a blocker: `fwd` listens on **8443**, an unprivileged port,
so binding needs no privilege at all. The root requirement is entirely about
writing `/etc`, running `pfctl`/`service`, reading bpf, and spawning the PTY.

**Fix.** Part 3. This is the plan's centrepiece.

#### SEC-2a — HIGH — `ndpi-helper` is the worst instance of SEC-2

`ndpi-helper` is spawned by `fwd` (`cmd/fwd/main.go:219`) and inherits uid 0. It
never drops. It links **libpcap and libnDPI** — tens of thousands of lines of C
protocol dissectors with a real CVE history — and points them at *raw frames off
the WAN*. That is the single highest-value remote code execution target on the
appliance and it is running as root with no sandbox.

It needs root for exactly one thing: opening `/dev/bpf*`. After
`pcap_activate()` and after connecting the label socket it needs no privilege at
all.

**Fix.** Drop to a dedicated `_fwdpcap` account immediately after the sources
and sink are open; grant bpf via a `devfs.rules` group grant rather than uid 0;
investigate `cap_enter(2)` (Capsicum) as a second layer once the drop lands.

### SEC-3 — HIGH — The config document is a root-code channel

Two paths, both of which matter *only after* the privilege split — and both of
which would make it decorative:

**a. `Shell.Shell` and `Shell.User` are completely unvalidated.**
`config.go:169-204` — `Shell.Shell` is exec'd (`shell.go:220`) and `Shell.User`
selects the credential dropped to (`shell.go:239`). Neither appears in
`validateStrings` or in any other validator. The UI cannot set them, but
`POST /system/restore` (`system.go:190`) accepts a whole config document and
`store.Replace` runs the same `Validate()`. Upload a backup with
`{"shell":{"enabled":true,"user":"root","shell":"/usr/bin/su"}}` and the next
`/shell/ws` is a root PTY.

**b. Rendered `rc.d` scripts are root code by construction.**
`render.Network` and `render.Pflow` emit `/usr/local/etc/rc.d/*` at mode 0755.
Any helper API shaped as "install this file content at this path" is
`exec-as-root(arbitrary bytes)` wearing a costume — SEC-1 is one instance of a
whole class.

**Fix.** (a) validate `Shell.User` against an allowlist (`nobody`, plus accounts
present in `/etc/passwd` with a real shell) and `Shell.Shell` against a fixed
set (`/bin/sh`, `/bin/csh`, `/bin/tcsh`, `/usr/local/bin/bash`); require an
explicit re-authentication (SEC-6) to select `root`. (b) is answered by the
helper design in §3.2: **the helper renders, it does not receive renders.**

### SEC-4 — HIGH — Pre-auth resource exhaustion on `/login`

Two independent unauthenticated denial-of-service paths, both from T2/T3 — a
LAN device with no credentials, against the box that is the household's only
route to the internet.

**a. argon2id memory amplification.** `argonMemory = 64 MiB`
(`auth/password.go:21`). `handleLogin` checks the limiter *before* hashing
(`server.go:355`) but records the failure *after* (`server.go:376`), so the
5-attempt cap does nothing against concurrency: N simultaneous POSTs are all
admitted and all allocate 64 MiB at once. 200 concurrent requests ≈ 12.8 GB on
a 16 GB box. Every unknown username still runs a full `DummyHash` verification
by design, so the attacker does not even need a valid account name.

**b. Unbounded multipart bodies.** No `http.MaxBytesReader` anywhere.
`r.FormValue` on a request with a multipart content type calls
`ParseMultipartForm(32 MiB)`, which buffers 32 MiB in RAM and then **spills the
remainder to temp files with no total cap**. `/login` is public and calls
`FormValue` (`server.go:349`). A LAN host with no credentials can fill the
filesystem. (URL-encoded bodies are capped at 10 MiB by `net/http` itself, so
this is specifically the multipart path.)

**c. The stored hash names its own cost.** Found while fixing (a):
`VerifyPassword` reads `m`, `t` and `p` out of the PHC string and honors them,
and `validateUsers` only checked that the hash starts with `$argon2id$`. A
restored backup carrying `m=16777216` makes every subsequent login attempt a
16 GiB allocation — an authenticated one-shot OOM, and a silent permanent
lockout of that account either way.

**Fix.** A semaphore (2–4 slots, sized to cores) around every
`VerifyPassword`/`HashPassword` call, returning the uniform login error when
saturated; `http.MaxBytesReader` middleware — 64 KiB default, a named larger
limit for `POST /system/restore` only; a single up-front form parse so a
truncated body is a 413 rather than a handler seeing empty strings and writing
them; reject multipart content types on `/login` and `/setup` outright; parse
and bound the hash parameters at the config boundary as well as at verify.

### SEC-5 — MED/HIGH — No admin plane; the LAN is uniformly trusted

`render.PF` emits `pass in on $lan_if inet all keep state` for the LAN and for
every OPT interface (`pf.go:80-88`, "LAN and OPT networks are trusted"). So:

- every device on the LAN can reach the admin UI on 8443 and sshd on 22;
- OPT (the natural home for a guest or IoT segment) has **full access to the
  LAN and to the firewall itself** — there is no inter-segment isolation at all;
- `fwd_listen` defaults to `0.0.0.0:8443` (`os/rc.d/fwd`), so the UI is bound on
  the WAN interface too and is only invisible because `block in log all`
  happens to come first. One misordered rule, one `pfctl -d`, one bad apply
  before rollback fires, and the admin UI is on the internet.
- pf.conf is `inet`-only end to end. That is fail-closed today (IPv6 forwarding
  is simply blocked), but it means the ruleset has **no IPv6 story at all**, and
  the day IPv6 support lands every one of these rules needs a v6 twin or the
  segmentation is v4-theatre.

**Fix.** A "Management access" config block: an explicit source allowlist
(default: the LAN prefix; optional: a named management prefix or host set) that
renders `pass in on $lan_if inet proto tcp from <mgmt> to ($lan_if) port {8443
22}` plus a `block in quick ... to ($lan_if) port {8443 22}` for everything
else. Bind `fwd` to the LAN address rather than `0.0.0.0`. Introduce an
interface `Trust` level (`trusted`/`guest`/`isolated`) so OPT stops implying
full LAN access. Track IPv6 rule parity as a hard prerequisite of any future
IPv6 work.

### SEC-6 — MED — No re-authentication for security-critical actions

One session cookie is sufficient for every one of these:

| Action | Handler | Consequence |
|---|---|---|
| Change **any** user's password | `system.go:257` | Full takeover of every account |
| Create an admin user | `system.go:216` | Persistence |
| Disable TOTP | `system.go:352` | Removes the second factor |
| Enable the web shell | `system.go:158` | Opens a PTY route |
| Restore a config | `system.go:190` | SEC-3a → root PTY |
| Download the backup | `system.go:179` | Every secret on the box |

The design review flagged the missing current-password check on admin creation
(§4.4) and it is still open. The broader shape is worse: **T4 (one stolen
cookie) currently equals permanent, un-revocable ownership of the appliance.**

**Fix.** A `reauth` gate: a password (and TOTP, when enrolled) prompt whose
success stamps the session with a 5-minute elevated window. Require it for
every row above. Additionally require the *current* password specifically for
changing one's own password, and forbid changing another user's password
outright once roles exist (SEC-7) — an admin resets it to a temporary value the
owner must change.

### SEC-7 — MED — No authorization model

`config.User` is `{username, password_hash, totp_secret}`. There is no role, no
flag, no distinction. Every account that can log in can do everything: edit the
firewall, read all flows, download every secret, open a shell. There is no
read-only account for "let me see what the network is doing" and no way to give
someone the Devices page without giving them pf.

**Fix.** Add `Role` (`admin` | `operator` | `viewer`) to `config.User`, default
`admin` on migration so nothing breaks. Enforce centrally in `ServeHTTP` from a
route→minimum-role table next to the `pages` slice, not per-handler. Ship with
the last remaining admin undeletable and un-demotable (the existing "cannot
delete the last user" check generalizes).

### SEC-8 — MED — Zero HTTP security headers

`grep` for `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-
Security`, `X-Content-Type-Options`, `Referrer-Policy`, `Cache-Control` across
the tree returns nothing. Consequences, in order:

- **Clickjacking on the whole admin UI.** Every state change is a form POST
  with a CSRF token that a framing attacker does not need to read — they only
  need the victim to click. This is the one that makes CSRF tokens
  insufficient on their own.
- **Secrets are cacheable.** `GET /system/backup` (the entire config, including
  argon2 hashes, TOTP seeds, WG private keys, the SMTP password),
  `GET /wireguard/server/clients/{id}/config` (a client private key),
  `GET /system/totp/qr.png` (an enrollment secret) — none set
  `Cache-Control: no-store`.
- No CSP, so any injection anywhere becomes a full-strength XSS.

**Fix.** One middleware in front of the mux:
`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`,
`Referrer-Policy: no-referrer`, `Strict-Transport-Security` (long max-age; the
UI is HTTPS-only and the cert is pinned by exception), and a CSP of
`default-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action
'self'; object-src 'none'`. `frame-ancestors 'self'` rather than `'none'`
because the Visibility page iframes the ntopng proxy from the same origin
(`visibility.html:85`). Inline `<script>`/`<style>` blocks exist in five
templates, so `script-src 'self'` requires either moving them to
`/static/*.js` or per-page nonces — moving them is cleaner and removes the
`onclick=` handlers in `wg_access.html` at the same time. Add
`Cache-Control: no-store` on the three secret-bearing responses.

### SEC-9 — MED — First-boot ownership race

`POST /setup` is public (`server.go:305`), unauthenticated, and self-guards only
on `len(c.Users) > 0`. From power-on until the owner reaches the UI, **whoever
gets there first owns the firewall** — and on a LAN with a hostile device
(T2/T3) that is not a race the owner reliably wins. For a product that ships to
someone else's house this is a shipping blocker, not a nicety.

**Fix.** Generate a one-time setup token at first boot; print it on the serial
console and to `/var/log/fwd.log`; require it as a form field on `/setup`.
Rate-limit `/setup` on the same limiter as `/login`. Refuse `/setup` from any
source outside the LAN prefix. Document the recovery path (delete the config,
restart, read the new token) in `docs/hw-bringup.md`.

### SEC-10 — MED — No audit trail

`auditShell` (`shell.go:301`) logs web-shell lifecycle events into the log ring
and that is the entire audit story. There is **no record of**: login success,
login failure, lockout, logout, user creation/deletion, password change, TOTP
enroll/disable, config change, apply/confirm/rollback, backup download, config
restore, SMTP settings change. After an incident there is nothing to read.

**Fix.** Promote `auditShell` to a general `s.audit(event, fields...)` writing
structured lines to the `system` source of the existing SQLite ring, and call it
from every mutation listed above (a `Store.Update` wrapper covers most of it in
one place — the actor comes from the request context). Add an `audit` filter to
the Logs page. Retention should outlive the 50k-row ring for audit lines
specifically; a separate table is the honest answer.

### SEC-11 — MED — Session lifecycle

- **No absolute lifetime.** `sessionTTL` is a 12 h *idle* timeout that every
  request extends (`session.go:56`), and the dashboard polls
  `/partials/stats` every 2 s (`dashboard.html:3`). An open tab is an immortal
  session. A cookie stolen from a laptop that is never closed never expires.
- **No session inventory.** A user cannot see or revoke their own sessions;
  there is no "sign out everywhere" short of deleting the account.
- **The CSRF token never rotates** within a session's life.
- Sessions are not bound to anything (address, user agent), which is a
  deliberate trade-off worth *stating* rather than leaving implicit.

**Fix.** Add an absolute `created` cap (24 h; re-login required regardless of
activity) alongside the idle TTL. Add a System-page session list (created, last
seen, source address) with per-session and revoke-all buttons. Rotate the CSRF
token on privilege elevation (SEC-6) and on password change.

### SEC-12 — MED — The login limiter is a self-inflicted DoS

The per-username bucket added in `1406893` (`server.go:353`) fixed the botnet
case and created a new one: **any LAN host can lock the admin out** of their
own firewall for 15 minutes with five bad guesses at a known username, in a
loop, forever. Related: the limiter map is keyed by attacker-supplied usernames
with pruning only on access (`limiter.go:56`), so username spraying grows it
unboundedly between calls.

**Fix.** Make the username bucket an escalating *delay* (exponential backoff,
capped) rather than a hard refusal, so a legitimate admin is slowed and never
locked out, while the address bucket keeps its hard cap. Bound the limiter map
(LRU, a few thousand entries) and prune on a timer rather than only on access.
Consider exempting an address that has completed a successful login recently.

### SEC-13 — LOW/MED — Untrusted network data reaches the admin browser

T5 controls: TLS SNI and HTTP Host values that become nDPI app labels, DHCP
client hostnames, DNS names, and pflog text. All of it lands on admin pages.

Server-rendered paths are safe (`html/template` autoescaping, verified in the
design review). The exception is the Visibility page, which builds table rows
in hand-written JS with a local `esc()` that escapes only `&`, `<`, `>`
(`visibility.html:107`). Every current interpolation is in element-content
position, where that is sufficient — so this is correct today and one careless
edit from being an XSS in data an attacker supplies by naming their TLS server.

**Fix.** Constrain at ingest: reject or strip app labels that are not
`[A-Za-z0-9._-]{1,64}` in `flow.Label` handling, and apply the same to DHCP
hostnames from lease files. Replace the `esc()` string-building with DOM
construction (`textContent`), matching what `traffic.html:125` already does
deliberately. SEC-8's CSP is the backstop.

### SEC-14 — LOW/MED — Localhost is a trust boundary that is not enforced

`set skip on lo0` (`pf.go:44`) plus:

- the flow collector accepts IPFIX on `127.0.0.1:9996` (`collector.go:13,55`)
  from **any** local process — after the privilege split, that includes the
  web-shell PTY user, `unbound`, `kea`, and `ntopng`. Forged flow records
  poison the Visibility page and the device usage table.
- ntopng's own web UI on `127.0.0.1` has no authentication of its own; it is
  private only because nothing else on the box is untrusted *yet*. The moment
  something is (a `nobody` shell), it is a local privilege-boundary hole.

**Fix.** After the split, restrict the label socket to the `_fwdpcap` peer uid
and the IPFIX listener to a socket with matching ownership (or accept only from
a `pflow` source address the kernel sets and validate the exporter id).
Document the localhost trust assumption explicitly in
`docs/visibility-design.md`. Consider whether ntopng should be jailed.

### SEC-15 — LOW — Login CSRF

`/login` and `/setup` are public paths and so bypass `checkCSRF`
(`server.go:243`), which is structurally correct — there is no session to bind a
token to. The residual is classic login-CSRF: an attacker can force a victim's
browser into a session on an account the attacker controls, then read what the
victim does in it. Low impact on an appliance, non-zero.

**Fix.** A pre-session double-submit cookie on the login form (a random value
set as a cookie and echoed as a hidden field), which costs ~20 lines and closes
it without needing session state.

### SEC-16 — LOW — Residual input validation gaps

- **Usernames** are not in `validateStrings` at all — the only check is
  non-empty and unique. They reach `auth.TOTPURL`, every audit line, and the
  session and limiter map keys. Restrict to `[A-Za-z0-9._-]{1,32}`.
- **NTP servers, DNS-over-TLS upstream hostnames, DNS override hosts** already
  reject whitespace (`validateSystem`, `DNS.validate`) — so the ntp.conf
  same-line injection this section originally claimed is *not* reachable. What
  is missing is a *shape* check: none of them, nor static lease hostnames, is
  validated as a hostname or IP. One validator used four times.

### SEC-17 — LOW — TLS and transport

Self-signed P-256, 10-year validity, regenerated only when a file is missing
(`cert.go:26`). If the LAN address or hostname changes, the SAN goes stale and
nothing regenerates it. No cipher suite policy; `MinVersion` is TLS 1.2. The
HTTP→HTTPS redirect listener echoes the client-supplied `Host`
(`main.go:173`), which is a redirect-target injection into an
attacker-controlled hostname.

**Fix.** Regenerate when the config's hostname/LAN address is absent from the
cert's SANs. Set an explicit modern cipher list and consider TLS 1.3-only
(nothing that talks to this box predates it). Redirect to the configured
hostname or LAN address, never to the request's `Host`.

### SEC-18 — Infrastructure — OS hardening is uncodified

`os/provision-appliance.sh` enables sshd and stops there. Not set anywhere:
`security.bsd.see_other_uids=0` / `see_other_gids=0` (which the privilege split
depends on to be worth anything), `sshd` `PermitRootLogin no` +
`PasswordAuthentication no`, `devfs.rules` for bpf, `net.bpf.maxbufsize` (which
`source_pcap.go:44` explicitly says must be raised), a package-audit cron,
`newsyslog` rules for `fwd.log` and the audit table. Packages come from the
public `pkg` repo at provision time with no pinning. The plan's signed-update
feed does not exist.

**Fix.** A `harden` section in `os/provision-appliance.sh` covering the sysctls,
sshd policy, devfs rules and newsyslog entries, with the same idempotence the
rest of that script has. Signed updates stay out of scope here — they belong
with the BE/update work.

---

## 3. Part A — The privilege model

### 3.1 What actually needs privilege

| Task | Privilege needed | Where it can live |
|---|---|---|
| Bind 8443 | **none** — unprivileged port | `fwd` |
| HTTP, TLS, templates, sessions | none | `fwd` |
| SQLite (logs, traffic, flows) | none | `fwd` |
| IPFIX collector on 127.0.0.1 | none | `fwd` |
| Interface byte counters, `arp -an`, `ndp -an` | none — sysctl reads | `fwd` |
| Read `/conf/config.json` | own it as `_fwd` | `fwd` |
| Write `/etc/pf.conf`, `/usr/local/etc/**`, `/usr/local/etc/rc.d/**` | **root** | helper |
| `pfctl -nf` / `-f` / `-e`, `sysrc`, `service` | **root** | helper |
| Spawn the web-shell PTY as another user | **root** | helper |
| `tcpdump -i pflog0` | bpf read | `_fwd` via `devfs.rules` group grant |
| `tail -F /var/log/messages` | none — 0644 on stock FreeBSD | `fwd` |
| libpcap capture on the NICs | bpf read | `_fwdpcap` via the same grant |
| `wg show` | root (kernel) | helper |

Two of those are worth calling out because they collapse the problem: **8443
needs no privilege**, and **bpf is grantable by group**. What is genuinely left
for root is a short, closed list: install files under `/etc` and
`/usr/local/etc`, run four named binaries, and fork a PTY with dropped
credentials.

### 3.2 The helper's API is a config document, not a file set

This is the load-bearing design decision, and SEC-1 and SEC-3b are why.

The obvious helper API is "install this content at this path, then run this
reload command". It is wrong. `render.Network` and `render.Pflow` produce
**executable rc.d scripts**, and the reload steps are `sh -c` strings
(`plan.go:153`). A helper accepting either is a root shell with extra steps, and
every future renderer widens it.

So the boundary is drawn one level up:

```
fwd (_fwd)                        fwd-helper (root)
──────────                        ─────────────────
Apply(configJSON)  ─────────────► Validate(cfg)          ← the SAME config.Validate
                                  plan(cfg)              ← render/ lives HERE
                                  stage → pfctl -nf …    ← fixed argv, no sh -c
                                  install → reload
                                  arm rollback timer
                   ◄───────────── {ok, deadline} | {error, diagnostics}
Confirm() / Rollback() / Status()
Shell(user, cols, rows) ────────► allowlist check, fork+setuid, PTY
                   ◄───────────── pty master fd (SCM_RIGHTS)
WGPeers()          ─────────────► wg show …, structured reply
```

`fwd` never names a path, never supplies file content, never supplies argv.
**The helper's entire untrusted input surface is one JSON document conforming
to a schema it validates itself** with the same code `fwd` validates it with —
so a bypass in `fwd` does not bypass the helper.

Consequences for the tree:

- `internal/render` and `internal/apply` move into the helper binary (or into a
  package both link, with only the helper calling the installing half). `fwd`
  keeps `render.PF` for the read-only `/system/pf.conf` preview — pure function,
  no privilege.
- The reload `sh -c` strings become an enum: `reloadPF`, `reloadKea`,
  `reloadUnbound`, `reloadNTP`, `reloadNtopng`, `reloadPflow`, `reloadNetwork`,
  `reloadWireGuard`, each mapping to a fixed `[]string` argv sequence inside the
  helper. Where a shell is genuinely needed (the `sysrc … ; service …` pairs),
  the helper runs the two steps as separate `exec` calls instead.
- The confirm/rollback timer and the file backups move to the helper, which
  also fixes design-review's open "backups live in memory, a crash in the 60 s
  window makes bad files permanent".

### 3.3 Accounts, ownership, transport

```
_fwd     uid/gid, nologin shell, no home    — fwd
_fwdpcap uid/gid, nologin shell, no home    — ndpi-helper
groups: _fwd is a member of _fwdbpf; _fwdpcap is a member of _fwdbpf
```

| Path | Owner | Mode | Note |
|---|---|---|---|
| `/conf` | `_fwd:_fwd` | 0700 | fwd owns the config document; the helper never reads it |
| `/conf/config.json` | `_fwd:_fwd` | 0600 | every secret on the box |
| `/conf/fw-{cert,key}.pem` | `_fwd:_fwd` | 0644 / 0600 | |
| `/var/db/fwd` | `_fwd:_fwd` | 0700 | SQLite + the label socket |
| `/var/run/fwd-helper.sock` | `root:_fwd` | 0660 | the only channel to root |
| `/var/log/fwd.log` | `_fwd:_fwd` | 0640 | newsyslog-rotated |

Transport: `SOCK_STREAM` unix socket, length-prefixed JSON frames, one request
per connection (the privileged side serves connections concurrently and lets
`apply.Manager`'s own locking serialize, so `Pending` still answers during an
apply), a hard frame-size cap checked before allocation, and a per-verb
timeout. Socket directory
permissions are the primary access control; the helper *additionally* verifies
the peer's uid (`LOCAL_PEERCRED` / `getpeereid(3)`; in Go,
`unix.GetsockoptXucred` — **to be confirmed on FreeBSD 15 during bring-up**) and
refuses anything that is not `_fwd`.

`devfs.rules` grants bpf to the group rather than to root:

```
[fwd_bpf=10]
add path 'bpf*' mode 0640 group _fwdbpf
```

with `devfs_system_ruleset="fwd_bpf"` in `rc.conf`. That is what lets both the
log collector (inside `fwd`) and `ndpi-helper` run unprivileged.

`security.bsd.see_other_uids=0` and `see_other_gids=0` are prerequisites, not
extras: without them a compromised `_fwd` reads the helper's and the shell
user's process state and the split buys much less.

### 3.4 `ndpi-helper` (SEC-2a)

Started by the helper, not by `fwd` (so `fwd` never needs to spawn anything).
Sequence: open every pcap handle → connect the label socket →
`setgroups/setgid/setuid` to `_fwdpcap` → verify the drop stuck
(`getuid() != 0`, and a `setuid(0)` attempt must fail) → only then enter the
capture loop. If the drop fails for any reason, **exit**; a root packet parser
is not an acceptable degraded mode.

Capsicum (`cap_enter(2)` after all descriptors are open) is the natural second
layer and would make a libnDPI memory bug nearly worthless. It is listed as a
stretch item because the interaction between `cap_enter` and the Go runtime's
lazy file access needs proving on the box before it is promised.

### 3.5 Migration

The split is not one commit. The order that keeps the tree working:

1. **DONE 2026-09-05.** Draw the boundary as a Go interface, `privsep.Ops`
   (`internal/privsep`), and make the web layer depend on it instead of on
   `*apply.Manager`. `fwd` still runs as root; nothing changes behaviourally.

   Note the correction against this step as originally written: the interface
   is **not** an extraction of `apply.System` (`ReadFile`/`WriteFile`/`Run`).
   That is the file-and-argv level, which §3.2 rejects — it is
   exec-as-root(arbitrary bytes). The boundary is the four methods the web
   layer actually uses, which are already exactly the config-document level
   §3.2 argues for: `Apply(config.Config)`, `Confirm`, `Rollback`, `Pending`.
   `apply.System` stays where it is, as the privileged side's own way of
   touching the host.

   `apply.Manager` carries a compile-time assertion that it satisfies the
   interface, so the day a method changes shape both sides fail to compile
   together. `internal/server` no longer imports `internal/apply` at all, and a
   test asserts that it does not — once `fwd-helper` exists, such an import
   would mean the privileged code had been linked back into the unprivileged
   binary.
2. **DONE 2026-09-05.** `cmd/fwd-helper` around the existing `apply`/`render`
   packages, with the config-document API of §3.2, plus `os/rc.d/fwd-helper`
   and its provisioning. `fwd` gains `-helper-socket`; without it nothing
   changes, so the two can be rolled out separately and the socket path is
   exercised end to end before anything drops privilege.

   Protocol: length-prefixed JSON, one exchange per connection, four verbs, one
   payload type. Connections are served concurrently on purpose — `apply.Manager`
   already separates its apply lock from its pending state so that `Pending`
   answers during a running apply, and serializing at the socket would have
   undone that and made the confirm button unreachable during the apply it
   exists to confirm.

   Two checks in each direction. The helper takes the caller's uid from the
   kernel (`SO_PEERCRED` / `LOCAL_PEERCRED`) and checks it against an allowlist,
   rather than trusting socket permissions alone; it re-validates the config
   document with the same `config.Validate` the sender used. `fwd` refuses to
   connect to anything that is not a socket owned by root or by its own uid —
   the document crossing the boundary carries every secret on the appliance, so
   a local process that won a race to create the socket path would otherwise be
   handed all of it.

   Note the correction to §3.3's "one request in flight", which this step found
   to be wrong: it is one request per *connection*, with `apply.Manager` doing
   the serializing. And the reachability log had to be throttled — `Pending`
   runs on the dashboard's 2 s poll, so an unthrottled "helper is down" line
   wrote twice a second per open tab, which would bury the SEC-10 audit trail
   this plan is adding.
3. **DONE 2026-09-05.** The PTY spawn moves to `fwd-helper`
   (`internal/ptyspawn`), with the master descriptor passed back over
   `SCM_RIGHTS`. `internal/server` no longer forks anything; it holds a
   descriptor and pumps bytes.

   The step turned out to be **more than a move**, and this is the part worth
   recording. The account a terminal runs as came from `Shell.User` in the
   config document — which fwd sends. A helper that honours that is a helper
   that hands root to whoever compromises fwd, so the split would have been
   decorative. The permitted set therefore now lives in the privileged process,
   set out-of-band (`fwd_helper_shell_users` in rc.conf, default empty = no web
   terminal at all). fwd names an account; the helper decides. A root web
   terminal is now a console action rather than a checkbox, and a restored
   backup cannot obtain one. See docs/shell.md §4a.

   Two implementation notes that were not obvious from the plan: on a
   `SOCK_STREAM` socket the descriptor arrives with a *specific byte* of the
   stream, so the framed response must be read with exact-length reads and no
   buffering, or a read-ahead swallows the descriptor; and the session's
   lifetime is tied to the request connection, so a crashed fwd cannot leave
   shells running — verified by killing fwd mid-session and watching the helper
   reap the shell.

   Also fixed en route: a nil shell opener panicked the WebSocket handler
   mid-upgrade instead of refusing, which a browser sees as a socket that opens
   and instantly dies.
4. **DONE 2026-09-05 (code); needs FreeBSD to verify.** Accounts, ownership,
   devfs rules, sysctls, sshd policy, log rotation, and the rc.d wiring that
   makes `fwd` run as `_fwd`.

   An audit of what `fwd` still did that needed privilege found **one** thing:
   `wg show`, which queries the interface through a root-only ioctl. It now
   goes through the boundary as a fourth capability (`privsep.WGStatus`,
   verb `wgpeers`, `internal/wgstat`); the web layer only formats the answer.
   Two entries in §3.1's table were wrong in `fwd`'s favour and are corrected
   below: `arp`/`ndp` read the routing table via sysctl and need nothing, and
   `/var/log/messages` is mode 0644 on a stock FreeBSD (per the base
   `newsyslog.conf`), so `tail -F` needs no group grant either. Only bpf does.

   Corrections to §3.3 found while writing the rc.d script:

   - **The rcvar cannot be called `fwd_user`.** `rc.subr` treats `${name}_user`
     as a standard variable and implements it with `su -m`, which execs the
     target account's login shell — and `_fwd` is a `nologin` service account,
     so it would silently fail to start. It is `fwd_runas`, passed to
     `daemon(8) -u`, which uses `setusercontext(3)` and needs no shell.
     `setusercontext` also applies the account's supplementary groups, which is
     what carries the `_fwdbpf` grant into `fwd` and its children.
   - **Neither rc.d script actually invoked `daemon(8)`**, despite a comment
     saying so. `service fwd start` would have blocked in the foreground and
     written no pidfile — a boot hang on the appliance. Both now run under
     `daemon -p -t -o`, which also gives the `-u` above.
   - **`fwd`'s prestart checked nothing.** An `install -d -o _fwd` that fails
     because the account does not exist used to be ignored, and `fwd` would
     start against state it could not write. Every step is now checked, and
     the two half-configured states — an account that does not exist, and
     `fwd_runas` set without a helper socket — are refused with a message
     naming the fix rather than started into.

   Provisioning creates `_fwd`, `_fwdpcap` and `_fwdbpf`, grants bpf by group
   via `devfs.rules`, sets `security.bsd.see_other_uids/gids=0` and
   `net.bpf.maxbufsize`, writes an sshd drop-in (**skipped when no
   `authorized_keys` exists** — locking password auth on a box whose only
   account has no key is how a bring-up ends with a serial cable), takes
   ownership of `/conf` and `/var/db/fwd`, and adds `newsyslog` entries. It sets
   `fwd_runas` **only when the helper binary is present**, so a partial deploy
   leaves `fwd` as root rather than half-applying the split.

   **Verified on a FreeBSD 15.1 VM** (`os/vm`, TCG — the sandbox has no
   `/dev/kvm`, so `run.sh`/`provision.sh` now fall back automatically):

   ```
   root  fwd-helper -socket /var/run/fwd-helper.sock -peer-user _fwd -socket-group _fwd
   _fwd  fwd -listen 0.0.0.0:8443 -helper-socket /var/run/fwd-helper.sock ...
   _fwd  tcpdump -l -n -e -q -i pflog0
   _fwd  tail -F -n 0 /var/log/messages
   ```

   `fwd-helper` is the only root process; `crw-r----- root _fwdbpf /dev/bpf`;
   `security.bsd.see_other_uids/gids` are 0 and `_fwd` running `ps` cannot see
   the helper; `/conf` and `/var/db/fwd` are `drwx------ _fwd _fwd`;
   `/var/run/fwd-helper.sock` is `srw-rw---- root _fwd`. Both §3.1 corrections
   hold in practice: tcpdump on `pflog0` works unprivileged through the group
   grant, and `tail -F /var/log/messages` needs no grant at all.

   Two bugs the VM caught that nothing else would have — see §3.6.

   **Not established:** an apply that runs to completion on the VM. The
   boundary demonstrably carries one — the helper ran `pfctl -nf` and
   `kea-dhcp4 -t` and their diagnostics came back through the socket to the
   browser verbatim, and file mtimes show the helper installing and rolling
   back as root while fwd stayed `_fwd` — but under TCG the *reload* phase
   (restarting kea, unbound, ntopng, redis) outruns both the 60 s confirm
   window and `OSSystem.Run`'s 2-minute per-command ceiling, so the apply
   rolls itself back every time. That is emulation speed, not a defect; on
   hardware or KVM those reloads take seconds. It stays on the bring-up list.
5. **DONE 2026-09-05 (code).** `ndpi-helper` drops to `_fwdpcap`, and stops
   being a child of `fwd`.

   The plan said "drop ndpi-helper to `_fwdpcap`" as if it were a flag. It is
   not: after step 4 `fwd` is unprivileged and **cannot fork anything as another
   account**, so the classifier could not have been dropped while it remained
   fwd's child. It became its own rc.d service (`os/rc.d/ndpi-helper`), which
   is better anyway — a C parser eating hostile frames should not inherit the
   web daemon's identity, and rc/`daemon(8)` supervises it more honestly than
   fwd's restart loop did. `superviseHelper` is gone from `cmd/fwd`.

   The drop is the helper's own, not `daemon -u`, because ordering matters: it
   opens the bpf devices and the label socket as root and *then* drops, before
   a single packet is parsed. `setgroups` → `setgid` → `setuid`, in that order
   (uid first would make the rest fail and leave the groups on), followed by a
   verification that includes attempting `setuid(0)` and requiring it to fail —
   proving the saved-set-uid is gone and the drop is irreversible. Every failure
   is fatal: a root packet parser is not an acceptable degraded mode.

   Consequences that had to be handled:

   - **The label socket moved.** It lived in fwd's state directory, which is
     now mode 0700 and owned by `_fwd`, so `_fwdpcap` could not reach it. It is
     `/var/run/fwd/ndpi.sock`, owned by `_fwd` with `_fwdpcap` as its group at
     mode 0660 (`-label-socket`/`-label-peer`).
   - **SEC-14, partly, falls out of this.** The label server now takes the
     peer's uid from the kernel and refuses anything that is not the classifier.
     What arrives on that socket is stamped onto flow records and shown to the
     admin, so it is worth knowing who wrote it.
   - `peerUID` was needed in two packages, so it is now `internal/peercred`
     rather than duplicated.
   - Dropping to the account the process already is must be a **no-op, not an
     error**: `setgroups` is refused even when the list is identical, so
     without that short-circuit a correctly-started process would fatal.
6. **DONE 2026-09-05.** The in-process privileged implementation is gone.

   `cmd/fwd` no longer imports `internal/apply`, `internal/ptyspawn` or
   `internal/render` at all — its only route to privilege is `internal/privsep`,
   and `privsep.Local`/`privsep.LocalWG` are deleted. `internal/privsep` now
   holds the boundary and the unprivileged client and nothing else: the
   WireGuard read moved into `cmd/fwd-helper`, because anything in `privsep` is
   linked into `fwd`. `Terminal` lost its in-process session field, so there is
   no longer a shape in the API that could own a process on this side.
   `-confirm-window` is gone from `fwd`; the window is the helper's
   (`fwd_helper_window`).

   A fallback is not a safety net here — it is a way for a misconfiguration to
   silently produce a root web daemon, which is the outcome the whole split
   exists to prevent. So the rc.d script and provisioning now treat the helper
   as mandatory: `fwd` refuses to start without it rather than starting into a
   state where every apply fails with a permissions error that reads like a bug.

   **The property is enforced, not just performed.** "We deleted it" is not a
   property — a later edit reintroducing an `apply.Manager` into `cmd/fwd` would
   compile and pass every other test. `internal/privsep/boundary_test.go` walks
   the real import graph of `cmd/fwd` and of `privsep` itself and fails if
   either grows a privileged dependency. It was checked by temporarily adding
   the import back and watching it fail.

   Cost, accepted deliberately: a dev box now runs both processes.
   `fwd-helper -root ./devroot -noexec` gives the whole pipeline without
   touching the system, and it exercises the same path the appliance runs
   instead of a second one that only exists for development.

   Verified on the FreeBSD VM: with `fwd-helper` moved aside,

   ```
   /usr/local/etc/rc.d/fwd: ERROR: fwd-helper is not installed;
                                   fwd cannot apply anything without it
   ```

   and fwd does not start. Restored, both come up with `fwd-helper` root and
   `fwd` as `_fwd`.

### 3.6 What only the VM could find

Both of these are the same shape: correct-looking code that fails only under
the appliance's real startup path, and neither is reachable from a unit test or
from running the daemons by hand.

**The daemons had no usable PATH.** rc.d starts services through `daemon(8)`,
which passes on the boot environment — `PATH=/sbin:/bin:/usr/sbin:/usr/bin`.
Every package-installed tool the appliance depends on lives outside it:
`kea-dhcp4` and `unbound-checkconf` in `/usr/local/sbin`, `wg` in
`/usr/local/bin`. So **the first apply on a real appliance failed at the kea
validator** with `executable file not found in $PATH`, and the WireGuard page
would have silently reported no handshakes forever. This predates the split —
it was hidden because the daemon had only ever been started by hand from a
login shell. Both mains now set an explicit `appliancePath` at startup, once,
rather than at each exec site.

**`_fwd` could not create the label socket.** Step 5 put it at
`/var/run/fw-ndpi.sock`, and `/var/run` is `root:wheel` 0755 — so an
unprivileged fwd got `bind: permission denied` and the flow-label pipeline was
simply dead. It now gets its own directory, `/var/run/fwd/`, created by root in
fwd's rc.d prestart before the drop, owned by `_fwd` with the classifier's
account as its group at mode 0750: fwd can create the socket, the classifier can
traverse in, nothing else can. `/var/run` is commonly a tmpfs rebuilt at boot,
so this happens on every start rather than once at provisioning.

---

## 4. Part B — CSRF: where it actually stands

The design review's §4.4 is **closed**, and it is worth recording precisely what
that means so the gap that remains is visible.

**What is in place** (`server.go:259-301`, `session.go:65`): a 256-bit
per-session synchronizer token, held only in session state and rendered into the
page; `checkCSRF` runs inside `ServeHTTP` *before* the mux, so it is
structurally impossible for a new route to forget it; every method except
GET/HEAD/OPTIONS is gated; the token arrives as a hidden field or, for htmx, via
`hx-headers` in `layout.html`; comparison is constant-time; the two
side-effecting GETs the review found (`/system/dns/test`, `/system/ntp/test`)
became POSTs. The ntopng subtree, whose third-party forms cannot be rewritten,
falls back to a strict same-origin check. The WebSocket route is a GET and so
skips the token, but carries its own default-deny Origin check
(`shell.go:77-99`) — which is the correct control there, since SameSite does not
cover WS.

**What CSRF tokens do not cover, and what remains:**

1. **Clickjacking (SEC-8).** A token the attacker never needs to read is no
   defense against a framed UI and a tricked click. `frame-ancestors` is the
   missing half. *This is the single most important remaining item in the CSRF
   story* — the design review closed the token half and left the framing half
   open.
2. **Login CSRF (SEC-15).** Structural, by construction, on the two pre-session
   forms.
3. **Token lifetime (SEC-11).** One token for the life of a session, never
   rotated, including across a password change.
4. **Same-origin fallback breadth.** The ntopng subtree accepts any request
   whose `Origin` matches `r.Host`. `r.Host` is client-supplied; a DNS-rebinding
   setup can make both sides agree. The session cookie is scoped to the IP/host
   the admin actually uses, so this is not exploitable today, but validating
   `r.Host` against the configured hostname/LAN address (which SEC-17 needs
   anyway) removes the question.
5. **No re-auth on the sensitive actions (SEC-6).** CSRF protects against a
   *cross-site* forgery. It does nothing about a same-site XSS or a stolen
   cookie, which is what actually reaches those six handlers.

So: tokens — done. The CSRF *problem* — three items short.

---

## 5. Sequenced plan

Phases are ordered by (risk closed) ÷ (effort), with the constraint that
anything that would be silently undone by the privilege split comes first.

### Phase S0 — Before the hardware arrives (days) — **DONE 2026-09-05**

Small, self-contained, no architecture change. Every one of these is a fix that
would otherwise have to be re-verified after the split.

- [x] **SEC-1** — `validDeviceName` grammar + `validateShellSafe` sweep called
      from `Validate`, and `render.shellQuote` applied at every interpolation in
      `render/network.go`. Two independent defenses, because the charset check
      is one forgotten field away from failing and the cost is root.
- [x] **SEC-3a** — `Shell.Shell` against a closed set of login shells,
      `Shell.User` against the unix account grammar, both at `Validate()` so
      `/system/restore` cannot smuggle them. An explicit `root` shell still
      validates: it is a deliberate choice, not a silent default.
- [x] **SEC-4** — `http.MaxBytesReader` (64 KiB, 8 MiB for restore); a single
      up-front `parseBody` so a truncated form is a 413 instead of a handler
      writing empty strings; multipart refused on `/login` and `/setup`; an
      argon2 slot limiter making peak hash memory a constant; and (SEC-4c)
      `auth.ParseHash` bounding the parameters, called from `validateUsers`.
- [x] **SEC-8** — security-header middleware (CSP, `X-Frame-Options`, nosniff,
      `Referrer-Policy`, HSTS) and `no-store` everywhere but `/static`. The
      four inline `<script>` blocks moved to `/static/*.js` and the `on*`
      attributes converted to listeners, so `script-src 'self'` is real; a test
      walks the embedded templates to keep it that way.
- [x] **SEC-16** — `validHostname` applied to NTP servers, DoT upstream
      hostnames, DNS overrides and static lease hostnames; `usernamePattern`
      applied to WebUI logins.

**Exit — met.** `go test ./...` green with new tests in `internal/config`
(`shellsafe_test.go`), `internal/auth` (`hashlimit_test.go`) and
`internal/server` (`hardening_test.go`). Verified live against a running `fwd`:
the header set is present on every response, an injected device name is refused
at the Interfaces form, an oversized POST is a 413 that writes nothing,
multipart on `/login` is a 415, and all four hostile backups (arbitrary shell
binary, metacharacter shell user, metacharacter device, 16 GiB argon2
parameter) are refused at restore while a clean one is accepted.

### Phase S1 — The privilege split (weeks) — *plan.md §10 Phase 0 exit criterion*

- [ ] **SEC-2** — §3.5 steps 1–4, ending with `fwd` running as `_fwd`
- [ ] **SEC-3b** — helper renders from the config document; no path or content
      ever crosses the socket
- [ ] Rollback backups move to the helper and become durable (closes the
      design-review residual)
- [ ] **SEC-18** — the sysctls, devfs rules, sshd policy and newsyslog entries
      that the split depends on

**Exit:** on the appliance, `ps -axo user,command` shows exactly one root
process from this project (`fwd-helper`); `fwd`, `ndpi-helper` and the PTY are
not root; an apply, a confirm, a rollback, a shell session and a WireGuard peer
listing all work through the socket.

### Phase S2 — Sandbox and segmentation — **DONE 2026-09-05**

- [x] **SEC-2a** — the drop landed with §3.5 step 5. **Capsicum: investigated,
      not adopted.** `unix.CapEnter` is available for FreeBSD in `x/sys`, and
      the process is a good candidate — after `pcap_activate` it needs no
      namespace at all. It is blocked by one design detail: the label sink
      *dials lazily and redials under backoff*, and capability mode forbids
      `connect()` by path. Adopting it therefore means connecting eagerly and
      **exiting on disconnect** so rc restarts the process, which trades a
      transparent fwd restart for a classifier restart. Two things also remain
      unknown without hardware: whether libnDPI opens any file after
      initialisation, and whether the Go runtime does. Shipping an unverified
      `cap_enter` into the default path risks silently killing app labels, so
      it stays out until it can be run on the box. Tracked as S4.
- [x] **SEC-5** — management-access allowlist, interface trust levels, and
      `fwd` binding the LAN address rather than `0.0.0.0`.

      One hole was introduced and caught during review: the first version of
      the management rule was interface-agnostic, so a source list containing a
      public prefix — a mistake, or a restored backup — would have opened the
      WebUI **on the WAN**. It is now emitted per non-WAN interface, so the
      ruleset does not offer that option whatever the list says, and
      `/system/management` is behind the re-auth gate because widening the
      admin plane is the first thing someone holding a stolen session would do.
- [x] **SEC-14** — peer-uid check on the label socket (landed with step 5), and
      the IPFIX collector now refuses datagrams from anything but the local
      exporter, with a counter so a non-zero value is visible.

**Exit — met, and checked against a real `pfctl`.** All four rulesets (default,
guest, isolated, explicit management sources) parse clean on FreeBSD 15.1, and
`pfctl -nvf` expands them the way the policy intends:

```
# guest
pass  in quick on vtnet2 ... to (self) port = domain|bootps|ntp
pass  in quick on vtnet2 ... icmp-type echoreq
block in log quick on vtnet2 from 192.168.9.0/24 to (self)
block in log quick on vtnet2 from 192.168.9.0/24 to 10.0.2.0/24
block in log quick on vtnet2 from 192.168.9.0/24 to 192.168.1.0/24
pass  in       on vtnet2 from 192.168.9.0/24 to any

# isolated adds
block in quick on vtnet2 from 192.168.9.0/24 to 192.168.9.0/24
```

The ordering is the part worth checking on a real parser rather than in a
string comparison: the blocks are `quick` and precede the pass-to-any, so the
route out cannot re-open what they closed. The admin-plane block likewise
expands to `block drop in log quick inet proto tcp from any to (self) port =
8443` sitting ahead of every segment pass.

What is still untested is behavioural rather than syntactic: no packet has been
sent from a guest segment to the LAN. That needs two hosts on two segments and
is on the `docs/hw-bringup.md` list.

**IPv6 rule parity — still a plan, not code.** Every rule the renderer emits is
`inet`. That is fail-closed today (v6 forwarding is simply blocked), so it is
not a hole; it is a prerequisite. Whoever adds IPv6 has to add a v6 twin for
each of the segment blocks above, plus ICMPv6 and DHCPv6, or the segmentation
becomes v4-theatre the day it lands. Kept in S4 with that framing rather than
listed as done.

### Phase S3 — Account and operational security — **DONE 2026-09-05**

- [x] **SEC-6** — a re-authentication gate with a 5-minute per-session window,
      applied by consequence rather than by verb: everything that changes who
      can log in, plus `GET /system/backup`, which is a download but what it
      downloads is every secret on the box. It re-checks the second factor too,
      because someone holding a stolen cookie may also know the password.
- [x] **SEC-9** — a console setup token, required once. 80 bits from an
      alphabet with no `I`/`L`/`O`/`U`/`0`/`1`, so it survives being read off a
      serial console. Rate-limited on the login bucket, and an *absent* token is
      treated as "accept nothing" rather than "accept anything".
- [x] **SEC-10** — an audit trail in its own table with its own retention.
      Separate from the log ring on purpose: the ring is trimmed by whatever is
      chattiest, and on a firewall that is pf — an audit trail a port scan can
      erase is not an audit trail. Surfaced as a source on the Logs page.
- [x] **SEC-11** — an absolute 24 h lifetime alongside the idle TTL, a session
      inventory with source and last-seen, per-session revoke and "sign out
      everywhere else". Inventory ids are hashes, never token prefixes: a
      prefix of a bearer token is a partial credential.
- [x] **SEC-12** — the username bucket became an escalating capped delay rather
      than a refusal. The address bucket keeps its hard cap. The map is bounded
      with coldest-first eviction, so a username spray cannot flush the entry
      tracking a real attack.
- [x] **SEC-13** — app labels are constrained at ingest (`flow.SanitizeApp`),
      and the Visibility page builds rows as DOM nodes instead of HTML strings.
      The old hand-rolled escaper covered `&<>`, which is correct for text
      position and silently is not the moment a value moves into an attribute.
- [x] **SEC-15** — a pre-session double-submit cookie on `/login` and `/setup`.
- [x] **SEC-17** — the certificate regenerates when the hostname or LAN address
      moves out from under it (an admin trained to click through a warning on
      their own firewall will click through a real one), an explicit
      forward-secret AEAD cipher list, and the HTTP→HTTPS redirect now targets
      the appliance's own address rather than echoing the client's `Host`.

### Phase S4 — Deferred, tracked

- [ ] **Capsicum for `ndpi-helper`** — see S2 above for what blocks it and what
      would have to change. Needs the box.
- [ ] **IPv6 rule parity** — a prerequisite of any IPv6 support, not of
      shipping v4.

- [ ] **SEC-7** — roles. Wanted, but it touches every handler and is better done
      once the handler set stops moving.
- [ ] Passkeys/WebAuthn (`plan.md` §7) — replaces the password-plus-TOTP
      surface rather than patching it.
- [ ] Encrypted config backup (a passphrase-wrapped export), so a `.json` in
      Downloads is not the whole appliance.
- [ ] Signed update feed and BE rollback verification.
- [ ] `internal/adblock`, when it is built, downloads attacker-influenceable
      content on a schedule: it must run in `fwd` (non-root), pin TLS
      verification, cap response size, validate every parsed domain, and never
      let a fetch failure break an apply. Writing that constraint down now so it
      is designed in rather than reviewed in.

---

## 6. Verification

Code-level, in-tree:

- Metacharacter fuzz over `Validate()` → every renderer, asserting rejection at
  the validator (SEC-1, SEC-16).
- A test that every registered non-GET route 403s without a token (the existing
  `TestCSRFRequired` generalized to walk the mux).
- A test that every secret-bearing response carries `no-store`, and that the
  header middleware is present on a sample of routes (SEC-8).
- A restore test asserting a hostile backup (`shell.user=root`, a metacharacter
  device) is rejected (SEC-3).
- A concurrency test asserting the argon2 semaphore bounds in-flight
  verifications (SEC-4a).
- Helper protocol tests: unknown verb, oversized frame, wrong peer uid, a
  config that fails validation — all refused without touching the filesystem.

On the box, added to `docs/hw-bringup.md` §8:

- `ps -axo user,command` — one root process from this project.
- `sockstat -4 -l` — `fwd` on the LAN address only; the IPFIX collector and
  ntopng on 127.0.0.1 only.
- `ls -l /var/run/fwd-helper.sock /conf/config.json /var/db/fwd` — ownership and
  modes match §3.3.
- From a second LAN host: the admin UI is reachable only from the management
  allowlist; from an OPT host, it is not reachable at all.
- `service fwd restart` with a config containing a metacharacter device —
  rejected at the UI, and the rendered script is unchanged.
- A web-shell session runs as `nobody` and `id` confirms no supplementary
  groups.

---

## 7. Explicitly out of scope

Named so they are decisions rather than oversights: physical attack (no full-
disk encryption, no secure boot — an appliance someone can open is an appliance
they own); supply chain beyond pinning (`pkg` trust, Go module trust);
rogue-admin containment (T7 — roles in S4 reduce blast radius, they do not
solve it); DoS from the WAN side beyond what pf already does; and formal
verification of the pf ruleset, which stays a golden-file test.
