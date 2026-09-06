# Shell Page — Implementation Plan

A web terminal page for the firewall WebUI, modeled on the TrueNAS "Shell"
page. The browser runs an xterm.js VT emulator; the Go server bridges that
terminal to a real PTY-backed login shell over a WebSocket. Off by default,
gated behind config, and quarantined behind the existing session auth.

This is the 9th and last page in plan.md §7. SSH remains the recommended
admin path; the web shell exists for the no-SSH-client case (a browser on a
locked-down workstation, initial bring-up, recovery).

## 1. How TrueNAS does it (reference)

- `middlewared` exposes a single WebSocket endpoint speaking JSON-RPC.
- The Shell page calls a `core.subscribe`-style method that makes middleware
  `fork`/`exec` a shell (or `tmux`/`/usr/bin/login`) attached to a PTY.
- Middleware pumps PTY master output to the client as messages and writes
  client keystrokes back into the PTY master. Window-resize is its own
  control message that triggers a `TIOCSWINSZ` ioctl.
- The browser is xterm.js: it renders the byte stream and emits keystrokes +
  resize events.

We copy the *shape* (xterm.js front-end, WebSocket byte bridge, PTY-backed
shell, resize control messages) but not the transport ceremony — we do not
need a full JSON-RPC layer for one endpoint. A minimal framed protocol
(§5) is enough.

## 2. Where this fits the existing code

| Concern | Existing mechanism | What the shell adds |
|---|---|---|
| Routing | `internal/server/server.go` `pages` slice + `mux` | new `/shell` page route, new `/shell/ws` upgrade route, registered in a `routesShell()` like the other `routes*()` |
| Auth | session cookie checked in `Server.ServeHTTP` | WS handshake reuses `sessionUser`; add Origin check (§6) |
| Config | `internal/config` `Config`/`System` structs, `Store` | new `Shell` config block, default disabled (§3) |
| Nav gating | `pages` slice drives nav + routes | page shown/registered only when enabled (§7) |
| Privilege split | plan.md §7: non-root UI + small root helper | PTY+shell spawned with root privilege via the helper, never by the web process (§4) |
| Templates/assets | `web/embed.go` embeds `templates` + `static` | vendor xterm.js into `static/`, add `pages/shell.html` |
| Audit | `internal/logs` SQLite ring buffer | every open/close/denied attempt logged (§8) |

## 3. Config model

Add to `internal/config/config.go`:

```go
type Shell struct {
    Enabled     bool   `json:"enabled"`      // master switch, default false
    Shell       string `json:"shell"`        // "" => /bin/sh (login shell of target user)
    User        string `json:"user"`         // target unix user; "" => unprivileged default
    IdleTimeout int    `json:"idleTimeout"`  // seconds of no I/O before kill; 0 => 15m default
    MaxSessions int    `json:"maxSessions"`  // concurrent ttys; 0 => 1
}
```

Wire it into the top-level `Config` struct and `Default()` with
`Shell{Enabled: false}`. Because the whole feature is dark until an admin
flips `Enabled`, a fresh appliance ships with no web-shell attack surface —
matching plan.md §7 ("off by default, big warning").

The toggle lives on the **System** page (where the placeholder TODO already
sits, `system.html:115`), not as a config that requires the apply/rollback
pipeline — it is a UI-service setting, not a packet-path setting, so it can
be a direct `Store.Update` + immediate effect.

## 4. Privilege architecture (the load-bearing decision)

**Built, 2026-09-05 — Option A** (docs/security-plan.md §3.5 step 3).

**Option A — helper owns the PTY, passes the master fd back.** `fwd-helper`
exposes `OpenShell(req) -> fd` (`internal/privsep`, verb `shell`). It creates
the PTY, `fork`/`exec`s the target shell as the target user, and sends the
**master fd** back to the web process over its unix-domain socket using
`SCM_RIGHTS`. The web process does the dumb byte-pump between that fd and the
WebSocket. Privileged work (setuid, PTY creation, reaping) stays in the helper;
the web process only ever shuttles bytes and never holds root.

Two details that were not obvious until it was built:

- **On a `SOCK_STREAM` socket the descriptor is delivered with a specific byte
  of the stream**, so it is sent alongside one payload byte and the receiver
  must `recvmsg` at exactly that point. The framed response is therefore read
  with exact-length reads and no buffering — a `bufio.Reader` reading ahead
  would swallow the byte the descriptor is attached to, and with it the
  descriptor.
- **The session's lifetime is tied to the connection.** The helper holds the
  request connection open, unread, for as long as the terminal lives; when fwd
  exits or is killed, the kernel closes its end, the helper's read returns, and
  it hangs up and reaps. A terminal cannot outlive the process that asked for
  it, so a crashed fwd cannot leave shells running on the appliance. Verified
  by killing fwd mid-session and watching the shell go with it.

**Option B — helper owns the whole bridge.** Helper spawns the shell *and*
proxies bytes over its socket to the web process, which relays to the WS.
Simpler fd handling but puts a byte loop in the privileged binary and doubles
the copy. Not taken.

In both cases the web process is the only thing touching the network; the
helper has no socket exposed beyond its local AF_UNIX control channel.

### 4a. Who decides the account (changed when the split landed)

The target account used to come from `Shell.User` in the config document — and
the config document is sent by fwd. If the helper simply honoured it, a
compromised or buggy fwd would ask for root and get it, which would make the
whole privilege split decorative.

So the permitted set now lives **in the privileged process**, configured
out-of-band by the operator:

```sh
sysrc fwd_helper_shell_users="nobody"   # what a terminal may run as
service fwd-helper restart
```

Empty (the default) means the appliance serves no web terminal at all, whatever
the UI says. fwd names an account when it asks; `fwd-helper` decides whether it
gets one, and fwd cannot widen the list — nor can a restored backup.

The practical consequence is deliberate: **a root web terminal now takes a
console action**, not a checkbox in a browser. The config's `Shell.User` still
selects *which* permitted account, so both sides must agree; when they do not,
the refusal names both (`"nobody" is not among the accounts this appliance
permits a terminal as (bz)`) rather than failing silently.

PTY mechanics: use `github.com/creack/pty` (supports FreeBSD, ~one file of
real code, no transitive deps) for `pty.Open` + `pty.Setsize`. Alternative
to avoid the dep entirely: hand-roll `posix_openpt`/`grantpt`/`unlockpt`/
`ptsname` + `TIOCSWINSZ` via `x/sys/unix` (~80 lines). Decide during build;
creack/pty is the low-risk default.

Process spawn: set the slave PTY as the child's controlling terminal
(`setsid` + `TIOCSCTTY`, or `syscall.SysProcAttr{Setctty,Setsid}`), set
`Credential{Uid,Gid}` for the target user, and exec the login shell with a
clean env (`TERM=xterm-256color`, `HOME`, `PATH`, `USER`). On FreeBSD,
`/usr/bin/login -f <user>` gives a proper login session; `/bin/sh -l` is the
lighter path.

## 5. Wire protocol (`/shell/ws`)

One WebSocket per terminal. Keep it minimal — no JSON-RPC envelope:

- **Binary frames** = raw terminal bytes, both directions. Client→server is
  keystrokes (PTY stdin); server→client is PTY output. This is what
  xterm.js's attach pattern expects and avoids base64 overhead.
- **Text frames** = JSON control messages:
  ```json
  {"type":"resize","cols":120,"rows":40}
  {"type":"ping"}
  ```
  Server may send `{"type":"exit","code":0}` before closing.

Resize handling: on a `resize` message the web process calls
`pty.Setsize` (or relays it to the helper in Option A if it does not hold
the fd — but in A it does hold the master fd, so it resizes directly).

WebSocket library: **`github.com/coder/websocket`** (pure Go, zero
transitive deps, context-aware, the modern successor to nhooyr). It fits the
single-static-binary ethos. `golang.org/x/net/websocket` is already in the
module graph and could be used to add *zero* new deps, but its API is dated
and it lacks good binary/close-code support; prefer coder/websocket and
accept the one dep.

Backpressure: bound the PTY→WS direction with a small buffered reader; if the
client cannot keep up, drop the connection rather than balloon memory. The
WS→PTY direction is naturally rate-limited by human typing.

## 6. Security model

The web shell is the single most dangerous page in the product. Defenses,
layered:

1. **Off by default.** No route, no nav entry, no listener until
   `Shell.Enabled` (§3, §7).
2. **Session required.** The `/shell/ws` upgrade runs *after*
   `Server.ServeHTTP`'s `sessionUser` gate — do **not** add `/shell` to
   `isPublic`. Re-check the session inside the handler before upgrading.
3. **Origin check.** WebSocket bypasses SameSite cookie protection, so
   reject the upgrade unless `Origin`'s host matches the request host
   (cross-site WS hijacking defense). coder/websocket's
   `AcceptOptions.OriginPatterns` handles this; default-deny.
4. **HTTPS only.** Already the server default; the WS rides the same TLS.
5. **LAN-only bind.** Inherited from the existing bind policy.
6. **Audit every event** to the logs store (§8): who opened a shell, from
   what IP, when it closed, exit reason.
7. **Idle + lifecycle kill.** Idle timeout (config) and hard kill of the
   child process group on WS close so a dropped browser never leaves an
   orphan root shell. Reap with `SIGHUP`→`SIGKILL`.
8. **Concurrency cap.** `MaxSessions` (default 1) prevents fork bombs of
   login shells.
9. **Big visible warning** on the page and at the System toggle, naming SSH
   as the preferred path (mirror the plan.md §7 language).

Explicitly out of scope for v1: per-command authorization, recording/replay,
read-only "view another admin's session." Document them as future work.

## 7. Front-end

- Vendor `xterm.js` + the `fit` addon into `web/static/` (e.g.
  `xterm.min.js`, `xterm.css`, `addon-fit.min.js`). No CDN — the appliance
  must work fully offline. `embed.go` already globs `static`, so no embed
  change is needed.
- `web/templates/pages/shell.html`: a warning banner, a `<div id="term">`,
  and a small inline script that:
  - constructs `new Terminal()`, loads the fit addon, opens into `#term`;
  - opens `new WebSocket("wss://"+location.host+"/shell/ws")` with
    `binaryType="arraybuffer"`;
  - `term.onData` → `ws.send` (binary); `ws.onmessage` → `term.write`;
  - `term.onResize` and a `ResizeObserver`/`fit()` → send a `resize` text
    frame;
  - shows a "disconnected" overlay on `ws.onclose`.
- Add the xterm stylesheet link in `layout.html` head only when needed, or
  unconditionally (small). The page itself is the only consumer.

## 8. Audit logging

Reuse `internal/logs`. On each lifecycle event write a structured line:
`shell open user=<u> from=<ip> tty=<pts> pid=<n>`, `shell close ... exit=<c>
duration=<s>`, `shell denied user=<u> reason=<disabled|origin|session>`.
This gives the Logs page a record of every privileged session — important
for a sellable appliance.

## 9. Nav / route gating

`pages` in `server.go` is static. Make the shell conditional:

- Build the effective nav and route set from `pages` **plus** a shell entry
  appended only when `Store.Get().Shell.Enabled`. Simplest: register the
  `/shell` page route and `/shell/ws` always, but have both return `403 +
  "web shell is disabled"` when not enabled, and filter the shell entry out
  of the nav slice passed to templates when disabled. That keeps routing
  static (matches current code style) while hiding/disabling cleanly.
- The nav is rendered from a `.Nav` slice in layout data; compute it
  per-request from config so toggling takes effect without a restart.

## 10. Implementation phases

1. **Config + gating** — add `Shell` struct + default; System-page toggle;
   conditional nav/route; `/shell` page returning the warning + an empty
   terminal that reports "disabled" until wired. (No PTY yet.) Testable.
2. **Root helper `OpenShell`** — PTY creation, setuid spawn, `SCM_RIGHTS` fd
   passing (Option A). Unit-test the spawn against `/bin/echo` in the VM.
3. **WS bridge** — `/shell/ws` upgrade with session + Origin checks, byte
   pump, resize, lifecycle kill, idle timeout, concurrency cap.
4. **Front-end** — vendor xterm.js, `shell.html`, wire data/resize/close.
5. **Audit + polish** — log lifecycle events; warning copy; docs.

## 11. Testing

- **Unit (CI, Linux/host):** config default is disabled; nav omits shell
  when disabled; `/shell` and `/shell/ws` return 403 when disabled; Origin
  check rejects foreign origins; resize JSON parsing; control-message
  framing.
- **Integration (FreeBSD VM, `os/vm`):** enable shell, open WS, spawn
  `/bin/sh`, send `echo hi\n`, assert `hi` comes back; send resize, assert
  `stty size` reflects it; drop the WS, assert the child is reaped (no
  orphan `pts`). The existing `serial_expect.py`/`run.sh` harness can drive
  this.

## 12. New dependencies

- `github.com/coder/websocket` — WebSocket server (zero transitive deps).
- `github.com/creack/pty` — PTY open/resize on FreeBSD (optional; can be
  replaced by `x/sys/unix` hand-roll to keep deps at one).
- `xterm.js` + fit addon — vendored static assets, not a Go dep.

Both Go deps are small, pure-Go, and align with the single-binary goal.

## 13. Open questions

- ~~Target user model~~ **DECIDED, then tightened:** a single configurable
  target unix user, because WebUI users are not unix users — default
  **unprivileged** (`nobody`), never root. An empty `user` resolves to that
  default. A configured user that does not exist is a hard error, never a
  silent fall back to root.

  Tightened in the privilege split (§4a): the config document now only
  *selects* among accounts `fwd-helper` permits, and the permitted set is
  operator-configured on the appliance. Writing `"root"` into the config — or
  restoring a backup that does — is no longer sufficient on its own.
- `/usr/bin/login -f` (full login session, PAM/login.conf, MOTD) vs
  `/bin/sh -l` (lighter). Recommend `login -f` for a faithful console.
- Should enabling the shell require re-auth or a TOTP step at the toggle?
  Reasonable hardening; defer to v1.1.
