// Package privsep defines the boundary between the unprivileged web daemon and
// the privileged operations it cannot perform itself (docs/security-plan.md §3).
//
// Today fwd runs as root and calls apply.Manager directly, so the boundary is
// only a Go interface. It exists ahead of the split so that the seam is drawn —
// and enforced by the compiler — before a second implementation depends on
// where it sits. Step 1 of docs/security-plan.md §3.5.
//
// # Why the interface is at this level
//
// The obvious privileged API is "install this content at this path, then run
// this reload command". It is wrong, and the reason is the whole design.
//
// render.Network and render.Pflow produce *executable rc.d scripts* installed
// at mode 0755, and the reload steps in apply/plan.go are `sh -c` strings. A
// privileged service accepting either is exec-as-root(arbitrary bytes) wearing
// a costume, and every renderer added later widens it. The root command
// injection in docs/security-plan.md SEC-1 was one instance of that class.
//
// So the boundary is drawn one level up: the only thing that crosses it is a
// config document. The privileged side re-validates it with the same
// config.Validate the unprivileged side used, then renders, stages, validates
// and installs on its own. Its entire untrusted input surface is one JSON
// document conforming to a schema it checks itself — which means a bypass on
// the unprivileged side is not a bypass of the privileged side.
//
// Nothing here names a path, a file's content, or a command.
package privsep

import (
	"io"
	"os"
	"time"

	"firewall/ui/internal/config"
	"firewall/ui/internal/ptyspawn"
)

// Ops is the set of operations that require privilege. apply.Manager is the
// in-process implementation used while fwd is still root; the socket client
// that talks to fwd-helper is the second one (§3.5 step 2), and the server
// cannot tell them apart.
//
// Errors returned here are shown to the admin verbatim, so an implementation
// that crosses a process boundary must carry the privileged side's diagnostics
// (pfctl's parse error, unbound-checkconf's complaint) in the error text rather
// than flattening them to "apply failed".
type Ops interface {
	// Apply renders cfg, validates the result, installs it, reloads the
	// affected services, and arms the confirm-or-rollback window. It refuses
	// while an apply is already pending, and installs nothing if any validator
	// rejects its staged file.
	Apply(cfg config.Config) error

	// Confirm accepts a pending apply, disarming the rollback timer.
	Confirm() error

	// Rollback restores the pre-apply files and reloads, whether or not the
	// window has expired.
	Rollback() error

	// Pending reports the rollback deadline of an unconfirmed apply. Every page
	// render calls it, so it must not block behind a running apply.
	Pending() (deadline time.Time, pending bool)
}

// Spawner is the privileged side's PTY spawner (internal/ptyspawn), consumed by
// Service. It returns a Session, which owns the process: the credentials, the
// account policy and the reaping all stay on that side.
type Spawner interface {
	// Open starts a login shell on a new PTY. The account named in the request
	// is a request, not an instruction: which accounts are permitted is the
	// implementation's decision, and that is why this operation is privileged.
	Open(ptyspawn.Request) (*ptyspawn.Session, error)
}

// ShellOpener is what the web layer depends on. It returns a Terminal, which
// owns only the PTY master — never a process. Client implements it by asking
// fwd-helper; Local implements it by spawning in-process, which is what fwd
// does while it is still root.
type ShellOpener interface {
	OpenShell(ptyspawn.Request) (*Terminal, error)
}

// Terminal is a live web terminal held by the unprivileged side: the PTY master
// plus the identity of what is running on it, for the audit line. Closing it
// ends the session.
//
// Whoever holds a Terminal never holds the process. Across the socket the
// privileged side reaps it; in-process the embedded session does. Either way
// this side sees a file descriptor and two strings.
type Terminal struct {
	PTY   *os.File
	RunAs string
	Pid   int

	// conn, when set, is the connection the descriptor arrived on. It is held
	// open for the life of the terminal because the privileged side treats its
	// closure as the signal to hang up and reap — so a crashed fwd cannot leave
	// shells running on the appliance.
	conn io.Closer

	// session, when set, is the in-process session this Terminal stands for.
	// Exactly one of conn and session is ever non-nil.
	session *ptyspawn.Session
}

// Close ends the terminal.
func (t *Terminal) Close() error {
	if t.session != nil {
		t.session.Hangup()
		t.session.Wait()
		return nil
	}
	if t.PTY != nil {
		t.PTY.Close()
	}
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// Local is the in-process ShellOpener: it spawns the terminal here rather than
// asking a helper. It is what fwd uses while it still runs as root, and it goes
// away with the last step of docs/security-plan.md §3.5.
type Local struct{ Spawner Spawner }

func (l Local) OpenShell(req ptyspawn.Request) (*Terminal, error) {
	sess, err := l.Spawner.Open(req)
	if err != nil {
		return nil, err
	}
	return &Terminal{PTY: sess.PTY, RunAs: sess.RunAs, Pid: sess.Pid, session: sess}, nil
}

// WGStatus reads live WireGuard peer state. It is a third capability alongside
// Ops and ShellOpener, and separate for the same reason: wg(8) queries the
// interface through a root-only ioctl, so on a split appliance the answer comes
// from fwd-helper, while an appliance without WireGuard has no use for it at
// all.
type WGStatus interface {
	// WGPeers returns each remote-access peer's last handshake time, keyed by
	// public key. Peers that have never handshaked are absent.
	WGPeers() (map[string]time.Time, error)
}
