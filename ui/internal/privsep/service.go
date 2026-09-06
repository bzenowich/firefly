package privsep

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"firewall/ui/internal/peercred"
	"firewall/ui/internal/ptyspawn"
)

// Service is the privileged side: it listens on a unix socket and performs the
// four operations of Ops on behalf of the unprivileged web daemon.
//
// It is the trust boundary, so it assumes nothing about its caller:
//
//   - the caller's uid is taken from the kernel, not from the message, and
//     checked against a fixed allowlist;
//   - the config document is re-validated here with the same config.Validate
//     the sender used, because a bypass on the sender's side must not be a
//     bypass on ours;
//   - the verb set is closed and checked before the payload is looked at;
//   - frames are size-capped before they are allocated.
type Service struct {
	ops Ops

	// wg reads live WireGuard peer state. Nil means the appliance reports no
	// handshake times, which is what a box without WireGuard should do.
	wg WGStatus

	// shell opens PTY-backed terminals. Nil means the appliance serves no web
	// terminal at all, which is the default: the feature is opt-in on the
	// privileged side, not just in the config document.
	shell Spawner

	// allowUID is the set of uids permitted to connect. Socket permissions are
	// the primary control; this is the second, and it is the one that still
	// holds if the socket is created with the wrong mode.
	allowUID map[uint32]bool

	// logf is overridable so tests can assert on refusals.
	logf func(string, ...any)
}

// NewService wraps ops for service over a socket. allowUID lists the uids
// permitted to connect; uid 0 is always permitted, since root can do
// everything this service does by other means anyway.
func NewService(ops Ops, allowUID []uint32) *Service {
	allow := map[uint32]bool{0: true}
	for _, uid := range allowUID {
		allow[uid] = true
	}
	return &Service{ops: ops, allowUID: allow, logf: log.Printf}
}

// WithWG enables live WireGuard peer reporting.
func (s *Service) WithWG(wg WGStatus) *Service {
	s.wg = wg
	return s
}

// WithShell enables the web terminal. Without it VerbShell is refused, so an
// appliance that has not deliberately turned the feature on at this layer
// cannot be talked into a terminal by anything fwd sends.
func (s *Service) WithShell(spawner Spawner) *Service {
	s.shell = spawner
	return s
}

// Listen creates the socket at path with the given mode and group, replacing a
// stale one left by an unclean shutdown.
//
// The mode is set explicitly after bind rather than relying on the process
// umask, which is inherited from whatever started us. gid < 0 leaves the group
// alone (root-owned, which is what mode 0600 wants).
func (s *Service) Listen(path string, mode os.FileMode, gid int) (*net.UnixListener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing stale socket: %w", err)
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			ln.Close()
			return nil, fmt.Errorf("setting socket group: %w", err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("setting socket mode: %w", err)
	}
	return ln, nil
}

// Serve accepts connections until ctx is cancelled.
//
// Connections are handled concurrently on purpose. The serialization that
// matters is apply.Manager's own: it holds one lock for the whole of an apply
// and a separate one for the pending state, so that Pending — which every page
// render calls — answers immediately even while an apply is reloading services.
// Serializing here would undo that and make the confirm button unreachable
// during the apply it is meant to confirm.
func (s *Service) Serve(ctx context.Context, ln *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// connTimeout bounds a single exchange's I/O. It is not a bound on the work:
// the deadline is cleared before the operation runs, because an apply legitimately
// takes minutes reloading services, and is re-armed to write the reply.
const connTimeout = 30 * time.Second

func (s *Service) handle(conn *net.UnixConn) {
	defer conn.Close()

	uid, err := peercred.UID(conn)
	if err != nil {
		s.logf("privsep: refusing a connection whose peer could not be identified: %v", err)
		return
	}
	if !s.allowUID[uid] {
		s.logf("privsep: refusing a connection from uid %d", uid)
		return
	}

	if err := conn.SetReadDeadline(time.Now().Add(connTimeout)); err != nil {
		return
	}
	var req request
	if err := readFrame(conn, &req); err != nil {
		s.logf("privsep: unreadable request from uid %d: %v", uid, err)
		// Say so on the wire when we can; a caller that sent something we could
		// not parse deserves better than a closed connection.
		s.reply(conn, response{Error: "malformed request: " + err.Error()})
		return
	}

	if req.Verb == VerbShell {
		// The shell exchange owns the rest of the connection: the descriptor
		// follows the response, and the connection then stays open for as long
		// as the terminal lives so that a dead fwd hangs the session up.
		s.serveShell(conn, req, uid)
		return
	}

	resp := s.dispatch(req)

	if err := conn.SetWriteDeadline(time.Now().Add(connTimeout)); err != nil {
		return
	}
	s.reply(conn, resp)
}

// serveShell opens a terminal and hands its PTY master to the caller.
//
// The connection is the session's lifeline in both directions. The descriptor
// travels over it, and it then stays open, unread, for as long as the terminal
// lives: if fwd exits or is killed, the kernel closes its end, the read below
// returns, and the shell is hung up. A terminal cannot outlive the process that
// asked for it, which is what keeps a crashed fwd from leaving root-adjacent
// shells running on the appliance.
func (s *Service) serveShell(conn *net.UnixConn, req request, uid uint32) {
	if s.shell == nil {
		s.reply(conn, response{Error: "the web terminal is not enabled on this appliance"})
		return
	}
	ask := ptyspawn.Request{}
	if req.Shell != nil {
		ask = *req.Shell
	}

	sess, err := s.shell.Open(ask)
	if err != nil {
		s.logf("privsep: terminal refused for uid %d: %v", uid, err)
		s.reply(conn, response{Error: err.Error()})
		return
	}
	s.logf("privsep: terminal opened for uid %d as %s (pid %d)", uid, sess.RunAs, sess.Pid)

	if err := conn.SetWriteDeadline(time.Now().Add(connTimeout)); err != nil {
		sess.Hangup()
		sess.Wait()
		return
	}
	if err := writeFrame(conn, response{RunAs: sess.RunAs, Pid: sess.Pid}); err != nil {
		s.logf("privsep: terminal response: %v", err)
		sess.Hangup()
		sess.Wait()
		return
	}
	if err := sendFD(conn, int(sess.PTY.Fd())); err != nil {
		s.logf("privsep: handing over the terminal: %v", err)
		sess.Hangup()
		sess.Wait()
		return
	}

	// The caller now holds its own descriptor for the same open file, so this
	// side does not need one. Keeping it would stop the shell ever seeing a
	// hangup when the caller closes theirs.
	sess.PTY.Close()

	// Block until the caller goes away, then hang up and reap.
	_ = conn.SetReadDeadline(time.Time{})
	var scratch [1]byte
	_, _ = conn.Read(scratch[:])

	sess.Hangup()
	code := sess.Wait()
	s.logf("privsep: terminal closed as %s (pid %d, exit %d)", sess.RunAs, sess.Pid, code)
}

func (s *Service) reply(conn *net.UnixConn, resp response) {
	if err := writeFrame(conn, resp); err != nil {
		s.logf("privsep: writing response: %v", err)
	}
}

// dispatch performs one operation. Every path through it either does exactly
// one of the four things Ops names, or refuses.
func (s *Service) dispatch(req request) response {
	if req.Version != ProtocolVersion {
		return response{Error: fmt.Sprintf(
			"protocol version %d is not supported (this helper speaks %d); fwd and fwd-helper are not the same build",
			req.Version, ProtocolVersion)}
	}

	switch req.Verb {
	case VerbApply:
		if req.Config == nil {
			return response{Error: "apply: no configuration in the request"}
		}
		// Re-validate on this side of the boundary. The sender validates too,
		// but that is its business: the whole point of the split is that a
		// compromised or buggy fwd cannot make the privileged side act on a
		// document it would not have accepted itself.
		cfg := *req.Config
		if err := cfg.Validate(); err != nil {
			return response{Error: "refusing an invalid configuration: " + err.Error()}
		}
		return errResponse(s.ops.Apply(cfg))
	case VerbConfirm:
		return errResponse(s.ops.Confirm())
	case VerbRollback:
		return errResponse(s.ops.Rollback())
	case VerbPending:
		deadline, pending := s.ops.Pending()
		return response{Deadline: deadline, Pending: pending}
	case VerbWGPeers:
		if s.wg == nil {
			return response{} // no WireGuard on this appliance: no peers, not an error
		}
		peers, err := s.wg.WGPeers()
		if err != nil {
			// The interface being down is the normal case on a box with no
			// clients connected; it is not worth an error banner.
			return response{}
		}
		return response{Peers: peers}
	case VerbShell:
		// Handled by serveShell, which needs the connection itself.
		return response{Error: "internal: shell must be handled on the connection"}
	default:
		return response{Error: fmt.Sprintf("unknown verb %q", req.Verb)}
	}
}

func errResponse(err error) response {
	if err != nil {
		return response{Error: err.Error()}
	}
	return response{}
}
