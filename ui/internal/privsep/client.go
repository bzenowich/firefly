package privsep

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"firewall/ui/internal/config"
	"firewall/ui/internal/ptyspawn"
)

// Client is the unprivileged side: an Ops that forwards each operation to
// fwd-helper over a unix socket. It is what fwd holds once the split lands, in
// place of an in-process apply.Manager.
type Client struct {
	path string

	// Reachability state, for throttling the log when the helper is down.
	mu         sync.Mutex
	down       bool
	lastLog    time.Time
	suppressed int
}

// NewClient returns an Ops backed by the helper listening at path.
func NewClient(path string) *Client { return &Client{path: path} }

var _ Ops = (*Client)(nil)

// Per-verb deadlines. An apply legitimately takes minutes — it restarts kea,
// unbound, ntopng and wireguard — so it gets a ceiling rather than a
// responsiveness budget. Pending is on every page render and must be quick or
// the UI stalls.
const (
	applyTimeout   = 5 * time.Minute
	pendingTimeout = 5 * time.Second
	// Opening a terminal is a fork and an exec; it is quick or it is broken.
	// This bounds the handshake only — the session that follows has no deadline.
	shellOpenTimeout = 15 * time.Second
)

func (c *Client) Apply(cfg config.Config) error {
	_, err := c.exchange(request{Verb: VerbApply, Config: &cfg}, applyTimeout)
	return err
}

func (c *Client) Confirm() error {
	_, err := c.exchange(request{Verb: VerbConfirm}, applyTimeout)
	return err
}

func (c *Client) Rollback() error {
	_, err := c.exchange(request{Verb: VerbRollback}, applyTimeout)
	return err
}

// WGPeers asks the privileged side for live peer state. It is a page-render
// read like Pending, so it gets the same short deadline.
func (c *Client) WGPeers() (map[string]time.Time, error) {
	resp, err := c.exchange(request{Verb: VerbWGPeers}, pendingTimeout)
	if err != nil {
		return nil, err
	}
	return resp.Peers, nil
}

func (c *Client) Pending() (time.Time, bool) {
	resp, err := c.exchange(request{Verb: VerbPending}, pendingTimeout)
	if err != nil {
		// Pending has no error channel — it renders a banner. Reporting "no
		// apply pending" when the helper is unreachable is the safe answer: it
		// offers no confirm button for an apply that could not be confirmed.
		// The log is where this becomes visible.
		c.noteUnreachable(err)
		return time.Time{}, false
	}
	c.noteReachable()
	return resp.Deadline, resp.Pending
}

// unreachableLogInterval throttles the "helper is down" line.
//
// Pending runs on every page render *and* on the dashboard's 2-second poll, so
// an unthrottled log would write a line twice a second per open tab — enough to
// bury the audit trail and roll /var/log. The condition is worth one line when
// it starts, an occasional reminder while it persists, and one line when it
// clears; the repetition in between says nothing new.
const unreachableLogInterval = time.Minute

func (c *Client) noteUnreachable(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.suppressed++
	if !c.down {
		c.down = true
		c.suppressed = 0
		c.lastLog = time.Now()
		log.Printf("privsep: %v", err)
		return
	}
	if time.Since(c.lastLog) >= unreachableLogInterval {
		log.Printf("privsep: still unreachable (%d attempts since the last message): %v", c.suppressed, err)
		c.lastLog = time.Now()
		c.suppressed = 0
	}
}

// noteReachable logs the recovery, once, so the log says when the gap ended
// rather than only when it began.
func (c *Client) noteReachable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		c.down = false
		log.Printf("privsep: privileged helper is reachable again")
	}
}

// exchange performs one request/response: dial, send, receive, close.
func (c *Client) exchange(req request, timeout time.Duration) (response, error) {
	req.Version = ProtocolVersion

	conn, err := c.dial()
	if err != nil {
		return response{}, err
	}
	defer conn.Close()

	// One deadline for the whole exchange. For an apply this is the ceiling on
	// the privileged side's work, not an expectation of it.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return response{}, err
	}
	if err := writeFrame(conn, req); err != nil {
		return response{}, transportError(err)
	}
	var resp response
	if err := readFrame(conn, &resp); err != nil {
		return response{}, transportError(err)
	}
	if resp.Error != "" {
		// The privileged side's own diagnostics, passed through unchanged: this
		// is pfctl's parse error as the admin needs to read it.
		return response{}, fmt.Errorf("%s", resp.Error)
	}
	return resp, nil
}

// allowedSocketOwner reports whether a socket owned by ownerUID may be
// connected to by a process running as selfUID.
//
// The check is not ceremony. The config document that crosses this boundary
// contains every secret on the appliance — argon2 password hashes, WireGuard
// private keys, TOTP seeds, the SMTP relay password. A local process that won a
// race to create /var/run/fwd-helper.sock would be handed all of it on the next
// apply.
//
// Two owners are acceptable, and only two:
//
//   - root, which is who the real helper runs as. On the appliance /var/run is
//     root-owned, so root is in practice the only account that can create the
//     socket there at all.
//   - our own uid, which cannot be an escalation: a process running as us
//     already has whatever we have, including read access to the config
//     document itself. Refusing this case would buy nothing and would make the
//     boundary impossible to run outside of production.
//
// Any third party is refused: that is the impersonation this exists to stop.
func allowedSocketOwner(ownerUID, selfUID uint32) bool {
	return ownerUID == 0 || ownerUID == selfUID
}

// dial opens the socket, refusing one whose owner we cannot vouch for.
func (c *Client) dial() (*net.UnixConn, error) {
	fi, err := os.Stat(c.path)
	if err != nil {
		return nil, fmt.Errorf("privileged helper socket %s: %w (is fwd-helper running?)", c.path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("privileged helper: %s is not a socket; refusing to send the configuration to it", c.path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("privileged helper: cannot determine the owner of %s", c.path)
	}
	if self := uint32(os.Geteuid()); !allowedSocketOwner(st.Uid, self) {
		return nil, fmt.Errorf(
			"privileged helper: %s is owned by uid %d, which is neither root nor this process (uid %d); "+
				"refusing to send the configuration to it", c.path, st.Uid, self)
	}

	addr, err := net.ResolveUnixAddr("unix", c.path)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("privileged helper: %w (is fwd-helper running?)", err)
	}
	return conn, nil
}

// transportError marks a failure of the channel rather than of the operation,
// so an admin is not left thinking pfctl rejected their ruleset when in fact
// the helper died mid-apply.
func transportError(err error) error {
	return fmt.Errorf("privileged helper: lost contact during the operation: %w", err)
}

// OpenShell asks the privileged side for a terminal and returns its PTY master.
//
// Unlike the other four operations this one keeps its connection: the
// privileged side hangs the session up and reaps the process when the
// connection closes, so the returned Terminal owns it and Close ends the
// session. That is deliberate — it means a terminal cannot outlive the fwd
// process that asked for it, however fwd goes away.
//
// The account named here is a request. What the appliance actually permits is
// fwd-helper's business (see internal/ptyspawn), and fwd cannot widen it.
func (c *Client) OpenShell(req ptyspawn.Request) (*Terminal, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(shellOpenTimeout)); err != nil {
		return nil, err
	}
	if err := writeFrame(conn, request{Version: ProtocolVersion, Verb: VerbShell, Shell: &req}); err != nil {
		return nil, transportError(err)
	}
	var resp response
	if err := readFrame(conn, &resp); err != nil {
		return nil, transportError(err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}

	ptmx, err := recvFD(conn, "pty")
	if err != nil {
		return nil, transportError(err)
	}
	// The terminal now lives as long as the session does, so the exchange
	// deadline must not still be armed on the connection whose closure signals
	// the end of it.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		ptmx.Close()
		return nil, err
	}

	ok = true
	return &Terminal{PTY: ptmx, RunAs: resp.RunAs, Pid: resp.Pid, conn: conn}, nil
}
