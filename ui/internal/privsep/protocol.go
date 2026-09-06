package privsep

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"firewall/ui/internal/config"
	"firewall/ui/internal/ptyspawn"
)

// The wire protocol between fwd and fwd-helper.
//
// Deliberately small: length-prefixed JSON, one request and one response per
// connection, four verbs, and exactly one payload type — a config document.
// Nothing here can name a path, a file's content, a user, or a command, which
// is the property the whole privilege split rests on (see the package comment).
//
// Each connection carries a single exchange and then closes. That is not just
// simplicity: it means the helper can serve connections concurrently and let
// apply.Manager's own locking do the serializing, which preserves the rule that
// Pending — called on every page render — never blocks behind a running apply.

// ProtocolVersion is bumped when the wire format changes incompatibly. The
// helper refuses anything else rather than guessing: a privileged service that
// half-understands its input is worse than one that stops.
const ProtocolVersion = 1

// maxFrame caps a single frame. A config document is a few KB; even an
// appliance with a hundred WireGuard clients is far under this. The cap exists
// so that a hostile or confused peer cannot make the helper allocate.
const maxFrame = 1 << 20

// Verb names the privileged operation. The set is closed; the helper rejects
// anything else without looking at the payload.
type Verb string

const (
	VerbApply    Verb = "apply"
	VerbConfirm  Verb = "confirm"
	VerbRollback Verb = "rollback"
	VerbPending  Verb = "pending"
	VerbShell    Verb = "shell"
	VerbWGPeers  Verb = "wgpeers"
)

// request is what crosses to the privileged side. Config is set only for
// VerbApply.
type request struct {
	Version int            `json:"version"`
	Verb    Verb           `json:"verb"`
	Config  *config.Config `json:"config,omitempty"`
	// Shell is set only for VerbShell. It names an account and a login shell;
	// which accounts are actually permitted is the privileged side's decision
	// alone (internal/ptyspawn).
	Shell *ptyspawn.Request `json:"shell,omitempty"`
}

// response is what comes back. Error carries the privileged side's own
// diagnostics — pfctl's parse error, unbound-checkconf's complaint — because
// after the split that string is all the admin will ever see of them.
type response struct {
	Error    string    `json:"error,omitempty"`
	Deadline time.Time `json:"deadline,omitempty"`
	Pending  bool      `json:"pending,omitempty"`

	// Peers is the answer to VerbWGPeers: public key -> last handshake.
	Peers map[string]time.Time `json:"peers,omitempty"`

	// Set for a successful VerbShell. The PTY master itself does not travel in
	// this message — it follows as a file descriptor over SCM_RIGHTS (see
	// sendFD). These are for the audit line on the unprivileged side.
	RunAs string `json:"run_as,omitempty"`
	Pid   int    `json:"pid,omitempty"`
}

// writeFrame writes one length-prefixed JSON message.
func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxFrame {
		return fmt.Errorf("message is %d bytes, over the %d byte limit", len(body), maxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// readFrame reads one length-prefixed JSON message into v.
//
// Decoding is strict: an unknown field is an error rather than something
// silently dropped. If fwd and fwd-helper disagree about the config schema —
// a partial upgrade, a hand-rolled client — the privileged side must refuse
// rather than apply a document it only partly understands.
func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return errors.New("empty frame")
	}
	if n > maxFrame {
		return fmt.Errorf("frame announces %d bytes, over the %d byte limit", n, maxFrame)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// File descriptor passing for VerbShell.
//
// The PTY master cannot be serialized into the JSON response — it is a kernel
// object, and the whole point is that the unprivileged side ends up holding the
// same open file the privileged side created. SCM_RIGHTS is how a unix socket
// carries one.
//
// On a SOCK_STREAM socket the ancillary data is delivered with a specific byte
// of the stream, so the descriptor is sent alongside one payload byte and the
// receiver must recvmsg at exactly that point. That is why the framed response
// is read with exact-length reads and no buffering: a bufio.Reader that read
// ahead would swallow the byte the descriptor is attached to, and with it the
// descriptor.

// fdByte is the one-byte payload the descriptor rides with. Its value carries
// no meaning; SCM_RIGHTS simply requires at least one byte of ordinary data.
var fdByte = []byte{0}

// sendFD writes the descriptor-carrying message. It must be called after the
// framed response, and only when that response reported success.
func sendFD(conn *net.UnixConn, fd int) error {
	rights := unix.UnixRights(fd)
	_, _, err := conn.WriteMsgUnix(fdByte, rights, nil)
	return err
}

// recvFD reads the descriptor-carrying message and returns the received
// descriptor as a file. name is used only for the returned file's name.
func recvFD(conn *net.UnixConn, name string) (*os.File, error) {
	oob := make([]byte, unix.CmsgSpace(4)) // exactly one descriptor
	buf := make([]byte, len(fdByte))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, err
	}
	if n != len(fdByte) {
		return nil, fmt.Errorf("expected %d payload byte, got %d", len(fdByte), n)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("parsing ancillary data: %w", err)
	}
	var fds []int
	for _, m := range msgs {
		got, err := unix.ParseUnixRights(&m)
		if err != nil {
			return nil, fmt.Errorf("parsing file descriptors: %w", err)
		}
		fds = append(fds, got...)
	}
	if len(fds) != 1 {
		// Close anything unexpected rather than leaking descriptors into a
		// long-lived process.
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("expected exactly one file descriptor, got %d", len(fds))
	}
	return os.NewFile(uintptr(fds[0]), name), nil
}
