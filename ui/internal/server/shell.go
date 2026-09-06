package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"firewall/ui/internal/config"
	"firewall/ui/internal/ptyspawn"

	"github.com/creack/pty"
	"golang.org/x/net/websocket"
)

// shellPage is registered like the others but kept out of the static `pages`
// slice: its route self-guards on Shell.Enabled and its nav entry is appended
// per-request only when enabled (docs/shell.md §9).
var shellPage = Page{Path: "/shell", Title: "Shell", tmpl: "shell.html"}

// handleShellPage renders the terminal page, or 403s when the feature is off
// so a disabled shell has no reachable surface beyond a flat refusal.
func (s *Server) handleShellPage(w http.ResponseWriter, r *http.Request) {
	if !s.store.Get().Shell.Enabled {
		http.Error(w, "web shell is disabled", http.StatusForbidden)
		return
	}
	s.render(w, r, shellPage)
}

// handleShellWS upgrades to a WebSocket bridged to a PTY-backed login shell.
// The session gate in ServeHTTP already ran (/shell is not public); this adds
// the feature switch, an Origin check, and a concurrency cap before spawning.
func (s *Server) handleShellWS(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey{}).(string)
	ip := remoteIP(r)
	cfg := s.store.Get().Shell

	if !cfg.Enabled {
		s.auditShell("denied user=%s from=%s reason=disabled", user, ip)
		http.Error(w, "web shell is disabled", http.StatusForbidden)
		return
	}
	// No opener means this build or deployment has no way to spawn a terminal
	// at all — the privileged side did not enable it. Refuse before the
	// upgrade, so the browser gets a status rather than a socket that opens
	// and immediately dies.
	if s.shell == nil {
		s.auditShell("denied user=%s from=%s reason=unavailable", user, ip)
		http.Error(w, "the web shell is not available on this appliance", http.StatusForbidden)
		return
	}
	if !s.shellAcquire(cfg.Sessions()) {
		s.auditShell("denied user=%s from=%s reason=maxsessions", user, ip)
		http.Error(w, "too many shell sessions", http.StatusTooManyRequests)
		return
	}
	defer s.shellRelease()

	// The http.Server arms ReadTimeout/WriteTimeout as absolute deadlines on
	// this connection; a hijacked WebSocket outlives both, so a shell session
	// would die ~10-30 s in. Clear them before the upgrade — a zero time means
	// "no deadline" — and let the idle watchdog below own session lifetime
	// instead (design-review §4.3). Deadline control is unavailable on HTTP/2,
	// which cannot carry this WebSocket anyway (no Hijack), so log and continue.
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("shell: clear read deadline: %v", err)
	}
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		log.Printf("shell: clear write deadline: %v", err)
	}

	// Origin check: WebSocket bypasses SameSite cookie protection, so reject
	// any upgrade whose Origin host differs from the request host (cross-site
	// WS hijacking defense). Default-deny when Origin is absent.
	handshake := func(c *websocket.Config, req *http.Request) error {
		// websocket.Origin parses the request's Origin header; a custom
		// Handshake replaces the library's default check, so c.Origin is not
		// pre-populated and we resolve it here.
		origin, err := websocket.Origin(c, req)
		if err != nil || !sameOrigin(origin, req.Host) {
			s.auditShell("denied user=%s from=%s reason=origin", user, ip)
			return errors.New("origin not allowed")
		}
		return nil
	}
	srv := websocket.Server{
		Handshake: handshake,
		Handler:   func(conn *websocket.Conn) { s.shellBridge(conn, cfg, user, ip) },
	}
	srv.ServeHTTP(w, r)
}

// sameOrigin enforces the cross-site WS hijacking defense: default-deny when
// the Origin header is missing, otherwise require its host to equal the
// request host.
func sameOrigin(origin *url.URL, host string) bool {
	return origin != nil && strings.EqualFold(origin.Host, host)
}

// shellBridge obtains a terminal and pumps bytes between its PTY and the
// WebSocket until either side closes.
//
// The shell is not forked here. It is opened through the privileged boundary
// (internal/privsep), which owns the credentials, the account policy and the
// reaping; this side holds only the PTY master. Closing the terminal is what
// ends the session, and because the boundary ties the session's life to the
// connection it was handed over on, a terminal cannot outlive this process
// (docs/security-plan.md §3.5 step 3).
func (s *Server) shellBridge(conn *websocket.Conn, cfg config.Shell, user, ip string) {
	term, err := s.shell.OpenShell(ptyspawn.Request{
		User:  cfg.User,
		Shell: cfg.Command(),
		Cols:  80,
		Rows:  24,
	})
	if err != nil {
		s.auditShell("denied user=%s from=%s reason=spawn:%v", user, ip, err)
		// The terminal is already open in the browser; without a word it just
		// sits blank.
		_ = frameCodec.Send(conn, wsFrame{typ: websocket.BinaryFrame,
			data: []byte("web shell unavailable: " + err.Error() + "\r\n")})
		return
	}
	defer term.Close()
	ptmx := term.PTY

	start := time.Now()
	s.auditShell("open user=%s from=%s as=%s pid=%d", user, ip, term.RunAs, term.Pid)

	// Idle watchdog: any frame in either direction refreshes lastActive; the
	// ticker closes the connection once the configured idle window elapses,
	// which unblocks the read loop and triggers the reap below.
	idle := time.Duration(cfg.IdleSeconds()) * time.Second
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())
	touch := func() { lastActive.Store(time.Now().UnixNano()) }
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastActive.Load())) > idle {
					conn.Close()
					return
				}
			}
		}
	}()

	// PTY -> WS: stream output as binary frames.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				touch()
				if frameCodec.Send(conn, wsFrame{typ: websocket.BinaryFrame, data: buf[:n]}) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		conn.Close()
	}()

	// WS -> PTY: binary frames are keystrokes; text frames are JSON control.
	for {
		var f wsFrame
		if err := frameCodec.Receive(conn, &f); err != nil {
			break
		}
		touch()
		switch f.typ {
		case websocket.BinaryFrame:
			if _, err := ptmx.Write(f.data); err != nil {
				break
			}
		case websocket.TextFrame:
			handleShellControl(f.data, ptmx)
		}
	}
	close(done)

	// Closing the terminal unblocks the PTY reader and tells the privileged
	// side to hang up and reap. The exit code is not observable from here —
	// the process is not ours — so the audit line records the session rather
	// than the status.
	term.Close()
	s.auditShell("close user=%s from=%s as=%s pid=%d duration=%s",
		user, ip, term.RunAs, term.Pid, time.Since(start).Round(time.Second))
}

// handleShellControl applies a JSON control frame. Only resize is defined;
// unknown messages are ignored so the protocol can grow.
func handleShellControl(data []byte, ptmx *os.File) {
	var c struct {
		Type string `json:"type"`
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	}
	if json.Unmarshal(data, &c) != nil {
		return
	}
	if c.Type == "resize" && c.Cols > 0 && c.Rows > 0 {
		_ = pty.Setsize(ptmx, &pty.Winsize{Cols: c.Cols, Rows: c.Rows})
	}
}

func (s *Server) shellAcquire(max int) bool {
	s.shellMu.Lock()
	defer s.shellMu.Unlock()
	if s.shellActive >= max {
		return false
	}
	s.shellActive++
	return true
}

func (s *Server) shellRelease() {
	s.shellMu.Lock()
	s.shellActive--
	s.shellMu.Unlock()
}

// auditShell records a lifecycle event to the log ring buffer and the process
// log, giving the Logs page a record of every privileged session.
func (s *Server) auditShell(format string, args ...any) {
	line := "shell " + fmt.Sprintf(format, args...)
	log.Print(line)
	if s.logStore != nil {
		_ = s.logStore.Insert("system", line, time.Now())
	}
}

// wsFrame carries one WebSocket frame's payload plus its type. frameCodec
// preserves the text/binary distinction that plain Conn.Read discards, so the
// bridge can tell keystrokes (binary) from control messages (text).
type wsFrame struct {
	typ  byte
	data []byte
}

var frameCodec = websocket.Codec{
	Marshal: func(v interface{}) ([]byte, byte, error) {
		f := v.(wsFrame)
		return f.data, f.typ, nil
	},
	Unmarshal: func(data []byte, typ byte, v interface{}) error {
		f := v.(*wsFrame)
		f.typ = typ
		f.data = append([]byte(nil), data...)
		return nil
	},
}
