package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"firewall/ui/internal/config"

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
	if !s.shellAcquire(cfg.Sessions()) {
		s.auditShell("denied user=%s from=%s reason=maxsessions", user, ip)
		http.Error(w, "too many shell sessions", http.StatusTooManyRequests)
		return
	}
	defer s.shellRelease()

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

// shellBridge spawns the shell and pumps bytes between the PTY and the
// WebSocket until either side closes, then reaps the child's process group.
func (s *Server) shellBridge(conn *websocket.Conn, cfg config.Shell, user, ip string) {
	cmd, err := buildShellCmd(cfg)
	if err != nil {
		s.auditShell("denied user=%s from=%s reason=spawn:%v", user, ip, err)
		return
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		s.auditShell("denied user=%s from=%s reason=pty:%v", user, ip, err)
		return
	}
	defer ptmx.Close()

	start := time.Now()
	s.auditShell("open user=%s from=%s pid=%d", user, ip, cmd.Process.Pid)

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

	ptmx.Close() // unblock the PTY reader
	killProcessGroup(cmd)
	code := exitCode(cmd.Wait())
	s.auditShell("close user=%s from=%s exit=%d duration=%s",
		user, ip, code, time.Since(start).Round(time.Second))
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

// buildShellCmd constructs the login-shell command with a clean env. When a
// target user is set and the process is root, it drops to that user's
// credentials; on a non-root dev box it runs as the current user.
func buildShellCmd(cfg config.Shell) (*exec.Cmd, error) {
	cmd := exec.Command(cfg.Command(), "-l")
	env := []string{
		"TERM=xterm-256color",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}

	u, err := shellUser(cfg.User)
	if err != nil {
		return nil, err
	}
	if cfg.User != "" && os.Geteuid() == 0 {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		}
	}
	cmd.Env = append(env, "USER="+u.Username, "HOME="+u.HomeDir)
	cmd.Dir = u.HomeDir
	return cmd, nil
}

// shellUser resolves the target user, falling back to the current process
// user when none is configured.
func shellUser(name string) (*user.User, error) {
	if name == "" {
		return user.Current()
	}
	return user.Lookup(name)
}

// killProcessGroup reaps the shell and everything it spawned. pty.Start sets
// Setsid, so the child leads its own process group (pgid == pid); signal the
// whole group, SIGHUP then SIGKILL, so a dropped browser never leaves an
// orphan shell behind.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGHUP)
	time.AfterFunc(2*time.Second, func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
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
