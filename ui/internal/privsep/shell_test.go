package privsep

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"firewall/ui/internal/ptyspawn"
)

// newShellPair starts a Service with a real PTY spawner behind it.
func newShellPair(t *testing.T, spawner Spawner) *Client {
	t.Helper()
	svc := NewService(&fakeOps{}, []uint32{uint32(os.Geteuid())})
	svc.logf = func(string, ...any) {}
	if spawner != nil {
		svc.WithShell(spawner)
	}

	dir, err := os.MkdirTemp("", "privsep")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")

	ln, err := svc.Listen(path, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); svc.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })

	return NewClient(path)
}

// The descriptor really crosses: what the unprivileged side gets back is the
// same open file the privileged side created, and driving it drives the shell.
func TestShellDescriptorCrossesTheBoundary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the spawner would drop credentials, which needs real accounts")
	}
	c := newShellPair(t, &ptyspawn.Spawner{MaxSessions: 2})

	term, err := c.OpenShell(ptyspawn.Request{Shell: "/bin/sh", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()

	if term.Pid <= 0 || term.RunAs == "" {
		t.Errorf("audit details missing: pid=%d runAs=%q", term.Pid, term.RunAs)
	}

	if _, err := io.WriteString(term.PTY, "echo crossed-the-boundary\nexit\n"); err != nil {
		t.Fatal(err)
	}
	out := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(term.PTY)
		out <- string(b)
	}()
	select {
	case got := <-out:
		if !strings.Contains(got, "crossed-the-boundary") {
			t.Errorf("shell output missing from the passed descriptor: %q", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no output from the passed descriptor")
	}
}

// A compromised fwd asking for an account the appliance does not permit must be
// refused by the privileged side, and no process may be created.
func TestShellAccountPolicyEnforcedAcrossTheBoundary(t *testing.T) {
	c := newShellPair(t, &ptyspawn.Spawner{AllowedUsers: []string{"nobody"}, MaxSessions: 1})

	_, err := c.OpenShell(ptyspawn.Request{User: "root", Shell: "/bin/sh"})
	if err == nil {
		t.Fatal("the privileged side granted a terminal as root")
	}
	if !strings.Contains(err.Error(), "not among the accounts") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// With no spawner configured the feature does not exist, whatever fwd asks.
func TestShellRefusedWhenNotEnabled(t *testing.T) {
	c := newShellPair(t, nil)
	if _, err := c.OpenShell(ptyspawn.Request{Shell: "/bin/sh"}); err == nil ||
		!strings.Contains(err.Error(), "not enabled") {
		t.Errorf("terminal served with no spawner configured: %v", err)
	}
}

// The session's lifetime is tied to the connection: when the holder goes away,
// the privileged side hangs up and reaps. A terminal must not be able to
// outlive the fwd process that asked for it.
func TestClosingTheTerminalEndsTheShell(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	spawner := &ptyspawn.Spawner{MaxSessions: 1}
	c := newShellPair(t, spawner)

	term, err := c.OpenShell(ptyspawn.Request{Shell: "/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	pid := term.Pid
	if err := term.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The slot is the observable: the privileged side only releases it after
	// reaping, so a freed slot means the process is genuinely gone.
	deadline := time.Now().Add(15 * time.Second)
	for {
		next, err := c.OpenShell(ptyspawn.Request{Shell: "/bin/sh"})
		if err == nil {
			next.Close()
			return // slot was released: the first shell was reaped
		}
		if time.Now().After(deadline) {
			t.Fatalf("shell pid %d was never reaped after the terminal closed: %v", pid, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
