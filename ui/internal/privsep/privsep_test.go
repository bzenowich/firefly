package privsep

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall/ui/internal/config"
)

// fakeOps stands in for apply.Manager on the privileged side.
type fakeOps struct {
	mu       sync.Mutex
	calls    []string
	applied  []config.Config
	err      error
	deadline time.Time
	block    chan struct{} // when non-nil, Apply waits on it
}

func (f *fakeOps) Apply(cfg config.Config) error {
	f.mu.Lock()
	f.calls = append(f.calls, "Apply")
	f.applied = append(f.applied, cfg)
	block, err := f.block, f.err
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	return err
}

func (f *fakeOps) Confirm() error  { return f.record("Confirm") }
func (f *fakeOps) Rollback() error { return f.record("Rollback") }

func (f *fakeOps) record(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	return f.err
}

func (f *fakeOps) Pending() (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Pending")
	return f.deadline, !f.deadline.IsZero()
}

func (f *fakeOps) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// newPair starts a Service on a temp socket and returns a Client for it.
func newPair(t *testing.T) (*Client, *fakeOps) {
	t.Helper()
	ops := &fakeOps{}
	// Allow this process's own uid, which is what the appliance does for the
	// _fwd account via fwd-helper's -peer-user flag.
	svc := NewService(ops, []uint32{uint32(os.Geteuid())})
	svc.logf = func(string, ...any) {} // refusals are asserted, not printed

	// t.TempDir() can be long; unix socket paths are capped near 104 bytes.
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

	return NewClient(path), ops
}

func TestRoundTrip(t *testing.T) {
	c, ops := newPair(t)

	cfg := config.Default()
	cfg.System.Hostname = "over-the-wire"
	if err := c.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := c.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := c.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	ops.mu.Lock()
	got := ops.applied
	ops.mu.Unlock()
	if len(got) != 1 || got[0].System.Hostname != "over-the-wire" {
		t.Fatalf("config did not survive the round trip: %+v", got)
	}
	if want := []string{"Apply", "Confirm", "Rollback"}; !equal(ops.seen(), want) {
		t.Errorf("calls = %v, want %v", ops.seen(), want)
	}
}

func TestPendingRoundTrip(t *testing.T) {
	c, ops := newPair(t)
	if _, pending := c.Pending(); pending {
		t.Error("reported pending with none set")
	}
	ops.deadline = time.Now().Add(time.Minute).Round(time.Millisecond)
	deadline, pending := c.Pending()
	if !pending || !deadline.Equal(ops.deadline) {
		t.Errorf("Pending = %v,%v; want %v,true", deadline, pending, ops.deadline)
	}
}

// The privileged side's diagnostics are all the admin will ever see of pfctl,
// so they must survive the crossing verbatim.
func TestDiagnosticsCrossTheBoundary(t *testing.T) {
	c, ops := newPair(t)
	ops.err = errors.New("/etc/pf.conf:12: syntax error near 'pss'")
	err := c.Apply(config.Default())
	if err == nil || !strings.Contains(err.Error(), "syntax error near 'pss'") {
		t.Errorf("diagnostics lost: %v", err)
	}
}

// The whole point of the split: a document the privileged side would not have
// accepted itself must be refused there, whatever the sender thought.
func TestServiceRevalidatesTheConfig(t *testing.T) {
	c, ops := newPair(t)

	bad := config.Default()
	for i := range bad.Interfaces {
		if bad.Interfaces[i].Role == "lan" {
			bad.Interfaces[i].Device = "igc1; touch /tmp/pwned"
		}
	}
	err := c.Apply(bad)
	if err == nil || !strings.Contains(err.Error(), "refusing an invalid configuration") {
		t.Fatalf("privileged side accepted an invalid document: %v", err)
	}
	if len(ops.seen()) != 0 {
		t.Errorf("invalid document reached the operations: %v", ops.seen())
	}
}

func TestUnknownVerbAndVersionRefused(t *testing.T) {
	c, ops := newPair(t)

	if _, err := c.exchange(request{Verb: "reboot"}, time.Second); err == nil ||
		!strings.Contains(err.Error(), `unknown verb "reboot"`) {
		t.Errorf("unknown verb: %v", err)
	}
	// A version mismatch must be refused, not guessed at.
	conn, err := c.dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeFrame(conn, request{Version: ProtocolVersion + 1, Verb: VerbConfirm}); err != nil {
		t.Fatal(err)
	}
	var resp response
	if err := readFrame(conn, &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Error, "not supported") {
		t.Errorf("version mismatch accepted: %+v", resp)
	}
	if len(ops.seen()) != 0 {
		t.Errorf("refused requests still reached the operations: %v", ops.seen())
	}
}

// An oversized frame must be refused from its header, before anything is
// allocated for it.
func TestOversizedFrameRefused(t *testing.T) {
	c, _ := newPair(t)
	conn, err := c.dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Announce a gigabyte and send nothing.
	if _, err := conn.Write([]byte{0x40, 0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	var resp response
	if err := readFrame(conn, &resp); err != nil {
		t.Fatalf("no reply to an oversized frame: %v", err)
	}
	if !strings.Contains(resp.Error, "over the") {
		t.Errorf("oversized frame not refused: %+v", resp)
	}
}

// Pending is called on every page render; it must answer while an apply is
// still reloading services, or the confirm button is unreachable during the
// apply it exists to confirm.
func TestPendingAnswersDuringApply(t *testing.T) {
	c, ops := newPair(t)
	ops.block = make(chan struct{})
	ops.deadline = time.Now().Add(time.Minute)

	applyDone := make(chan error, 1)
	go func() { applyDone <- c.Apply(config.Default()) }()

	// Wait for the apply to be in flight.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(ops.seen()) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("apply never started")
		}
		time.Sleep(5 * time.Millisecond)
	}

	answered := make(chan bool, 1)
	go func() { _, p := c.Pending(); answered <- p }()
	select {
	case p := <-answered:
		if !p {
			t.Error("Pending answered but reported nothing pending")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Pending blocked behind a running apply")
	}

	close(ops.block)
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
}

// The owner policy is unit-tested directly: creating a socket owned by a third
// uid needs privileges a test does not have, and the policy is the part worth
// pinning down anyway.
func TestAllowedSocketOwner(t *testing.T) {
	const self = 1000
	cases := []struct {
		owner uint32
		want  bool
		why   string
	}{
		{0, true, "root: who the real helper runs as"},
		{self, true, "ourselves: already has everything we have"},
		{1234, false, "a third party: the impersonation this stops"},
		{65534, false, "nobody: still a third party"},
	}
	for _, c := range cases {
		if got := allowedSocketOwner(c.owner, self); got != c.want {
			t.Errorf("allowedSocketOwner(%d, %d) = %v, want %v (%s)", c.owner, self, got, c.want, c.why)
		}
	}
	// A root process accepts only root's socket: "ourselves" and "root"
	// coincide, and nothing else is admitted.
	if allowedSocketOwner(1000, 0) {
		t.Error("a root client accepted a socket owned by an ordinary user")
	}
}

// fwd must not hand the config document — which carries every secret on the
// appliance — to something that is not the helper.
func TestClientRefusesMissingAndNonSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "privsep")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	missing := NewClient(filepath.Join(dir, "absent.sock"))
	if err := missing.Apply(config.Default()); err == nil ||
		!strings.Contains(err.Error(), "fwd-helper") {
		t.Errorf("absent socket: %v", err)
	}

	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewClient(regular).Apply(config.Default()); err == nil ||
		!strings.Contains(err.Error(), "not a socket") {
		t.Errorf("regular file: %v", err)
	}
}

func TestServiceRefusesDisallowedUID(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: root is always allowed, so there is no refusal to observe")
	}
	ops := &fakeOps{}
	// Allow only uid 0, so this test process (not root) is refused.
	svc := NewService(ops, nil)
	var refusals []string
	var mu sync.Mutex
	svc.logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		refusals = append(refusals, f)
	}

	dir, err := os.MkdirTemp("", "privsep")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := svc.Listen(path, 0o666, -1) // permissive mode: the uid check is what must hold
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); svc.Serve(ctx, ln) }()
	defer func() { cancel(); <-done }()

	if err := NewClient(path).Apply(config.Default()); err == nil {
		t.Error("a disallowed uid was served")
	}
	if len(ops.seen()) != 0 {
		t.Errorf("a disallowed uid reached the operations: %v", ops.seen())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(refusals) == 0 || !strings.Contains(refusals[0], "refusing a connection from uid") {
		t.Errorf("refusal not logged: %v", refusals)
	}
}

func TestListenSetsModeAndReplacesStaleSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "privsep")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")

	// A stale file from an unclean shutdown must not block startup.
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := NewService(&fakeOps{}, nil)
	ln, err := svc.Listen(path, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Error("stale file was not replaced by a socket")
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %04o, want 0600", perm)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Pending runs on every page render and on the dashboard's 2-second poll, so an
// unthrottled "helper is down" log writes a line twice a second per open tab —
// enough to bury the audit trail and roll /var/log.
func TestUnreachableLogIsThrottled(t *testing.T) {
	dir, err := os.MkdirTemp("", "privsep")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	var lines []string
	restore := log.Writer()
	log.SetOutput(writerFunc(func(b []byte) (int, error) {
		lines = append(lines, string(b))
		return len(b), nil
	}))
	t.Cleanup(func() { log.SetOutput(restore) })

	c := NewClient(filepath.Join(dir, "absent.sock"))
	for i := 0; i < 50; i++ {
		if _, pending := c.Pending(); pending {
			t.Fatal("reported an apply pending while unreachable")
		}
	}
	if len(lines) != 1 {
		t.Errorf("50 polls with the helper down produced %d log lines, want 1", len(lines))
	}

	// Recovery is logged once, so the log says when the gap ended.
	ops := &fakeOps{}
	svc := NewService(ops, []uint32{uint32(os.Geteuid())})
	svc.logf = func(string, ...any) {}
	path := filepath.Join(dir, "up.sock")
	ln, err := svc.Listen(path, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); svc.Serve(ctx, ln) }()
	defer func() { cancel(); <-done }()

	up := NewClient(path)
	up.down = true // as if it had been failing
	up.Pending()
	up.Pending()
	if got := len(lines); got != 2 {
		t.Errorf("recovery produced %d total lines, want 2 (one down, one back up)", got)
	}
	if !strings.Contains(lines[len(lines)-1], "reachable again") {
		t.Errorf("recovery not logged: %q", lines[len(lines)-1])
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
