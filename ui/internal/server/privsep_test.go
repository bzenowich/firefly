package server

import (
	"errors"
	"go/build"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall/ui/internal/config"
)

// fakePriv is a second implementation of the privileged boundary
// (internal/privsep). Its whole point is to be nothing like apply.Manager: it
// touches no filesystem and runs no commands. If the server ever reaches past
// the interface for something Manager happens to provide, these tests stop
// compiling — which is the property step 1 of docs/security-plan.md §3.5 is
// meant to establish, ahead of the socket client that will be the real second
// implementation.
type fakePriv struct {
	mu       sync.Mutex
	calls    []string
	applied  []config.Config
	err      error     // returned by Apply/Confirm/Rollback
	deadline time.Time // reported by Pending when non-zero
}

func (f *fakePriv) Apply(cfg config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Apply")
	f.applied = append(f.applied, cfg)
	return f.err
}

func (f *fakePriv) Confirm() error  { return f.record("Confirm") }
func (f *fakePriv) Rollback() error { return f.record("Rollback") }

func (f *fakePriv) record(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	return f.err
}

func (f *fakePriv) Pending() (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadline, !f.deadline.IsZero()
}

func (f *fakePriv) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// newFakePrivServer is newTestServer with the privileged side replaced.
func newFakePrivServer(t *testing.T) (*client, *config.Store, *fakePriv) {
	t.Helper()
	store, err := config.Open(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatal(err)
	}
	priv := &fakePriv{}
	srv, err := New(store, priv, nil, nil, newTestLogStore(t), newTestTrafficStore(t), newTestFlowStore(t))
	if err != nil {
		t.Fatal(err)
	}
	c := &client{srv: srv}
	c.cookie = setup(t, srv)
	c.csrf, _ = srv.sessions.CSRF(c.cookie.Value)
	return c, store, priv
}

// The three apply routes must reach the boundary and nothing else, and must
// hand the admin whatever diagnostics the privileged side produced — across a
// socket those are all that is left of pfctl's parse error.
func TestApplyRoutesGoThroughTheBoundary(t *testing.T) {
	c, store, priv := newFakePrivServer(t)

	if loc := c.post(t, "/system/apply", nil); loc.Query().Get("err") != "" {
		t.Fatalf("apply: %s", loc.Query().Get("err"))
	}
	c.post(t, "/system/apply/confirm", nil)
	c.post(t, "/system/apply/rollback", nil)

	if got := priv.seen(); !slices.Equal(got, []string{"Apply", "Confirm", "Rollback"}) {
		t.Errorf("boundary calls = %v, want [Apply Confirm Rollback]", got)
	}
	// Apply carries the live config document — the only thing that crosses.
	if len(priv.applied) != 1 || priv.applied[0].System.Hostname != store.Get().System.Hostname {
		t.Errorf("Apply did not receive the current config document")
	}

	priv.err = errors.New("/etc/pf.conf:12: syntax error")
	loc := c.post(t, "/system/apply", nil)
	if got := loc.Query().Get("err"); !strings.Contains(got, "syntax error") {
		t.Errorf("privileged diagnostics lost: %q", got)
	}
}

// Pending drives the rollback banner on every page, so it must be read through
// the interface too.
func TestPendingRendersFromTheBoundary(t *testing.T) {
	c, _, priv := newFakePrivServer(t)

	body := c.get(t, "/system").Body.String()
	if strings.Contains(body, "auto-rollback at") {
		t.Error("rollback banner shown with no apply pending")
	}

	priv.deadline = time.Date(2026, 9, 5, 17, 4, 5, 0, time.UTC)
	body = c.get(t, "/system").Body.String()
	if !strings.Contains(body, "auto-rollback at") {
		t.Error("rollback banner missing while an apply is pending")
	}
}

// The seam is only real while the web layer cannot reach the implementation.
// Once fwd-helper exists, an import of internal/apply here would mean the
// privileged code had been linked back into the unprivileged binary
// (docs/security-plan.md §3.5).
func TestServerDoesNotImportApply(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Guard against the check passing vacuously: build.ImportDir reports
	// non-test imports in Imports and the _test.go ones in TestImports, and
	// this package's tests legitimately construct an apply.Manager.
	if len(pkg.Imports) == 0 {
		t.Fatal("no imports resolved; the check would pass vacuously")
	}
	for _, imp := range pkg.Imports {
		if imp == "firewall/ui/internal/apply" {
			t.Errorf("internal/server imports %s; it must depend only on internal/privsep", imp)
		}
	}
}

// A build or deployment with no way to spawn a terminal must refuse cleanly.
// This used to dereference a nil opener and panic the handler mid-upgrade,
// which the browser sees as a socket that opens and instantly dies.
func TestShellRefusedWithNoOpener(t *testing.T) {
	store, err := config.Open(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(store, &fakePriv{}, nil, nil, newTestLogStore(t), newTestTrafficStore(t), newTestFlowStore(t))
	if err != nil {
		t.Fatal(err)
	}
	c := &client{srv: srv}
	c.cookie = setup(t, srv)
	c.csrf, _ = srv.sessions.CSRF(c.cookie.Value)

	if err := store.Update(func(cfg *config.Config) error {
		cfg.Shell.Enabled = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/shell/ws", nil)
	req.AddCookie(c.cookie)
	req.Header.Set("Origin", "https://example.invalid")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req) // must not panic
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
