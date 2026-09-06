package apply

import (
	"io/fs"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"firewall/ui/internal/config"
)

// fakeSys records writes and commands; failCmd makes matching commands fail.
type fakeSys struct {
	mu      sync.Mutex
	files   map[string]string
	cmds    []string
	failCmd string
}

func newFakeSys() *fakeSys { return &fakeSys{files: map[string]string{}} }

func (s *fakeSys) ReadFile(p string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(c), nil
}

func (s *fakeSys) WriteFile(p string, data []byte, _ fs.FileMode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[p] = string(data)
	return nil
}

func (s *fakeSys) Remove(p string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.files, p)
	return nil
}

func (s *fakeSys) Glob(pattern string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for p := range s.files {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *fakeSys) Run(name string, args ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	s.cmds = append(s.cmds, cmd)
	// Substring, not prefix: most reloads are now `sh -c "sysrc …; service …"`
	// so the interesting part is in the middle of the command line.
	if s.failCmd != "" && strings.Contains(cmd, s.failCmd) {
		return &CmdError{Cmd: cmd, Output: "synthetic failure", Err: fs.ErrInvalid}
	}
	return nil
}

func (s *fakeSys) ran(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// order returns -1 when the command matching a came before the one matching b
// (the expected ordering), otherwise the index of the offending b command.
func (s *fakeSys) order(a, b string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	seenA := false
	for i, c := range s.cmds {
		if strings.Contains(c, a) {
			seenA = true
		}
		if strings.Contains(c, b) && !seenA {
			return i
		}
	}
	return -1
}

func (s *fakeSys) get(p string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.files[p]
	return c, ok
}

func TestApplyInstallsValidatesReloads(t *testing.T) {
	sys := newFakeSys()
	m := New(sys, time.Minute)

	if err := m.Apply(config.Default()); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{PFConfPath, KeaConfPath, UnboundConfPath} {
		if _, ok := sys.get(p); !ok {
			t.Errorf("%s not installed", p)
		}
		if _, ok := sys.get(p + ".staged"); ok {
			t.Errorf("%s.staged left behind", p)
		}
	}
	for _, cmd := range []string{
		"pfctl -nf", "kea-dhcp4 -t", "unbound-checkconf", "pfctl -f",
		// Reloads use the one* forms, which work whether or not the rcvar is
		// set, and set the rcvar so the service also comes back after a boot.
		"sysrc kea_enable=YES", "service kea onerestart",
		"sysrc unbound_enable=YES", "service unbound onerestart",
		"sysrc pf_enable=YES pflog_enable=YES",
		// Addressing is applied before pf loads rules that resolve against it.
		"service fwnetwork onerestart",
	} {
		if !sys.ran(cmd) {
			t.Errorf("command %q not run", cmd)
		}
	}
	// Interface addressing must be reloaded before pf reads :network macros.
	if got := sys.order("service fwnetwork onerestart", "pfctl -f"); got >= 0 {
		t.Errorf("pf reloaded before interface addressing (index %d)", got)
	}
	if _, ok := m.Pending(); !ok {
		t.Error("apply must leave a pending window")
	}
}

func TestApplyValidationFailureInstallsNothing(t *testing.T) {
	sys := newFakeSys()
	sys.failCmd = "pfctl -nf"
	m := New(sys, time.Minute)

	err := m.Apply(config.Default())
	if err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("want validation error, got %v", err)
	}
	if _, ok := sys.get(PFConfPath); ok {
		t.Error("pf.conf installed despite failed validation")
	}
	if sys.ran("service") || sys.ran("pfctl -f") {
		t.Error("services reloaded despite failed validation")
	}
	if _, ok := m.Pending(); ok {
		t.Error("failed apply must not leave a pending window")
	}
}

func TestConfirmKeepsFiles(t *testing.T) {
	sys := newFakeSys()
	m := New(sys, 30*time.Millisecond)

	if err := m.Apply(config.Default()); err != nil {
		t.Fatal(err)
	}
	if err := m.Confirm(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond) // window would have expired
	if _, ok := sys.get(PFConfPath); !ok {
		t.Error("confirmed files were rolled back")
	}
	if _, ok := m.Pending(); ok {
		t.Error("pending window survived confirm")
	}
}

func TestWindowExpiryRollsBack(t *testing.T) {
	sys := newFakeSys()
	sys.files[PFConfPath] = "old ruleset"
	m := New(sys, 30*time.Millisecond)

	if err := m.Apply(config.Default()); err != nil {
		t.Fatal(err)
	}
	if got, _ := sys.get(PFConfPath); got == "old ruleset" {
		t.Fatal("apply did not install")
	}

	deadline := time.Now().Add(time.Second)
	for {
		if got, _ := sys.get(PFConfPath); got == "old ruleset" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("window expiry did not restore old pf.conf")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Files absent before apply are removed again on rollback.
	if _, ok := sys.get(KeaConfPath); ok {
		t.Error("rollback kept a file that did not exist before")
	}
}

func TestSecondApplyBlockedWhilePending(t *testing.T) {
	m := New(newFakeSys(), time.Minute)
	if err := m.Apply(config.Default()); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(config.Default()); err == nil || !strings.Contains(err.Error(), "already pending") {
		t.Fatalf("want already-pending error, got %v", err)
	}
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestNoChangesIsAnError(t *testing.T) {
	sys := newFakeSys()
	m := New(sys, 0) // auto-confirm
	if err := m.Apply(config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Pending(); ok {
		t.Error("window 0 must auto-confirm")
	}
	if err := m.Apply(config.Default()); err == nil || !strings.Contains(err.Error(), "no changes") {
		t.Fatalf("want no-changes error, got %v", err)
	}
}

func TestStaleWireGuardFileRemoved(t *testing.T) {
	sys := newFakeSys()
	sys.files[path.Join(WGConfDir, "wg3.conf")] = "stale tunnel"
	m := New(sys, time.Minute)

	if err := m.Apply(config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, ok := sys.get(path.Join(WGConfDir, "wg3.conf")); ok {
		t.Error("stale wg conf not removed")
	}
	if !sys.ran("service wireguard") {
		t.Error("wireguard not restarted after stale removal")
	}
	// With every tunnel gone the rc script must be told so, or it keeps
	// managing interfaces that no longer have configs.
	if !sys.ran("wireguard_interfaces=") {
		t.Error("wireguard_interfaces not updated after stale removal")
	}
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got, _ := sys.get(path.Join(WGConfDir, "wg3.conf")); got != "stale tunnel" {
		t.Error("rollback did not restore removed wg conf")
	}
}

func TestReloadFailureRollsBack(t *testing.T) {
	sys := newFakeSys()
	sys.files[PFConfPath] = "old ruleset"
	sys.failCmd = "pfctl -f"
	m := New(sys, time.Minute)

	err := m.Apply(config.Default())
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("want rolled-back error, got %v", err)
	}
	if got, _ := sys.get(PFConfPath); got != "old ruleset" {
		t.Error("failed reload did not restore old pf.conf")
	}
	if _, ok := m.Pending(); ok {
		t.Error("failed apply must not leave a pending window")
	}
}
