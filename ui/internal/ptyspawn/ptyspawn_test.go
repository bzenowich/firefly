package ptyspawn

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// The account policy is the point of this package: fwd names an account, the
// privileged side decides. A compromised fwd asking for root must be refused
// by the allowlist, not by anything fwd itself applies.
func TestAccountPolicy(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		ask     string
		wantErr bool
	}{
		{"nil allowlist trusts the request (pre-split)", nil, "root", false},
		{"empty allowlist refuses everything", []string{}, "nobody", true},
		{"an allowed account passes", []string{"nobody"}, "nobody", false},
		{"root is refused unless the operator listed it", []string{"nobody"}, "root", true},
		{"root passes when the operator listed it", []string{"nobody", "root"}, "root", false},
		{"the default account is what an empty request means", []string{DefaultUser}, "", false},
		{"the default is refused if not listed", []string{"someoneelse"}, "", true},
	}
	for _, c := range cases {
		s := &Spawner{AllowedUsers: c.allowed}
		ask := c.ask
		if ask == "" {
			ask = DefaultUser
		}
		err := s.permit(ask)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: permit(%q) = %v, wantErr %v", c.name, ask, err, c.wantErr)
		}
		if err != nil && !errors.Is(err, ErrShellNotPermitted) {
			t.Errorf("%s: refusal should be ErrShellNotPermitted, got %v", c.name, err)
		}
	}
}

// The shell binary is a second closed set. Neither fwd nor a restored backup
// may name something outside it.
func TestShellBinaryPolicy(t *testing.T) {
	s := &Spawner{}
	for _, bad := range []string{"/usr/bin/su", "sh", "/bin/sh -c id", "../../bin/sh", "/bin/sh\x00"} {
		if _, err := s.Open(Request{Shell: bad}); err == nil {
			t.Errorf("Open accepted shell %q", bad)
		} else if !strings.Contains(err.Error(), "permitted login shells") {
			t.Errorf("shell %q refused for the wrong reason: %v", bad, err)
		}
	}
}

func TestOpenRunsAShell(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: this test asserts the unprivileged inherit path")
	}
	s := &Spawner{MaxSessions: 2}
	sess, err := s.Open(Request{Shell: "/bin/sh", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Wait()

	if _, err := io.WriteString(sess.PTY, "echo hello-from-pty\nexit\n"); err != nil {
		t.Fatal(err)
	}
	out := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(sess.PTY)
		out <- string(b)
	}()
	select {
	case got := <-out:
		if !strings.Contains(got, "hello-from-pty") {
			t.Errorf("shell output missing: %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shell produced no output")
	}
	if sess.Pid <= 0 {
		t.Error("no pid recorded")
	}
	if sess.RunAs == "" {
		t.Error("no account recorded for the audit line")
	}
}

// The privileged side bounds the number of processes on the box. The
// unprivileged side has its own cap, but a compromised fwd would not apply it.
func TestSessionCapIsEnforcedHere(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	s := &Spawner{MaxSessions: 1}
	first, err := s.Open(Request{Shell: "/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(Request{Shell: "/bin/sh"}); err == nil {
		t.Error("second session opened past the cap")
	} else if !strings.Contains(err.Error(), "too many terminal sessions") {
		t.Errorf("wrong refusal: %v", err)
	}
	// A finished session frees its slot.
	first.Hangup()
	first.Wait()
	second, err := s.Open(Request{Shell: "/bin/sh"})
	if err != nil {
		t.Fatalf("slot not released after the first session ended: %v", err)
	}
	second.Hangup()
	second.Wait()
}

// A refused request must not consume a slot, or a few refusals would wedge the
// feature until restart.
func TestRefusedRequestsDoNotLeakSlots(t *testing.T) {
	s := &Spawner{AllowedUsers: []string{"nobody"}, MaxSessions: 1}
	for i := 0; i < 5; i++ {
		if _, err := s.Open(Request{User: "root", Shell: "/bin/sh"}); err == nil {
			t.Fatal("policy did not refuse")
		}
	}
	s.mu.Lock()
	live := s.live
	s.mu.Unlock()
	if live != 0 {
		t.Errorf("%d slots leaked by refused requests", live)
	}
}

func TestHangupEndsTheSession(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	s := &Spawner{}
	sess, err := s.Open(Request{Shell: "/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() { done <- sess.Wait() }()
	sess.Hangup()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("closing the master did not end the shell")
	}
}
