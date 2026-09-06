package flow

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"
)

// The label socket carries data that is stamped onto flow records and shown to
// the admin, and after the privilege split it is shared between two accounts.
// Socket permissions are the primary control; the peer check is the second
// (docs/security-plan.md SEC-14).
func TestLabelServerPeerRestriction(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	dir, err := os.MkdirTemp("", "labelsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "l.sock")

	srv := NewLabelServer(path, NewLabelCache(), nil).WithPeer(u.Username)
	if len(srv.allowUID) == 0 {
		t.Fatal("WithPeer configured no allowlist")
	}
	if !srv.allowUID[uint32(os.Getuid())] {
		t.Error("our own uid must always be permitted")
	}

	// A uid outside the allowlist is refused. permit() is exercised directly
	// because manufacturing a connection from another uid needs privileges a
	// test does not have.
	srv.allowUID = map[uint32]bool{99999: true}

	ln, err := net.Listen("unix", path+".probe")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", path+".probe")
		if err == nil {
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if srv.permit(conn) {
		t.Error("a uid outside the allowlist was permitted")
	}

	// With no allowlist, permissions are the only control — the pre-split
	// behaviour, which must still work.
	srv.allowUID = nil
	if !srv.permit(conn) {
		t.Error("with no allowlist configured every peer should be accepted")
	}
}

// A peer account that does not exist must leave the socket private rather than
// silently opening it up.
func TestLabelServerUnknownPeerStaysPrivate(t *testing.T) {
	srv := NewLabelServer("/tmp/unused.sock", NewLabelCache(), nil).WithPeer("no-such-account-hopefully")
	if srv.group != "" {
		t.Errorf("group left set to %q for an account that does not exist", srv.group)
	}
	if len(srv.allowUID) != 0 {
		t.Error("allowlist configured from an account that does not exist")
	}
}
