package main

import (
	"net"
	"sync"
	"time"

	"firewall/ui/internal/flow"
)

// socketSink streams labels to the collector's unix socket as NDJSON (design
// §3). It dials lazily and reconnects with backoff: the collector (fwd) may
// start after the helper, or restart under it, and a dropped socket must never
// crash the helper. Labels emitted while disconnected are dropped — they are
// best-effort enrichment, and the flow will be reclassified if it recurs.
type socketSink struct {
	path string

	mu       sync.Mutex
	conn     net.Conn
	backoff  time.Duration
	lastDial time.Time
}

const (
	minBackoff = 200 * time.Millisecond
	maxBackoff = 5 * time.Second
	// writeTimeout bounds a single label write. The engine is single-goroutine
	// and calls Emit inline, so a collector that accepted the connection and
	// then stopped reading (a stalled SQLite write, a hung fwd) would otherwise
	// fill the socket buffer and block the classifier forever — capture keeps
	// running and the packet channel silently overflows. A short deadline turns
	// that into a dropped label and a redial instead.
	writeTimeout = 2 * time.Second
)

func newSocketSink(path string) *socketSink {
	return &socketSink{path: path, backoff: minBackoff}
}

// Emit writes one label, dialing if needed. A write error — including the
// deadline expiring on a collector that stopped reading — drops the connection
// so the next Emit redials; the label itself is lost (best-effort).
func (s *socketSink) Emit(l flow.Label) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if !s.dialLocked() {
			return nil // still backing off; drop this label
		}
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		s.dropLocked()
		return err
	}
	if err := flow.WriteLabel(s.conn, l); err != nil {
		s.dropLocked()
		return err
	}
	return nil
}

// dropLocked tears down a connection that failed a write, so the next Emit
// redials (under backoff). Caller holds s.mu.
func (s *socketSink) dropLocked() {
	s.conn.Close()
	s.conn = nil
}

// dialLocked attempts a connection, honoring backoff so a down collector can't
// turn every Emit into a blocking dial. Returns whether a live connection is
// available. Caller holds s.mu.
func (s *socketSink) dialLocked() bool {
	now := time.Now()
	if !s.lastDial.IsZero() && now.Sub(s.lastDial) < s.backoff {
		return false // within the backoff window; don't redial yet
	}
	s.lastDial = now
	conn, err := net.DialTimeout("unix", s.path, time.Second)
	if err != nil {
		if s.backoff < maxBackoff {
			s.backoff *= 2
		}
		return false
	}
	s.conn = conn
	s.backoff = minBackoff
	return true
}

func (s *socketSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
