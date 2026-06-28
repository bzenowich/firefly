package flow

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// labelTTL bounds how long a cached app label is held waiting for its pflow
// flow to be exported and inserted. nDPI classifies at flow start; pflow
// exports at flow expiry — minutes later at most under the active timeout — so
// a few minutes covers the gap with margin.
const labelTTL = 5 * time.Minute

// evictInterval throttles cache sweeps: expired entries are reaped at most this
// often, on Put, rather than scanning the map on every label.
const evictInterval = time.Minute

// LabelCache holds recent app labels keyed by the direction-normalized 5-tuple,
// so the collector can stamp the app onto a matching pflow flow at insert time
// (design §5, path 1). Bounded by TTL, not count — home/SMB flow rates keep it
// small. Safe for concurrent use: the socket listener writes, the collector's
// ingest path reads.
type LabelCache struct {
	mu        sync.Mutex
	entries   map[key]cacheEntry
	lastEvict time.Time
}

type cacheEntry struct {
	app string
	at  time.Time
}

func NewLabelCache() *LabelCache {
	return &LabelCache{entries: map[key]cacheEntry{}}
}

// Put records a label, then opportunistically reaps expired entries.
func (c *LabelCache) Put(l Label, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[l.key()] = cacheEntry{app: l.App, at: now}
	if now.Sub(c.lastEvict) >= evictInterval {
		c.lastEvict = now
		for k, e := range c.entries {
			if now.Sub(e.at) > labelTTL {
				delete(c.entries, k)
			}
		}
	}
}

// lookup returns the cached app for a flow's normalized key, honoring the TTL.
func (c *LabelCache) lookup(k key, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || now.Sub(e.at) > labelTTL {
		return "", false
	}
	return e.app, true
}

// appFor returns the cached app label for a flow record, if any.
func (c *LabelCache) appFor(r Record, now time.Time) (string, bool) {
	return c.lookup(normKey(r.Src, r.SPort, r.Dst, r.DPort, r.Proto), now)
}

// LabelServer listens on a unix socket for the ndpi-helper's NDJSON label
// stream (design §3). Each label is written to the cache (for stamp-at-insert)
// and backfilled onto recent raw flows (for the late-label race). fwd owns the
// helper process; this is the receiving end.
type LabelServer struct {
	path  string
	cache *LabelCache
	store *Store
}

func NewLabelServer(path string, cache *LabelCache, store *Store) *LabelServer {
	return &LabelServer{path: path, cache: cache, store: store}
}

// Run binds the unix socket and serves helper connections until ctx is
// cancelled. A stale socket file from a previous run is removed first. Only one
// helper connects at a time, but connections are handled in goroutines so a
// reconnect is never blocked.
func (s *LabelServer) Run(ctx context.Context) error {
	// Remove a leftover socket; bind would fail with EADDRINUSE otherwise.
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	defer ln.Close()
	// Helper runs as the same service user; 0600 keeps other users off the
	// socket. Best-effort — bind already succeeded.
	_ = os.Chmod(s.path, 0o600)
	log.Printf("flow: label server listening on %s", s.path)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("flow: label accept: %v", err)
			continue
		}
		go s.handle(conn)
	}
}

func (s *LabelServer) handle(conn net.Conn) {
	defer conn.Close()
	err := ReadLabels(conn, func(l Label) error {
		now := time.Now()
		s.cache.Put(l, now)
		if err := s.store.BackfillApp(now, l); err != nil {
			log.Printf("flow: backfill app: %v", err)
		}
		return nil
	})
	if err != nil {
		log.Printf("flow: label stream: %v", err)
	}
}
