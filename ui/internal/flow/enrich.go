package flow

import (
	"context"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"firewall/ui/internal/peercred"
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

// Put records a label, then opportunistically reaps expired entries. It reports
// whether the label is news — a flow not cached (or cached but expired), or one
// whose app changed. The helper re-emits every live flow's label every couple of
// minutes (labelRefresh) purely to keep this cache warm; those repeats carry no
// new information, so the caller skips the raw-table backfill for them.
func (c *LabelCache) Put(l Label, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := l.key()
	prev, had := c.entries[k]
	fresh := had && now.Sub(prev.at) <= labelTTL && prev.app == l.App
	c.entries[k] = cacheEntry{app: l.App, at: now}
	if now.Sub(c.lastEvict) >= evictInterval {
		c.lastEvict = now
		for k, e := range c.entries {
			if now.Sub(e.at) > labelTTL {
				delete(c.entries, k)
			}
		}
	}
	return !fresh
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

// backfillDepth bounds the queue of pending backfills. The socket read loop
// hands new labels to it and never waits: a full queue drops the backfill (the
// label is still cached, so the flow is stamped at insert — only the late-label
// correction of rows already written is lost). Deep enough to ride out a slow
// SQLite write or a checkpoint, small enough that a wedged writer can't grow it
// into a memory problem.
const backfillDepth = 512

// backfillReport throttles the dropped-backfill log line to one per interval.
const backfillReport = time.Minute

// LabelServer listens on a unix socket for the ndpi-helper's NDJSON label
// stream (design §3). Each label is written to the cache (for stamp-at-insert)
// and queued for backfill onto recent raw flows (for the late-label race). fwd
// owns the helper process; this is the receiving end.
//
// The backfill is deliberately off the read loop: a SQLite UPDATE that stalls
// would otherwise stop reading the socket, fill the socket buffer, and block the
// helper's Emit — stalling the classifier engine itself, which is the one thing
// in the pipeline that must keep up with the wire.
type LabelServer struct {
	path  string
	cache *LabelCache
	store *Store

	// group, when set, owns the socket alongside us at mode 0660. After the
	// privilege split the classifier runs as its own account (_fwdpcap), so
	// 0600 would shut out the only thing meant to connect
	// (docs/security-plan.md §3.5 step 5). Empty keeps the socket private to
	// us at 0600.
	group string
	// allowUID, when non-empty, is the set of uids permitted to connect. What
	// arrives on this socket is stamped onto flow records and shown to the
	// admin, so it is worth knowing who wrote it: socket permissions are the
	// primary control and this is the second (docs/security-plan.md SEC-14).
	allowUID map[uint32]bool

	backfill chan Label
	dropped  atomic.Uint64
}

func NewLabelServer(path string, cache *LabelCache, store *Store) *LabelServer {
	return &LabelServer{
		path:     path,
		cache:    cache,
		store:    store,
		backfill: make(chan Label, backfillDepth),
	}
}

// WithPeer restricts the socket to one account: the socket is group-owned by it
// at mode 0660, and connections from any other uid are refused. Our own uid is
// always permitted.
func (s *LabelServer) WithPeer(name string) *LabelServer {
	s.group = name
	u, err := user.Lookup(name)
	if err != nil {
		log.Printf("flow: label peer %q: %v; leaving the socket private", name, err)
		s.group = ""
		return s
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		log.Printf("flow: label peer %q: unusable uid %q", name, u.Uid)
		s.group = ""
		return s
	}
	s.allowUID = map[uint32]bool{uint32(uid): true, uint32(os.Getuid()): true}
	return s
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
	mode := os.FileMode(0o600)
	if s.group != "" {
		if g, err := user.LookupGroup(s.group); err == nil {
			if gid, err := strconv.Atoi(g.Gid); err == nil {
				if err := os.Chown(s.path, os.Getuid(), gid); err == nil {
					mode = 0o660
				} else {
					log.Printf("flow: label socket group %s: %v; staying private", s.group, err)
				}
			}
		} else {
			log.Printf("flow: label socket group %s: %v; staying private", s.group, err)
		}
	}
	// Set the mode explicitly rather than relying on the process umask, which
	// is inherited from whatever started us.
	if err := os.Chmod(s.path, mode); err != nil {
		log.Printf("flow: label socket mode: %v", err)
	}
	log.Printf("flow: label server listening on %s (mode %04o)", s.path, mode)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go s.backfillLoop(ctx)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("flow: label accept: %v", err)
			continue
		}
		if !s.permit(conn) {
			conn.Close()
			continue
		}
		go s.handle(conn)
	}
}

// permit applies the peer-uid allowlist. With no allowlist configured every
// connection is accepted and socket permissions are the only control, which is
// the pre-split behaviour.
func (s *LabelServer) permit(conn net.Conn) bool {
	if len(s.allowUID) == 0 {
		return true
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	uid, err := peercred.UID(uc)
	if err != nil {
		log.Printf("flow: refusing a label connection whose peer could not be identified: %v", err)
		return false
	}
	if !s.allowUID[uid] {
		log.Printf("flow: refusing a label connection from uid %d", uid)
		return false
	}
	return true
}

func (s *LabelServer) handle(conn net.Conn) {
	defer conn.Close()
	err := ReadLabels(conn, func(l Label) error {
		// Cache first (cheap, in-memory, and what stamp-at-insert reads), then
		// queue the backfill — but only when the label is new information, so a
		// long-lived flow's every-2-minute refresh doesn't re-run the same
		// UPDATE over the whole raw window.
		if s.cache.Put(l, time.Now()) {
			select {
			case s.backfill <- l:
			default:
				s.dropped.Add(1)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("flow: label stream: %v", err)
	}
}

// backfillLoop applies queued backfills on its own goroutine until ctx is
// cancelled, and periodically reports drops (invisible otherwise).
func (s *LabelServer) backfillLoop(ctx context.Context) {
	report := time.NewTicker(backfillReport)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case l := <-s.backfill:
			if err := s.store.BackfillApp(time.Now(), l); err != nil {
				log.Printf("flow: backfill app: %v", err)
			}
		case <-report.C:
			if n := s.dropped.Swap(0); n > 0 {
				log.Printf("flow: backfill queue full, dropped %d label backfills", n)
			}
		}
	}
}
