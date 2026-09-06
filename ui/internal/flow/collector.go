package flow

import (
	"context"
	"log"
	"net"
	"time"
)

// DefaultAddr is the localhost UDP endpoint the collector listens on and that
// pflow(4) is rendered to export to (render.Pflow). Localhost-only: the flow
// export never leaves the box.
const DefaultAddr = "127.0.0.1:9996"

// RollupInterval is how often raw flows are folded into the rollups. A minute
// matches the finest bucket width, so a freshly closed minute bucket is
// complete within one interval.
const RollupInterval = time.Minute

// maxDatagram bounds a single read. IPFIX/NetFlow export datagrams are small
// (well under an MTU-sized payload); 64 KiB is the UDP ceiling and ample.
const maxDatagram = 65535

// Collector listens for pflow's IPFIX/NetFlow export on a localhost UDP port,
// decodes each datagram into flow records, and writes them to the store. A
// companion ticker folds raw flows into the rollups. It runs in-process as a
// goroutine in fwd, mirroring the traffic sampler; on a dev box nothing exports
// to it, so the store simply stays empty (as the logs collector does off
// FreeBSD).
type Collector struct {
	store *Store
	dec   *Decoder
	addr  string
	cache *LabelCache // app labels from the ndpi-helper; nil disables enrichment
}

func NewCollector(store *Store, addr string) *Collector {
	if addr == "" {
		addr = DefaultAddr
	}
	return &Collector{store: store, dec: NewDecoder(), addr: addr}
}

// WithLabels enables app-layer enrichment: flows are stamped from cache at
// insert (design §5, path 1). The same cache is fed by a LabelServer.
func (c *Collector) WithLabels(cache *LabelCache) *Collector {
	c.cache = cache
	return c
}

// Run binds the UDP listener and serves until ctx is cancelled. It returns the
// bind error if the socket can't be opened; read and decode errors are logged
// and skipped so one bad datagram never stops collection.
func (c *Collector) Run(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", c.addr)
	if err != nil {
		return err
	}
	defer pc.Close()
	log.Printf("flow: collector listening on udp/%s", c.addr)

	// Closing the socket on cancellation unblocks the read loop; the deadline
	// is a backstop so a wedged read can't pin the goroutine past shutdown.
	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	go c.rollupLoop(ctx)

	buf := make([]byte, maxDatagram)
	for {
		if ctx.Err() != nil {
			return nil
		}
		pc.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("flow: read: %v", err)
			continue
		}
		c.ingest(buf[:n])
	}
}

// ingest decodes one datagram and stores the flows it carried, dropping records
// without a usable src/dst pair (e.g. options-template data or partial reads).
func (c *Collector) ingest(pkt []byte) {
	recs, err := c.dec.Decode(pkt)
	if err != nil {
		log.Printf("flow: decode: %v", err)
		return
	}
	// Arrival time is the flow's timestamp: pflow exports at pf state teardown,
	// so a long flow is charged to the minute it ended, not the minutes it ran
	// (see the flows.ts comment in store.go — the IPFIX flowStart/End IEs are
	// present but can't be used for bucketing as the schema stands).
	now := time.Now()
	out := recs[:0]
	for _, r := range recs {
		if !r.Src.IsValid() || !r.Dst.IsValid() {
			continue
		}
		// Stamp the app label if the helper already classified this flow (the
		// common ordering — classify at flow start, export at flow expiry).
		if c.cache != nil {
			if app, ok := c.cache.appFor(r, now); ok {
				r.App = app
			}
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return
	}
	if err := c.store.Insert(now, out); err != nil {
		log.Printf("flow: insert: %v", err)
	}
}

func (c *Collector) rollupLoop(ctx context.Context) {
	t := time.NewTicker(RollupInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := c.store.Rollup(now); err != nil {
				log.Printf("flow: rollup: %v", err)
			}
		}
	}
}
