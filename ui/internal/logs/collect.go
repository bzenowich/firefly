package logs

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"time"
)

// Collector feeds the store from the two appliance sources:
//   - pf: tcpdump decoding the pflog0 capture interface
//   - system: syslogd's flat files via tail -F (survives rotation)
//
// Both are child processes whose stdout we scan — the same approach pfSense
// uses for pflog, and it keeps this package free of pcap parsing.
type Collector struct {
	store *Store
}

func NewCollector(store *Store) *Collector { return &Collector{store: store} }

// Run starts both readers and restarts them with backoff until ctx ends.
func (c *Collector) Run(ctx context.Context) {
	go c.loop(ctx, "pf", []string{"tcpdump", "-l", "-n", "-e", "-q", "-i", "pflog0"})
	go c.loop(ctx, "system", []string{"tail", "-F", "-n", "0", "/var/log/messages"})
}

func (c *Collector) loop(ctx context.Context, source string, argv []string) {
	for ctx.Err() == nil {
		if err := c.runOnce(ctx, source, argv); err != nil && ctx.Err() == nil {
			log.Printf("logs: %s reader: %v (restarting in 5s)", source, err)
		}
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
		}
	}
}

func (c *Collector) runOnce(ctx context.Context, source string, argv []string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			if err := c.store.Insert(source, line, time.Now()); err != nil {
				log.Printf("logs: insert: %v", err)
			}
		}
	}
	return cmd.Wait()
}
