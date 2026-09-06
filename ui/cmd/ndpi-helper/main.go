// Command ndpi-helper performs deep-packet inspection on the flow head and
// streams {5-tuple → app} enrichment to the fwd flow collector over a unix
// socket (docs/ndpi-helper-design.md). It is a separate process so that libnDPI
// (LGPL) and libpcap link here, never into the GPL-clean fwd binary (plan.md
// §8).
//
// It is its own service (os/rc.d/ndpi-helper), not a child of fwd. Two reasons,
// and the second is the load-bearing one: fwd runs unprivileged after the
// privilege split and so cannot fork anything as another account, and this
// process should not be root for longer than it takes to open the capture
// devices. With -user it opens bpf as root and then drops irreversibly
// (docs/security-plan.md SEC-2a) — which matters because libnDPI is a large C
// parser aimed at raw frames off the WAN, and is the most likely thing on the
// appliance to be exploitable.
//
// Build tags select the capture and classification backends:
//   - default: no capture (idle) + stub port-based classifier — builds and runs
//     anywhere, used for dev and protocol testing.
//   - -tags pcap: libpcap capture.
//   - -tags ndpi: libnDPI classification.
//
// The OS image builds with `-tags "pcap ndpi"`.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	socket := flag.String("socket", "/var/run/fw-ndpi.sock", "collector unix socket to stream labels to")
	devs := flag.String("devices", "", "comma-separated capture devices (with -tags pcap)")
	runAs := flag.String("user", "", "drop to this account once capture is open (recommended: _fwdpcap)")
	flag.Parse()

	log.SetPrefix("ndpi-helper: ")

	var devices []string
	for _, d := range strings.Split(*devs, ",") {
		if d = strings.TrimSpace(d); d != "" {
			devices = append(devices, d)
		}
	}

	// Open what needs privilege first — the bpf devices. That is the only
	// thing here that does.
	src, err := newSource(devices)
	if err != nil {
		log.Fatalf("capture source: %v", err)
	}
	defer src.Close()

	// The sink does not connect yet: it dials lazily on the first label, and
	// redials under backoff, which is what lets this service start before fwd
	// has bound the socket. That means it connects *after* the drop below, as
	// the unprivileged account — which is precisely why the label socket is
	// group-owned by that account at mode 0660 rather than being 0600 inside
	// fwd's 0700 state directory (docs/security-plan.md §3.5 step 5).
	sink := newSocketSink(*socket)
	defer sink.Close()

	// Then give the privilege up, before a single packet is parsed. Every
	// failure here is fatal: a root packet parser is not an acceptable
	// degraded mode, so there is no path that carries on with more privilege
	// than was asked for.
	if *runAs != "" {
		name, err := dropPrivilege(*runAs)
		if err != nil {
			log.Fatalf("dropping privilege: %v", err)
		}
		log.Printf("running as %s (uid %d)", name, os.Getuid())
	} else if os.Geteuid() == 0 {
		log.Printf("WARNING: running as root; pass -user to drop privilege after capture is open")
	}

	eng := NewEngine(src, newClassifier(), sink)
	log.Printf("streaming labels to %s", *socket)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := eng.Run(ctx); err != nil {
		log.Fatalf("engine: %v", err)
	}
}
