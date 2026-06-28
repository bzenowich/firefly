// Command ndpi-helper performs deep-packet inspection on the flow head and
// streams {5-tuple → app} enrichment to the fwd flow collector over a unix
// socket (docs/ndpi-helper-design.md). It is a separate process so that libnDPI
// (LGPL) and libpcap link here, never into the GPL-clean fwd binary (plan.md
// §8). fwd spawns and supervises it on the appliance.
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
	flag.Parse()

	var devices []string
	for _, d := range strings.Split(*devs, ",") {
		if d = strings.TrimSpace(d); d != "" {
			devices = append(devices, d)
		}
	}

	src, err := newSource(devices)
	if err != nil {
		log.Fatalf("ndpi-helper: capture source: %v", err)
	}
	defer src.Close()

	sink := newSocketSink(*socket)
	defer sink.Close()

	eng := NewEngine(src, newClassifier(), sink)
	log.SetPrefix("ndpi-helper: ")
	log.Printf("streaming labels to %s", *socket)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := eng.Run(ctx); err != nil {
		log.Fatalf("engine: %v", err)
	}
}
