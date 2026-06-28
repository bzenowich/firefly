//go:build !pcap

package main

import "log"

// Without the `pcap` build tag no capture backend is linked, so the helper has
// nothing to sniff. newSource returns a no-op source whose channel never
// delivers: the helper stays up and connected to the collector (useful for
// protocol testing) but classifies nothing. Production images build with
// `-tags pcap` to link the libpcap source (source_pcap.go).
func newSource(devices []string) (Source, error) {
	log.Printf("ndpi-helper: no capture backend compiled in (build with -tags pcap); idle")
	return newChanSource(0), nil
}
