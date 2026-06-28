//go:build pcap

package main

// libpcap capture backend (design §6, build phase 3). Compiled only with
// `-tags pcap` in the OS image pipeline, where libpcap is present. It opens each
// capture device, parses link/IP/transport headers into Packet, and feeds the
// engine. Kept behind a tag so the rest of the helper builds and tests on a dev
// box without the C dependency.
//
// SKELETON: the cgo binding and header parsing are implemented in the image
// build, not on the dev box. The signature and contract are fixed here so main
// and the engine compile against the same Source in every build.

// #cgo LDFLAGS: -lpcap
// #include <pcap.h>
import "C"

import "fmt"

func newSource(devices []string) (Source, error) {
	// TODO(image-build): for each device, pcap_open_live, set a BPF that skips
	// the appliance's own management traffic, then in a goroutine pcap_next_ex
	// → parse Ethernet/IP/TCP|UDP → Packet → channel. Close tears down handles.
	return nil, fmt.Errorf("pcap source not yet implemented")
}
