//go:build pcap

package main

// libpcap capture backend (design §6, build phase 3). Compiled only with
// `-tags pcap` in the OS image pipeline, where libpcap is present. It opens each
// capture device, sets a BPF that keeps only IP traffic, and runs one goroutine
// per device that copies each captured frame out of libpcap's reused buffer and
// hands it to parseFrame (pure Go, parse.go). The engine never sees raw frames.
//
// The C surface is deliberately tiny: open/compile/set-filter/next/close. All
// header parsing is Go (parse.go), so only capture itself is untestable off the
// appliance.

// #cgo LDFLAGS: -lpcap
// #include <stdlib.h>
// #include <string.h>
// #include <pcap.h>
import "C"

import (
	"fmt"
	"net"
	"sync"
	"unsafe"
)

// snaplen bounds how many bytes of each frame we capture. nDPI reaches a verdict
// from the flow head (TLS ClientHello SNI, HTTP Host, QUIC, protocol
// fingerprints) which lives in the first data packet(s), so a snaplen a little
// over one MTU captures everything the classifier needs while bounding the
// per-packet copy cost — we are not doing byte accounting here (that is pflow's
// job, design §2).
const snaplen = 1600

// captureBPF keeps only IP traffic off the wire. ARP/STP/LLDP and other
// non-IP L2 chatter can't produce a flow label, so filtering them in the kernel
// avoids copying them into userland at all.
const captureBPF = "ip or ip6"

// pcapSource captures from one or more devices into a shared packet channel.
// Each device gets its own libpcap handle and goroutine; all feed e.ch. The
// engine reads e.ch single-threaded.
type pcapSource struct {
	handles []*C.pcap_t
	ch      chan Packet
	closing chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

// chanBuffer absorbs bursts between the capture goroutines and the engine; a
// full channel drops packets (best-effort enrichment, design §3), never blocks
// capture.
const chanBuffer = 4096

func newSource(devices []string) (Source, error) {
	if len(devices) == 0 {
		return nil, fmt.Errorf("no capture devices given")
	}
	s := &pcapSource{
		ch:      make(chan Packet, chanBuffer),
		closing: make(chan struct{}),
	}
	for _, dev := range devices {
		h, lt, err := openDevice(dev)
		if err != nil {
			s.closeHandles()
			return nil, fmt.Errorf("open %s: %w", dev, err)
		}
		s.handles = append(s.handles, h)
		var ifIndex uint32
		if iface, err := net.InterfaceByName(dev); err == nil {
			ifIndex = uint32(iface.Index)
		}
		s.wg.Add(1)
		go s.capture(h, lt, ifIndex)
	}
	return s, nil
}

// openDevice opens a live capture handle on dev, installs the BPF, and resolves
// the datalink to our linkType enum.
func openDevice(dev string) (*C.pcap_t, linkType, error) {
	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))

	errbuf := make([]C.char, C.PCAP_ERRBUF_SIZE)
	// promisc=0: as the gateway we already receive the frames we route, so we
	// don't need promiscuous mode (and it reduces load). to_ms=100 lets
	// pcap_next_ex return periodically so the goroutine can observe closing.
	h := C.pcap_open_live(cdev, C.int(snaplen), 0, 100, &errbuf[0])
	if h == nil {
		return nil, 0, fmt.Errorf("pcap_open_live: %s", C.GoString(&errbuf[0]))
	}

	if err := setFilter(h, captureBPF); err != nil {
		C.pcap_close(h)
		return nil, 0, err
	}

	lt, err := resolveLinkType(C.pcap_datalink(h))
	if err != nil {
		C.pcap_close(h)
		return nil, 0, err
	}
	return h, lt, nil
}

func setFilter(h *C.pcap_t, expr string) error {
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))
	var bpf C.struct_bpf_program
	if C.pcap_compile(h, &bpf, cexpr, 1, C.PCAP_NETMASK_UNKNOWN) != 0 {
		return fmt.Errorf("pcap_compile %q: %s", expr, C.GoString(C.pcap_geterr(h)))
	}
	defer C.pcap_freecode(&bpf)
	if C.pcap_setfilter(h, &bpf) != 0 {
		return fmt.Errorf("pcap_setfilter: %s", C.GoString(C.pcap_geterr(h)))
	}
	return nil
}

// resolveLinkType maps the platform's DLT_* datalink constant onto the stable
// linkType enum parse.go understands. DLT values differ across OSes, so this is
// the one place they are read.
func resolveLinkType(dlt C.int) (linkType, error) {
	switch dlt {
	case C.DLT_EN10MB:
		return linkEthernet, nil
	case C.DLT_RAW:
		return linkRaw, nil
	case C.DLT_NULL, C.DLT_LOOP:
		return linkNull, nil
	}
	return 0, fmt.Errorf("unsupported datalink type %d", int(dlt))
}

// capture pulls frames from one handle until closing is signalled, copying each
// out of libpcap's reused buffer (the bytes are invalid after the next
// pcap_next_ex) and parsing it into a Packet.
func (s *pcapSource) capture(h *C.pcap_t, lt linkType, ifIndex uint32) {
	defer s.wg.Done()
	var hdr *C.struct_pcap_pkthdr
	var data *C.u_char
	for {
		select {
		case <-s.closing:
			return
		default:
		}
		switch C.pcap_next_ex(h, &hdr, &data) {
		case 1:
			// A packet: copy it out before the next call reuses the buffer.
			n := C.int(hdr.caplen)
			frame := C.GoBytes(unsafe.Pointer(data), n)
			p, ok := parseFrame(lt, frame, ifIndex)
			if !ok {
				continue
			}
			select {
			case s.ch <- p:
			case <-s.closing:
				return
			default:
				// Channel full: drop. Enrichment is best-effort and a recurring
				// flow will be reclassified on a later packet.
			}
		case 0:
			continue // read timeout, no packet — loop to check closing
		default:
			return // -1 error or -2 end-of-capture: this handle is done
		}
	}
}

func (s *pcapSource) Packets() <-chan Packet { return s.ch }

// Close stops all capture goroutines, then tears down the handles. Order
// matters: goroutines must stop sending before the channel is abandoned, and
// pcap_close must not race an in-flight pcap_next_ex.
func (s *pcapSource) Close() error {
	s.once.Do(func() {
		close(s.closing)
		s.wg.Wait()
		s.closeHandles()
	})
	return nil
}

func (s *pcapSource) closeHandles() {
	for _, h := range s.handles {
		C.pcap_close(h)
	}
	s.handles = nil
}
