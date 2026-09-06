//go:build pcap

package main

// libpcap capture backend (design §6, build phase 3). Compiled only with
// `-tags pcap` in the OS image pipeline, where libpcap is present. It opens each
// capture device, sets a BPF that keeps only IP traffic, and runs one goroutine
// per device that copies each captured frame out of libpcap's reused buffer and
// hands it to parseFrame (pure Go, parse.go). The engine never sees raw frames.
//
// The C surface is deliberately tiny: create/activate/compile/set-filter/next/
// stats/close. All header parsing is Go (parse.go), so only capture itself is
// untestable off the appliance.

// #cgo LDFLAGS: -lpcap
// #include <stdlib.h>
// #include <string.h>
// #include <pcap.h>
import "C"

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
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

// captureBuffer is the kernel capture buffer requested per device. FreeBSD's BPF
// default (net.bpf.bufsize) is tiny — a small fraction of a second of a routed
// 2.5GbE path — so any burst that outruns the reader goroutine is dropped in the
// kernel, silently (see reportStats). 8 MiB per device costs little on a 16 GB
// box. It is a request, not a guarantee: the kernel caps it at
// net.bpf.maxbufsize (512 KiB by default) and libpcap retries with progressively
// smaller sizes, so raise that sysctl on the appliance to actually get this.
// Setting it at all requires the pcap_create/activate path — the older
// pcap_open_live has no way to express it.
const captureBuffer = 8 << 20

// statsInterval is how often each capture goroutine polls pcap_stats. Kernel
// drops are otherwise completely invisible: libpcap simply hands us fewer
// packets and the classifier quietly labels fewer flows.
const statsInterval = time.Minute

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
			// Tear the partial source down through Close, not closeHandles:
			// the devices opened so far already have capture goroutines that
			// may be sitting inside pcap_next_ex, and pcap_close under them is
			// a use-after-free in C (a segfault plus a 3 s supervisor restart
			// loop). Close signals, waits, then closes — the same order the
			// normal shutdown path uses, for the same reason.
			s.Close()
			return nil, fmt.Errorf("open %s: %w", dev, err)
		}
		s.handles = append(s.handles, h)
		var ifIndex uint32
		if iface, err := net.InterfaceByName(dev); err == nil {
			ifIndex = uint32(iface.Index)
		}
		s.wg.Add(1)
		go s.capture(dev, h, lt, ifIndex)
	}
	return s, nil
}

// openDevice opens a live capture handle on dev, installs the BPF, and resolves
// the datalink to our linkType enum. It uses the create/configure/activate form
// rather than pcap_open_live so the capture buffer size can be set (see
// captureBuffer); the settings themselves match what open_live would have done.
func openDevice(dev string) (*C.pcap_t, linkType, error) {
	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))

	errbuf := make([]C.char, C.PCAP_ERRBUF_SIZE)
	h := C.pcap_create(cdev, &errbuf[0])
	if h == nil {
		return nil, 0, fmt.Errorf("pcap_create: %s", C.GoString(&errbuf[0]))
	}
	C.pcap_set_snaplen(h, C.int(snaplen))
	// promisc=0: as the gateway we already receive the frames we route, so we
	// don't need promiscuous mode (and it reduces load). to_ms=100 lets
	// pcap_next_ex return periodically so the goroutine can observe closing.
	C.pcap_set_promisc(h, 0)
	C.pcap_set_timeout(h, 100)
	C.pcap_set_buffer_size(h, C.int(captureBuffer))
	// A negative status is fatal; a positive one is a warning (an unsupported
	// option, say) on an otherwise usable handle.
	if rc := C.pcap_activate(h); rc < 0 {
		err := fmt.Errorf("pcap_activate: %s: %s",
			C.GoString(C.pcap_statustostr(rc)), C.GoString(C.pcap_geterr(h)))
		C.pcap_close(h)
		return nil, 0, err
	} else if rc > 0 {
		log.Printf("pcap: %s activated with warning: %s", dev, C.GoString(C.pcap_statustostr(rc)))
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
// pcap_next_ex) and parsing it into a Packet. It also polls the handle's drop
// counters every statsInterval (see reportStats).
func (s *pcapSource) capture(dev string, h *C.pcap_t, lt linkType, ifIndex uint32) {
	defer s.wg.Done()
	var hdr *C.struct_pcap_pkthdr
	var data *C.u_char
	var lastDrop, lastIfDrop uint64
	nextStats := time.Now().Add(statsInterval)
	for {
		select {
		case <-s.closing:
			return
		default:
		}
		if now := time.Now(); !now.Before(nextStats) {
			nextStats = now.Add(statsInterval)
			reportStats(dev, h, &lastDrop, &lastIfDrop)
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

// reportStats logs how many packets the kernel dropped for this handle since the
// last poll: ps_drop is the capture buffer overflowing (we are too slow, or
// captureBuffer is too small), ps_ifdrop is the driver dropping before BPF ever
// saw the frame. Both are cumulative and monotonic while the handle lives, so
// only the deltas are reported, and only when non-zero — a quiet log means no
// drops. Missing labels with no line here mean the loss is somewhere else.
func reportStats(dev string, h *C.pcap_t, lastDrop, lastIfDrop *uint64) {
	var st C.struct_pcap_stat
	if C.pcap_stats(h, &st) != 0 {
		return // not supported on this handle, or the handle is gone
	}
	drop, ifdrop := uint64(st.ps_drop), uint64(st.ps_ifdrop)
	// Subtract only when the counter moved forward: a 32-bit counter that
	// wrapped (or a platform that resets it on read) must not print a delta of
	// nearly 2^64.
	var dropped, ifDropped uint64
	if drop > *lastDrop {
		dropped = drop - *lastDrop
	}
	if ifdrop > *lastIfDrop {
		ifDropped = ifdrop - *lastIfDrop
	}
	*lastDrop, *lastIfDrop = drop, ifdrop
	if dropped > 0 || ifDropped > 0 {
		log.Printf("pcap: %s kernel drops in the last %v: %d buffer, %d interface",
			dev, statsInterval, dropped, ifDropped)
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
