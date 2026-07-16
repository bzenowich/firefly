//go:build ndpi

package main

// libnDPI classifier (design §6, build phase 3). Compiled only with `-tags ndpi`
// in the OS image pipeline. It links libnDPI **dynamically** — never static — so
// the LGPL boundary stays at the dynamic-link line and never enters the fwd
// binary (this is a separate process; plan.md §8).
//
// Per flow it lazily allocates an ndpi_flow_struct, feeds the flow head through
// ndpi_detection_process_packet until nDPI names a protocol, then reports the
// verdict. If the engine's packet cap (maxClassifyPkts) is reached first, it
// calls ndpi_detection_giveup for nDPI's best guess so short flows still get a
// label. The C flow handle is freed via Release (engine calls it on verdict and
// on eviction).
//
// API version: written against nDPI 5.0 (FreeBSD ports net/ndpi, verified on
// the 15.1 VM). nDPI's C API churns across majors (plan.md §8 calls this out);
// the 4.x→5.0 breaks this file already absorbed: the protocol-bitmask setup
// API was removed (all dissectors are on by default), ndpi_detection_giveup
// lost its out-param, ndpi_protocol nests the verdict pair in .proto, and
// ndpi_protocol2name takes that ndpi_master_app_protocol pair.

// #cgo CFLAGS: -I/usr/local/include/ndpi
// #cgo LDFLAGS: -L/usr/local/lib -lndpi
// #include <stdlib.h>
// #include <string.h>
// #include <ndpi_api.h>
//
// // alloc_flow allocates and zeroes an ndpi_flow_struct using nDPI's own
// // allocator, paired with ndpi_free_flow.
// static struct ndpi_flow_struct *alloc_flow(void) {
//     size_t sz = ndpi_detection_get_sizeof_ndpi_flow_struct();
//     struct ndpi_flow_struct *f = ndpi_malloc(sz);
//     if (f) memset(f, 0, sz);
//     return f;
// }
import "C"

import (
	"unsafe"
)

// ndpiClassifier holds the shared detection module (allocated once) and a
// monotonic tick used as the "current time" nDPI expects. Single-goroutine
// (the engine), so the tick needs no locking.
type ndpiClassifier struct {
	mod  *C.struct_ndpi_detection_module_struct
	tick C.u_int64_t
}

func newClassifier() Classifier {
	mod := C.ndpi_init_detection_module(nil)
	if mod == nil {
		panic("ndpi: ndpi_init_detection_module returned NULL")
	}
	// Every protocol dissector is enabled by default; finalize compiles the
	// automata and locks configuration.
	if C.ndpi_finalize_initialization(mod) != 0 {
		panic("ndpi: ndpi_finalize_initialization failed")
	}
	return &ndpiClassifier{mod: mod}
}

// Classify feeds one packet into this flow's nDPI state and reports the verdict.
// While nDPI is undecided it returns done=false so the engine keeps feeding the
// flow head; on the last allowed packet it gives up with nDPI's best guess.
func (c *ndpiClassifier) Classify(st *FlowState, p Packet) (string, bool) {
	if len(p.Payload) == 0 {
		// No L3 bytes to inspect (e.g. a later fragment). Wait for more.
		return "", false
	}
	fl := c.flowFor(st)

	c.tick++
	proto := C.ndpi_detection_process_packet(
		c.mod, fl,
		(*C.uchar)(unsafe.Pointer(&p.Payload[0])),
		C.u_int16_t(len(p.Payload)),
		c.tick,
		nil,
	)

	if proto.proto.app_protocol != C.NDPI_PROTOCOL_UNKNOWN || proto.proto.master_protocol != C.NDPI_PROTOCOL_UNKNOWN {
		return c.name(proto.proto), true
	}

	// Still unknown. If this was the last packet the engine will feed, force a
	// best-effort guess so short flows aren't left unlabeled.
	if st.Pkts >= maxClassifyPkts {
		final := C.ndpi_detection_giveup(c.mod, fl)
		return c.name(final.proto), true
	}
	return "", false
}

// flowFor lazily allocates the per-flow nDPI handle and stashes it in st.cls.
func (c *ndpiClassifier) flowFor(st *FlowState) *C.struct_ndpi_flow_struct {
	if fl, ok := st.cls.(*C.struct_ndpi_flow_struct); ok && fl != nil {
		return fl
	}
	fl := C.alloc_flow()
	if fl == nil {
		panic("ndpi: flow allocation failed")
	}
	st.cls = fl
	return fl
}

// name renders a verdict pair to a label string (e.g. "TLS.Netflix"). An
// all-unknown verdict yields "" so the engine emits nothing.
func (c *ndpiClassifier) name(proto C.ndpi_master_app_protocol) string {
	if proto.app_protocol == C.NDPI_PROTOCOL_UNKNOWN && proto.master_protocol == C.NDPI_PROTOCOL_UNKNOWN {
		return ""
	}
	var buf [64]C.char
	C.ndpi_protocol2name(c.mod, proto, &buf[0], C.uint(len(buf)))
	return C.GoString(&buf[0])
}

// Release frees the per-flow nDPI handle. Idempotent: a nil st.cls (already
// freed at the verdict) is a no-op when the engine later evicts the flow.
func (c *ndpiClassifier) Release(st *FlowState) {
	if fl, ok := st.cls.(*C.struct_ndpi_flow_struct); ok && fl != nil {
		C.ndpi_free_flow(fl)
		st.cls = nil
	}
}
