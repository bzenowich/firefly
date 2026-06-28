//go:build ndpi

package main

// libnDPI classifier (design §6, build phase 3). Compiled only with `-tags ndpi`
// in the OS image pipeline. It links libnDPI **dynamically** — never static —
// so the LGPL boundary stays at the dynamic-link line and never enters the fwd
// binary (this is a separate process; plan.md §8). Per flow it allocates an
// ndpi_flow_t, feeds the flow head through ndpi_detection_process_packet until a
// protocol is detected, and maps the result to a label string.
//
// SKELETON: the cgo binding lives in the image build, not on the dev box. The
// contract matches the stub (classifier_stub.go) so either builds against the
// same engine.

// #cgo LDFLAGS: -lndpi
// #include <ndpi_api.h>
import "C"

type ndpiClassifier struct {
	// detection module handle (ndpi_detection_module_struct), allocated once.
}

func newClassifier() Classifier {
	// TODO(image-build): ndpi_init_detection_module + ndpi_finalize_initialization.
	return ndpiClassifier{}
}

// Classify feeds one packet into this flow's nDPI state and reports the verdict.
// Returns done=false while nDPI is still undecided so the engine keeps feeding
// the flow head (up to maxClassifyPkts).
func (ndpiClassifier) Classify(st *FlowState, p Packet) (string, bool) {
	// TODO(image-build): lazily allocate st.cls = ndpi_flow_t on first packet;
	// call ndpi_detection_process_packet; on a confident match return
	// ndpi_protocol2name(...) and done=true.
	_ = st
	_ = p
	return "", true
}
