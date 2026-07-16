package main

// FlowState is the engine's per-flow accumulator. Pkts counts packets seen so
// far; cls is private scratch the Classifier owns (e.g. a libnDPI flow handle)
// and is opaque to the engine.
type FlowState struct {
	Pkts int
	cls  any
}

// Classifier turns a flow's packets into an app label. Classify is fed one
// packet at a time and returns the current verdict plus whether it is final.
// While done is false the engine keeps feeding packets (up to a cap); once done
// is true the engine emits the label (if non-empty) and stops inspecting.
//
// The real implementation links libnDPI (classifier_ndpi.go, //go:build ndpi).
// The default is the stub below, so the helper builds and runs without the C
// library.
type Classifier interface {
	Classify(st *FlowState, p Packet) (app string, done bool)
	// Release frees any per-flow resources the classifier attached to st (e.g. a
	// libnDPI flow handle in st.cls). The engine calls it once when a flow
	// reaches its verdict and again if the flow is later evicted, so it must be
	// idempotent — a nil st.cls means already released.
	Release(st *FlowState)
}
