package main

import "net/netip"

// Packet is the per-packet metadata the engine and classifier need: the
// 5-tuple, the ingress ifindex, and the bytes nDPI inspects. The Source layer
// parses link/IP/transport headers and hands this up; the engine never touches
// raw frames.
type Packet struct {
	Src, Dst     netip.Addr
	SPort, DPort uint16
	Proto        uint8
	IfIndex      uint32
	Payload      []byte // L3+ bytes for the classifier; may be nil for the stub
}

// Source yields parsed packets until it is exhausted or closed. The real source
// is libpcap (source_pcap.go, behind //go:build pcap); a channel-fed source
// drives tests, and a no-op source is the default when no capture backend is
// compiled in.
type Source interface {
	// Packets returns a channel of packets, closed when the source ends.
	Packets() <-chan Packet
	Close() error
}

// chanSource is a Source backed by a channel — used by tests and as the no-op
// default (an empty, never-closed channel just blocks the engine).
type chanSource struct {
	ch chan Packet
}

func newChanSource(buf int) *chanSource { return &chanSource{ch: make(chan Packet, buf)} }

func (c *chanSource) Packets() <-chan Packet { return c.ch }
func (c *chanSource) Close() error           { return nil }
