package main

import (
	"encoding/binary"
	"net/netip"
)

// Packet header parsing, factored out of the libpcap source so it is pure Go
// and unit-testable on a dev box without the C capture backend. source_pcap.go
// (//go:build pcap) resolves the capture handle's DLT_* datalink to a linkType
// and hands each captured frame here; the engine and classifier never see raw
// frames.
//
// The parser is deliberately permissive: anything it can't turn into an
// IPv4/IPv6 packet with a transport 5-tuple is dropped (ok=false) rather than
// erroring. It is enrichment, not accounting — a frame we can't parse simply
// goes unlabeled.

// linkType is the resolved link-layer encapsulation. The cgo source maps the
// platform's DLT_* constant (which varies across OSes — DLT_RAW is 12 on Linux,
// 14 on BSD) onto this stable enum so the parser needs no C constants.
type linkType int

const (
	linkEthernet linkType = iota // DLT_EN10MB: 14-byte Ethernet header (+ optional VLAN tags)
	linkRaw                      // DLT_RAW: frame starts at the IP header
	linkNull                     // DLT_NULL / DLT_LOOP: 4-byte address-family header, then IP
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD
	etherTypeVLAN = 0x8100 // 802.1Q
	etherTypeQinQ = 0x88A8 // 802.1ad
)

const (
	protoTCP = 6
	protoUDP = 17
)

// parseFrame strips the link layer and parses the L3 packet into a Packet.
func parseFrame(lt linkType, data []byte, ifIndex uint32) (Packet, bool) {
	switch lt {
	case linkEthernet:
		return parseEthernet(data, ifIndex)
	case linkRaw:
		return parseIP(data, ifIndex)
	case linkNull:
		// BSD loopback: a 4-byte host-endian address family precedes the IP
		// packet. We don't need the family value — the IP version nibble tells
		// us v4 vs v6 — so skip the 4 bytes.
		if len(data) < 4 {
			return Packet{}, false
		}
		return parseIP(data[4:], ifIndex)
	}
	return Packet{}, false
}

// parseEthernet skips the Ethernet header and any stacked VLAN tags, then parses
// the payload as IP.
func parseEthernet(data []byte, ifIndex uint32) (Packet, bool) {
	if len(data) < 14 {
		return Packet{}, false
	}
	etherType := binary.BigEndian.Uint16(data[12:14])
	off := 14
	// Peel stacked VLAN tags (QinQ). Each 802.1Q/802.1ad tag is 4 bytes: the
	// TPID we already read, then 2 bytes TCI followed by the next EtherType.
	for etherType == etherTypeVLAN || etherType == etherTypeQinQ {
		if len(data) < off+4 {
			return Packet{}, false
		}
		etherType = binary.BigEndian.Uint16(data[off+2 : off+4])
		off += 4
	}
	switch etherType {
	case etherTypeIPv4, etherTypeIPv6:
		return parseIP(data[off:], ifIndex)
	}
	return Packet{}, false
}

// parseIP dispatches on the IP version nibble. Payload on the returned Packet is
// the whole L3 packet (IP header included) — the form nDPI wants
// (ndpi_detection_process_packet takes a pointer to the IP header).
func parseIP(b []byte, ifIndex uint32) (Packet, bool) {
	if len(b) < 1 {
		return Packet{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b, ifIndex)
	case 6:
		return parseIPv6(b, ifIndex)
	}
	return Packet{}, false
}

func parseIPv4(b []byte, ifIndex uint32) (Packet, bool) {
	if len(b) < 20 {
		return Packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return Packet{}, false
	}
	proto := b[9]
	src, _ := netip.AddrFromSlice(b[12:16])
	dst, _ := netip.AddrFromSlice(b[16:20])

	p := Packet{Src: src, Dst: dst, Proto: proto, IfIndex: ifIndex, Payload: b}
	// Only read ports for the first fragment (fragment offset 0). A later
	// fragment has no transport header; leave its ports zero.
	fragOff := binary.BigEndian.Uint16(b[6:8]) & 0x1fff
	if fragOff == 0 {
		p.SPort, p.DPort = parsePorts(proto, b[ihl:])
	}
	return p, true
}

func parseIPv6(b []byte, ifIndex uint32) (Packet, bool) {
	const fixedHdr = 40
	if len(b) < fixedHdr {
		return Packet{}, false
	}
	src, _ := netip.AddrFromSlice(b[8:24])
	dst, _ := netip.AddrFromSlice(b[24:40])

	// Walk the extension-header chain to the transport header. Only the common
	// well-known extension headers are skipped; anything unrecognized (or a
	// fragment) stops the walk, leaving ports zero but the flow still usable.
	next := b[6]
	off := fixedHdr
	for extHeader(next) {
		if len(b) < off+2 {
			break
		}
		hdrLen := (int(b[off+1]) + 1) * 8 // in 8-octet units, not counting first 8
		next = b[off]
		off += hdrLen
		if off > len(b) {
			off = len(b)
			break
		}
	}
	p := Packet{Src: src, Dst: dst, Proto: next, IfIndex: ifIndex, Payload: b}
	if off <= len(b) {
		p.SPort, p.DPort = parsePorts(next, b[off:])
	}
	return p, true
}

// extHeader reports whether an IPv6 next-header value is a skippable extension
// header (not a transport protocol). Fragment (44) is intentionally treated as
// terminal: past the first fragment there is no transport header to read.
func extHeader(nh uint8) bool {
	switch nh {
	case 0, // Hop-by-Hop
		43, // Routing
		60: // Destination Options
		return true
	}
	return false
}

// parsePorts reads the transport source/destination ports for TCP/UDP. Other
// protocols (ICMP, ESP, …) have no ports and return zero.
func parsePorts(proto uint8, l4 []byte) (sport, dport uint16) {
	switch proto {
	case protoTCP:
		if len(l4) < 4 {
			return 0, 0
		}
		return binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
	case protoUDP:
		if len(l4) < 4 {
			return 0, 0
		}
		return binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
	}
	return 0, 0
}
