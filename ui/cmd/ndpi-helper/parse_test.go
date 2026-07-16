package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// buildIPv4 assembles a minimal IPv4 packet with the given L4 protocol and a
// TCP/UDP header carrying the ports, for parser tests.
func buildIPv4(t *testing.T, src, dst string, proto uint8, sport, dport uint16) []byte {
	t.Helper()
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)

	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	ip[9] = proto
	copy(ip[12:16], netip.MustParseAddr(src).AsSlice())
	copy(ip[16:20], netip.MustParseAddr(dst).AsSlice())
	return append(ip, l4...)
}

func ethFrame(etherType uint16, payload []byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], etherType)
	return append(eth, payload...)
}

func TestParseEthernetIPv4TCP(t *testing.T) {
	ip := buildIPv4(t, "10.0.0.5", "1.1.1.1", protoTCP, 51000, 443)
	p, ok := parseFrame(linkEthernet, ethFrame(etherTypeIPv4, ip), 3)
	if !ok {
		t.Fatal("parse failed")
	}
	if p.Src != netip.MustParseAddr("10.0.0.5") || p.Dst != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("addrs = %v→%v", p.Src, p.Dst)
	}
	if p.SPort != 51000 || p.DPort != 443 {
		t.Errorf("ports = %d→%d, want 51000→443", p.SPort, p.DPort)
	}
	if p.Proto != protoTCP {
		t.Errorf("proto = %d, want %d", p.Proto, protoTCP)
	}
	if p.IfIndex != 3 {
		t.Errorf("ifindex = %d, want 3", p.IfIndex)
	}
	// Payload must be the whole L3 packet (IP header included) for nDPI.
	if len(p.Payload) != len(ip) || p.Payload[0] != 0x45 {
		t.Errorf("payload not the L3 packet: len=%d first=%#x", len(p.Payload), p.Payload[0])
	}
}

func TestParseVLANTagged(t *testing.T) {
	ip := buildIPv4(t, "192.168.1.2", "8.8.8.8", protoUDP, 5353, 53)
	// One 802.1Q tag: TPID 0x8100, 2-byte TCI, then inner EtherType.
	vlan := make([]byte, 4)
	binary.BigEndian.PutUint16(vlan[0:2], 0x000a) // TCI (VID 10)
	binary.BigEndian.PutUint16(vlan[2:4], etherTypeIPv4)
	frame := ethFrame(etherTypeVLAN, append(vlan, ip...))

	p, ok := parseFrame(linkEthernet, frame, 0)
	if !ok {
		t.Fatal("VLAN parse failed")
	}
	if p.DPort != 53 || p.Proto != protoUDP {
		t.Errorf("got dport=%d proto=%d, want 53/udp", p.DPort, p.Proto)
	}
}

func TestParseIPv6UDP(t *testing.T) {
	ip := make([]byte, 40)
	ip[0] = 0x60 // version 6
	ip[6] = protoUDP
	copy(ip[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(ip[24:40], netip.MustParseAddr("2606:4700:4700::1111").AsSlice())
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:2], 40000)
	binary.BigEndian.PutUint16(l4[2:4], 443)
	ip = append(ip, l4...)

	p, ok := parseFrame(linkEthernet, ethFrame(etherTypeIPv6, ip), 0)
	if !ok {
		t.Fatal("IPv6 parse failed")
	}
	if p.Src != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("src = %v", p.Src)
	}
	if p.DPort != 443 || p.Proto != protoUDP {
		t.Errorf("got dport=%d proto=%d, want 443/udp", p.DPort, p.Proto)
	}
}

func TestParseRawAndNull(t *testing.T) {
	ip := buildIPv4(t, "10.0.0.1", "10.0.0.2", protoTCP, 1234, 80)
	if p, ok := parseFrame(linkRaw, ip, 0); !ok || p.DPort != 80 {
		t.Errorf("linkRaw: ok=%v dport=%d", ok, p.DPort)
	}
	// linkNull prepends a 4-byte address family.
	nullFrame := append([]byte{2, 0, 0, 0}, ip...)
	if p, ok := parseFrame(linkNull, nullFrame, 0); !ok || p.DPort != 80 {
		t.Errorf("linkNull: ok=%v dport=%d", ok, p.DPort)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, ok := parseFrame(linkEthernet, []byte{1, 2, 3}, 0); ok {
		t.Error("short frame should not parse")
	}
	if _, ok := parseFrame(linkEthernet, ethFrame(0x0806 /* ARP */, []byte{1, 2, 3, 4}), 0); ok {
		t.Error("ARP should not parse as IP")
	}
}

func TestParseFragmentNoPorts(t *testing.T) {
	ip := buildIPv4(t, "10.0.0.5", "1.1.1.1", protoTCP, 51000, 443)
	// Set a non-zero fragment offset (bytes 6-7, low 13 bits).
	binary.BigEndian.PutUint16(ip[6:8], 100)
	p, ok := parseFrame(linkRaw, ip, 0)
	if !ok {
		t.Fatal("fragment should still parse as a flow")
	}
	if p.SPort != 0 || p.DPort != 0 {
		t.Errorf("later fragment should have zero ports, got %d→%d", p.SPort, p.DPort)
	}
}
