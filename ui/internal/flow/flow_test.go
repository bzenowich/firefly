package flow

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// ipfixField is one (id,length) pair in a template.
type ipfixField struct{ id, length uint16 }

// buildTemplateSet builds an IPFIX template set (set id 2) for one template.
func buildTemplateSet(tmplID uint16, fields []ipfixField) []byte {
	var rec []byte
	rec = be16(rec, tmplID)
	rec = be16(rec, uint16(len(fields)))
	for _, f := range fields {
		rec = be16(rec, f.id)
		rec = be16(rec, f.length)
	}
	set := be16(nil, 2)                 // set id 2 = template
	set = be16(set, uint16(4+len(rec))) // set length
	return append(set, rec...)
}

// buildDataSet wraps record bytes in a data set with the given template id.
func buildDataSet(tmplID uint16, record []byte) []byte {
	set := be16(nil, tmplID)
	set = be16(set, uint16(4+len(record)))
	return append(set, record...)
}

// buildIPFIX wraps sets in a 16-byte IPFIX message header.
func buildIPFIX(domain uint32, sets ...[]byte) []byte {
	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	hdr := be16(nil, 10)                  // version
	hdr = be16(hdr, uint16(16+len(body))) // total length
	hdr = be32(hdr, 0)                    // export time
	hdr = be32(hdr, 0)                    // sequence
	hdr = be32(hdr, domain)               // observation domain
	return append(hdr, body...)
}

func be16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func be32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }
func be64(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }

var ipv4Template = []ipfixField{
	{ieSourceIPv4Address, 4},
	{ieDestIPv4Address, 4},
	{ieSourceTransportPort, 2},
	{ieDestTransportPort, 2},
	{ieProtocolIdentifier, 1},
	{ieOctetDeltaCount, 8},
	{iePacketDeltaCount, 8},
	{ieIngressInterface, 4},
}

// encodeV4Flow lays out one record matching ipv4Template.
func encodeV4Flow(src, dst netip.Addr, sport, dport uint16, proto uint8, bytes, pkts uint64, iface uint32) []byte {
	s4, d4 := src.As4(), dst.As4()
	var r []byte
	r = append(r, s4[:]...)
	r = append(r, d4[:]...)
	r = be16(r, sport)
	r = be16(r, dport)
	r = append(r, proto)
	r = be64(r, bytes)
	r = be64(r, pkts)
	r = be32(r, iface)
	return r
}

func TestDecodeIPFIXRoundTrip(t *testing.T) {
	d := NewDecoder()

	// A data set before any template yields nothing, not an error.
	rec := encodeV4Flow(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("1.1.1.1"),
		51000, 443, 6, 1500, 3, 2)
	pre := buildIPFIX(1, buildDataSet(256, rec))
	if got, err := d.Decode(pre); err != nil || len(got) != 0 {
		t.Fatalf("pre-template decode: got %d recs, err %v; want 0, nil", len(got), err)
	}

	// Template then data: the data now decodes.
	pkt := buildIPFIX(1,
		buildTemplateSet(256, ipv4Template),
		buildDataSet(256, rec),
	)
	recs, err := d.Decode(pkt)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.Src.String() != "10.0.0.5" || r.Dst.String() != "1.1.1.1" {
		t.Errorf("addrs: %v -> %v", r.Src, r.Dst)
	}
	if r.SPort != 51000 || r.DPort != 443 || r.Proto != 6 {
		t.Errorf("ports/proto: %d %d %d", r.SPort, r.DPort, r.Proto)
	}
	if r.Bytes != 1500 || r.Pkts != 3 || r.IfIndex != 2 {
		t.Errorf("counts: bytes=%d pkts=%d if=%d", r.Bytes, r.Pkts, r.IfIndex)
	}

	// Templates persist across packets: a later data-only packet still decodes.
	rec2 := encodeV4Flow(netip.MustParseAddr("10.0.0.6"), netip.MustParseAddr("8.8.8.8"),
		33000, 53, 17, 200, 1, 2)
	recs, err = d.Decode(buildIPFIX(1, buildDataSet(256, rec2)))
	if err != nil || len(recs) != 1 {
		t.Fatalf("data-only follow-up: %d recs, err %v", len(recs), err)
	}
}

func TestDecodeReducedSizeCounter(t *testing.T) {
	d := NewDecoder()
	// Same fields but octet/packet counts as 4-byte reduced-size encodings.
	tmpl := []ipfixField{
		{ieSourceIPv4Address, 4}, {ieDestIPv4Address, 4},
		{ieOctetDeltaCount, 4}, {iePacketDeltaCount, 4},
	}
	var rec []byte
	s4 := netip.MustParseAddr("192.168.1.2").As4()
	d4 := netip.MustParseAddr("9.9.9.9").As4()
	rec = append(rec, s4[:]...)
	rec = append(rec, d4[:]...)
	rec = be32(rec, 70000) // bytes in 4 bytes
	rec = be32(rec, 50)    // pkts in 4 bytes
	pkt := buildIPFIX(7, buildTemplateSet(300, tmpl), buildDataSet(300, rec))
	recs, err := d.Decode(pkt)
	if err != nil || len(recs) != 1 {
		t.Fatalf("decode: %d recs, err %v", len(recs), err)
	}
	if recs[0].Bytes != 70000 || recs[0].Pkts != 50 {
		t.Errorf("reduced-size counters: bytes=%d pkts=%d", recs[0].Bytes, recs[0].Pkts)
	}
}

func TestDecodeRejectsBadVersion(t *testing.T) {
	d := NewDecoder()
	pkt := make([]byte, 16)
	binary.BigEndian.PutUint16(pkt, 7) // not 9 or 10
	if _, err := d.Decode(pkt); err == nil {
		t.Fatal("want error for unsupported version")
	}
}

func TestStoreRollupAndQuery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	recs := []Record{
		{Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("1.1.1.1"),
			SPort: 51000, DPort: 443, Proto: 6, Bytes: 1500, Pkts: 3, IfIndex: 2},
		{Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("8.8.8.8"),
			SPort: 33000, DPort: 53, Proto: 17, Bytes: 500, Pkts: 2, IfIndex: 2},
		{Src: netip.MustParseAddr("9.9.9.9"), Dst: netip.MustParseAddr("10.0.0.7"),
			SPort: 443, DPort: 40000, Proto: 6, Bytes: 9000, Pkts: 7, IfIndex: 1},
	}
	if err := s.Insert(now, recs); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Rollup folds only whole seconds strictly in the past, so it must run at
	// least a second after the insert for these rows to be in scope.
	if err := s.Rollup(now.Add(time.Second)); err != nil {
		t.Fatalf("rollup: %v", err)
	}

	res, err := s.Query("hour")
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	// 10.0.0.5 sent 1500+500=2000 across two flows; top talker overall is
	// whichever host moved the most bytes total. 9.9.9.9 sent 9000 (out),
	// 10.0.0.7 received 9000 (in) — both tie for the top.
	byHost := map[string]Talker{}
	for _, tk := range res.Talkers {
		byHost[tk.Host] = tk
	}
	if got := byHost["10.0.0.5"]; got.Out != 2000 || got.In != 0 {
		t.Errorf("10.0.0.5: in=%d out=%d, want in=0 out=2000", got.In, got.Out)
	}
	if got := byHost["9.9.9.9"]; got.Out != 9000 {
		t.Errorf("9.9.9.9 out=%d, want 9000", got.Out)
	}
	if got := byHost["10.0.0.7"]; got.In != 9000 {
		t.Errorf("10.0.0.7 in=%d, want 9000", got.In)
	}

	// Volume is the traffic that actually crossed the box: each flow's bytes
	// once, not once per endpoint.
	var vol int64
	for _, p := range res.Volume {
		vol += p.Bytes
	}
	if want := int64(1500 + 500 + 9000); vol != want {
		t.Errorf("volume sum = %d, want %d", vol, want)
	}

	if len(res.Recent) != 3 {
		t.Errorf("recent flows = %d, want 3", len(res.Recent))
	}

	// A second rollup must not double-count: the watermark already covers
	// these flows.
	if err := s.Rollup(now.Add(time.Second)); err != nil {
		t.Fatalf("rollup 2: %v", err)
	}
	res2, _ := s.Query("hour")
	if got := talkerByHost(res2.Talkers, "9.9.9.9"); got.Out != 9000 {
		t.Errorf("after re-rollup 9.9.9.9 out=%d, want 9000 (no double count)", got.Out)
	}
}

// TestRollupSameSecondNotStranded pins the fix for the watermark bug: a row
// inserted after a rollup pass but inside the same one-second tick used to land
// at or below the watermark (which was MAX(ts) of the folded rows) and was never
// counted. Folding only whole seconds already past makes that impossible.
func TestRollupSameSecondNotStranded(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	first := Record{Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("1.1.1.1"),
		SPort: 51000, DPort: 443, Proto: 6, Bytes: 1000, Pkts: 1}
	if err := s.Insert(now, []Record{first}); err != nil {
		t.Fatal(err)
	}
	// A pass inside the still-filling second.
	if err := s.Rollup(now); err != nil {
		t.Fatalf("rollup 1: %v", err)
	}
	// A second row lands in that same second, after the pass.
	second := Record{Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("8.8.8.8"),
		SPort: 33000, DPort: 53, Proto: 17, Bytes: 400, Pkts: 1}
	if err := s.Insert(now, []Record{second}); err != nil {
		t.Fatal(err)
	}
	// The next pass, a second later, must account for both.
	if err := s.Rollup(now.Add(time.Second)); err != nil {
		t.Fatalf("rollup 2: %v", err)
	}

	res, err := s.Query("hour")
	if err != nil {
		t.Fatal(err)
	}
	if got := talkerByHost(res.Talkers, "10.0.0.5"); got.Out != 1400 {
		t.Errorf("10.0.0.5 out = %d, want 1400 (neither row stranded)", got.Out)
	}

	// And a further pass over the same rows still doesn't double-count.
	if err := s.Rollup(now.Add(2 * time.Second)); err != nil {
		t.Fatalf("rollup 3: %v", err)
	}
	res, _ = s.Query("hour")
	if got := talkerByHost(res.Talkers, "10.0.0.5"); got.Out != 1400 {
		t.Errorf("10.0.0.5 out = %d after re-rollup, want 1400", got.Out)
	}
}

func talkerByHost(ts []Talker, host string) Talker {
	for _, t := range ts {
		if t.Host == host {
			return t
		}
	}
	return Talker{}
}
