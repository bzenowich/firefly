package flow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Decoder turns IPFIX (RFC 7011, version 10) and NetFlow v9 export packets into
// flow Records. Both protocols are template-driven: the exporter periodically
// sends template records describing the layout of the data records that follow,
// and data records carry no field identifiers of their own. The decoder caches
// templates and can only decode a data set once it has seen the matching
// template — early data sets (before the first template, or after a restart)
// are skipped, which is normal and self-healing.
//
// pflow(4) exports IPFIX, so that is the primary path; NetFlow v9 is supported
// because the two share this template machinery and goflow2 (our reference)
// handles both. Reimplemented here in Go rather than pulled in as a dependency
// — the subset of fields we store is small.
type Decoder struct {
	// templates is keyed by (observation domain / source id, template id), so
	// distinct exporters or domains can't collide on template ids.
	templates map[tmplKey]*template
}

func NewDecoder() *Decoder {
	return &Decoder{templates: map[tmplKey]*template{}}
}

type tmplKey struct {
	domain uint32
	id     uint16
}

type field struct {
	id     uint16
	length uint16
}

type template struct {
	fields   []field
	totalLen int // sum of field lengths; the fixed data-record size
}

// IANA Information Element ids we extract. Everything else in a record is
// stepped over by its declared length.
const (
	ieOctetDeltaCount     = 1
	iePacketDeltaCount    = 2
	ieProtocolIdentifier  = 4
	ieSourceTransportPort = 7
	ieSourceIPv4Address   = 8
	ieIngressInterface    = 10
	ieDestTransportPort   = 11
	ieDestIPv4Address     = 12
	ieEgressInterface     = 14
	ieSourceIPv6Address   = 27
	ieDestIPv6Address     = 28
	ieOctetTotalCount     = 85
	iePacketTotalCount    = 86
)

// Decode parses one export packet and returns the flow records it carried.
// Template-only packets (and data sets whose template is not yet known) return
// no records and no error. A malformed packet returns an error; the collector
// logs and drops it rather than tearing down the listener.
func (d *Decoder) Decode(pkt []byte) ([]Record, error) {
	if len(pkt) < 16 {
		return nil, fmt.Errorf("short packet: %d bytes", len(pkt))
	}
	switch version := binary.BigEndian.Uint16(pkt[0:2]); version {
	case 10:
		return d.decodeIPFIX(pkt)
	case 9:
		return d.decodeV9(pkt)
	default:
		return nil, fmt.Errorf("unsupported export version %d", version)
	}
}

// decodeIPFIX walks an IPFIX message: 16-byte header then a sequence of sets.
func (d *Decoder) decodeIPFIX(pkt []byte) ([]Record, error) {
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if msgLen < 16 || msgLen > len(pkt) {
		return nil, fmt.Errorf("ipfix message length %d out of range (%d)", msgLen, len(pkt))
	}
	domain := binary.BigEndian.Uint32(pkt[12:16])

	var recs []Record
	off := 16
	for off+4 <= msgLen {
		setID := binary.BigEndian.Uint16(pkt[off : off+2])
		setLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if setLen < 4 || off+setLen > msgLen {
			return nil, fmt.Errorf("ipfix set length %d at offset %d invalid", setLen, off)
		}
		body := pkt[off+4 : off+setLen]
		switch {
		case setID == 2: // template set
			d.parseTemplates(domain, body, false)
		case setID == 3: // options template set — cache layout so we can skip its data
			d.parseTemplates(domain, body, true)
		case setID >= 256: // data set
			if t := d.templates[tmplKey{domain, setID}]; t != nil {
				recs = append(recs, t.decodeData(body)...)
			}
		}
		off += setLen
	}
	return recs, nil
}

// decodeV9 walks a NetFlow v9 message: 20-byte header then flowsets. The header
// count counts records, not flowsets, so we iterate by length to the end.
func (d *Decoder) decodeV9(pkt []byte) ([]Record, error) {
	if len(pkt) < 20 {
		return nil, fmt.Errorf("short v9 packet: %d bytes", len(pkt))
	}
	domain := binary.BigEndian.Uint32(pkt[16:20]) // source id

	var recs []Record
	off := 20
	for off+4 <= len(pkt) {
		fsID := binary.BigEndian.Uint16(pkt[off : off+2])
		fsLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if fsLen < 4 || off+fsLen > len(pkt) {
			return nil, fmt.Errorf("v9 flowset length %d at offset %d invalid", fsLen, off)
		}
		body := pkt[off+4 : off+fsLen]
		switch {
		case fsID == 0: // template flowset
			d.parseTemplates(domain, body, false)
		case fsID == 1: // options template flowset
			d.parseV9OptionsTemplate(domain, body)
		case fsID >= 256: // data flowset
			if t := d.templates[tmplKey{domain, fsID}]; t != nil {
				recs = append(recs, t.decodeData(body)...)
			}
		}
		off += fsLen
	}
	return recs, nil
}

// parseTemplates reads a template (or IPFIX options template) set body and
// caches each template. IPFIX and NetFlow v9 share the regular-template layout:
// templateID(2), fieldCount(2), then fieldCount × (id(2), length(2)). IPFIX
// options templates add a scope-field-count word, handled by options=true.
func (d *Decoder) parseTemplates(domain uint32, body []byte, options bool) {
	off := 0
	for off+4 <= len(body) {
		id := binary.BigEndian.Uint16(body[off : off+2])
		count := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if options { // IPFIX options template: skip the scope field count word
			if off+2 > len(body) {
				return
			}
			off += 2
		}

		t := &template{}
		bad := false
		for i := 0; i < count; i++ {
			if off+4 > len(body) {
				return
			}
			fid := binary.BigEndian.Uint16(body[off : off+2])
			flen := binary.BigEndian.Uint16(body[off+2 : off+4])
			off += 4
			if fid&0x8000 != 0 { // enterprise-specific: 4-byte PEN follows
				if off+4 > len(body) {
					return
				}
				off += 4
			}
			if flen == 0xffff { // variable-length; pflow doesn't use these
				bad = true
			}
			t.fields = append(t.fields, field{id: fid, length: flen})
			t.totalLen += int(flen)
		}
		if !bad && t.totalLen > 0 {
			d.templates[tmplKey{domain, id}] = t
		}
	}
}

// parseV9OptionsTemplate caches a v9 options template's record size so its data
// flowsets are stepped over cleanly rather than misread as flow data. Layout:
// templateID(2), optionScopeLength(2), optionLength(2), then the field defs.
func (d *Decoder) parseV9OptionsTemplate(domain uint32, body []byte) {
	if len(body) < 6 {
		return
	}
	id := binary.BigEndian.Uint16(body[0:2])
	scopeLen := int(binary.BigEndian.Uint16(body[2:4]))
	optLen := int(binary.BigEndian.Uint16(body[4:6]))
	total := scopeLen + optLen
	if total <= 0 {
		return
	}
	// One synthetic field of the combined length: enough to skip the data
	// records; none of the ids match the flow IEs we extract.
	d.templates[tmplKey{domain, id}] = &template{
		fields:   []field{{id: 0, length: uint16(total)}},
		totalLen: total,
	}
}

// decodeData splits a data set into fixed-size records and decodes each.
func (t *template) decodeData(body []byte) []Record {
	if t.totalLen == 0 {
		return nil
	}
	var recs []Record
	for off := 0; off+t.totalLen <= len(body); off += t.totalLen {
		recs = append(recs, t.decodeRecord(body[off:off+t.totalLen]))
	}
	return recs
}

// decodeRecord pulls the fields we care about out of one record. Counters use
// reduced-size encoding (any length 1–8), so they are read big-endian over
// their declared width. Byte/packet totals fall back to the *TotalCount IEs
// when the delta IEs are absent.
func (t *template) decodeRecord(rec []byte) Record {
	var r Record
	off := 0
	for _, f := range t.fields {
		end := off + int(f.length)
		if end > len(rec) {
			break
		}
		v := rec[off:end]
		switch f.id {
		case ieOctetDeltaCount, ieOctetTotalCount:
			if r.Bytes == 0 {
				r.Bytes = readUint(v)
			}
		case iePacketDeltaCount, iePacketTotalCount:
			if r.Pkts == 0 {
				r.Pkts = readUint(v)
			}
		case ieProtocolIdentifier:
			r.Proto = uint8(readUint(v))
		case ieSourceTransportPort:
			r.SPort = uint16(readUint(v))
		case ieDestTransportPort:
			r.DPort = uint16(readUint(v))
		case ieSourceIPv4Address, ieSourceIPv6Address:
			if a, ok := readAddr(v); ok {
				r.Src = a
			}
		case ieDestIPv4Address, ieDestIPv6Address:
			if a, ok := readAddr(v); ok {
				r.Dst = a
			}
		case ieIngressInterface:
			r.IfIndex = uint32(readUint(v))
		case ieEgressInterface:
			if r.IfIndex == 0 {
				r.IfIndex = uint32(readUint(v))
			}
		}
		off = end
	}
	return r
}

// readUint decodes a big-endian unsigned integer of 1–8 bytes (IPFIX
// reduced-size encoding). Wider or empty fields yield 0.
func readUint(b []byte) uint64 {
	if len(b) == 0 || len(b) > 8 {
		return 0
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// readAddr decodes a 4- or 16-byte address field.
func readAddr(b []byte) (netip.Addr, bool) {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b)), true
	case 16:
		return netip.AddrFrom16([16]byte(b)), true
	default:
		return netip.Addr{}, false
	}
}
