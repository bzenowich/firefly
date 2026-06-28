package flow

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestLabelCacheStampAtInsert(t *testing.T) {
	cache := NewLabelCache()
	now := time.Now()
	// Helper saw the flow in the reverse direction; the stamp must still match.
	cache.Put(Label{
		Src: netip.MustParseAddr("1.1.1.1"), Dst: netip.MustParseAddr("10.0.0.5"),
		SPort: 443, DPort: 51000, Proto: 6, App: "TLS.Netflix",
	}, now)

	rec := Record{
		Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("1.1.1.1"),
		SPort: 51000, DPort: 443, Proto: 6, Bytes: 1500, Pkts: 3,
	}
	app, ok := cache.appFor(rec, now)
	if !ok || app != "TLS.Netflix" {
		t.Fatalf("appFor: %q, %v; want TLS.Netflix, true", app, ok)
	}

	// A different flow misses.
	miss := Record{
		Src: netip.MustParseAddr("10.0.0.9"), Dst: netip.MustParseAddr("1.1.1.1"),
		SPort: 51000, DPort: 443, Proto: 6,
	}
	if _, ok := cache.appFor(miss, now); ok {
		t.Error("unrelated flow should not match a cached label")
	}
}

func TestLabelCacheTTL(t *testing.T) {
	cache := NewLabelCache()
	t0 := time.Now()
	cache.Put(Label{
		Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("1.1.1.1"),
		SPort: 51000, DPort: 443, Proto: 6, App: "TLS",
	}, t0)
	rec := Record{
		Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("1.1.1.1"),
		SPort: 51000, DPort: 443, Proto: 6,
	}
	if _, ok := cache.appFor(rec, t0.Add(labelTTL-time.Second)); !ok {
		t.Error("label should be live within TTL")
	}
	if _, ok := cache.appFor(rec, t0.Add(labelTTL+time.Second)); ok {
		t.Error("label should expire past TTL")
	}
}

func TestBackfillApp(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	// Flow inserted before its label arrives (the race path 2 handles).
	rec := Record{
		Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("1.1.1.1"),
		SPort: 51000, DPort: 443, Proto: 6, Bytes: 1500, Pkts: 3,
	}
	if err := s.Insert(now, []Record{rec}); err != nil {
		t.Fatal(err)
	}

	// Label arrives in the reverse direction; backfill must still match.
	lbl := Label{
		Src: netip.MustParseAddr("1.1.1.1"), Dst: netip.MustParseAddr("10.0.0.5"),
		SPort: 443, DPort: 51000, Proto: 6, App: "TLS.Netflix",
	}
	if err := s.BackfillApp(now, lbl); err != nil {
		t.Fatal(err)
	}

	res, err := s.Query("hour")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Recent) != 1 || res.Recent[0].App != "TLS.Netflix" {
		t.Fatalf("recent app = %q, want TLS.Netflix", appOf(res.Recent))
	}

	// A non-matching label leaves other flows untouched.
	other := Label{
		Src: netip.MustParseAddr("9.9.9.9"), Dst: netip.MustParseAddr("10.0.0.5"),
		SPort: 53, DPort: 33000, Proto: 17, App: "DNS",
	}
	if err := s.BackfillApp(now, other); err != nil {
		t.Fatal(err)
	}
	res, _ = s.Query("hour")
	if res.Recent[0].App != "TLS.Netflix" {
		t.Errorf("unrelated backfill clobbered app: %q", res.Recent[0].App)
	}
}

func appOf(fs []Flow) string {
	if len(fs) == 0 {
		return ""
	}
	return fs[0].App
}
