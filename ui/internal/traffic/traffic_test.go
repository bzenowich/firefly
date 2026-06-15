package traffic

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPerSecClampsResets(t *testing.T) {
	if got := perSec(100, 200, 10); got != 10 {
		t.Errorf("perSec rising = %v, want 10", got)
	}
	if got := perSec(500, 100, 10); got != 0 {
		t.Errorf("perSec after counter reset = %v, want 0", got)
	}
}

func TestQueryBuckets(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	// Two samples 30s apart land in the same 60s "hour" bucket; their rx
	// should average.
	base := now.Add(-90 * time.Second)
	if err := s.insert(base, []ifRate{{iface: "eth0", rx: 100, tx: 10}}); err != nil {
		t.Fatal(err)
	}
	if err := s.insert(base.Add(20*time.Second), []ifRate{{iface: "eth0", rx: 300, tx: 30}}); err != nil {
		t.Fatal(err)
	}

	res, err := s.Query("hour")
	if err != nil {
		t.Fatal(err)
	}
	if res.Range != "hour" || res.Step != 60 || res.Span != 3600 {
		t.Fatalf("range=%q step=%d span=%d", res.Range, res.Step, res.Span)
	}
	if len(res.Series) != 1 || res.Series[0].Iface != "eth0" {
		t.Fatalf("series = %+v", res.Series)
	}
	pts := res.Series[0].Points
	if len(pts) != 1 {
		t.Fatalf("points = %d, want 1 bucket", len(pts))
	}
	if pts[0].Rx != 200 || pts[0].Tx != 20 {
		t.Errorf("bucket avg rx=%v tx=%v, want 200/20", pts[0].Rx, pts[0].Tx)
	}
}

func TestQueryUnknownRangeDefaultsHour(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := s.Query("decade")
	if err != nil {
		t.Fatal(err)
	}
	if res.Range != "hour" {
		t.Errorf("range = %q, want hour fallback", res.Range)
	}
}
