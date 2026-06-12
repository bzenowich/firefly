package logs

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestRingBufferAndFilter(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "logs.db"), 50)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	for i := 0; i < 60; i++ {
		src := "system"
		if i%2 == 0 {
			src = "pf"
		}
		if err := s.Insert(src, fmt.Sprintf("line %d 50%% _done_", i), now); err != nil {
			t.Fatal(err)
		}
	}

	// Ring trimmed to capacity; newest first.
	all, err := s.Recent(Filter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 50 {
		t.Fatalf("ring size: got %d want 50", len(all))
	}
	if all[0].Line != "line 59 50% _done_" {
		t.Fatalf("newest entry: %q", all[0].Line)
	}

	pf, err := s.Recent(Filter{Source: "pf"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pf {
		if e.Source != "pf" {
			t.Fatalf("source filter leaked: %+v", e)
		}
	}

	// LIKE metacharacters in the needle are matched literally.
	hit, err := s.Recent(Filter{Contains: "50% _done_"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hit) == 0 {
		t.Fatal("literal %/_ search found nothing")
	}
	miss, err := s.Recent(Filter{Contains: "51% Xdone"})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wildcard leak: %d hits", len(miss))
	}
}
