// Package traffic samples per-interface throughput into a SQLite ring buffer
// and serves it to the Traffic page (plan.md §7). A goroutine reads the
// kernel byte counters on a fixed interval, converts them to a rate
// (bytes/sec) so counter resets and reboots can't poison the series, and
// stores one row per interface per tick. The HTTP layer queries bucketed
// averages for hour/day/week/month views.
package traffic

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"firewall/ui/internal/system"

	_ "modernc.org/sqlite"
)

// SampleInterval is the gap between counter reads. Five seconds keeps the
// hour view smooth without bloating the database.
const SampleInterval = 5 * time.Second

// retention bounds the buffer by age: a little over the longest (month) view.
const retention = 32 * 24 * time.Hour

const schema = `
CREATE TABLE IF NOT EXISTS samples (
	ts    INTEGER NOT NULL,  -- unix seconds
	iface TEXT    NOT NULL,
	rx    REAL    NOT NULL,  -- bytes/sec, averaged over the tick
	tx    REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
`

// Store is the throughput ring buffer.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the sample database at path.
func Open(path string) (*Store, error) {
	// One writer connection mirrors the logs store: SQLite serializes writes
	// and a single conn sidesteps SQLITE_BUSY between sampler and trim.
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("traffic schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// insert appends one tick's worth of per-interface rates and trims the ring.
func (s *Store) insert(t time.Time, rates []ifRate) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO samples (ts, iface, rx, tx) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rates {
		if _, err := stmt.Exec(t.Unix(), r.iface, r.rx, r.tx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM samples WHERE ts < ?`, t.Add(-retention).Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// Point is one bucketed sample: rx/tx are bytes/sec averaged over the bucket.
type Point struct {
	T  int64   `json:"t"` // unix seconds, bucket start
	Rx float64 `json:"rx"`
	Tx float64 `json:"tx"`
}

// Series is one interface's time series.
type Series struct {
	Iface  string  `json:"iface"`
	Points []Point `json:"points"`
}

// Result is the JSON payload the Traffic page graphs.
type Result struct {
	Range  string   `json:"range"`
	Step   int      `json:"step"` // bucket width, seconds
	Series []Series `json:"series"`
}

type window struct{ span, bucket int } // seconds

// windows map a range name to its lookback span and bucket width, chosen so
// each view returns a few hundred points regardless of sample rate.
var windows = map[string]window{
	"hour":  {3600, 60},
	"day":   {86400, 300},
	"week":  {604800, 1800},
	"month": {2592000, 7200},
}

// Query returns bucketed averages for a named range ("hour" is the default
// for an unknown name).
func (s *Store) Query(rangeName string) (Result, error) {
	w, ok := windows[rangeName]
	if !ok {
		rangeName, w = "hour", windows["hour"]
	}
	since := time.Now().Add(-time.Duration(w.span) * time.Second).Unix()
	rows, err := s.db.Query(`
		SELECT iface, (ts/?)*? AS b, AVG(rx), AVG(tx)
		FROM samples WHERE ts >= ?
		GROUP BY iface, b ORDER BY iface, b`, w.bucket, w.bucket, since)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()

	res := Result{Range: rangeName, Step: w.bucket}
	idx := map[string]int{} // iface -> res.Series index
	for rows.Next() {
		var iface string
		var p Point
		if err := rows.Scan(&iface, &p.T, &p.Rx, &p.Tx); err != nil {
			return Result{}, err
		}
		i, ok := idx[iface]
		if !ok {
			i = len(res.Series)
			idx[iface] = i
			res.Series = append(res.Series, Series{Iface: iface})
		}
		res.Series[i].Points = append(res.Series[i].Points, p)
	}
	return res, rows.Err()
}

type ifRate struct {
	iface  string
	rx, tx float64
}

// Sampler reads interface counters and writes rates to the store until its
// context ends. It works on any platform system.Collect supports, so the
// Traffic page is live during dev too, not just on the FreeBSD appliance.
type Sampler struct {
	store *Store
	prev  map[string][2]uint64 // iface -> {rx, tx} cumulative bytes
	last  time.Time
}

func NewSampler(store *Store) *Sampler {
	return &Sampler{store: store, prev: map[string][2]uint64{}}
}

// Run samples every SampleInterval until ctx is cancelled. The first tick only
// seeds the baseline counters; rates start on the second.
func (s *Sampler) Run(ctx context.Context) {
	t := time.NewTicker(SampleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.tick(now)
		}
	}
}

func (s *Sampler) tick(now time.Time) {
	stats := system.Collect()
	dt := now.Sub(s.last).Seconds()
	first := s.last.IsZero()
	s.last = now

	var rates []ifRate
	for _, ifc := range stats.Ifaces {
		cur := [2]uint64{ifc.RxBytes, ifc.TxBytes}
		prev, seen := s.prev[ifc.Name]
		s.prev[ifc.Name] = cur
		if first || !seen || dt <= 0 {
			continue
		}
		rates = append(rates, ifRate{
			iface: ifc.Name,
			rx:    perSec(prev[0], cur[0], dt),
			tx:    perSec(prev[1], cur[1], dt),
		})
	}
	if len(rates) == 0 {
		return
	}
	if err := s.store.insert(now, rates); err != nil {
		log.Printf("traffic: insert: %v", err)
	}
}

// perSec is the byte rate between two cumulative counter reads. A counter that
// went backwards (interface reset, reboot, wrap) yields 0 rather than a spike.
func perSec(prev, cur uint64, dt float64) float64 {
	if cur < prev {
		return 0
	}
	return float64(cur-prev) / dt
}
