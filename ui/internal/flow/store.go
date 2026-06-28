// Package flow is the baseline network-visibility pipeline (plan.md §8,
// docs/visibility-design.md): the kernel's pflow(4) exporter ships the pf state
// table as IPFIX, a UDP collector decodes it, and flows land in a SQLite store
// of short-lived raw records plus age-bounded rollups. The Visibility page
// queries the rollups for top talkers and a volume series, and the raw table
// for a recent flow log. It is pure Go + kernel — no Redis, no ntopng, no C —
// so it ships always-on in the base image; the nDPI app labels and the ntopng
// power tier layer on top of this later.
//
// The data model mirrors the traffic sampler: one writer connection, WAL mode,
// and retention trimming. Raw flows are high-volume and kept ~1h; never query
// them for long windows — query the rollups.
package flow

import (
	"database/sql"
	"fmt"
	"net/netip"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// rawRetention bounds the high-volume raw flow log. The flow log view only
	// looks back minutes; an hour is generous headroom.
	rawRetention = time.Hour
	// rollRetention bounds the rollups by age: a little over the longest
	// (month) view, matching the traffic store.
	rollRetention = 32 * 24 * time.Hour
)

// Bucket widths the rollup pass maintains. Every flow is folded into both its
// minute and its hour bucket, so the hour/day views read width=60 and the
// week/month views read width=3600 without re-aggregating raw.
const (
	minuteWidth = 60
	hourWidth   = 3600
)

const schema = `
CREATE TABLE IF NOT EXISTS flows (
	ts    INTEGER NOT NULL,  -- unix seconds the record was collected
	src   TEXT    NOT NULL,
	dst   TEXT    NOT NULL,
	sport INTEGER NOT NULL,
	dport INTEGER NOT NULL,
	proto INTEGER NOT NULL,  -- IP protocol number (6=TCP, 17=UDP, …)
	bytes INTEGER NOT NULL,
	pkts  INTEGER NOT NULL,
	iface INTEGER NOT NULL,  -- ingress ifindex from pflow (0 if absent)
	app   TEXT              -- nDPI app label; NULL until the helper lands
);
CREATE INDEX IF NOT EXISTS flows_ts ON flows(ts);

-- Per-host rollup: bytes a host sent (out, as flow src) and received (in, as
-- flow dst). Direction is decided at the flow level — src sent, dst received —
-- so no local-subnet knowledge is needed. Top talkers = in+out.
CREATE TABLE IF NOT EXISTS host_roll (
	bucket INTEGER NOT NULL,  -- unix seconds, bucket start
	width  INTEGER NOT NULL,  -- bucket width seconds (60 or 3600)
	host   TEXT    NOT NULL,
	inb    INTEGER NOT NULL,  -- bytes received (host == dst)
	outb   INTEGER NOT NULL,  -- bytes sent (host == src)
	pkts   INTEGER NOT NULL,
	PRIMARY KEY (bucket, width, host)
);
CREATE INDEX IF NOT EXISTS host_roll_w ON host_roll(width, bucket);

-- Per-app rollup, populated once the nDPI helper enriches flows. Empty at
-- baseline, but the schema and query path ship now so app labels light up with
-- no migration.
CREATE TABLE IF NOT EXISTS app_roll (
	bucket INTEGER NOT NULL,
	width  INTEGER NOT NULL,
	app    TEXT    NOT NULL,
	bytes  INTEGER NOT NULL,
	pkts   INTEGER NOT NULL,
	PRIMARY KEY (bucket, width, app)
);
CREATE INDEX IF NOT EXISTS app_roll_w ON app_roll(width, bucket);

-- Single-row watermark: the ts of the newest raw flow already folded into the
-- rollups, so each raw flow is counted exactly once across rollup passes.
CREATE TABLE IF NOT EXISTS rollup_meta (
	id        INTEGER PRIMARY KEY CHECK (id = 0),
	watermark INTEGER NOT NULL
);
INSERT OR IGNORE INTO rollup_meta (id, watermark) VALUES (0, 0);
`

// Record is one decoded flow handed to the store by the collector. Bytes/Pkts
// are the flow's totals as reported by pflow; App is empty until nDPI lands.
type Record struct {
	Src, Dst     netip.Addr
	SPort, DPort uint16
	Proto        uint8
	Bytes, Pkts  uint64
	IfIndex      uint32
	App          string
}

// Store owns the flow database: a single writer connection, like the traffic
// and logs stores, so SQLite's write serialization sidesteps SQLITE_BUSY
// between the collector, the rollup pass, and retention trimming.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the flow database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("flow schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Insert appends decoded flows and trims the raw ring to rawRetention. The
// collector batches a packet's records into one call so the insert and trim
// share a transaction.
func (s *Store) Insert(t time.Time, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO flows
		(ts, src, dst, sport, dport, proto, bytes, pkts, iface, app)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range recs {
		var app any
		if r.App != "" {
			app = r.App
		}
		if _, err := stmt.Exec(t.Unix(), r.Src.String(), r.Dst.String(),
			r.SPort, r.DPort, r.Proto, r.Bytes, r.Pkts, r.IfIndex, app); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM flows WHERE ts < ?`,
		t.Add(-rawRetention).Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// Rollup folds every raw flow newer than the watermark into the host and app
// rollups (both minute and hour buckets), advances the watermark, and trims the
// rollups to rollRetention. Idempotent and safe to call on a timer: a flow at
// or below the watermark is never re-counted.
func (s *Store) Rollup(now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var watermark int64
	if err := tx.QueryRow(`SELECT watermark FROM rollup_meta WHERE id = 0`).Scan(&watermark); err != nil {
		return err
	}

	// Fold the host totals for each width. The bucket key floors ts to the
	// width; ON CONFLICT accumulates so repeated passes over a still-filling
	// bucket sum correctly.
	for _, width := range []int{minuteWidth, hourWidth} {
		if _, err := tx.Exec(`
			INSERT INTO host_roll (bucket, width, host, inb, outb, pkts)
			SELECT (ts/?)*?, ?, host, SUM(inb), SUM(outb), SUM(pkts) FROM (
				SELECT ts, src AS host, 0 AS inb, bytes AS outb, pkts FROM flows WHERE ts > ?
				UNION ALL
				SELECT ts, dst AS host, bytes AS inb, 0 AS outb, pkts FROM flows WHERE ts > ?
			)
			GROUP BY (ts/?)*?, host
			ON CONFLICT(bucket, width, host) DO UPDATE SET
				inb  = inb  + excluded.inb,
				outb = outb + excluded.outb,
				pkts = pkts + excluded.pkts`,
			width, width, width, watermark, watermark, width, width); err != nil {
			return fmt.Errorf("host rollup w=%d: %w", width, err)
		}
		if _, err := tx.Exec(`
			INSERT INTO app_roll (bucket, width, app, bytes, pkts)
			SELECT (ts/?)*?, ?, app, SUM(bytes), SUM(pkts)
			FROM flows WHERE ts > ? AND app IS NOT NULL
			GROUP BY (ts/?)*?, app
			ON CONFLICT(bucket, width, app) DO UPDATE SET
				bytes = bytes + excluded.bytes,
				pkts  = pkts  + excluded.pkts`,
			width, width, width, watermark, width, width); err != nil {
			return fmt.Errorf("app rollup w=%d: %w", width, err)
		}
	}

	// Advance the watermark to the newest raw ts we just folded.
	var newWatermark sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(ts) FROM flows WHERE ts > ?`, watermark).Scan(&newWatermark); err != nil {
		return err
	}
	if newWatermark.Valid {
		if _, err := tx.Exec(`UPDATE rollup_meta SET watermark = ? WHERE id = 0`, newWatermark.Int64); err != nil {
			return err
		}
	}

	cutoff := now.Add(-rollRetention).Unix()
	if _, err := tx.Exec(`DELETE FROM host_roll WHERE bucket < ?`, cutoff); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM app_roll WHERE bucket < ?`, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

type window struct{ span, width int } // seconds

// windows map a range name to its lookback span and the rollup bucket width to
// read, chosen so each view returns a manageable number of points.
var windows = map[string]window{
	"hour":  {3600, minuteWidth},
	"day":   {86400, minuteWidth},
	"week":  {604800, hourWidth},
	"month": {2592000, hourWidth},
}

func resolveWindow(name string) (string, window) {
	w, ok := windows[name]
	if !ok {
		return "hour", windows["hour"]
	}
	return name, w
}

// Talker is one host's traffic over the query window.
type Talker struct {
	Host string `json:"host"`
	In   int64  `json:"in"`  // bytes received
	Out  int64  `json:"out"` // bytes sent
	Pkts int64  `json:"pkts"`
}

// VolumePoint is total bytes across all hosts in one bucket.
type VolumePoint struct {
	T     int64 `json:"t"` // unix seconds, bucket start
	Bytes int64 `json:"bytes"`
}

// AppTotal is one app's byte total over the window (empty until nDPI lands).
type AppTotal struct {
	App   string `json:"app"`
	Bytes int64  `json:"bytes"`
	Pkts  int64  `json:"pkts"`
}

// Flow is one recent raw flow for the flow-log table.
type Flow struct {
	T     int64  `json:"t"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	SPort int    `json:"sport"`
	DPort int    `json:"dport"`
	Proto int    `json:"proto"`
	Bytes int64  `json:"bytes"`
	Pkts  int64  `json:"pkts"`
	App   string `json:"app,omitempty"`
}

// Result is the JSON payload the Visibility baseline view renders.
type Result struct {
	Range   string        `json:"range"`
	Step    int           `json:"step"` // bucket width, seconds
	Span    int           `json:"span"` // lookback window, seconds
	Talkers []Talker      `json:"talkers"`
	Apps    []AppTotal    `json:"apps"`
	Volume  []VolumePoint `json:"volume"`
	Recent  []Flow        `json:"recent"`
}

// topN bounds the talker and app lists so a busy box returns a readable page.
const topN = 20

// Query assembles the baseline view for a named range: top talkers and per-app
// totals and the volume series from the rollups, plus a recent flow log from
// the raw table. "hour" is the default for an unknown name.
func (s *Store) Query(rangeName string) (Result, error) {
	rangeName, w := resolveWindow(rangeName)
	since := time.Now().Add(-time.Duration(w.span) * time.Second).Unix()
	res := Result{Range: rangeName, Step: w.width, Span: w.span}

	talkers, err := s.queryTalkers(w.width, since)
	if err != nil {
		return Result{}, err
	}
	res.Talkers = talkers

	apps, err := s.queryApps(w.width, since)
	if err != nil {
		return Result{}, err
	}
	res.Apps = apps

	volume, err := s.queryVolume(w.width, since)
	if err != nil {
		return Result{}, err
	}
	res.Volume = volume

	recent, err := s.queryRecent()
	if err != nil {
		return Result{}, err
	}
	res.Recent = recent
	return res, nil
}

func (s *Store) queryTalkers(width int, since int64) ([]Talker, error) {
	rows, err := s.db.Query(`
		SELECT host, SUM(inb), SUM(outb), SUM(pkts)
		FROM host_roll WHERE width = ? AND bucket >= ?
		GROUP BY host ORDER BY SUM(inb) + SUM(outb) DESC LIMIT ?`,
		width, since, topN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Talker
	for rows.Next() {
		var t Talker
		if err := rows.Scan(&t.Host, &t.In, &t.Out, &t.Pkts); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) queryApps(width int, since int64) ([]AppTotal, error) {
	rows, err := s.db.Query(`
		SELECT app, SUM(bytes), SUM(pkts)
		FROM app_roll WHERE width = ? AND bucket >= ?
		GROUP BY app ORDER BY SUM(bytes) DESC LIMIT ?`,
		width, since, topN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppTotal
	for rows.Next() {
		var a AppTotal
		if err := rows.Scan(&a.App, &a.Bytes, &a.Pkts); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) queryVolume(width int, since int64) ([]VolumePoint, error) {
	rows, err := s.db.Query(`
		SELECT bucket, SUM(inb) + SUM(outb)
		FROM host_roll WHERE width = ? AND bucket >= ?
		GROUP BY bucket ORDER BY bucket`,
		width, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VolumePoint
	for rows.Next() {
		var p VolumePoint
		if err := rows.Scan(&p.T, &p.Bytes); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// recentLimit caps the flow log. The raw window is short (rawRetention), so the
// newest few hundred flows are all the table can show.
const recentLimit = 200

func (s *Store) queryRecent() ([]Flow, error) {
	rows, err := s.db.Query(`
		SELECT ts, src, dst, sport, dport, proto, bytes, pkts, COALESCE(app, '')
		FROM flows ORDER BY ts DESC LIMIT ?`, recentLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Flow
	for rows.Next() {
		var f Flow
		if err := rows.Scan(&f.T, &f.Src, &f.Dst, &f.SPort, &f.DPort,
			&f.Proto, &f.Bytes, &f.Pkts, &f.App); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
