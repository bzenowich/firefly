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
	"log"
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
	// minuteRollRetention bounds the *minute-width* rollup rows separately.
	// They back only the hour and day views (see windows), so nothing ever
	// reads one older than 24h — but every remote IP a host talks to is its own
	// "host" row, so keeping them the full rollRetention leaves millions of rows
	// no query touches, slowing every upsert and bloating the file. Two days is
	// a day of slack over the widest minute-width view.
	minuteRollRetention = 2 * 24 * time.Hour
	// clockStepSlack bounds how far the watermark may sit ahead of the current
	// second before Rollup treats it as a backwards clock step (an NTP
	// correction of a bad RTC, typically at boot) rather than ordinary skew.
	// A small step just strands the rows that land below the watermark — a
	// bounded one-time undercount. A large one would park the watermark in the
	// future and stop the rollups for as long as the step lasted, so past this
	// slack the watermark is pulled back to the current second; at worst the
	// raw window is then folded twice, which is far cheaper than rollups that
	// silently stay dead for hours.
	clockStepSlack = rawRetention
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
	-- ts is when the collector received the record, not when the flow ran.
	-- pflow(4) exports a flow once, at pf state teardown, and does carry
	-- flowStart/flowEnd (IEs 150/151 and 152/153), but bucketing by them would
	-- be wrong in both directions: a flow's bytes belong spread across its
	-- lifetime, not stacked on either endpoint, and a start timestamp minutes
	-- or hours in the past would land below the rollup watermark (never folded)
	-- and inside the raw-retention trim (deleted on insert). So an hour-long
	-- transfer is charged to the minute it ended; the totals are right, the
	-- shape of the volume series is not. Spreading a flow across the buckets it
	-- spans is the real fix and needs its own design pass.
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
-- Late-label backfill index (BackfillApp): the update touches the still-NULL
-- rows of one 5-tuple, so index exactly those. Partial on app IS NULL keeps it
-- to the rows the update can ever hit — a row leaves the index the moment it is
-- stamped — instead of indexing the whole high-volume raw table; without it the
-- update falls back to the ts index and visits the entire raw window per label.
-- New indexes are added here: the schema is CREATE ... IF NOT EXISTS and is
-- executed on every Open, so adding a line migrates existing databases.
CREATE INDEX IF NOT EXISTS flows_unlabeled ON flows(src, sport, dst, dport) WHERE app IS NULL;

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

-- Single-row watermark: the last whole second fully folded into the rollups
-- (not merely the newest ts seen), so each raw flow is counted exactly once
-- across rollup passes and none can fall between two passes. See Rollup.
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

// BackfillApp stamps an app label onto recent raw flows that were inserted
// before the label arrived (design §5, path 2). It matches the flow in either
// direction and only fills rows still NULL, bounded to the raw window so the
// scan stays cheap (the flows_unlabeled partial index serves both directions).
// This corrects the flow-log view for the late-label race; the common case
// (label before insert) is handled by stamp-at-insert instead. Callers skip it
// for a label they have already applied — the helper re-emits every live flow's
// label every couple of minutes, and re-running this update for each of those
// would be pure waste (enrich.go).
func (s *Store) BackfillApp(now time.Time, l Label) error {
	since := now.Add(-rawRetention).Unix()
	src, dst := l.Src.String(), l.Dst.String()
	_, err := s.db.Exec(`
		UPDATE flows SET app = ?
		WHERE app IS NULL AND proto = ? AND ts > ? AND (
			(src = ? AND sport = ? AND dst = ? AND dport = ?) OR
			(src = ? AND sport = ? AND dst = ? AND dport = ?)
		)`,
		l.App, l.Proto, since,
		src, l.SPort, dst, l.DPort,
		dst, l.DPort, src, l.SPort)
	return err
}

// Rollup folds raw flows newer than the watermark into the host and app rollups
// (both minute and hour buckets), advances the watermark, and trims the rollups
// by age. Idempotent and safe to call on a timer: a flow at or below the
// watermark is never re-counted, and no flow can be skipped.
//
// Only whole seconds strictly in the past are folded. ts has 1 s granularity,
// so the second `now` falls in is still filling: folding it and parking the
// watermark on MAX(ts) — as this used to — left every row inserted after the
// pass but inside that same second below the watermark forever, a silent
// undercount concentrated in exactly the bursts that matter. Folding up to
// `now` exclusive and setting the watermark to the last whole second instead
// makes stranding impossible: a row is either already folded or still above
// the watermark.
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

	// upto is exclusive: rows in the current second are left for the next pass.
	upto := now.Unix()
	if watermark-upto > int64(clockStepSlack/time.Second) {
		// The clock stepped backwards far enough that the watermark is stuck in
		// the future and nothing would ever fold again (see clockStepSlack).
		log.Printf("flow: rollup watermark %d is %ds ahead of the clock; "+
			"resetting (backwards clock step?)", watermark, watermark-upto)
		watermark = upto - 1
	}

	// Fold the host totals for each width. The bucket key floors ts to the
	// width; ON CONFLICT accumulates so repeated passes over a still-filling
	// bucket sum correctly.
	for _, width := range []int{minuteWidth, hourWidth} {
		if _, err := tx.Exec(`
			INSERT INTO host_roll (bucket, width, host, inb, outb, pkts)
			SELECT (ts/?)*?, ?, host, SUM(inb), SUM(outb), SUM(pkts) FROM (
				SELECT ts, src AS host, 0 AS inb, bytes AS outb, pkts FROM flows WHERE ts > ? AND ts < ?
				UNION ALL
				SELECT ts, dst AS host, bytes AS inb, 0 AS outb, pkts FROM flows WHERE ts > ? AND ts < ?
			)
			GROUP BY (ts/?)*?, host
			ON CONFLICT(bucket, width, host) DO UPDATE SET
				inb  = inb  + excluded.inb,
				outb = outb + excluded.outb,
				pkts = pkts + excluded.pkts`,
			width, width, width, watermark, upto, watermark, upto, width, width); err != nil {
			return fmt.Errorf("host rollup w=%d: %w", width, err)
		}
		if _, err := tx.Exec(`
			INSERT INTO app_roll (bucket, width, app, bytes, pkts)
			SELECT (ts/?)*?, ?, app, SUM(bytes), SUM(pkts)
			FROM flows WHERE ts > ? AND ts < ? AND app IS NOT NULL
			GROUP BY (ts/?)*?, app
			ON CONFLICT(bucket, width, app) DO UPDATE SET
				bytes = bytes + excluded.bytes,
				pkts  = pkts  + excluded.pkts`,
			width, width, width, watermark, upto, width, width); err != nil {
			return fmt.Errorf("app rollup w=%d: %w", width, err)
		}
	}

	// Park the watermark on the last whole second: everything at or below it is
	// now folded, whether or not a row happened to carry that exact ts. The
	// watermark only ever advances, so a small backwards clock step can't move
	// it down and re-fold rows already counted (the big-step case is handled
	// above).
	if upto-1 > watermark {
		if _, err := tx.Exec(`UPDATE rollup_meta SET watermark = ? WHERE id = 0`, upto-1); err != nil {
			return err
		}
	}

	// Trim the rollups. Minute-width rows are cut early: only the hour and day
	// views read them (minuteRollRetention), while the hour-width rows backing
	// the week and month views keep the full rollRetention.
	cutoff := now.Add(-rollRetention).Unix()
	minCutoff := now.Add(-minuteRollRetention).Unix()
	if _, err := tx.Exec(`DELETE FROM host_roll WHERE bucket < ? OR (width = ? AND bucket < ?)`,
		cutoff, minuteWidth, minCutoff); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM app_roll WHERE bucket < ? OR (width = ? AND bucket < ?)`,
		cutoff, minuteWidth, minCutoff); err != nil {
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

// HostTotals returns per-host in/out byte and packet totals over the named
// range, keyed by host IP string, for every host seen (not just the top talkers
// Query returns). The device table (internal/devices) joins this onto ARP/lease
// data to attach per-device usage. An unknown range name defaults to "hour".
func (s *Store) HostTotals(rangeName string) (map[string]Talker, error) {
	_, w := resolveWindow(rangeName)
	since := time.Now().Add(-time.Duration(w.span) * time.Second).Unix()
	rows, err := s.db.Query(`
		SELECT host, SUM(inb), SUM(outb), SUM(pkts)
		FROM host_roll WHERE width = ? AND bucket >= ?
		GROUP BY host`, w.width, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Talker{}
	for rows.Next() {
		var t Talker
		if err := rows.Scan(&t.Host, &t.In, &t.Out, &t.Pkts); err != nil {
			return nil, err
		}
		out[t.Host] = t
	}
	return out, rows.Err()
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

// queryVolume returns total bytes per bucket: the traffic the box actually
// moved in that bucket, each flow counted once. Every flow contributes its bytes
// to exactly two host_roll rows — its source's outb and its destination's inb —
// so SUM(outb) across hosts is the true total (SUM(inb) is the identical
// number, and summing both, as this used to, doubled every byte). The chart is
// "how much traffic crossed the firewall", not "how much each end saw"; the
// per-direction split lives in the talker table, which reports in and out
// separately.
func (s *Store) queryVolume(width int, since int64) ([]VolumePoint, error) {
	rows, err := s.db.Query(`
		SELECT bucket, SUM(outb)
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
