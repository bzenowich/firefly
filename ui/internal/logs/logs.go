// Package logs is the appliance log pipeline: pflog and syslog lines land in
// a SQLite ring buffer (plan.md §6) that the Logs page filters and tails.
package logs

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Entry is one captured log line.
type Entry struct {
	ID     int64
	Time   time.Time
	Source string // "pf" | "system"
	Line   string
}

// Store is the ring buffer. Writes trim to Cap rows, so the database stays
// bounded no matter how chatty pf gets.
type Store struct {
	db  *sql.DB
	cap int64
}

const schema = `
CREATE TABLE IF NOT EXISTS logs (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     INTEGER NOT NULL,           -- unix seconds
	source TEXT    NOT NULL,
	line   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_source_id ON logs(source, id);
`

// Open opens (creating if needed) the ring buffer at path, keeping at most
// capacity rows.
func Open(path string, capacity int64) (*Store, error) {
	// Single writer connection: SQLite serializes writes anyway, and one
	// connection sidesteps SQLITE_BUSY between collector and trim.
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("logs schema: %w", err)
	}
	return &Store{db: db, cap: capacity}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Insert appends one line and trims the ring.
func (s *Store) Insert(source, line string, t time.Time) error {
	_, err := s.db.Exec(`INSERT INTO logs (ts, source, line) VALUES (?, ?, ?)`,
		t.Unix(), source, strings.TrimRight(line, "\n"))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM logs WHERE id <= (SELECT MAX(id) FROM logs) - ?`, s.cap)
	return err
}

// Filter selects entries; zero values mean "any".
type Filter struct {
	Source   string
	Contains string
	Limit    int
}

// Recent returns the newest matching entries, newest first.
func (s *Store) Recent(f Filter) ([]Entry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q := `SELECT id, ts, source, line FROM logs WHERE 1=1`
	var args []any
	if f.Source != "" {
		q += ` AND source = ?`
		args = append(args, f.Source)
	}
	if f.Contains != "" {
		q += ` AND line LIKE ? ESCAPE '\'`
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(f.Contains)
		args = append(args, "%"+esc+"%")
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Line); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}
