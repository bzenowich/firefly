package logs

import (
	"strings"
	"time"
)

// The audit trail (docs/security-plan.md SEC-10).
//
// Before this, the only thing the appliance recorded was web-shell lifecycle
// events. There was no record of a login — succeeded or failed — nor of a user
// being created, a password changed, 2FA disabled, a config applied, a backup
// downloaded, or a config restored. After an incident there was nothing to read.
//
// It is a separate table from the log ring on purpose. The ring is trimmed to
// its cap by whatever is chattiest, and on a firewall that is pf: a scan that
// fills the ring would quietly evict the very lines an admin needs afterwards.
// An audit trail that a burst of traffic can erase is not an audit trail.
const auditSchema = `
CREATE TABLE IF NOT EXISTS audit (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     INTEGER NOT NULL,           -- unix seconds
	event  TEXT    NOT NULL,           -- dotted action, e.g. "login.failed"
	actor  TEXT    NOT NULL,           -- authenticated user, or "-" pre-login
	detail TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_event_id ON audit(event, id);
`

// AuditCap is how many audit rows are kept. Deliberately its own number, and
// deliberately generous: these rows are small, rare compared to packet logs,
// and the ones worth having are often the oldest ones in the window.
const AuditCap = 20000

// AuditEntry is one recorded action.
type AuditEntry struct {
	ID     int64
	Time   time.Time
	Event  string
	Actor  string
	Detail string
}

// Audit records one action. Actor is the authenticated user, or empty for
// something that happened before or without a login.
func (s *Store) Audit(event, actor, detail string, t time.Time) error {
	if actor == "" {
		actor = "-"
	}
	_, err := s.db.Exec(`INSERT INTO audit (ts, event, actor, detail) VALUES (?, ?, ?, ?)`,
		t.Unix(), event, actor, strings.TrimRight(detail, "\n"))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - ?`, AuditCap)
	return err
}

// AuditFilter selects audit entries; zero values mean "any".
type AuditFilter struct {
	Event    string
	Contains string
	Limit    int
}

// RecentAudit returns the newest matching audit entries, newest first.
func (s *Store) RecentAudit(f AuditFilter) ([]AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q := `SELECT id, ts, event, actor, detail FROM audit WHERE 1=1`
	var args []any
	if f.Event != "" {
		// Prefix match, so "login" selects login.ok, login.failed and
		// login.blocked without the admin needing to know the full set.
		q += ` AND event LIKE ? ESCAPE '\'`
		args = append(args, escapeLike(f.Event)+"%")
	}
	if f.Contains != "" {
		q += ` AND (detail LIKE ? ESCAPE '\' OR actor LIKE ? ESCAPE '\')`
		pat := "%" + escapeLike(f.Contains) + "%"
		args = append(args, pat, pat)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Event, &e.Actor, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// escapeLike neutralises LIKE wildcards in operator-supplied filter text, so a
// filter of "100%" means what it says.
func escapeLike(v string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(v)
}
