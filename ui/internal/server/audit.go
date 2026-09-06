package server

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// The audit trail (docs/security-plan.md SEC-10).
//
// Every security-relevant action records who did it, from where, and what
// happened. "Security-relevant" here means: anything that changes who can log
// in, anything that changes what the firewall does, and anything that hands out
// a secret. After an incident, these are the lines someone reads.
//
// Writes go to a table with its own retention, not to the log ring — see
// logs.Audit for why that distinction is load-bearing.

// audit records an action with no authenticated actor, or where the actor is
// already in the detail (the login handlers, which run before a session
// exists).
func (s *Server) audit(event, format string, args ...any) {
	s.auditAs("", event, format, args...)
}

// auditRequest records an action attributed to the request's authenticated
// user, with its source address appended — the two facts an incident review
// always wants and that a handler should never have to remember to include.
func (s *Server) auditRequest(r *http.Request, event, format string, args ...any) {
	actor, _ := r.Context().Value(userKey{}).(string)
	detail := fmt.Sprintf(format, args...)
	if detail != "" {
		detail += " "
	}
	s.auditAs(actor, event, "%sfrom=%s", detail, remoteIP(r))
}

func (s *Server) auditAs(actor, event, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)
	// The process log too: on a box whose SQLite is wedged or whose disk is
	// full, the thing you most want recorded is exactly the thing that cannot
	// be written to the database.
	log.Printf("audit %s actor=%s %s", event, orDash(actor), detail)
	if s.logStore != nil {
		if err := s.logStore.Audit(event, actor, detail, time.Now()); err != nil {
			log.Printf("audit: %v", err)
		}
	}
}

func orDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

// auditResult renders an operation's outcome for the trail. The error text
// matters: "apply failed" without pfctl's complaint is not worth storing.
func auditResult(err error) string {
	if err == nil {
		return "ok"
	}
	return fmt.Sprintf("error: %v", err)
}
