package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Sessions is an in-memory session store keyed by opaque random tokens.
// Sessions die with the daemon, which is the right failure mode for an
// appliance: reboot = re-login.
//
// Two clocks bound a session (docs/security-plan.md SEC-11). The idle TTL is
// what an admin notices: activity keeps a login alive. The absolute lifetime is
// what an attacker notices: it does not move, whatever the session does. Only
// the idle timer existed before, and the dashboard polls every two seconds —
// so an open tab was an immortal session, and a cookie stolen from a laptop
// that is never closed never expired.
type Sessions struct {
	mu       sync.Mutex
	ttl      time.Duration
	lifetime time.Duration
	m        map[string]*session

	// now is overridable for tests; nil means time.Now.
	now func() time.Time
}

type session struct {
	user    string
	csrf    string // synchronizer token echoed by every state-changing request
	expires time.Time
	created time.Time
	// deadline is the absolute end of the session, set once at creation and
	// never extended.
	deadline time.Time

	// lastSeen and from make the session inventory meaningful: an admin looking
	// at the list needs to recognise their own sessions to know which of the
	// others to revoke.
	lastSeen time.Time
	from     string

	// elevated is when the re-authentication window expires (SEC-6). Zero means
	// the session has not re-authenticated, which is the normal state.
	elevated time.Time
}

// Session is one entry in the inventory shown to an admin.
type Session struct {
	// ID identifies the session for revocation without handing the page the
	// bearer token itself: a session list that printed live cookies into HTML
	// would be a credential disclosure, not a security feature.
	ID       string
	User     string
	From     string
	Created  time.Time
	LastSeen time.Time
	Expires  time.Time
	Current  bool
}

func NewSessions(ttl, lifetime time.Duration) *Sessions {
	return &Sessions{ttl: ttl, lifetime: lifetime, m: map[string]*session{}}
}

func (s *Sessions) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Create starts a session for user, from the given source address, and returns
// its token.
func (s *Sessions) Create(user, from string) string {
	token := randomToken()
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	s.m[token] = &session{
		user:     user,
		csrf:     randomToken(),
		expires:  now.Add(s.ttl),
		created:  now,
		deadline: now.Add(s.lifetime),
		lastSeen: now,
		from:     from,
	}
	return token
}

// SetupToken returns the first-run setup token: short enough to read off a
// console and retype, long enough that guessing it is not worth trying.
//
// 8 groups would be unreadable; 4 groups of 4 from a 32-symbol alphabet is 80
// bits, which is far past what a rate-limited form can be brute-forced for. The
// alphabet omits I, L, O, U and 0/1 — the characters people misread off a
// serial console, and the ones that make "is that a one or an ell" a support
// call.
func SetupToken() string {
	const alphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	out := make([]byte, 0, 19)
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(v)%len(alphabet)])
	}
	return string(out)
}

// RandomToken returns a 256-bit opaque secret in hex. Exported because the
// pre-session login token (docs/security-plan.md SEC-15) needs the same
// quality of randomness as a session token and there is no reason to have two
// generators.
func RandomToken() string { return randomToken() }

// randomToken returns a 256-bit opaque secret in hex.
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return hex.EncodeToString(b[:])
}

// Get returns the user owning token and extends the idle timer. Activity keeps
// a login alive against the idle TTL, and does nothing at all to the absolute
// deadline.
func (s *Sessions) Get(token string) (string, bool) {
	return s.GetFrom(token, "")
}

// GetFrom is Get, recording where the request came from for the inventory. An
// empty address leaves the recorded one alone.
func (s *Sessions) GetFrom(token, from string) (string, bool) {
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	if !ok {
		return "", false
	}
	if s.deadLocked(sess, now) {
		delete(s.m, token)
		return "", false
	}
	sess.expires = now.Add(s.ttl)
	sess.lastSeen = now
	if from != "" {
		sess.from = from
	}
	return sess.user, true
}

// deadLocked reports whether a session has hit either clock. Caller holds mu.
func (s *Sessions) deadLocked(sess *session, now time.Time) bool {
	return now.After(sess.expires) || now.After(sess.deadline)
}

// List returns the live sessions, newest first, marking the caller's own.
//
// The IDs are derived from the tokens, never the tokens themselves — see
// Session.ID.
func (s *Sessions) List(currentToken string) []Session {
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	out := make([]Session, 0, len(s.m))
	for token, sess := range s.m {
		if s.deadLocked(sess, now) {
			continue
		}
		expires := sess.expires
		if sess.deadline.Before(expires) {
			expires = sess.deadline
		}
		out = append(out, Session{
			ID:       sessionID(token),
			User:     sess.user,
			From:     sess.from,
			Created:  sess.created,
			LastSeen: sess.lastSeen,
			Expires:  expires,
			Current:  token == currentToken,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// DeleteID revokes one session by its inventory id and reports whether it
// existed. Revoking by id rather than by token is what lets the page offer the
// action without ever holding the credential.
func (s *Sessions) DeleteID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token := range s.m {
		if sessionID(token) == id {
			delete(s.m, token)
			return true
		}
	}
	return false
}

// DeleteOthers revokes every session belonging to user except the one named by
// keep, and reports how many were dropped. This is "sign out everywhere else":
// the action someone takes when they think a cookie has been stolen, so it must
// not log them out of the session they are taking it from.
func (s *Sessions) DeleteOthers(user, keep string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for token, sess := range s.m {
		if sess.user == user && token != keep {
			delete(s.m, token)
			n++
		}
	}
	return n
}

// sessionID is a stable, non-reversible handle for a session token.
//
// It is a hash, not a prefix: a prefix of a bearer token is a partial
// credential, and printing one into every rendered page would narrow a brute
// force by exactly as many bits as it revealed.
func sessionID(token string) string {
	sum := sha256.Sum256([]byte("fw-session-id:" + token))
	return hex.EncodeToString(sum[:8])
}

// Elevate marks a session as freshly re-authenticated for d
// (docs/security-plan.md SEC-6).
func (s *Sessions) Elevate(token string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[token]; ok {
		sess.elevated = s.clock().Add(d)
	}
}

// Elevated reports whether a session is inside its re-authentication window.
func (s *Sessions) Elevated(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	return ok && s.clock().Before(sess.elevated)
}

// DropElevation ends the re-authentication window early, which is what a
// password change or an explicit "lock" should do.
func (s *Sessions) DropElevation(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[token]; ok {
		sess.elevated = time.Time{}
	}
}

// CSRF returns the anti-CSRF token bound to a session. It is a second secret
// that only lives in the rendered page and never in a cookie, so a cross-site
// request — which cannot read the page — has nothing to send. Unlike Get it
// does not extend the session; the caller has already done that.
func (s *Sessions) CSRF(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	if !ok || s.deadLocked(sess, s.clock()) {
		return "", false
	}
	return sess.csrf, true
}

// DeleteUser revokes every session belonging to user and reports how many were
// dropped. Deleting an account or changing its password must not leave an
// already-issued cookie working (design-review §4.5).
func (s *Sessions) DeleteUser(user string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for token, sess := range s.m {
		if sess.user == user {
			delete(s.m, token)
			n++
		}
	}
	return n
}

// Delete ends the session for token (logout).
func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
}

// prune drops expired sessions so abandoned logins cannot grow the map
// without bound. Caller holds mu.
func (s *Sessions) prune() {
	now := s.clock()
	for token, sess := range s.m {
		if s.deadLocked(sess, now) {
			delete(s.m, token)
		}
	}
}
