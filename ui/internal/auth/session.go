package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Sessions is an in-memory session store keyed by opaque random tokens.
// Sessions die with the daemon, which is the right failure mode for an
// appliance: reboot = re-login.
type Sessions struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]*session
}

type session struct {
	user    string
	csrf    string // synchronizer token echoed by every state-changing request
	expires time.Time
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{ttl: ttl, m: map[string]*session{}}
}

// Create starts a session for user and returns its token.
func (s *Sessions) Create(user string) string {
	token := randomToken()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	s.m[token] = &session{user: user, csrf: randomToken(), expires: time.Now().Add(s.ttl)}
	return token
}

// randomToken returns a 256-bit opaque secret in hex.
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return hex.EncodeToString(b[:])
}

// Get returns the user owning token and extends the session: the TTL is an
// idle timeout, so activity keeps a login alive.
func (s *Sessions) Get(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	if !ok {
		return "", false
	}
	if time.Now().After(sess.expires) {
		delete(s.m, token)
		return "", false
	}
	sess.expires = time.Now().Add(s.ttl)
	return sess.user, true
}

// CSRF returns the anti-CSRF token bound to a session. It is a second secret
// that only lives in the rendered page and never in a cookie, so a cross-site
// request — which cannot read the page — has nothing to send. Unlike Get it
// does not extend the session; the caller has already done that.
func (s *Sessions) CSRF(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	if !ok || time.Now().After(sess.expires) {
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
	now := time.Now()
	for token, sess := range s.m {
		if now.After(sess.expires) {
			delete(s.m, token)
		}
	}
}
