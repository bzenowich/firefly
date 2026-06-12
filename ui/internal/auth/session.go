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
	expires time.Time
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{ttl: ttl, m: map[string]*session{}}
}

// Create starts a session for user and returns its token.
func (s *Sessions) Create(user string) string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	token := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	s.m[token] = &session{user: user, expires: time.Now().Add(s.ttl)}
	return token
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
