package auth

import (
	"sync"
	"time"
)

// Limiter throttles login attempts per key (remote IP): after max failures
// within window, further attempts are refused until the window expires.
// A successful login resets the key.
type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	m      map[string]*attempts
}

type attempts struct {
	fails int
	first time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, m: map[string]*attempts{}}
}

// Allow reports whether key may attempt a login now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune()
	a, ok := l.m[key]
	return !ok || a.fails < l.max
}

// Fail records a failed login for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.m[key]
	if !ok || time.Since(a.first) > l.window {
		l.m[key] = &attempts{fails: 1, first: time.Now()}
		return
	}
	a.fails++
}

// Reset clears the failure count for key after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, key)
}

// prune drops entries whose window has passed. Caller holds mu.
func (l *Limiter) prune() {
	now := time.Now()
	for key, a := range l.m {
		if now.Sub(a.first) > l.window {
			delete(l.m, key)
		}
	}
}
