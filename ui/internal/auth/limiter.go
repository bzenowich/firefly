package auth

import (
	"sync"
	"time"
)

// Limiter throttles login attempts per key.
//
// It answers two different questions with two different mechanisms, because
// the buckets it is asked about have opposite failure modes
// (docs/security-plan.md SEC-12):
//
//   - An *address* bucket is a hard cap. A host that has guessed wrong five
//     times is not going to be inconvenienced by being told to wait, and
//     refusing outright is the cheapest thing the box can do.
//
//   - A *username* bucket must never refuse outright. It was added to stop a
//     botnet grinding one account, but a hard cap there means any LAN device
//     can lock the admin out of their own firewall for the window, in a loop,
//     forever — trading a remote brute-force for a local denial of service.
//     So it delays instead: escalating, capped, and applied to the attempt
//     rather than blocking it. An attacker gets a few attempts an hour; a
//     legitimate admin waits a few seconds and gets in.
//
// The map is bounded. Its keys are attacker-supplied usernames, so a spray of
// distinct names would otherwise grow it without limit between the accesses
// that prune it.
type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	m      map[string]*attempts

	// now is overridable for tests; nil means time.Now.
	now func() time.Time
}

type attempts struct {
	fails int
	first time.Time
	seen  time.Time // last touch, for LRU eviction
}

// maxKeys bounds the map. Well above any real appliance's traffic — a few
// admins and their addresses — and small enough that a username spray cannot
// turn the limiter into the memory exhaustion it exists to prevent.
const maxKeys = 4096

// maxDelay caps the escalating username delay. Long enough to make automated
// guessing worthless, short enough that a legitimate admin who fat-fingered
// their password a few times is annoyed rather than locked out.
const maxDelay = 30 * time.Second

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, m: map[string]*attempts{}}
}

func (l *Limiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// Allow reports whether key may attempt a login now. It is the hard cap, for
// address buckets.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune()
	a, ok := l.m[key]
	if !ok {
		return true
	}
	a.seen = l.clock()
	return a.fails < l.max
}

// Delay returns how long this key should be made to wait before its attempt is
// processed. It is the soft alternative to Allow, for username buckets: the
// attempt always proceeds, eventually.
//
// The delay doubles per failure past the cap and is capped at maxDelay, so the
// cost of guessing grows without ever becoming a lockout someone else can
// inflict on the account's owner.
func (l *Limiter) Delay(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune()
	a, ok := l.m[key]
	if !ok {
		return 0
	}
	a.seen = l.clock()
	over := a.fails - l.max
	if over < 0 {
		return 0
	}
	// 1s, 2s, 4s, ... capped. A shift rather than a power so a long-running
	// attack cannot overflow its way back to zero delay.
	if over > 30 {
		return maxDelay
	}
	if d := time.Duration(1<<uint(over)) * time.Second; d < maxDelay {
		return d
	}
	return maxDelay
}

// Fail records a failed login for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	a, ok := l.m[key]
	if !ok || now.Sub(a.first) > l.window {
		l.evictIfFull()
		l.m[key] = &attempts{fails: 1, first: now, seen: now}
		return
	}
	a.fails++
	a.seen = now
}

// Reset clears the failure count for key after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, key)
}

// prune drops entries whose window has passed. Caller holds mu.
func (l *Limiter) prune() {
	now := l.clock()
	for key, a := range l.m {
		if now.Sub(a.first) > l.window {
			delete(l.m, key)
		}
	}
}

// evictIfFull drops the least recently touched entry when the map is at its
// bound. Caller holds mu.
//
// Evicting the *coldest* key is what keeps this honest under a spray: the
// attacker's thousands of one-shot usernames are all cold, while the handful
// of keys belonging to a real attack — or a real admin — are touched
// repeatedly and survive.
func (l *Limiter) evictIfFull() {
	if len(l.m) < maxKeys {
		return
	}
	var oldestKey string
	var oldest time.Time
	for key, a := range l.m {
		if oldestKey == "" || a.seen.Before(oldest) {
			oldestKey, oldest = key, a.seen
		}
	}
	delete(l.m, oldestKey)
}
