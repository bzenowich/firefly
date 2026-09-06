// Package auth is the WebUI security boundary from plan.md §7: argon2id
// local users, opaque session cookies, and login rate limiting. TOTP is
// planned but not yet implemented.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// RFC 9106 second recommended parameter set (64 MiB, t=1). Comfortable on
// the appliance's RAM budget and adds ~50 ms per login attempt, which also
// helps the rate limiter.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// hashSlots bounds how many argon2 derivations run at once.
//
// Each one allocates argonMemory — 64 MiB — for its whole duration. The login
// limiter checks its buckets *before* hashing and records the failure *after*,
// so N simultaneous POSTs to /login are all admitted and all allocate at once:
// the 5-attempt cap is no defense against concurrency. Unauthenticated, from
// any LAN host, ~200 concurrent requests would be ~12.8 GB on a 16 GB box, and
// an unknown username still costs a full DummyHash verification by design
// (docs/security-plan.md SEC-4a).
//
// Capping concurrency rather than total attempts is the right shape: peak
// memory becomes a constant (slots × 64 MiB) no matter how hard the box is
// hit, and a legitimate login that has to queue for a few hundred milliseconds
// has not noticed.
var hashSlots = make(chan struct{}, hashConcurrency())

// hashConcurrency sizes the pool: enough that concurrent admins never queue
// behind each other, few enough that the worst case is a few hundred MiB.
func hashConcurrency() int {
	n := runtime.NumCPU()
	switch {
	case n < 1:
		return 1
	case n > 4:
		return 4
	default:
		return n
	}
}

// hashWait is how long a verification queues for a slot before giving up. It is
// generously above the ~50 ms a derivation takes, so only a real flood reaches
// it; past that, refusing is better than growing an unbounded backlog of
// requests each holding a connection.
const hashWait = 10 * time.Second

// acquireHashSlot takes a slot, waiting up to hashWait. It reports whether one
// was obtained; the caller must release it when obtained.
func acquireHashSlot() bool {
	select {
	case hashSlots <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(hashWait)
	defer t.Stop()
	select {
	case hashSlots <- struct{}{}:
		return true
	case <-t.C:
		return false
	}
}

func releaseHashSlot() { <-hashSlots }

// DummyHash is verified against when a login names an unknown user, so
// response timing does not reveal which usernames exist.
var DummyHash = HashPassword("dummy")

// HashPassword returns an argon2id hash of password in PHC string format.
//
// It queues for a slot rather than failing: every caller (first-run setup, user
// creation, password change) is a single deliberate admin action, not something
// an attacker can drive in a loop.
func HashPassword(password string) string {
	hashSlots <- struct{}{}
	defer releaseHashSlot()

	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// maxVerifyMemory caps the argon2 memory parameter this will honor from a
// stored hash.
//
// The parameters come from the hash itself so that stored hashes keep verifying
// across a defaults change — but the hash is not always ours: config.Users
// arrives wholesale from POST /system/restore, and validateUsers only checks
// the "$argon2id$" prefix. A crafted backup with m=16777216 turns one login
// attempt into a 16 GiB allocation. Anything above this is refused rather than
// attempted; it is 4x the current default, which is all the headroom a
// parameter increase could plausibly need (docs/security-plan.md SEC-4a).
const (
	maxVerifyMemory = 4 * argonMemory
	maxVerifyTime   = 16
)

// ParseHash validates a PHC-format argon2id hash and returns its parameters.
//
// It is exported so config.Validate can reject a bad hash at the point a config
// document enters the system rather than at the login that then mysteriously
// never succeeds — POST /system/restore accepts whole documents, and a hash
// this refuses is an account nobody can ever log into.
func ParseHash(hash string) (salt, key []byte, m, t uint32, p uint8, err error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, errors.New("not an argon2id hash")
	}
	var version int
	if _, e := fmt.Sscanf(parts[2], "v=%d", &version); e != nil || version != argon2.Version {
		return nil, nil, 0, 0, 0, fmt.Errorf("unsupported argon2 version")
	}
	if _, e := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); e != nil {
		return nil, nil, 0, 0, 0, errors.New("malformed parameters")
	}
	if m == 0 || m > maxVerifyMemory || t == 0 || t > maxVerifyTime || p == 0 {
		return nil, nil, 0, 0, 0, fmt.Errorf("parameters out of range (m=%d t=%d p=%d)", m, t, p)
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, nil, 0, 0, 0, errors.New("malformed salt")
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(key) == 0 {
		return nil, nil, 0, 0, 0, errors.New("malformed key")
	}
	return salt, key, m, t, p, nil
}

// VerifyPassword reports whether password matches the PHC-format hash. The
// parameters come from the hash itself, so stored hashes keep verifying if
// the defaults above ever change.
func VerifyPassword(hash, password string) bool {
	salt, want, m, t, p, err := ParseHash(hash)
	if err != nil {
		return false
	}
	// Bound concurrent derivations: see hashSlots. A refusal here is reported
	// as a failed login, which is what the caller shows anyway — the uniform
	// error means an attacker cannot tell saturation from a bad password.
	if !acquireHashSlot() {
		return false
	}
	defer releaseHashSlot()

	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
