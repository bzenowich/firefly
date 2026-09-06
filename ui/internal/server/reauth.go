package server

import (
	"errors"
	"net/http"
	"strings"

	"firewall/ui/internal/auth"
)

// Re-authentication for security-critical actions (docs/security-plan.md SEC-6).
//
// A session cookie alone used to be enough to change any user's password,
// create an admin, disable 2FA, enable the web shell, restore a config, or
// download the backup with every secret on the box in it. That made one stolen
// cookie — from an unlocked laptop, a shoulder-surf, an XSS — permanent and
// unrevocable ownership of the appliance.
//
// CSRF tokens do not help here: they stop a *cross-site* forgery, and none of
// those is what reaches these handlers. What helps is asking for the password
// again, close in time to the action.
//
// The window is per-session and short. It exists so that a sequence of related
// admin actions does not prompt six times, not so that a walked-away-from
// laptop stays authorised.

// reauthRoutes are the paths that require a fresh password.
//
// Chosen by consequence, not by HTTP verb: everything that changes who can log
// in, or that hands out a secret. GET /system/backup is here for the second
// reason — it is a download, but what it downloads is every password hash,
// WireGuard private key, TOTP seed and the SMTP password.
var reauthRoutes = map[string]string{
	"/system/users":        "create an account",
	"/system/restore":      "restore a configuration",
	"/system/backup":       "download the backup",
	"/system/totp/disable": "disable two-factor authentication",
	"/system/shell":        "change the web terminal setting",
	"/system/sessions/all": "revoke sessions",
	// Widening the admin plane is exactly what an attacker holding a session
	// would do first, so it is gated like the account changes. The ruleset
	// separately refuses to expose it on the WAN whatever the list says.
	"/system/management": "change management access",
}

// needsReauth reports the action description if this request is gated.
//
// Path prefixes are matched for the parameterised routes (a user's password and
// delete both live under /system/users/{name}/...), because listing every
// possible expansion is how one gets missed.
func needsReauth(r *http.Request) (string, bool) {
	if what, ok := reauthRoutes[r.URL.Path]; ok {
		return what, true
	}
	if strings.HasPrefix(r.URL.Path, "/system/users/") {
		switch {
		case strings.HasSuffix(r.URL.Path, "/password"):
			return "change a password", true
		case strings.HasSuffix(r.URL.Path, "/delete"):
			return "delete an account", true
		}
	}
	if strings.HasPrefix(r.URL.Path, "/system/sessions/") && strings.HasSuffix(r.URL.Path, "/revoke") {
		return "revoke a session", true
	}
	return "", false
}

// checkReauth gates a request, writing the refusal itself and reporting whether
// it may proceed.
func (s *Server) checkReauth(w http.ResponseWriter, r *http.Request) bool {
	what, gated := needsReauth(r)
	if !gated {
		return true
	}
	if s.sessions.Elevated(sessionToken(r)) {
		return true
	}
	s.auditRequest(r, "reauth.required", "action=%q", what)
	// Send them to the prompt rather than a flat error: this is a routine
	// interruption of a legitimate action, not an attack being blocked.
	redirect(w, r, "/system", errors.New("confirm your password to "+what))
	return false
}

// handleReauth verifies the password (and TOTP, when enrolled) and opens the
// elevated window.
//
// It deliberately re-checks the *second* factor too. Someone who stole a
// session cookie may also know the password — from a reused credential, or a
// keylogger — and 2FA is precisely the thing that is supposed to stop them
// there.
func (s *Server) handleReauth(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey{}).(string)

	// Rate-limited on the same address bucket as login. Without it this is an
	// unthrottled password oracle for anyone holding a session.
	bucket := limiterAddrKey(remoteIP(r))
	if !s.logins.Allow(bucket) {
		s.auditRequest(r, "reauth.blocked", "reason=address-rate-limit")
		redirect(w, r, "/system", errors.New("too many attempts, try again later"))
		return
	}

	var hash, totpSecret string
	for _, u := range s.store.Get().Users {
		if u.Username == user {
			hash, totpSecret = u.PasswordHash, u.TOTPSecret
		}
	}
	if hash == "" || !auth.VerifyPassword(hash, r.FormValue("password")) {
		s.logins.Fail(bucket)
		s.auditRequest(r, "reauth.failed", "reason=password")
		redirect(w, r, "/system", errors.New("that password is not correct"))
		return
	}
	if totpSecret != "" {
		step, ok := auth.VerifyTOTPStep(totpSecret, r.FormValue("totp"))
		if !ok || !s.totpSpend(user, step) {
			s.logins.Fail(bucket)
			s.auditRequest(r, "reauth.failed", "reason=totp")
			redirect(w, r, "/system", errors.New("that code is not correct"))
			return
		}
	}

	s.logins.Reset(bucket)
	s.sessions.Elevate(sessionToken(r), reauthWindow)
	s.auditRequest(r, "reauth.ok", "window=%s", reauthWindow)
	redirect(w, r, "/system", nil)
}

// handleLock ends the elevated window early, so an admin who has finished a
// sensitive task can drop the privilege rather than wait it out.
func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	s.sessions.DropElevation(sessionToken(r))
	s.auditRequest(r, "reauth.dropped", "")
	redirect(w, r, "/system", nil)
}
