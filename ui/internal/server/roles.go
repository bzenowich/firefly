package server

import (
	"errors"
	"net/http"
	"strings"

	"firewall/ui/internal/config"
)

// Route authorisation (docs/security-plan.md SEC-7).
//
// Every account used to be able to do everything: edit the firewall, read every
// flow, download every secret, open a shell. There was no read-only account for
// "let me see what the network is doing", so anyone who needed to look at
// anything was given the keys to the appliance.
//
// The mapping lives here, in one table, rather than as a check inside each
// handler. Seventy-odd handlers each remembering to ask is seventy-odd chances
// to forget, and the one that forgets is not discoverable by reading any single
// file.

// operatorRoutes are the state-changing routes an operator may use: the network
// itself. Anything absent needs admin — see routeRole for why that direction.
var operatorRoutes = map[string]bool{
	"/system/apply":          true,
	"/system/apply/confirm":  true,
	"/system/apply/rollback": true,
	"/system/hostname":       true,
	"/system/time":           true,
	"/system/dns/servers":    true,
	"/system/dns/test":       true,
	"/system/ntp/servers":    true,
	"/system/ntp/test":       true,
	"/services":              true,
	"/nat/forwards":          true,
	"/dns/settings":          true,
	"/dns/overrides":         true,
	"/dns/blocklists":        true,
	"/flow/settings":         true,
	"/visibility/settings":   true,
	"/wireguard/settings":    true,
	"/wireguard/tunnels":     true,
	"/wireguard/server":      true,
}

// operatorPrefixes cover the parameterised forms of the routes above
// (/nat/forwards/{id}/delete and friends).
var operatorPrefixes = []string{
	"/services/",
	"/nat/forwards/",
	"/dns/overrides/",
	"/dns/blocklists/",
	"/interfaces/",
	"/system/dns/servers/",
	"/system/ntp/servers/",
	"/wireguard/tunnels/",
	"/wireguard/server/",
}

// secretGETs are read routes that hand out a credential rather than a view, so
// they need admin despite being GETs. A WireGuard client config *is* its
// private key; the backup is every secret on the box.
var secretGETs = []string{
	"/system/backup",
	"/system/totp/qr.png",
	"/config", // .../clients/{id}/config and .../peers/{peer}/config
	"/qr.png", // the same, as an image
}

// routeRole returns the minimum role a request needs.
//
// Two defaults, chosen in opposite directions on purpose:
//
//   - A read is viewer. Pages and partials are what a viewer account exists
//     for, and defaulting reads closed would make the role useless.
//   - A write is admin. A route added later with no entry here is refused for
//     everyone but an administrator, which fails toward "an operator cannot do
//     something they should" rather than "an operator can do something they
//     should not". The first is a bug report; the second is a vulnerability.
func routeRole(r *http.Request) string {
	path := r.URL.Path

	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		for _, p := range secretGETs {
			if path == p || strings.HasSuffix(path, p) {
				return config.RoleAdmin
			}
		}
		// The web terminal is a shell on the appliance whatever the verb.
		if path == "/shell" || path == "/shell/ws" {
			return config.RoleAdmin
		}
		return config.RoleViewer
	}

	// Anything a session may always do, regardless of role.
	switch path {
	case "/logout", "/system/reauth", "/system/lock":
		return config.RoleViewer
	}

	if operatorRoutes[path] {
		return config.RoleOperator
	}
	for _, p := range operatorPrefixes {
		if strings.HasPrefix(path, p) {
			return config.RoleOperator
		}
	}
	return config.RoleAdmin
}

// checkRole gates a request, writing the refusal itself and reporting whether
// it may proceed.
func (s *Server) checkRole(w http.ResponseWriter, r *http.Request, user string) bool {
	want := routeRole(r)
	u, ok := s.store.Get().User(user)
	if !ok {
		// The session names an account that no longer exists. Sessions are
		// revoked on delete, so this is a race rather than a normal state —
		// refuse it either way.
		http.Error(w, "account no longer exists", http.StatusForbidden)
		return false
	}
	if u.AtLeast(want) {
		return true
	}

	s.auditRequest(r, "authz.denied", "path=%s role=%s needs=%s", r.URL.Path, u.EffectiveRole(), want)
	if r.Method == http.MethodGet {
		http.Error(w, "your account does not have access to this", http.StatusForbidden)
		return false
	}
	redirect(w, r, "/", errors.New("your account does not have permission to do that"))
	return false
}
