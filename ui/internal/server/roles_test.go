package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

// asRole logs in a second account with the given role and returns a client for
// it.
func asRole(t *testing.T, c *client, store *config.Store, name, role string) *client {
	t.Helper()
	c.reauth(t)
	if loc := c.post(t, "/system/users", url.Values{
		"username": {name}, "password": {"a good long password"}, "role": {role},
	}); loc.Query().Get("err") != "" {
		t.Fatalf("create %s: %s", name, loc.Query().Get("err"))
	}
	w := login(c.srv, "10.0.7.1:1234", name, "a good long password")
	if w.Header().Get("Location") != "/" {
		t.Fatalf("%s login: %s", name, w.Header().Get("Location"))
	}
	out := &client{srv: c.srv}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			out.cookie = ck
		}
	}
	if out.cookie == nil {
		t.Fatalf("%s: no session cookie", name)
	}
	out.csrf, _ = c.srv.sessions.CSRF(out.cookie.Value)
	return out
}

func (c *client) try(t *testing.T, method, path string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfHeader, c.csrf)
	req.AddCookie(c.cookie)
	w := httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)
	if w.Code == http.StatusSeeOther {
		if loc, _ := url.Parse(w.Header().Get("Location")); strings.Contains(loc.Query().Get("err"), "permission") {
			return http.StatusForbidden
		}
	}
	return w.Code
}

// A viewer may read the pages that exist for them, and change nothing.
func TestViewerCannotChangeAnything(t *testing.T) {
	c, store := newTestServer(t)
	viewer := asRole(t, c, store, "vera", config.RoleViewer)

	for _, path := range []string{"/", "/traffic", "/devices", "/logs", "/api/flows"} {
		if got := viewer.try(t, "GET", path); got == http.StatusForbidden {
			t.Errorf("viewer denied a read of %s", path)
		}
	}
	for _, path := range []string{
		"/system/apply", "/nat/forwards", "/system/hostname",
		"/dns/settings", "/wireguard/settings", "/system/users",
	} {
		if got := viewer.try(t, "POST", path); got != http.StatusForbidden {
			t.Errorf("viewer allowed to POST %s (status %d)", path, got)
		}
	}
}

// An operator runs the network but does not manage accounts or handle secrets.
func TestOperatorScope(t *testing.T) {
	c, store := newTestServer(t)
	op := asRole(t, c, store, "olly", config.RoleOperator)

	for _, path := range []string{"/system/apply", "/system/hostname", "/nat/forwards", "/dns/settings"} {
		if got := op.try(t, "POST", path); got == http.StatusForbidden {
			t.Errorf("operator denied %s, which is network configuration", path)
		}
	}
	for _, path := range []string{
		"/system/users", "/system/shell", "/system/smtp",
		"/system/restore", "/system/management", "/system/sessions/all",
	} {
		if got := op.try(t, "POST", path); got != http.StatusForbidden {
			t.Errorf("operator allowed %s (status %d)", path, got)
		}
	}
	// Secrets are admin-only even as reads.
	for _, path := range []string{"/system/backup", "/system/totp/qr.png"} {
		if got := op.try(t, "GET", path); got != http.StatusForbidden {
			t.Errorf("operator allowed to read %s (status %d)", path, got)
		}
	}
	// So is the web terminal.
	if got := op.try(t, "GET", "/shell"); got != http.StatusForbidden {
		t.Errorf("operator reached the web terminal (status %d)", got)
	}
}

// A route with no entry in the table must need admin. The alternative fails
// toward "an operator can do something they should not", which is the direction
// that is a vulnerability rather than a bug report.
func TestUnknownWriteRoutesDefaultToAdmin(t *testing.T) {
	for _, path := range []string{"/some/new/route", "/system/future-thing"} {
		req := httptest.NewRequest("POST", path, nil)
		if got := routeRole(req); got != config.RoleAdmin {
			t.Errorf("a new POST route %s defaults to %q, not admin", path, got)
		}
	}
	// ...while a new read defaults to viewer, or the role would be useless.
	req := httptest.NewRequest("GET", "/some/new/page", nil)
	if got := routeRole(req); got != config.RoleViewer {
		t.Errorf("a new GET route defaults to %q, not viewer", got)
	}
}

// An appliance with no administrator can only be recovered from the console.
func TestLastAdminIsProtected(t *testing.T) {
	c, store := newTestServer(t)
	c.reauth(t)
	c.post(t, "/system/users", url.Values{
		"username": {"vera"}, "password": {"a good long password"}, "role": {config.RoleViewer},
	})

	if loc := c.post(t, "/system/users/admin/role", url.Values{"role": {config.RoleViewer}}); !strings.Contains(loc.Query().Get("err"), "last administrator") {
		t.Errorf("demoting the last admin: %q", loc.Query().Get("err"))
	}
	if loc := c.post(t, "/system/users/admin/delete", url.Values{}); !strings.Contains(loc.Query().Get("err"), "last administrator") {
		t.Errorf("deleting the last admin: %q", loc.Query().Get("err"))
	}
	if store.Get().Admins() != 1 {
		t.Error("the last administrator was lost")
	}

	// A document with no admin at all is refused outright.
	cfg := store.Get()
	for i := range cfg.Users {
		cfg.Users[i].Role = config.RoleViewer
	}
	if err := cfg.Validate(); err == nil {
		t.Error("a config document with no administrator validated")
	}
}

// An unset role means admin, so restoring a config written before roles existed
// does not silently demote everyone and lock the operator out.
func TestUnsetRoleIsAdminForMigration(t *testing.T) {
	u := config.User{Username: "old", PasswordHash: "x"}
	if got := u.EffectiveRole(); got != config.RoleAdmin {
		t.Errorf("an account from a pre-roles document is %q, want admin", got)
	}
	if !u.AtLeast(config.RoleAdmin) {
		t.Error("a pre-roles account lost admin access on upgrade")
	}
}

// Changing a role must not leave the account's existing sessions running at the
// old privilege level.
func TestRoleChangeRevokesSessions(t *testing.T) {
	c, store := newTestServer(t)
	op := asRole(t, c, store, "olly", config.RoleOperator)

	if got := op.try(t, "POST", "/system/apply"); got == http.StatusForbidden {
		t.Fatal("operator could not apply before the demotion")
	}
	c.reauth(t)
	if loc := c.post(t, "/system/users/olly/role", url.Values{"role": {config.RoleViewer}}); loc.Query().Get("err") != "" {
		t.Fatalf("demote: %s", loc.Query().Get("err"))
	}
	if _, ok := c.srv.sessions.Get(op.cookie.Value); ok {
		t.Error("the demoted account's session survived the role change")
	}
}

// The System page must not offer controls the account cannot use. This is
// presentation, not enforcement — routeRole is the boundary — but a page full
// of buttons that all refuse is a bad way to say no.
func TestSystemPageHidesAdminSectionsFromOperators(t *testing.T) {
	c, store := newTestServer(t)
	op := asRole(t, c, store, "olly", config.RoleOperator)

	body := op.get(t, "/system").Body.String()
	for _, hidden := range []string{"Users", "Backup &amp; restore", "Management access", "Email (SMTP relay)"} {
		if strings.Contains(body, "<h2>"+hidden+"</h2>") {
			t.Errorf("operator is shown the %q section", hidden)
		}
	}
	// ...and still sees the ones they can use.
	for _, shown := range []string{"Identification", "Apply"} {
		if !strings.Contains(body, "<h2>"+shown+"</h2>") {
			t.Errorf("operator cannot see the %q section", shown)
		}
	}

	// An admin sees everything.
	adminBody := c.get(t, "/system").Body.String()
	for _, shown := range []string{"Users", "Backup &amp; restore"} {
		if !strings.Contains(adminBody, "<h2>"+shown+"</h2>") {
			t.Errorf("admin cannot see the %q section", shown)
		}
	}
}
