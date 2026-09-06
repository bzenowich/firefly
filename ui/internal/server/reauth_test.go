package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"firewall/ui/internal/logs"
)

// gatedRoutes are the actions that must not be reachable on a session cookie
// alone. Each is chosen by consequence: it changes who can log in, or it hands
// out a secret (docs/security-plan.md SEC-6).
var gatedRoutes = []struct {
	method, path, what string
}{
	{"POST", "/system/users", "create an account"},
	{"POST", "/system/users/admin/password", "change a password"},
	{"POST", "/system/users/admin/delete", "delete an account"},
	{"POST", "/system/totp/disable", "disable 2FA"},
	{"POST", "/system/shell", "enable the web terminal"},
	{"POST", "/system/restore", "restore a configuration"},
	{"GET", "/system/backup", "download every secret on the box"},
	{"POST", "/system/sessions/all", "revoke sessions"},
}

func TestSensitiveActionsRequireReauth(t *testing.T) {
	c, _ := newTestServer(t)

	for _, rt := range gatedRoutes {
		req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(csrfHeader, c.csrf)
		req.AddCookie(c.cookie)
		w := httptest.NewRecorder()
		c.srv.ServeHTTP(w, req)

		loc, _ := url.Parse(w.Header().Get("Location"))
		if !strings.Contains(loc.Query().Get("err"), "confirm your password") {
			t.Errorf("%s %s (%s) was not gated: status %d err %q",
				rt.method, rt.path, rt.what, w.Code, loc.Query().Get("err"))
		}
	}

	// After confirming, the same requests reach their handlers. Backup is the
	// clearest check: it either returns the document or it does not.
	c.reauth(t)
	req := httptest.NewRequest("GET", "/system/backup", nil)
	req.AddCookie(c.cookie)
	w := httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Disposition") == "" {
		t.Errorf("backup after reauth: status %d disposition %q",
			w.Code, w.Header().Get("Content-Disposition"))
	}
}

// A wrong password must not open the window, and must be rate-limited — an
// unthrottled re-auth endpoint is a password oracle for anyone holding a
// session cookie.
func TestReauthRejectsWrongPassword(t *testing.T) {
	c, _ := newTestServer(t)

	form := url.Values{"password": {"not the password"}}
	req := httptest.NewRequest("POST", "/system/reauth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfHeader, c.csrf)
	req.AddCookie(c.cookie)
	w := httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)

	if c.srv.sessions.Elevated(c.cookie.Value) {
		t.Fatal("a wrong password elevated the session")
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.Contains(loc.Query().Get("err"), "not correct") {
		t.Errorf("wrong password: %q", loc.Query().Get("err"))
	}
}

// Locking gives up the window early, so an admin who has finished does not
// leave a browser standing authorised.
func TestLockEndsTheWindow(t *testing.T) {
	c, _ := newTestServer(t)
	c.reauth(t)
	c.post(t, "/system/lock", url.Values{})
	if c.srv.sessions.Elevated(c.cookie.Value) {
		t.Error("lock did not end the elevated window")
	}
}

// The trail must record what happened, with an actor, for the actions an
// incident review reads (SEC-10).
func TestAuditTrailRecordsSensitiveActions(t *testing.T) {
	c, _ := newTestServer(t)
	c.reauth(t)
	c.post(t, "/system/users", url.Values{"username": {"bob"}, "password": {"bobs password"}})

	entries, err := c.srv.logStore.RecentAudit(logsAuditAll())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"setup.ok":     false, // first-run account creation
		"reauth.ok":    false,
		"user.created": false,
	}
	for _, e := range entries {
		if _, ok := want[e.Event]; ok {
			want[e.Event] = true
			if e.Actor == "" {
				t.Errorf("%s recorded with no actor", e.Event)
			}
		}
	}
	for event, seen := range want {
		if !seen {
			t.Errorf("no audit entry for %s", event)
		}
	}

	// Failures matter at least as much as successes.
	login(c.srv, "10.0.5.1:1234", "admin", "wrong")
	entries, _ = c.srv.logStore.RecentAudit(logsAuditAll())
	var sawFailure bool
	for _, e := range entries {
		if e.Event == "login.failed" {
			sawFailure = true
			if !strings.Contains(e.Detail, "from=10.0.5.1") {
				t.Errorf("login.failed does not record the source: %q", e.Detail)
			}
		}
	}
	if !sawFailure {
		t.Error("a failed login was not audited")
	}
}

func logsAuditAll() logs.AuditFilter { return logs.AuditFilter{Limit: 500} }
