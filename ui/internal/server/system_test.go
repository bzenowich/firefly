package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"firewall/ui/internal/auth"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	c, store := newTestServer(t)

	// Make the config distinctive, download it.
	c.post(t, "/system/hostname", url.Values{"hostname": {"backup-test"}})
	w := c.get(t, "/system/backup")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "fw-config.json") {
		t.Fatalf("backup: status %d disposition %q", w.Code, w.Header().Get("Content-Disposition"))
	}
	backup := w.Body.Bytes()

	// Change it, then restore the download.
	c.post(t, "/system/hostname", url.Values{"hostname": {"changed"}})
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("backup", "fw-config.json")
	fw.Write(backup)
	mw.Close()
	req := httptest.NewRequest("POST", "/system/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(c.cookie)
	rec := httptest.NewRecorder()
	c.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("restore: status %d body %s", rec.Code, rec.Body.String())
	}
	if got := store.Get().System.Hostname; got != "backup-test" {
		t.Fatalf("hostname after restore: %q", got)
	}

	// Garbage upload must be rejected.
	body.Reset()
	mw = multipart.NewWriter(&body)
	fw, _ = mw.CreateFormFile("backup", "junk.json")
	fw.Write([]byte(`{"surprise": true}`))
	mw.Close()
	req = httptest.NewRequest("POST", "/system/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(c.cookie)
	rec = httptest.NewRecorder()
	c.srv.ServeHTTP(rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.Contains(loc.Query().Get("err"), "not a valid backup") {
		t.Fatalf("junk restore: %q", loc.Query().Get("err"))
	}
	if got := store.Get().System.Hostname; got != "backup-test" {
		t.Fatalf("hostname after junk restore: %q", got)
	}
}

func TestUserManagement(t *testing.T) {
	c, store := newTestServer(t)

	// Last user is protected.
	if loc := c.post(t, "/system/users/admin/delete", url.Values{}); !strings.Contains(loc.Query().Get("err"), "last user") {
		t.Fatalf("last-user delete: %q", loc.Query().Get("err"))
	}

	if loc := c.post(t, "/system/users", url.Values{"username": {"bob"}, "password": {"short"}}); loc.Query().Get("err") == "" {
		t.Fatal("short password accepted")
	}
	if loc := c.post(t, "/system/users", url.Values{"username": {"bob"}, "password": {"longenough"}}); loc.Query().Get("err") != "" {
		t.Fatalf("user create: %s", loc.Query().Get("err"))
	}
	if loc := c.post(t, "/system/users", url.Values{"username": {"bob"}, "password": {"longenough"}}); loc.Query().Get("err") == "" {
		t.Fatal("duplicate username accepted")
	}

	if loc := c.post(t, "/system/users/bob/password", url.Values{
		"password": {"newpassword"}, "confirm": {"newpassword"},
	}); loc.Query().Get("err") != "" {
		t.Fatalf("password change: %s", loc.Query().Get("err"))
	}
	for _, u := range store.Get().Users {
		if u.Username == "bob" && !auth.VerifyPassword(u.PasswordHash, "newpassword") {
			t.Fatal("new password does not verify")
		}
	}

	if loc := c.post(t, "/system/users/bob/delete", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("user delete: %s", loc.Query().Get("err"))
	}
	if len(store.Get().Users) != 1 {
		t.Fatal("bob not deleted")
	}
}

func TestTOTPEnrollmentAndLogin(t *testing.T) {
	c, store := newTestServer(t)

	if loc := c.post(t, "/system/totp/begin", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("totp begin: %s", loc.Query().Get("err"))
	}
	if w := c.get(t, "/system/totp/qr.png"); w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("totp qr: status %d type %s", w.Code, w.Header().Get("Content-Type"))
	}

	// Wrong code rejected, secret not committed.
	if loc := c.post(t, "/system/totp/confirm", url.Values{"code": {"000000"}}); loc.Query().Get("err") == "" {
		t.Fatal("wrong code accepted")
	}
	if store.Get().Users[0].TOTPSecret != "" {
		t.Fatal("secret committed despite wrong code")
	}

	// Right code: pull the pending secret straight from the server.
	c.srv.totpMu.Lock()
	secret := c.srv.totpPending["admin"]
	c.srv.totpMu.Unlock()
	code, err := auth.CurrentTOTP(secret)
	if err != nil {
		t.Fatal(err)
	}
	if loc := c.post(t, "/system/totp/confirm", url.Values{"code": {code}}); loc.Query().Get("err") != "" {
		t.Fatalf("totp confirm: %s", loc.Query().Get("err"))
	}
	if store.Get().Users[0].TOTPSecret != secret {
		t.Fatal("secret not committed")
	}

	// Login without the code now fails; with it, succeeds.
	login := func(totp string) *httptest.ResponseRecorder {
		form := url.Values{"username": {"admin"}, "password": {"correct horse"}, "totp": {totp}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		c.srv.ServeHTTP(w, req)
		return w
	}
	if w := login(""); w.Header().Get("Location") == "/" {
		t.Fatal("login without totp succeeded")
	}
	code, _ = auth.CurrentTOTP(secret)
	if w := login(code); w.Header().Get("Location") != "/" {
		t.Fatalf("login with totp failed: %s", w.Header().Get("Location"))
	}

	if loc := c.post(t, "/system/totp/disable", url.Values{}); loc.Query().Get("err") != "" {
		t.Fatalf("totp disable: %s", loc.Query().Get("err"))
	}
	if store.Get().Users[0].TOTPSecret != "" {
		t.Fatal("secret not cleared")
	}
}
