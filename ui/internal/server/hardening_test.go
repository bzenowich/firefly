package server

import (
	"bytes"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"firewall/ui/web"
)

// Every response must carry the containment headers, and the CSP must keep the
// two directives that are load-bearing: no inline script, and no framing by
// anyone but us (docs/security-plan.md SEC-8).
func TestSecurityHeaders(t *testing.T) {
	c, _ := newTestServer(t)

	for _, path := range []string{"/", "/system", "/login", "/static/style.css"} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(c.cookie)
		rec := httptest.NewRecorder()
		c.srv.ServeHTTP(rec, req)

		h := rec.Header()
		for key, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "SAMEORIGIN",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := h.Get(key); got != want {
				t.Errorf("%s: %s = %q, want %q", path, key, got, want)
			}
		}
		csp := h.Get("Content-Security-Policy")
		for _, directive := range []string{"script-src 'self'", "frame-ancestors 'self'", "object-src 'none'"} {
			if !strings.Contains(csp, directive) {
				t.Errorf("%s: CSP missing %q: %s", path, directive, csp)
			}
		}
		if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("%s: CSP allows inline script: %s", path, csp)
		}
	}
}

// Pages render live config and three routes hand out outright secrets, so
// nothing outside /static may be cached.
func TestNoStoreExceptStatic(t *testing.T) {
	c, _ := newTestServer(t)
	for path, want := range map[string]string{
		"/":                 "no-store",
		"/system":           "no-store",
		"/system/backup":    "no-store",
		"/static/style.css": "",
	} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(c.cookie)
		rec := httptest.NewRecorder()
		c.srv.ServeHTTP(rec, req)
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control = %q, want %q", path, got, want)
		}
	}
}

// r.FormValue on a multipart body calls ParseMultipartForm, which spills past
// 32 MiB to temp files with no total cap. /login is public and calls FormValue,
// so an unauthenticated LAN host could fill the filesystem
// (docs/security-plan.md SEC-4b).
func TestPublicRoutesRefuseMultipart(t *testing.T) {
	c, _ := newTestServer(t)
	for _, path := range []string{"/login", "/setup"} {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("username", "admin")
		mw.Close()

		req := httptest.NewRequest("POST", path, &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		c.srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s: multipart accepted with status %d", path, rec.Code)
		}
	}
	// The ordinary urlencoded login still reaches the handler (and fails
	// authentication, which is a redirect, not a 415).
	req := httptest.NewRequest("POST", "/login",
		strings.NewReader(url.Values{"username": {"admin"}, "password": {"wrong"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c.srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnsupportedMediaType {
		t.Error("urlencoded login refused")
	}
}

// Ordinary form routes take a small body; only the config restore may be large.
func TestBodyLimits(t *testing.T) {
	if got := bodyLimit(httptest.NewRequest("POST", "/system/hostname", nil)); got != maxBodyBytes {
		t.Errorf("form route limit = %d, want %d", got, maxBodyBytes)
	}
	if got := bodyLimit(httptest.NewRequest("POST", "/system/restore", nil)); got != maxUploadBytes {
		t.Errorf("restore limit = %d, want %d", got, maxUploadBytes)
	}

	c, _ := newTestServer(t)
	big := url.Values{"hostname": {strings.Repeat("a", maxBodyBytes+1)}}.Encode()
	req := httptest.NewRequest("POST", "/system/hostname", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(c.cookie)
	req.Header.Set(csrfHeader, c.csrf)
	rec := httptest.NewRecorder()
	c.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	// The handler must not have run on a half-parsed form: a truncated body
	// reaching r.FormValue would have written an empty hostname.
	if got := c.srv.store.Get().System.Hostname; got == "" {
		t.Error("oversized body reached the handler and blanked the hostname")
	}
}

// The CSP's script-src 'self' is only true as long as the templates keep it
// true. An inline <script> block or an on* attribute added later would be
// silently dead in the browser rather than loudly broken here, so assert it
// (docs/security-plan.md SEC-8).
func TestTemplatesHaveNoInlineScript(t *testing.T) {
	banned := []string{"<script>", "<style>", "onclick=", "oninput=", "onchange=", "onsubmit=", "onload=", "javascript:"}
	err := fs.WalkDir(web.FS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := web.FS.ReadFile(path)
		if err != nil {
			return err
		}
		for _, bad := range banned {
			if bytes.Contains(bytes.ToLower(b), []byte(bad)) {
				t.Errorf("%s contains %q, which the CSP blocks; move it to /static", path, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Every script a template references must actually exist in the embedded FS: a
// typo'd src is a page that silently does nothing.
func TestTemplateScriptSourcesExist(t *testing.T) {
	re := regexp.MustCompile(`<script src="/static/([^"]+)"`)
	err := fs.WalkDir(web.FS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := web.FS.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllSubmatch(b, -1) {
			name := string(m[1])
			if _, err := web.FS.ReadFile("static/" + name); err != nil {
				t.Errorf("%s references /static/%s, which is not embedded", path, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
