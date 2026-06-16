package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"firewall/ui/internal/apply"
	"firewall/ui/internal/config"
	"firewall/ui/internal/logs"
	"firewall/ui/internal/traffic"
)

// client wraps a Server with the session cookie obtained from first-run
// setup, since every route except /login and /setup requires auth.
type client struct {
	srv    *Server
	cookie *http.Cookie
}

func newTestServer(t *testing.T) (*client, *config.Store) {
	t.Helper()
	store, err := config.Open(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := apply.New(apply.OSSystem{Root: filepath.Join(t.TempDir(), "root"), NoExec: true}, time.Minute)
	srv, err := New(store, mgr, newTestLogStore(t), newTestTrafficStore(t))
	if err != nil {
		t.Fatal(err)
	}
	c := &client{srv: srv}
	c.cookie = setup(t, srv)
	return c, store
}

func newTestLogStore(t *testing.T) *logs.Store {
	t.Helper()
	ls, err := logs.Open(filepath.Join(t.TempDir(), "logs.db"), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ls.Close() })
	return ls
}

func newTestTrafficStore(t *testing.T) *traffic.Store {
	t.Helper()
	ts, err := traffic.Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.Close() })
	return ts
}

// setup runs first-run admin creation and returns the session cookie.
func setup(t *testing.T, srv *Server) *http.Cookie {
	t.Helper()
	form := url.Values{
		"username": {"admin"},
		"password": {"correct horse"},
		"confirm":  {"correct horse"},
	}
	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("setup: status %d, location %q, body %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatal("setup: no session cookie")
	return nil
}

// post submits an authenticated form and returns the redirect location.
func (c *client) post(t *testing.T, path string, form url.Values) *url.URL {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(c.cookie)
	w := httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST %s: status %d, body %s", path, w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// get fetches an authenticated page.
func (c *client) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(c.cookie)
	w := httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)
	return w
}

func TestAuthRequired(t *testing.T) {
	c, _ := newTestServer(t)

	// No cookie: redirect to login.
	w := httptest.NewRecorder()
	c.srv.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("unauthenticated: status %d, location %q", w.Code, w.Header().Get("Location"))
	}

	// htmx request: HX-Redirect instead of a 3xx the swap would eat.
	req := httptest.NewRequest("GET", "/partials/stats", nil)
	req.Header.Set("HX-Request", "true")
	w = httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || w.Header().Get("HX-Redirect") != "/login" {
		t.Errorf("htmx unauthenticated: status %d, HX-Redirect %q", w.Code, w.Header().Get("HX-Redirect"))
	}

	// Static assets stay public (login page needs the stylesheet).
	w = httptest.NewRecorder()
	c.srv.ServeHTTP(w, httptest.NewRequest("GET", "/static/style.css", nil))
	if w.Code != http.StatusOK {
		t.Errorf("static: status %d", w.Code)
	}

	// Valid session: page renders with username and logout.
	w = c.get(t, "/")
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated: status %d", w.Code)
	}
	for _, want := range []string{"admin", "/logout"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestFirstRunSetup(t *testing.T) {
	store, err := config.Open(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(store, apply.New(apply.OSSystem{Root: t.TempDir(), NoExec: true}, 0), newTestLogStore(t), newTestTrafficStore(t))
	if err != nil {
		t.Fatal(err)
	}

	// No users yet: login page offers admin creation.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
	if !strings.Contains(w.Body.String(), "/setup") {
		t.Error("first-run login page missing setup form")
	}

	cookie := setup(t, srv)
	users := store.Get().Users
	if len(users) != 1 || users[0].Username != "admin" {
		t.Fatalf("users after setup: %+v", users)
	}
	if !strings.HasPrefix(users[0].PasswordHash, "$argon2id$") {
		t.Errorf("stored hash: %q", users[0].PasswordHash)
	}

	// Second setup attempt fails.
	form := url.Values{"username": {"evil"}, "password": {"password123"}, "confirm": {"password123"}}
	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.Contains(loc.Query().Get("err"), "already") {
		t.Errorf("re-setup: want already-completed error, got %q", loc.Query().Get("err"))
	}

	// Login page now shows the normal form.
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
	if strings.Contains(w.Body.String(), "/setup") {
		t.Error("setup form still offered after setup")
	}
	_ = cookie
}

// login posts credentials from addr and returns the recorder.
func login(srv *Server, addr, user, pass string) *httptest.ResponseRecorder {
	form := url.Values{"username": {user}, "password": {pass}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestLoginLogout(t *testing.T) {
	c, _ := newTestServer(t)

	w := login(c.srv, "10.0.0.1:1234", "admin", "wrong")
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("err") == "" {
		t.Error("wrong password: no error flash")
	}

	// Unknown user gets the same error as a bad password.
	w2 := login(c.srv, "10.0.0.1:1234", "nobody", "wrong")
	loc2, _ := url.Parse(w2.Header().Get("Location"))
	if loc.Query().Get("err") != loc2.Query().Get("err") {
		t.Error("unknown-user error differs from wrong-password error")
	}

	w = login(c.srv, "10.0.0.1:1234", "admin", "correct horse")
	if w.Header().Get("Location") != "/" {
		t.Fatalf("login: location %q", w.Header().Get("Location"))
	}
	var cookie *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatalf("session cookie: %+v", cookie)
	}

	// Logout kills the session server-side.
	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(cookie)
	c.srv.ServeHTTP(httptest.NewRecorder(), req)
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("after logout: status %d", w.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	c, _ := newTestServer(t)
	for range loginMaxFails {
		login(c.srv, "10.0.0.9:1234", "admin", "wrong")
	}
	// Even correct credentials are refused once the IP is locked out.
	w := login(c.srv, "10.0.0.9:1234", "admin", "correct horse")
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.Contains(loc.Query().Get("err"), "too many") {
		t.Errorf("want lockout error, got %q", loc.Query().Get("err"))
	}
	// Another IP is unaffected.
	w = login(c.srv, "10.0.0.10:1234", "admin", "correct horse")
	if w.Header().Get("Location") != "/" {
		t.Errorf("clean IP blocked: location %q", w.Header().Get("Location"))
	}
}

// makeService creates one service via the Services page and returns its ID, so
// NAT and WireGuard tests have a catalog entry to reference.
func makeService(t *testing.T, c *client, store *config.Store) string {
	t.Helper()
	if loc := c.post(t, "/services", url.Values{
		"name": {"web"}, "ip": {"192.168.1.10"}, "port": {"443"}, "proto": {"tcp"},
	}); loc.Query().Get("err") != "" {
		t.Fatalf("service create: %s", loc.Query().Get("err"))
	}
	svcs := store.Get().Services
	return svcs[len(svcs)-1].ID
}

func TestForwardCRUD(t *testing.T) {
	c, store := newTestServer(t)
	svcID := makeService(t, c, store)
	form := url.Values{
		"name": {"web"}, "service_id": {svcID}, "wan_port": {"443"}, "enabled": {"on"},
	}

	// Create.
	if loc := c.post(t, "/nat/forwards", form); loc.Query().Get("err") != "" {
		t.Fatalf("create failed: %s", loc.Query().Get("err"))
	}
	fwds := store.Get().NAT.PortForwards
	if len(fwds) != 1 || fwds[0].Name != "web" || fwds[0].ServiceID != svcID || !fwds[0].Enabled {
		t.Fatalf("create: %+v", fwds)
	}
	id := fwds[0].ID

	// Update keeps ID and Enabled.
	form.Set("wan_port", "8443")
	form.Del("enabled")
	c.post(t, "/nat/forwards/"+id, form)
	pf := store.Get().NAT.PortForwards[0]
	if pf.WANPort != 8443 || pf.ID != id || !pf.Enabled {
		t.Fatalf("update: %+v", pf)
	}

	// Toggle.
	c.post(t, "/nat/forwards/"+id+"/toggle", nil)
	if store.Get().NAT.PortForwards[0].Enabled {
		t.Fatal("toggle: still enabled")
	}

	// Invalid create surfaces as flash error, config unchanged.
	bad := url.Values{"name": {"bad"}, "service_id": {svcID}, "wan_port": {"99999"}}
	if loc := c.post(t, "/nat/forwards", bad); loc.Query().Get("err") == "" {
		t.Fatal("want flash error for invalid wan port")
	}
	if len(store.Get().NAT.PortForwards) != 1 {
		t.Fatal("invalid create must not persist")
	}

	// Delete.
	c.post(t, "/nat/forwards/"+id+"/delete", nil)
	if len(store.Get().NAT.PortForwards) != 0 {
		t.Fatal("delete: forward still present")
	}

	// Acting on a missing ID flashes an error.
	if loc := c.post(t, "/nat/forwards/"+id+"/delete", nil); !strings.Contains(loc.Query().Get("err"), "not found") {
		t.Fatalf("want not-found error, got %q", loc.Query().Get("err"))
	}
}

func TestPFPreview(t *testing.T) {
	c, store := newTestServer(t)
	svcID := makeService(t, c, store)
	c.post(t, "/nat/forwards", url.Values{
		"name": {"web"}, "service_id": {svcID}, "wan_port": {"443"}, "enabled": {"on"},
	})
	if len(store.Get().NAT.PortForwards) != 1 {
		t.Fatal("setup: forward not created")
	}
	w := c.get(t, "/system/pf.conf")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"block in log all", "rdr on $wan_if", "192.168.1.10 port 443"} {
		if !strings.Contains(body, want) {
			t.Errorf("pf.conf preview missing %q", want)
		}
	}
}

func TestApplyConfirmFlow(t *testing.T) {
	c, _ := newTestServer(t)

	if loc := c.post(t, "/system/apply", nil); loc.Query().Get("err") != "" {
		t.Fatalf("apply failed: %s", loc.Query().Get("err"))
	}

	// Pending banner shows on every page until confirmed.
	if !strings.Contains(c.get(t, "/").Body.String(), "auto-rollback") {
		t.Error("pending banner missing")
	}

	if loc := c.post(t, "/system/apply/confirm", nil); loc.Query().Get("err") != "" {
		t.Fatalf("confirm failed: %s", loc.Query().Get("err"))
	}
	if strings.Contains(c.get(t, "/").Body.String(), "auto-rollback") {
		t.Error("pending banner survived confirm")
	}
}

func TestApplyWritesFiles(t *testing.T) {
	store, err := config.Open(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "root")
	mgr := apply.New(apply.OSSystem{Root: root, NoExec: true}, 0)
	srv, err := New(store, mgr, newTestLogStore(t), newTestTrafficStore(t))
	if err != nil {
		t.Fatal(err)
	}
	c := &client{srv: srv, cookie: setup(t, srv)}
	c.post(t, "/system/apply", nil)
	data, err := os.ReadFile(filepath.Join(root, "etc/pf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "block in log all") {
		t.Error("installed pf.conf missing ruleset")
	}
}

func TestPagesRender(t *testing.T) {
	c, _ := newTestServer(t)
	for _, p := range pages {
		w := c.get(t, p.Path)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: status %d", p.Path, w.Code)
		}
		if !strings.Contains(w.Body.String(), p.Title) {
			t.Errorf("GET %s: missing title %q", p.Path, p.Title)
		}
	}
}
