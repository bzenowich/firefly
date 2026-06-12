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
)

func newTestServer(t *testing.T) (*Server, *config.Store) {
	t.Helper()
	store, err := config.Open(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := apply.New(apply.OSSystem{Root: filepath.Join(t.TempDir(), "root"), NoExec: true}, time.Minute)
	srv, err := New(store, mgr)
	if err != nil {
		t.Fatal(err)
	}
	return srv, store
}

// post submits a form and returns the redirect location.
func post(t *testing.T, srv *Server, path string, form url.Values) *url.URL {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST %s: status %d, body %s", path, w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestForwardCRUD(t *testing.T) {
	srv, store := newTestServer(t)
	form := url.Values{
		"name": {"web"}, "proto": {"tcp"}, "wan_port": {"443"},
		"dest_ip": {"192.168.1.10"}, "dest_port": {"443"}, "enabled": {"on"},
	}

	// Create.
	if loc := post(t, srv, "/nat/forwards", form); loc.Query().Get("err") != "" {
		t.Fatalf("create failed: %s", loc.Query().Get("err"))
	}
	fwds := store.Get().NAT.PortForwards
	if len(fwds) != 1 || fwds[0].Name != "web" || !fwds[0].Enabled {
		t.Fatalf("create: %+v", fwds)
	}
	id := fwds[0].ID

	// Update keeps ID and Enabled.
	form.Set("wan_port", "8443")
	form.Del("enabled")
	post(t, srv, "/nat/forwards/"+id, form)
	pf := store.Get().NAT.PortForwards[0]
	if pf.WANPort != 8443 || pf.ID != id || !pf.Enabled {
		t.Fatalf("update: %+v", pf)
	}

	// Toggle.
	post(t, srv, "/nat/forwards/"+id+"/toggle", nil)
	if store.Get().NAT.PortForwards[0].Enabled {
		t.Fatal("toggle: still enabled")
	}

	// Invalid create surfaces as flash error, config unchanged.
	bad := url.Values{
		"name": {"bad"}, "proto": {"tcp"}, "wan_port": {"99999"},
		"dest_ip": {"192.168.1.11"}, "dest_port": {"80"},
	}
	if loc := post(t, srv, "/nat/forwards", bad); loc.Query().Get("err") == "" {
		t.Fatal("want flash error for invalid wan port")
	}
	if len(store.Get().NAT.PortForwards) != 1 {
		t.Fatal("invalid create must not persist")
	}

	// Delete.
	post(t, srv, "/nat/forwards/"+id+"/delete", nil)
	if len(store.Get().NAT.PortForwards) != 0 {
		t.Fatal("delete: forward still present")
	}

	// Acting on a missing ID flashes an error.
	if loc := post(t, srv, "/nat/forwards/"+id+"/delete", nil); !strings.Contains(loc.Query().Get("err"), "not found") {
		t.Fatalf("want not-found error, got %q", loc.Query().Get("err"))
	}
}

func TestPFPreview(t *testing.T) {
	srv, store := newTestServer(t)
	post(t, srv, "/nat/forwards", url.Values{
		"name": {"web"}, "proto": {"tcp"}, "wan_port": {"443"},
		"dest_ip": {"192.168.1.10"}, "dest_port": {"443"}, "enabled": {"on"},
	})
	if len(store.Get().NAT.PortForwards) != 1 {
		t.Fatal("setup: forward not created")
	}
	req := httptest.NewRequest("GET", "/system/pf.conf", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
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
	srv, _ := newTestServer(t)

	if loc := post(t, srv, "/system/apply", nil); loc.Query().Get("err") != "" {
		t.Fatalf("apply failed: %s", loc.Query().Get("err"))
	}

	// Pending banner shows on every page until confirmed.
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "auto-rollback") {
		t.Error("pending banner missing")
	}

	if loc := post(t, srv, "/system/apply/confirm", nil); loc.Query().Get("err") != "" {
		t.Fatalf("confirm failed: %s", loc.Query().Get("err"))
	}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if strings.Contains(w.Body.String(), "auto-rollback") {
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
	srv, err := New(store, mgr)
	if err != nil {
		t.Fatal(err)
	}
	post(t, srv, "/system/apply", nil)
	data, err := os.ReadFile(filepath.Join(root, "etc/pf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "block in log all") {
		t.Error("installed pf.conf missing ruleset")
	}
}

func TestPagesRender(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, p := range pages {
		req := httptest.NewRequest("GET", p.Path, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: status %d", p.Path, w.Code)
		}
		if !strings.Contains(w.Body.String(), p.Title) {
			t.Errorf("GET %s: missing title %q", p.Path, p.Title)
		}
	}
}
