package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"firewall/ui/internal/config"

	"golang.org/x/net/websocket"
)

func TestShellDisabledByDefault(t *testing.T) {
	c, store := newTestServer(t)
	c.reauth(t)

	if store.Get().Shell.Enabled {
		t.Fatal("shell enabled in default config")
	}

	// Nav on a normal page omits the Shell entry.
	if body := c.get(t, "/").Body.String(); strings.Contains(body, `href="/shell"`) {
		t.Error("nav shows Shell link while disabled")
	}

	// Both routes refuse with 403 while disabled.
	if w := c.get(t, "/shell"); w.Code != http.StatusForbidden {
		t.Errorf("GET /shell disabled: status %d, want 403", w.Code)
	}
	if w := c.get(t, "/shell/ws"); w.Code != http.StatusForbidden {
		t.Errorf("GET /shell/ws disabled: status %d, want 403", w.Code)
	}
}

func TestShellToggleEnablesNavAndPage(t *testing.T) {
	c, store := newTestServer(t)
	c.reauth(t)

	c.post(t, "/system/shell", url.Values{"enabled": {"on"}})
	if !store.Get().Shell.Enabled {
		t.Fatal("toggle did not enable shell")
	}

	// Nav now carries the Shell link and the page renders the warning + terminal.
	body := c.get(t, "/").Body.String()
	if !strings.Contains(body, `href="/shell"`) {
		t.Error("nav missing Shell link after enable")
	}
	page := c.get(t, "/shell")
	if page.Code != http.StatusOK {
		t.Fatalf("GET /shell enabled: status %d", page.Code)
	}
	if !strings.Contains(page.Body.String(), `id="term"`) {
		t.Error("shell page missing terminal element")
	}

	// Toggling back off restores the dark state.
	c.post(t, "/system/shell", url.Values{}) // no "enabled" => off
	if store.Get().Shell.Enabled {
		t.Error("shell still enabled after toggle off")
	}
	if c.get(t, "/shell").Code != http.StatusForbidden {
		t.Error("GET /shell still served after disable")
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		origin string
		host   string
		want   bool
	}{
		{"https://fw.lan", "fw.lan", true},
		{"https://FW.lan", "fw.lan", true}, // host compare is case-insensitive
		{"https://evil.example", "fw.lan", false},
		{"https://fw.lan:8443", "fw.lan", false}, // port mismatch is a mismatch
		{"", "fw.lan", false},                    // missing Origin: default-deny
	}
	for _, tc := range cases {
		var o *url.URL
		if tc.origin != "" {
			o, _ = url.Parse(tc.origin)
		}
		if got := sameOrigin(o, tc.host); got != tc.want {
			t.Errorf("sameOrigin(%q, %q) = %v, want %v", tc.origin, tc.host, got, tc.want)
		}
	}
}

// TestShellBridgeEcho drives a real PTY-backed /bin/sh end to end: dial the
// WebSocket, type a command, and read its output back through the bridge.
func TestShellBridgeEcho(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	c, _ := newTestServer(t)
	c.reauth(t)
	c.post(t, "/system/shell", url.Values{"enabled": {"on"}})

	ts := httptest.NewServer(c.srv)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/shell/ws"
	cfg, err := websocket.NewConfig(wsURL, ts.URL) // Origin == server host: allowed
	if err != nil {
		t.Fatal(err)
	}
	cfg.Header.Add("Cookie", c.cookie.String())
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	if err := frameCodec.Send(ws, wsFrame{typ: websocket.BinaryFrame, data: []byte("echo bridge_ok\n")}); err != nil {
		t.Fatalf("send: %v", err)
	}

	ws.SetDeadline(time.Now().Add(10 * time.Second))
	var got strings.Builder
	for !strings.Contains(got.String(), "bridge_ok") {
		var f wsFrame
		if err := frameCodec.Receive(ws, &f); err != nil {
			t.Fatalf("receive (got %q): %v", got.String(), err)
		}
		got.Write(f.data)
	}
}

func TestShellConfigDefaults(t *testing.T) {
	var sh config.Shell
	if sh.IdleSeconds() != 15*60 {
		t.Errorf("default idle = %d, want 900", sh.IdleSeconds())
	}
	if sh.Sessions() != 1 {
		t.Errorf("default sessions = %d, want 1", sh.Sessions())
	}
	if sh.Command() != "/bin/sh" {
		t.Errorf("default command = %q, want /bin/sh", sh.Command())
	}
}
