package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"firewall/ui/internal/config"
	"firewall/ui/internal/render"
)

// Visibility is the deep traffic-analysis page (plan.md §8): settings plus an
// embedded ntopng view. ntopng binds to localhost and is reverse-proxied under
// render.NtopngHTTPPrefix behind the session gate, so it inherits the
// appliance's auth and adds no separate listener.
func (s *Server) routesVisibility() {
	s.mux.HandleFunc("POST /visibility/settings", s.handleVisibilitySettings)
	// Subtree proxy to ntopng. The prefix matches ntopng's --http-prefix so the
	// links it generates route straight back here. All methods (it POSTs too).
	// ServeHTTP's session gate already covers this non-public subtree.
	s.mux.Handle(render.NtopngHTTPPrefix+"/", s.handleVisibilityProxy())
}

func (s *Server) handleVisibilitySettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirect(w, r, "/visibility", err)
		return
	}
	enabled := r.FormValue("enabled") == "on"
	// Checkboxes: each checked interface posts its Name under "interfaces".
	selected := r.Form["interfaces"]
	port := 0
	if p := strings.TrimSpace(r.FormValue("http_port")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			redirect(w, r, "/visibility", fmt.Errorf("http port must be a number"))
			return
		}
		port = n
	}

	err := s.store.Update(func(c *config.Config) error {
		c.Visibility.Enabled = enabled
		c.Visibility.HTTPPort = port
		// Empty == all interfaces. Treat "every interface checked" as the same
		// default so the stored config stays minimal.
		if len(selected) == len(c.Interfaces) {
			c.Visibility.Interfaces = nil
		} else {
			c.Visibility.Interfaces = selected
		}
		return nil
	})
	redirect(w, r, "/visibility", err)
}

// handleVisibilityProxy reverse-proxies ntopng's localhost web UI. It is built
// per request because the target port is config-driven; constructing a
// ReverseProxy is cheap. A friendly 503 replaces the raw connection error when
// ntopng is not running (the common dev-box and feature-off case).
func (s *Server) handleVisibilityProxy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := s.store.Get().Visibility
		if !v.Enabled {
			http.Error(w, "network visibility is disabled", http.StatusForbidden)
			return
		}
		target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(v.Port())}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			s.auditShell("visibility proxy error: %v", err) // reuses the log-ring helper
			http.Error(w, "traffic analyzer unavailable — apply the config to start ntopng", http.StatusServiceUnavailable)
		}
		proxy.ServeHTTP(w, r)
	}
}
