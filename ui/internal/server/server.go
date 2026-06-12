// Package server is the HTTP layer: routes, middleware, and template
// rendering. Pages are server-rendered; htmx handles partial refresh.
package server

import (
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"

	"firewall/ui/internal/config"
	"firewall/ui/internal/system"
	"firewall/ui/web"
)

type Page struct {
	Path  string
	Title string
	tmpl  string // template file under templates/pages/
}

// Nav order matches plan.md §7. Shell is intentionally absent until the
// off-by-default ttyd integration lands.
var pages = []Page{
	{Path: "/", Title: "Dashboard", tmpl: "dashboard.html"},
	{Path: "/nat", Title: "NAT", tmpl: "nat.html"},
	{Path: "/dhcp", Title: "DHCP", tmpl: "dhcp.html"},
	{Path: "/dns", Title: "DNS", tmpl: "dns.html"},
	{Path: "/wireguard", Title: "WireGuard", tmpl: "wireguard.html"},
	{Path: "/logs", Title: "Logs", tmpl: "logs.html"},
	{Path: "/traffic", Title: "Traffic", tmpl: "traffic.html"},
	{Path: "/system", Title: "System", tmpl: "system.html"},
}

type Server struct {
	store *config.Store
	mux   *http.ServeMux
	tmpls map[string]*template.Template // page path -> parsed set
}

var funcs = template.FuncMap{
	"humanBytes": humanBytes,
}

func New(store *config.Store) (*Server, error) {
	s := &Server{
		store: store,
		mux:   http.NewServeMux(),
		tmpls: map[string]*template.Template{},
	}

	for _, p := range pages {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(web.FS,
			"templates/layout.html",
			"templates/partials/*.html",
			"templates/pages/"+p.tmpl,
		)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p.tmpl, err)
		}
		s.tmpls[p.Path] = t
		// "/" alone would match every unregistered path; "{$}" pins it to
		// the root. Other paths already match exactly.
		pattern := "GET " + p.Path
		if p.Path == "/" {
			pattern = "GET /{$}"
		}
		p := p
		s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			s.render(w, p)
		})
	}

	static, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, err
	}
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	s.mux.HandleFunc("GET /partials/stats", s.handleStatsPartial)
	s.mux.HandleFunc("POST /system/hostname", s.handleSetHostname)

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: session auth middleware (argon2 local users, optional TOTP,
	// login rate limiting) before any handler runs. LAN-only bind plus
	// this middleware is the v1 security boundary.
	s.mux.ServeHTTP(w, r)
}

type pageData struct {
	Title  string
	Active string
	Nav    []Page
	Cfg    config.Config
	Stats  system.Stats
}

func (s *Server) data(p Page) pageData {
	return pageData{
		Title:  p.Title,
		Active: p.Path,
		Nav:    pages,
		Cfg:    s.store.Get(),
		Stats:  system.Collect(),
	}
}

func (s *Server) render(w http.ResponseWriter, p Page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpls[p.Path].Execute(w, s.data(p)); err != nil {
		log.Printf("render %s: %v", p.Path, err)
	}
}

// handleStatsPartial serves the dashboard stats fragment that htmx polls.
func (s *Server) handleStatsPartial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpls["/"].ExecuteTemplate(w, "stats", s.data(pages[0])); err != nil {
		log.Printf("render stats partial: %v", err)
	}
}

// handleSetHostname is the first full vertical slice through the config
// engine: form -> Store.Update (validate + atomic save) -> re-render.
func (s *Server) handleSetHostname(w http.ResponseWriter, r *http.Request) {
	hostname := r.FormValue("hostname")
	err := s.store.Update(func(c *config.Config) error {
		c.System.Hostname = hostname
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/system", http.StatusSeeOther)
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
