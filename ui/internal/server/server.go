// Package server is the HTTP layer: routes, middleware, and template
// rendering. Pages are server-rendered; htmx handles partial refresh.
package server

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"firewall/ui/internal/config"
	"firewall/ui/internal/render"
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
			s.render(w, r, p)
		})
	}

	static, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, err
	}
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	s.mux.HandleFunc("GET /partials/stats", s.handleStatsPartial)
	s.mux.HandleFunc("GET /system/pf.conf", s.handlePFPreview)
	s.mux.HandleFunc("POST /system/hostname", s.handleSetHostname)

	s.mux.HandleFunc("POST /nat/forwards", s.handleForwardCreate)
	s.mux.HandleFunc("POST /nat/forwards/{id}", s.handleForwardUpdate)
	s.mux.HandleFunc("POST /nat/forwards/{id}/toggle", s.handleForwardToggle)
	s.mux.HandleFunc("POST /nat/forwards/{id}/delete", s.handleForwardDelete)

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
	Error  string // flash message carried via ?err=
	EditID string // list entry being edited inline, via ?edit=
}

func (s *Server) data(p Page, r *http.Request) pageData {
	d := pageData{
		Title:  p.Title,
		Active: p.Path,
		Nav:    pages,
		Cfg:    s.store.Get(),
		Stats:  system.Collect(),
	}
	if r != nil {
		d.Error = r.URL.Query().Get("err")
		d.EditID = r.URL.Query().Get("edit")
	}
	return d
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, p Page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpls[p.Path].Execute(w, s.data(p, r)); err != nil {
		log.Printf("render %s: %v", p.Path, err)
	}
}

// redirect sends the post-action redirect, carrying any error as a flash
// message in the query string.
func redirect(w http.ResponseWriter, r *http.Request, path string, err error) {
	if err != nil {
		path += "?err=" + url.QueryEscape(err.Error())
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// handleStatsPartial serves the dashboard stats fragment that htmx polls.
func (s *Server) handleStatsPartial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpls["/"].ExecuteTemplate(w, "stats", s.data(pages[0], r)); err != nil {
		log.Printf("render stats partial: %v", err)
	}
}

// handlePFPreview serves the ruleset the current config renders to, before
// any apply. Plain text — view-source for the firewall.
func (s *Server) handlePFPreview(w http.ResponseWriter, r *http.Request) {
	out, err := render.PF(s.store.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, out)
}

// parseForward reads port-forward form fields; semantic checks (port ranges,
// IP syntax, duplicates) are config.Validate's job.
func parseForward(r *http.Request) (config.PortForward, error) {
	wanPort, err := strconv.Atoi(r.FormValue("wan_port"))
	if err != nil {
		return config.PortForward{}, errors.New("wan port must be a number")
	}
	destPort, err := strconv.Atoi(r.FormValue("dest_port"))
	if err != nil {
		return config.PortForward{}, errors.New("destination port must be a number")
	}
	return config.PortForward{
		Name:     strings.TrimSpace(r.FormValue("name")),
		Proto:    r.FormValue("proto"),
		WANPort:  wanPort,
		DestIP:   strings.TrimSpace(r.FormValue("dest_ip")),
		DestPort: destPort,
		Enabled:  r.FormValue("enabled") == "on",
	}, nil
}

func (s *Server) handleForwardCreate(w http.ResponseWriter, r *http.Request) {
	pf, err := parseForward(r)
	if err == nil {
		pf.ID = config.NewID()
		err = s.store.Update(func(c *config.Config) error {
			c.NAT.PortForwards = append(c.NAT.PortForwards, pf)
			return nil
		})
	}
	redirect(w, r, "/nat", err)
}

func (s *Server) handleForwardUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	pf, err := parseForward(r)
	if err == nil {
		pf.ID = id
		err = s.store.Update(updateForward(id, func(cur *config.PortForward) {
			pf.Enabled = cur.Enabled // toggle owns this flag; edit form doesn't carry it
			*cur = pf
		}))
	}
	redirect(w, r, "/nat", err)
}

func (s *Server) handleForwardToggle(w http.ResponseWriter, r *http.Request) {
	err := s.store.Update(updateForward(r.PathValue("id"), func(pf *config.PortForward) {
		pf.Enabled = !pf.Enabled
	}))
	redirect(w, r, "/nat", err)
}

func (s *Server) handleForwardDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.Update(func(c *config.Config) error {
		for i, pf := range c.NAT.PortForwards {
			if pf.ID == id {
				c.NAT.PortForwards = append(c.NAT.PortForwards[:i], c.NAT.PortForwards[i+1:]...)
				return nil
			}
		}
		return errors.New("port forward not found")
	})
	redirect(w, r, "/nat", err)
}

// updateForward builds a Store.Update mutation that applies fn to the forward
// with the given id, or fails if it no longer exists.
func updateForward(id string, fn func(*config.PortForward)) func(*config.Config) error {
	return func(c *config.Config) error {
		for i := range c.NAT.PortForwards {
			if c.NAT.PortForwards[i].ID == id {
				fn(&c.NAT.PortForwards[i])
				return nil
			}
		}
		return errors.New("port forward not found")
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
	redirect(w, r, "/system", err)
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
