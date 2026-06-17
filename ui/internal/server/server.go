// Package server is the HTTP layer: routes, middleware, and template
// rendering. Pages are server-rendered; htmx handles partial refresh.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"firewall/ui/internal/apply"
	"firewall/ui/internal/auth"
	"firewall/ui/internal/config"
	"firewall/ui/internal/logs"
	"firewall/ui/internal/render"
	"firewall/ui/internal/system"
	"firewall/ui/internal/traffic"
	"firewall/ui/web"
)

type Page struct {
	Path  string
	Title string
	tmpl  string // template file under templates/pages/
}

// Nav order matches plan.md §7. The Shell entry lives in shellPage (shell.go)
// and is appended to the nav per-request only when Shell.Enabled.
var pages = []Page{
	{Path: "/", Title: "Dashboard", tmpl: "dashboard.html"},
	{Path: "/services", Title: "Services", tmpl: "services.html"},
	{Path: "/nat", Title: "NAT", tmpl: "nat.html"},
	{Path: "/interfaces", Title: "Interfaces", tmpl: "interfaces.html"},
	{Path: "/dns", Title: "DNS", tmpl: "dns.html"},
	{Path: "/wireguard", Title: "WireGuard", tmpl: "wireguard.html"},
	{Path: "/logs", Title: "Logs", tmpl: "logs.html"},
	{Path: "/traffic", Title: "Traffic", tmpl: "traffic.html"},
	{Path: "/visibility", Title: "Visibility", tmpl: "visibility.html"},
	{Path: "/system", Title: "System", tmpl: "system.html"},
}

const (
	sessionCookie = "fw_session"
	sessionTTL    = 12 * time.Hour // idle timeout; activity extends it
	loginMaxFails = 5
	loginWindow   = 15 * time.Minute
)

type Server struct {
	store     *config.Store
	mgr       *apply.Manager
	logStore  *logs.Store
	traffic   *traffic.Store
	mux       *http.ServeMux
	sessions  *auth.Sessions
	logins    *auth.Limiter
	tmpls     map[string]*template.Template // page path -> parsed set
	loginTmpl *template.Template

	totpMu      sync.Mutex
	totpPending map[string]string // user -> secret awaiting confirmation

	shellMu     sync.Mutex
	shellActive int // live web-shell sessions, capped by Shell.MaxSessions
}

var funcs = template.FuncMap{
	"humanBytes": humanBytes,
	"contains":   contains,
	"service":    serviceByID,
}

// serviceByID resolves a service for display in templates (NAT shows the
// destination of the service a port forward references). Returns a zero Service
// if the id is unknown, so the template renders blanks rather than erroring.
func serviceByID(services []config.Service, id string) config.Service {
	for _, svc := range services {
		if svc.ID == id {
			return svc
		}
	}
	return config.Service{}
}

// contains reports whether v is in the slice; used by the WireGuard template to
// pre-check a client's granted-service boxes.
func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func New(store *config.Store, mgr *apply.Manager, logStore *logs.Store, trafStore *traffic.Store) (*Server, error) {
	s := &Server{
		store:       store,
		mgr:         mgr,
		logStore:    logStore,
		traffic:     trafStore,
		mux:         http.NewServeMux(),
		sessions:    auth.NewSessions(sessionTTL),
		logins:      auth.NewLimiter(loginMaxFails, loginWindow),
		tmpls:       map[string]*template.Template{},
		totpPending: map[string]string{},
	}

	loginTmpl, err := template.ParseFS(web.FS, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("parse login.html: %w", err)
	}
	s.loginTmpl = loginTmpl

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

	// The web shell is parsed and routed unconditionally; the handlers and the
	// nav both gate on Shell.Enabled at request time (docs/shell.md §9).
	shellTmpl, err := template.New("layout.html").Funcs(funcs).ParseFS(web.FS,
		"templates/layout.html",
		"templates/partials/*.html",
		"templates/pages/"+shellPage.tmpl,
	)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", shellPage.tmpl, err)
	}
	s.tmpls[shellPage.Path] = shellTmpl
	s.mux.HandleFunc("GET /shell", s.handleShellPage)
	s.mux.HandleFunc("GET /shell/ws", s.handleShellWS)

	// The per-client WireGuard access editor is a sub-page (not in the nav),
	// rendered with the shared layout like the shell page.
	accessTmpl, err := template.New("layout.html").Funcs(funcs).ParseFS(web.FS,
		"templates/layout.html",
		"templates/partials/*.html",
		"templates/pages/wg_access.html",
	)
	if err != nil {
		return nil, fmt.Errorf("parse wg_access.html: %w", err)
	}
	s.tmpls[wgAccessKey] = accessTmpl

	static, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, err
	}
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLogin)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("POST /setup", s.handleSetup)

	s.mux.HandleFunc("GET /partials/stats", s.handleStatsPartial)
	s.mux.HandleFunc("GET /partials/logs", s.handleLogsPartial)
	s.mux.HandleFunc("GET /api/traffic", s.handleTrafficAPI)
	s.mux.HandleFunc("GET /system/pf.conf", s.handlePFPreview)
	s.mux.HandleFunc("POST /system/hostname", s.handleSetHostname)
	s.mux.HandleFunc("POST /interfaces/{name}/address", s.handleInterfaceAddress)
	s.mux.HandleFunc("POST /system/apply", s.handleApply)
	s.mux.HandleFunc("POST /system/apply/confirm", s.handleApplyConfirm)
	s.mux.HandleFunc("POST /system/apply/rollback", s.handleApplyRollback)

	s.mux.HandleFunc("POST /nat/forwards", s.handleForwardCreate)
	s.mux.HandleFunc("POST /nat/forwards/{id}", s.handleForwardUpdate)
	s.mux.HandleFunc("POST /nat/forwards/{id}/toggle", s.handleForwardToggle)
	s.mux.HandleFunc("POST /nat/forwards/{id}/delete", s.handleForwardDelete)

	s.routesServices()
	s.routesDHCP()
	s.routesDNS()
	s.routesWireGuard()
	s.routesWGServer()
	s.routesVisibility()
	s.routesSystem()

	return s, nil
}

// userKey carries the authenticated username in the request context.
type userKey struct{}

// ServeHTTP gates every route behind session auth. LAN-only bind plus this
// check is the v1 security boundary (plan.md §7). TOTP still TODO.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isPublic(r.URL.Path) {
		s.mux.ServeHTTP(w, r)
		return
	}
	user, ok := s.sessionUser(r)
	if !ok {
		// htmx swaps a 3xx target into the page instead of navigating;
		// HX-Redirect makes the browser do a real redirect to /login.
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
}

// isPublic lists the routes reachable without a session: the login/setup
// flow and the assets it needs. /setup self-guards once users exist.
func isPublic(path string) bool {
	return path == "/login" || path == "/setup" || strings.HasPrefix(path, "/static/")
}

func (s *Server) sessionUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	return s.sessions.Get(c.Value)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode, // blocks cross-site POSTs; v1 CSRF defense
	})
}

type loginData struct {
	FirstRun bool // no users yet: show the create-admin form
	Error    string
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessionUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	d := loginData{
		FirstRun: len(s.store.Get().Users) == 0,
		Error:    r.URL.Query().Get("err"),
	}
	if err := s.loginTmpl.Execute(w, d); err != nil {
		log.Printf("render login: %v", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if !s.logins.Allow(ip) {
		redirect(w, r, "/login", errors.New("too many failed attempts, try again later"))
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))

	// Always run one argon2 verification, against DummyHash when the user
	// does not exist, so timing does not reveal valid usernames.
	hash, totpSecret, found := auth.DummyHash, "", false
	for _, u := range s.store.Get().Users {
		if u.Username == username {
			hash, totpSecret, found = u.PasswordHash, u.TOTPSecret, true
		}
	}
	if !auth.VerifyPassword(hash, r.FormValue("password")) || !found {
		s.logins.Fail(ip)
		redirect(w, r, "/login", errors.New("invalid username or password"))
		return
	}
	if totpSecret != "" && !auth.VerifyTOTP(totpSecret, r.FormValue("totp")) {
		s.logins.Fail(ip)
		redirect(w, r, "/login", errors.New("invalid TOTP code"))
		return
	}

	s.logins.Reset(ip)
	s.setSessionCookie(w, r, s.sessions.Create(username))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleSetup creates the first admin account and logs it in. Only valid
// while no users exist; afterwards user management belongs to the System
// page (TODO).
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	if len(password) < 8 {
		redirect(w, r, "/login", errors.New("password must be at least 8 characters"))
		return
	}
	if r.FormValue("confirm") != password {
		redirect(w, r, "/login", errors.New("passwords do not match"))
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	hash := auth.HashPassword(password) // hash before Update: don't hold the store lock for ~50 ms
	err := s.store.Update(func(c *config.Config) error {
		if len(c.Users) > 0 {
			return errors.New("setup already completed")
		}
		c.Users = append(c.Users, config.User{Username: username, PasswordHash: hash})
		return nil
	})
	if err != nil {
		redirect(w, r, "/login", err)
		return
	}
	s.setSessionCookie(w, r, s.sessions.Create(username))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// remoteIP keys the login limiter. The UI binds LAN-only with no proxy in
// front, so RemoteAddr is trustworthy — no X-Forwarded-For parsing.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type pageData struct {
	Title  string
	Active string
	User   string // authenticated username, for the header
	Nav    []Page
	Cfg    config.Config
	Stats  system.Stats
	Error  string // flash message carried via ?err=
	EditID string // list entry being edited inline, via ?edit=

	ApplyPending  bool // an unconfirmed apply is live
	ApplyDeadline time.Time

	TOTPEnrolled bool // logged-in user has 2FA active
	TOTPPending  bool // enrollment QR awaiting confirmation

	Timezones []string // System page timezone dropdown options

	Logs      []logs.Entry // Logs page only
	LogFilter logs.Filter

	WGSessions map[string]string // WireGuard page: client ID -> last-seen text
}

func (s *Server) data(p Page, r *http.Request) pageData {
	cfg := s.store.Get()
	nav := pages
	if cfg.Shell.Enabled {
		nav = append(append([]Page{}, pages...), shellPage)
	}
	d := pageData{
		Title:  p.Title,
		Active: p.Path,
		Nav:    nav,
		Cfg:    cfg,
		Stats:  system.Collect(),
	}
	if r != nil {
		d.Error = r.URL.Query().Get("err")
		d.EditID = r.URL.Query().Get("edit")
		d.User, _ = r.Context().Value(userKey{}).(string)
		for _, u := range d.Cfg.Users {
			if u.Username == d.User {
				d.TOTPEnrolled = u.TOTPSecret != ""
			}
		}
		s.totpMu.Lock()
		d.TOTPPending = s.totpPending[d.User] != ""
		s.totpMu.Unlock()
	}
	d.ApplyDeadline, d.ApplyPending = s.mgr.Pending()
	if p.Path == "/system" {
		d.Timezones = config.Timezones()
	}
	if p.Path == "/wireguard" {
		d.WGSessions = s.wgSessions(d.Cfg)
	}
	if p.Path == "/logs" && r != nil {
		d.LogFilter = logs.Filter{
			Source:   r.URL.Query().Get("source"),
			Contains: r.URL.Query().Get("contains"),
		}
		var err error
		if d.Logs, err = s.logStore.Recent(d.LogFilter); err != nil {
			log.Printf("logs query: %v", err)
		}
	}
	return d
}

// handleLogsPartial serves the table fragment the Logs page polls, keeping
// the active filter via query params.
func (s *Server) handleLogsPartial(w http.ResponseWriter, r *http.Request) {
	var logsPage Page
	for _, p := range pages {
		if p.Path == "/logs" {
			logsPage = p
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpls["/logs"].ExecuteTemplate(w, "logtable", s.data(logsPage, r)); err != nil {
		log.Printf("render logs partial: %v", err)
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, p Page) {
	// Render into a buffer first: a template execution error mid-page would
	// otherwise leave a 200 with truncated HTML (a silent, hard-to-spot bug).
	// Buffering lets us fail with a 500 instead, which tests can catch.
	var buf bytes.Buffer
	if err := s.tmpls[p.Path].Execute(&buf, s.data(p, r)); err != nil {
		log.Printf("render %s: %v", p.Path, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
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

// handleTrafficAPI serves bucketed per-interface throughput as JSON for the
// Traffic page chart. The ?range= param selects hour/day/week/month.
func (s *Server) handleTrafficAPI(w http.ResponseWriter, r *http.Request) {
	res, err := s.traffic.Query(r.URL.Query().Get("range"))
	if err != nil {
		log.Printf("traffic query: %v", err)
		http.Error(w, "traffic query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("traffic encode: %v", err)
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

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	redirect(w, r, "/system", s.mgr.Apply(s.store.Get()))
}

func (s *Server) handleApplyConfirm(w http.ResponseWriter, r *http.Request) {
	redirect(w, r, "/system", s.mgr.Confirm())
}

func (s *Server) handleApplyRollback(w http.ResponseWriter, r *http.Request) {
	redirect(w, r, "/system", s.mgr.Rollback())
}

// parseForward reads port-forward form fields; semantic checks (port range,
// service existence, duplicates) are config.Validate's job. The destination
// comes from the referenced service, not the form.
func parseForward(r *http.Request) (config.PortForward, error) {
	wanPort, err := strconv.Atoi(r.FormValue("wan_port"))
	if err != nil {
		return config.PortForward{}, errors.New("wan port must be a number")
	}
	return config.PortForward{
		Name:      strings.TrimSpace(r.FormValue("name")),
		ServiceID: strings.TrimSpace(r.FormValue("service_id")),
		WANPort:   wanPort,
		Enabled:   r.FormValue("enabled") == "on",
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

// handleInterfaceAddress edits one interface's device and addressing on the
// Interfaces page. Role assignments are fixed at three (wan/lan/opt); only the
// hardware mapping and address change here. Non-WAN forms omit the mode
// selector, so an absent "mode" means static — the only valid choice for an
// interface that hosts a DHCP server.
func (s *Server) handleInterfaceAddress(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.store.Update(func(c *config.Config) error {
		for i := range c.Interfaces {
			if c.Interfaces[i].Name != name {
				continue
			}
			c.Interfaces[i].Device = strings.TrimSpace(r.FormValue("device"))
			c.Interfaces[i].DHCPClient = r.FormValue("mode") == "dhcp"
			c.Interfaces[i].IPv4 = ""
			if !c.Interfaces[i].DHCPClient {
				c.Interfaces[i].IPv4 = strings.TrimSpace(r.FormValue("ipv4"))
			}
			return nil
		}
		return fmt.Errorf("interface %s not found", name)
	})
	redirect(w, r, "/interfaces", err)
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
