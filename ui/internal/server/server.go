// Package server is the HTTP layer: routes, middleware, and template
// rendering. Pages are server-rendered; htmx handles partial refresh.
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"firewall/ui/internal/auth"
	"firewall/ui/internal/config"
	"firewall/ui/internal/devices"
	"firewall/ui/internal/flow"
	"firewall/ui/internal/logs"
	"firewall/ui/internal/privsep"
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
	{Path: "/devices", Title: "Devices", tmpl: "devices.html"},
	{Path: "/system", Title: "System", tmpl: "system.html"},
}

const (
	sessionCookie = "fw_session"
	sessionTTL    = 12 * time.Hour // idle timeout; activity extends it
	// sessionLifetime is the absolute cap. It does not move, whatever the
	// session does — the dashboard's 2 s poll would otherwise keep an open tab
	// alive forever (docs/security-plan.md SEC-11).
	sessionLifetime = 24 * time.Hour
	loginMaxFails   = 5
	loginWindow     = 15 * time.Minute

	// reauthWindow is how long a re-authentication counts for. Long enough to
	// finish the task that prompted it, short enough that a walked-away-from
	// laptop is not a standing authorisation (SEC-6).
	reauthWindow = 5 * time.Minute

	// loginCSRFCookie is the pre-session double-submit cookie. /login has no
	// session to bind a synchronizer token to, so the token is its own cookie
	// and the form echoes it: an attacker who cannot read the victim's cookies
	// cannot produce a matching pair (SEC-15).
	loginCSRFCookie = "fw_login_csrf"
	loginCSRFField  = "login_csrf"

	// CSRF synchronizer token: forms carry it as a hidden field, htmx sends it
	// as a header via layout.html's hx-headers.
	csrfHeader = "X-CSRF-Token"
	csrfField  = "csrf_token"

	// deviceUsageRange is the flow window the Devices page attributes usage
	// over — a day, which is what "how much has this thing used" means to an
	// admin looking at the table.
	deviceUsageRange = "day"

	// auditSource is the pseudo-source the Logs page uses to select the audit
	// trail. It is not a row in the log ring — the trail lives in its own table
	// — but reusing the page's existing source selector keeps one filter UI
	// rather than two.
	auditSource = "audit"

	// Request body ceilings (docs/security-plan.md SEC-4b). Nothing bounded
	// request bodies before this. r.FormValue on a multipart request calls
	// ParseMultipartForm, which buffers 32 MiB and then spills the remainder to
	// temp files with *no total cap* — and /login is public and calls
	// FormValue, so a LAN host with no credentials could fill the filesystem.
	//
	// Every form on the appliance is a handful of short fields; 64 KiB is
	// generous for all of them. The config document is the one real upload.
	maxBodyBytes   = 64 << 10
	maxUploadBytes = 8 << 20

	// contentSecurityPolicy is the page-level containment for the admin UI
	// (docs/security-plan.md SEC-8).
	//
	//   script-src 'self'      — no inline script anywhere; every page's JS
	//                            lives under /static. This is the directive
	//                            that matters, and the reason the templates'
	//                            inline <script> blocks were moved out.
	//   frame-ancestors 'self' — the clickjacking defense CSRF tokens do not
	//                            provide: a token the attacker never has to
	//                            read is no help against a framed UI and a
	//                            tricked click. 'self' rather than 'none'
	//                            because the Visibility page frames the
	//                            same-origin ntopng proxy.
	//   style-src adds 'unsafe-inline' — xterm.js builds its terminal styling
	//                            by injecting <style> elements at runtime,
	//                            which CSP governs. Inline *style* is a far
	//                            weaker vector than inline script, and this is
	//                            the price of not vendoring a patched xterm.
	//   img-src adds data:     — ntopng's UI, which we proxy but do not own.
	contentSecurityPolicy = "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'self'; " +
		"form-action 'self'; " +
		"base-uri 'none'; " +
		"object-src 'none'"
)

// errInvalidLogin is the single failure message the login form ever shows. A
// distinct "invalid TOTP code" would confirm the password was right, turning
// the second factor into a password oracle (design-review §4.6).
var errInvalidLogin = errors.New("invalid username, password, or code")

type Server struct {
	store *config.Store
	// priv is the privileged boundary (internal/privsep). The server holds the
	// interface, not apply.Manager, so that when the root helper lands the only
	// thing that changes here is which implementation main.go constructs.
	priv privsep.Ops
	// shell opens web terminals through that same boundary. It is separate from
	// priv because the two are unrelated capabilities: an appliance may have
	// the config pipeline without the terminal, and nil here means the feature
	// is unavailable however the config document is set.
	shell privsep.ShellOpener
	// wg reads live WireGuard peer state through the same boundary. Nil means
	// the WireGuard page reports "never" for every client, which is what an
	// appliance with no way to ask should say.
	wg        privsep.WGStatus
	logStore  *logs.Store
	traffic   *traffic.Store
	flow      *flow.Store
	mux       *http.ServeMux
	sessions  *auth.Sessions
	logins    *auth.Limiter
	tmpls     map[string]*template.Template // page path -> parsed set
	loginTmpl *template.Template

	totpMu       sync.Mutex
	totpPending  map[string]string // user -> secret awaiting confirmation
	totpLastStep map[string]int64  // user -> newest TOTP step already spent

	shellMu     sync.Mutex
	shellActive int // live web-shell sessions, capped by Shell.MaxSessions

	// setupToken gates first-run account creation (SEC-9). Minted at startup
	// only when the appliance has no users, printed to the console, and never
	// stored: a reboot mints a new one, which is the recovery path.
	setupToken string
}

var funcs = template.FuncMap{
	"humanBytes": humanBytes,
	"humanCount": humanCount,
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

func New(store *config.Store, priv privsep.Ops, shell privsep.ShellOpener, wg privsep.WGStatus, logStore *logs.Store, trafStore *traffic.Store, flowStore *flow.Store) (*Server, error) {
	s := &Server{
		store:        store,
		priv:         priv,
		shell:        shell,
		wg:           wg,
		logStore:     logStore,
		traffic:      trafStore,
		flow:         flowStore,
		mux:          http.NewServeMux(),
		sessions:     auth.NewSessions(sessionTTL, sessionLifetime),
		logins:       auth.NewLimiter(loginMaxFails, loginWindow),
		tmpls:        map[string]*template.Template{},
		totpPending:  map[string]string{},
		totpLastStep: map[string]int64{},
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

	// Mint the first-run setup token before any route is served. Only when the
	// appliance has no users: on a configured box there is nothing to claim, so
	// printing a token would be noise that teaches operators to ignore it.
	if len(store.Get().Users) == 0 {
		s.setupToken = auth.SetupToken()
		log.Printf("=====================================================================")
		log.Printf(" No admin account exists yet. To create one, browse to the WebUI and")
		log.Printf(" enter this setup token:")
		log.Printf("")
		log.Printf("     %s", s.setupToken)
		log.Printf("")
		log.Printf(" It is printed only here, changes on every restart, and is required")
		log.Printf(" once so that whoever reaches the box first cannot claim it.")
		log.Printf("=====================================================================")
	}

	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLogin)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("POST /setup", s.handleSetup)

	s.mux.HandleFunc("GET /partials/stats", s.handleStatsPartial)
	s.mux.HandleFunc("GET /partials/logs", s.handleLogsPartial)
	s.mux.HandleFunc("GET /api/traffic", s.handleTrafficAPI)
	s.mux.HandleFunc("GET /api/flows", s.handleFlowsAPI)
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
	setSecurityHeaders(w, r)
	r.Body = http.MaxBytesReader(w, r.Body, bodyLimit(r))
	if isPublic(r.URL.Path) {
		// The pre-session forms are the only place an unauthenticated caller
		// reaches a body parser, so they take the narrowest possible one: a
		// short urlencoded form and nothing else. Refusing multipart outright
		// closes the temp-file spill without depending on the size cap above
		// (docs/security-plan.md SEC-4b).
		if r.Method == http.MethodPost && !isURLEncodedForm(r) {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
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
	if !s.parseBody(w, r) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	// The user must be in the context before the re-auth gate: its refusals are
	// audited, and an audit line with no actor is worth much less.
	r = r.WithContext(context.WithValue(r.Context(), userKey{}, user))
	// Authorisation before re-authentication: an account that may not do a
	// thing at all should be told so, not asked to confirm its password first.
	if !s.checkRole(w, r, user) {
		return
	}
	if !s.checkReauth(w, r) {
		return
	}
	s.mux.ServeHTTP(w, r)
}

// parseBody parses a state-changing request's form up front, writing the
// refusal itself and reporting whether the request may proceed.
//
// It exists so that a body truncated by the MaxBytesReader in ServeHTTP is a
// visible error rather than a silent one. Handlers read fields with
// r.FormValue, which discards the parse error and returns "" — so an oversized
// POST used to reach a handler as a form full of empty strings and *write them*.
// For /system/hostname that surfaced as a confusing "hostname is required"; for
// /system/smtp it would have quietly blanked the relay. Failing here means a
// handler either sees the whole form or never runs (docs/security-plan.md
// SEC-4b).
func (s *Server) parseBody(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	// The web shell hijacks its connection and the ntopng proxy streams a body
	// we must pass through untouched; neither is a form.
	if r.URL.Path == "/shell/ws" || strings.HasPrefix(r.URL.Path, render.NtopngHTTPPrefix+"/") {
		return true
	}

	var err error
	if mediaType, _, e := mime.ParseMediaType(r.Header.Get("Content-Type")); e == nil &&
		strings.HasPrefix(mediaType, "multipart/") {
		// The in-memory bound is the route's whole body budget, so nothing ever
		// spills to a temp file.
		err = r.ParseMultipartForm(bodyLimit(r))
	} else {
		err = r.ParseForm()
	}
	if err == nil {
		return true
	}

	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return false
	}
	http.Error(w, "malformed form data", http.StatusBadRequest)
	return false
}

// checkCSRF enforces the synchronizer token on every state-changing request,
// writing the refusal itself and reporting whether the request may proceed.
// SameSite=Lax alone is not a boundary: it still allows top-level cross-site
// navigation and it is the browser's policy rather than ours (design-review
// §4.4). The token is bound to the session and reaches us either as a hidden
// form field or, for htmx, as the header layout.html's hx-headers attaches.
// /login and /setup never get here — ServeHTTP short-circuits public paths —
// which is deliberate: there is no session to bind a token to before login.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	// The ntopng subtree proxies a third-party UI whose forms we cannot rewrite,
	// so it falls back to an Origin check: browsers send Origin on every
	// state-changing request, and a cross-site one names a different host.
	if strings.HasPrefix(r.URL.Path, render.NtopngHTTPPrefix+"/") {
		if origin, err := url.Parse(r.Header.Get("Origin")); err == nil && sameOrigin(origin, r.Host) {
			return true
		}
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return false
	}
	var want string
	if c, err := r.Cookie(sessionCookie); err == nil {
		want, _ = s.sessions.CSRF(c.Value)
	}
	got := r.Header.Get(csrfHeader)
	if got == "" {
		got = r.FormValue(csrfField) // parses the body; handlers reuse the cache
	}
	if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		http.Error(w, "CSRF token missing or invalid", http.StatusForbidden)
		return false
	}
	return true
}

// setSecurityHeaders applies the response-header half of the browser-side
// containment (docs/security-plan.md SEC-8). None of these existed before, which
// left the admin UI framable — and CSRF tokens are no defense against a framed
// UI, since a forged click never needs to read the token.
//
// no-store is applied to everything except /static because on this UI it is
// simply true: every page renders live config, and three routes hand out
// outright secrets (the config backup with every hash, key and password in it;
// a WireGuard client config containing its private key; the TOTP enrollment QR).
// Enumerating those three invites forgetting the fourth.
func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN") // pre-CSP browsers; frame-ancestors supersedes it
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	if !strings.HasPrefix(r.URL.Path, "/static/") {
		h.Set("Cache-Control", "no-store")
	}
	if r.TLS != nil {
		// Two years, no preload: this is a private name/address, so the
		// preload list is neither available nor appropriate.
		h.Set("Strict-Transport-Security", "max-age=63072000")
	}
}

// bodyLimit is the request-body ceiling for a route. Only the config restore
// legitimately carries more than a few short form fields.
func bodyLimit(r *http.Request) int64 {
	if r.URL.Path == "/system/restore" {
		return maxUploadBytes
	}
	return maxBodyBytes
}

// isURLEncodedForm reports whether the request body is a plain HTML form post.
// A POST with no Content-Type at all is treated as one, since that is what a
// minimal client sends and the parser handles it.
func isURLEncodedForm(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && mediaType == "application/x-www-form-urlencoded"
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
	// Record where the request came from: the session inventory is only useful
	// if an admin can tell their own session from the one they are about to
	// revoke (docs/security-plan.md SEC-11).
	return s.sessions.GetFrom(c.Value, remoteIP(r))
}

// sessionToken returns the caller's raw session token, for the operations that
// must act on "this session" specifically.
func sessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
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
	FirstRun       bool // no users yet: show the create-admin form
	NeedSetupToken bool // ...and it needs the console token
	Error          string
	CSRF           string // pre-session double-submit token (SEC-15)
}

// issueLoginCSRF mints the pre-session double-submit token and sets its cookie.
//
// /login and /setup cannot carry a synchronizer token: there is no session to
// bind one to. The residual is login-CSRF — an attacker forcing a victim's
// browser into a session on an account the attacker controls, then reading
// what the victim does in it. A cookie the attacker cannot read, echoed in the
// form, closes it: producing a matching pair requires reading the victim's
// cookies, and an attacker who can do that does not need this.
func (s *Server) issueLoginCSRF(w http.ResponseWriter, r *http.Request) string {
	token := auth.RandomToken()
	http.SetCookie(w, &http.Cookie{
		Name:     loginCSRFCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((30 * time.Minute).Seconds()),
	})
	return token
}

// checkLoginCSRF verifies the double-submit pair on a pre-session form.
func (s *Server) checkLoginCSRF(r *http.Request) bool {
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.FormValue(loginCSRFField)
	return got != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) == 1
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
		CSRF:     s.issueLoginCSRF(w, r),
	}
	d.NeedSetupToken = d.FirstRun && s.setupToken != ""
	if err := s.loginTmpl.Execute(w, d); err != nil {
		log.Printf("render login: %v", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.checkLoginCSRF(r) {
		redirect(w, r, "/login", errors.New("your login form expired — try again"))
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))

	// Two buckets with deliberately different behaviour (SEC-12). The address
	// bucket is a hard cap: a host that has guessed wrong five times can wait.
	// The username bucket is an escalating delay, never a refusal — a hard cap
	// there lets any LAN device lock the admin out of their own firewall, which
	// trades a remote brute-force for a local denial of service.
	addrBucket, userBucket := limiterAddrKey(remoteIP(r)), limiterUserKey(username)
	if !s.logins.Allow(addrBucket) {
		s.audit("login.blocked", "user=%s from=%s reason=address-rate-limit", username, remoteIP(r))
		redirect(w, r, "/login", errors.New("too many failed attempts from this address, try again later"))
		return
	}
	if d := s.logins.Delay(userBucket); d > 0 {
		// Sleep rather than refuse. The cost lands on the attempt, so guessing
		// gets slower and slower while the account's owner is only ever
		// delayed.
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}

	// Every failure below reports errInvalidLogin: which factor was wrong is
	// exactly what an attacker wants to know.
	fail := func(reason string) {
		s.logins.Fail(addrBucket)
		s.logins.Fail(userBucket)
		s.audit("login.failed", "user=%s from=%s reason=%s", username, remoteIP(r), reason)
		redirect(w, r, "/login", errInvalidLogin)
	}

	// Always run one argon2 verification, against DummyHash when the user
	// does not exist, so timing does not reveal valid usernames.
	hash, totpSecret, found := auth.DummyHash, "", false
	for _, u := range s.store.Get().Users {
		if u.Username == username {
			hash, totpSecret, found = u.PasswordHash, u.TOTPSecret, true
		}
	}
	if !auth.VerifyPassword(hash, r.FormValue("password")) || !found {
		fail("password")
		return
	}
	if totpSecret != "" {
		step, ok := auth.VerifyTOTPStep(totpSecret, r.FormValue("totp"))
		if !ok || !s.totpSpend(username, step) {
			fail("totp")
			return
		}
	}

	s.logins.Reset(addrBucket)
	s.logins.Reset(userBucket)
	s.setSessionCookie(w, r, s.sessions.Create(username, remoteIP(r)))
	s.audit("login.ok", "user=%s from=%s", username, remoteIP(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// totpSpend records a TOTP time step as used by user and reports whether it was
// still unspent. The ±1 step skew window keeps one code valid for up to 90
// seconds, so without this a shoulder-surfed or replayed code works twice
// (design-review §4.6).
func (s *Server) totpSpend(user string, step int64) bool {
	s.totpMu.Lock()
	defer s.totpMu.Unlock()
	if last, ok := s.totpLastStep[user]; ok && step <= last {
		return false
	}
	s.totpLastStep[user] = step
	return true
}

// limiterAddrKey buckets the login limiter by source address: IPv4 exactly,
// IPv6 by /64. A single subscriber usually holds a whole /64, so keying on the
// full address would let one attacker rotate addresses for unlimited tries
// (design-review §4.6).
func limiterAddrKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ip
	}
	p, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// limiterUserKey namespaces the per-username bucket so it cannot collide with
// an address bucket.
func limiterUserKey(username string) string { return "user:" + username }

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auditRequest(r, "logout", "")
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(c.Value)
	}
	// A half-finished TOTP enrollment is session state, not config state: it
	// must not survive the logout that abandoned it (design-review §4.8).
	if user, ok := r.Context().Value(userKey{}).(string); ok {
		s.totpMu.Lock()
		delete(s.totpPending, user)
		s.totpMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleSetup creates the first admin account and logs it in. Only valid while
// no users exist; afterwards user management belongs to the System page.
//
// It requires the setup token printed on the console at first boot
// (docs/security-plan.md SEC-9). Without it, the window between power-on and
// the owner reaching the UI is a race for ownership of the firewall — and on a
// LAN with a hostile device that is not a race the owner reliably wins. For a
// product that ships to someone else's house that is a shipping blocker, not a
// nicety.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.checkLoginCSRF(r) {
		redirect(w, r, "/login", errors.New("your setup form expired — try again"))
		return
	}
	// Rate-limited on the same address bucket as login: the token is short
	// enough to type, so it is short enough to guess if guessing is free.
	addrBucket := limiterAddrKey(remoteIP(r))
	if !s.logins.Allow(addrBucket) {
		s.audit("setup.blocked", "from=%s reason=address-rate-limit", remoteIP(r))
		redirect(w, r, "/login", errors.New("too many attempts from this address, try again later"))
		return
	}
	if !s.checkSetupToken(r.FormValue("setup_token")) {
		s.logins.Fail(addrBucket)
		s.audit("setup.failed", "from=%s reason=token", remoteIP(r))
		redirect(w, r, "/login", errors.New("wrong setup token — it is printed on the console at first boot"))
		return
	}

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
	s.logins.Reset(addrBucket)
	s.audit("setup.ok", "user=%s from=%s", username, remoteIP(r))
	s.setSessionCookie(w, r, s.sessions.Create(username, remoteIP(r)))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// checkSetupToken compares the submitted token against the one minted at
// startup, in constant time.
//
// An empty stored token means the appliance never printed one — which happens
// only when users already exist, and handleSetup is refused on that ground
// anyway. Treating it as "accept anything" would turn a missing token into no
// protection at all, so it is treated as "accept nothing".
func (s *Server) checkSetupToken(got string) bool {
	if s.setupToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.setupToken), []byte(strings.TrimSpace(got))) == 1
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
	CSRF   string // per-session synchronizer token every form and htmx call carries
	Nav    []Page
	Cfg    config.Config
	Stats  system.Stats
	Error  string // flash message carried via ?err=
	EditID string // list entry being edited inline, via ?edit=

	ApplyPending  bool // an unconfirmed apply is live
	ApplyDeadline time.Time

	TOTPEnrolled bool // logged-in user has 2FA active
	TOTPPending  bool // enrollment QR awaiting confirmation

	// Elevated reports whether this session is inside its re-authentication
	// window; the System page shows the confirm-password prompt when it is not
	// (docs/security-plan.md SEC-6).
	Elevated     bool
	ReauthWindow string
	Sessions     []auth.Session // session inventory (SEC-11)
	// Role is the signed-in account's role, and CanAdmin/CanOperate are the
	// two comparisons templates actually make (SEC-7). Hiding a control a role
	// cannot use is presentation, not enforcement — routeRole is the boundary.
	Role       string
	CanAdmin   bool
	CanOperate bool

	Timezones []string // System page timezone dropdown options

	Logs      []logs.Entry // Logs page only
	LogFilter logs.Filter
	// Audit is the security trail, shown when the Logs page's source filter
	// selects it. It is a separate table with its own retention, so a burst of
	// pf logging cannot evict it (docs/security-plan.md SEC-10).
	Audit     []logs.AuditEntry
	ShowAudit bool

	WGSessions map[string]string // WireGuard page: client ID -> last-seen text

	Devices []devices.Device // Devices page only
}

func (s *Server) data(p Page, r *http.Request) pageData {
	cfg := s.store.Get()
	nav := pages
	// The shell is admin-only (routeRole); offering the nav entry to an account
	// that would be refused is just a worse way to say no.
	if cfg.Shell.Enabled && r != nil {
		if user, _ := r.Context().Value(userKey{}).(string); user != "" {
			if u, ok := cfg.User(user); ok && u.AtLeast(config.RoleAdmin) {
				nav = append(append([]Page{}, pages...), shellPage)
			}
		}
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
		if c, err := r.Cookie(sessionCookie); err == nil {
			d.CSRF, _ = s.sessions.CSRF(c.Value)
		}
		if u, ok := d.Cfg.User(d.User); ok {
			d.TOTPEnrolled = u.TOTPSecret != ""
			d.Role = u.EffectiveRole()
			d.CanAdmin = u.AtLeast(config.RoleAdmin)
			d.CanOperate = u.AtLeast(config.RoleOperator)
		}
		s.totpMu.Lock()
		d.TOTPPending = s.totpPending[d.User] != ""
		s.totpMu.Unlock()
		if tok := sessionToken(r); tok != "" {
			d.Elevated = s.sessions.Elevated(tok)
			if p.Path == "/system" {
				d.Sessions = s.sessions.List(tok)
			}
		}
		d.ReauthWindow = reauthWindow.String()
	}
	d.ApplyDeadline, d.ApplyPending = s.priv.Pending()
	if p.Path == "/system" {
		d.Timezones = config.Timezones()
	}
	if p.Path == "/wireguard" {
		d.WGSessions = s.wgSessions(d.Cfg)
	}
	if p.Path == "/devices" {
		d.Devices = s.deviceTable(d.Cfg)
	}
	if p.Path == "/logs" && r != nil {
		d.LogFilter = logs.Filter{
			Source:   r.URL.Query().Get("source"),
			Contains: r.URL.Query().Get("contains"),
		}
		if d.LogFilter.Source == auditSource {
			d.ShowAudit = true
			var err error
			if d.Audit, err = s.logStore.RecentAudit(logs.AuditFilter{
				Contains: d.LogFilter.Contains,
			}); err != nil {
				log.Printf("audit query: %v", err)
			}
		} else {
			var err error
			if d.Logs, err = s.logStore.Recent(d.LogFilter); err != nil {
				log.Printf("logs query: %v", err)
			}
		}
	}
	return d
}

// deviceTable joins the durable device registry with the live ARP/NDP and DHCP
// views and the flow store's per-host usage (internal/devices). Every input is
// read at request time and nothing is cached: the neighbor tables are the
// answer to "who is here now", and a stale answer is worse than a slow one.
// Sources that are missing (a dev box with no arp, an appliance with no leases
// yet) simply contribute nothing.
func (s *Server) deviceTable(cfg config.Config) []devices.Device {
	var totals map[string]flow.Talker
	if s.flow != nil {
		var err error
		if totals, err = s.flow.HostTotals(deviceUsageRange); err != nil {
			log.Printf("device usage: %v", err) // usage columns render as zero
		}
	}
	return devices.Build(cfg, totals, devices.DefaultSources(cfg))
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

// handleFlowsAPI serves the baseline flow summary (top talkers, per-app totals,
// volume series, and a recent flow log) as JSON for the Visibility page. The
// ?range= param selects hour/day/week/month.
func (s *Server) handleFlowsAPI(w http.ResponseWriter, r *http.Request) {
	res, err := s.flow.Query(r.URL.Query().Get("range"))
	if err != nil {
		log.Printf("flow query: %v", err)
		http.Error(w, "flow query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("flow encode: %v", err)
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
	err := s.priv.Apply(s.store.Get())
	s.auditRequest(r, "apply", "result=%s", auditResult(err))
	redirect(w, r, "/system", err)
}

func (s *Server) handleApplyConfirm(w http.ResponseWriter, r *http.Request) {
	err := s.priv.Confirm()
	s.auditRequest(r, "apply.confirm", "result=%s", auditResult(err))
	redirect(w, r, "/system", err)
}

func (s *Server) handleApplyRollback(w http.ResponseWriter, r *http.Request) {
	err := s.priv.Rollback()
	s.auditRequest(r, "apply.rollback", "result=%s", auditResult(err))
	redirect(w, r, "/system", err)
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
			// Trust is only offered for non-LAN segments: the LAN is the admin
			// plane's home and demoting it would lock the operator out of the
			// page they are standing on.
			if c.Interfaces[i].Role != "lan" {
				c.Interfaces[i].Trust = r.FormValue("trust")
			}
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

// humanCount is humanBytes for the signed counters the flow store returns
// (Devices page). Template functions match argument types exactly, so the
// conversion has to live somewhere; here beats duplicating the formatter.
func humanCount(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	return humanBytes(uint64(n))
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
