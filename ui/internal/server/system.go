package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"firewall/ui/internal/auth"
	"firewall/ui/internal/config"
)

func (s *Server) routesSystem() {
	s.mux.HandleFunc("GET /system/backup", s.handleBackup)
	s.mux.HandleFunc("POST /system/restore", s.handleRestore)
	s.mux.HandleFunc("POST /system/users", s.handleUserCreate)
	s.mux.HandleFunc("POST /system/users/{name}/delete", s.handleUserDelete)
	s.mux.HandleFunc("POST /system/users/{name}/password", s.handleUserPassword)
	s.mux.HandleFunc("POST /system/totp/begin", s.handleTOTPBegin)
	s.mux.HandleFunc("GET /system/totp/qr.png", s.handleTOTPQR)
	s.mux.HandleFunc("POST /system/totp/confirm", s.handleTOTPConfirm)
	s.mux.HandleFunc("POST /system/totp/disable", s.handleTOTPDisable)
	s.mux.HandleFunc("POST /system/shell", s.handleShellToggle)
	s.mux.HandleFunc("POST /system/smtp", s.handleSMTPSettings)
	s.mux.HandleFunc("POST /system/time", s.handleSetTimezone)
	s.mux.HandleFunc("POST /system/dns/servers", s.handleDNSServerAdd)
	s.mux.HandleFunc("POST /system/dns/servers/delete", s.handleDNSServerDelete)
	s.mux.HandleFunc("GET /system/dns/test", s.handleDNSTest)
	s.mux.HandleFunc("POST /system/ntp/servers", s.handleNTPServerAdd)
	s.mux.HandleFunc("POST /system/ntp/servers/delete", s.handleNTPServerDelete)
	s.mux.HandleFunc("GET /system/ntp/test", s.handleNTPTest)
}

// handleSetTimezone stores the appliance's UTC offset (config.Timezones).
func (s *Server) handleSetTimezone(w http.ResponseWriter, r *http.Request) {
	tz := r.FormValue("timezone")
	err := s.store.Update(func(c *config.Config) error {
		c.System.Timezone = tz
		return nil
	})
	redirect(w, r, "/system", err)
}

func (s *Server) handleDNSServerAdd(w http.ResponseWriter, r *http.Request) {
	server := config.DNSServer{
		Address:  strings.TrimSpace(r.FormValue("address")),
		Hostname: strings.TrimSpace(r.FormValue("hostname")),
	}
	err := s.store.Update(func(c *config.Config) error {
		c.System.DNSServers = append(c.System.DNSServers, server)
		return nil
	})
	redirect(w, r, "/interfaces", err)
}

func (s *Server) handleDNSServerDelete(w http.ResponseWriter, r *http.Request) {
	addr := r.FormValue("address")
	err := s.store.Update(func(c *config.Config) error {
		for i, d := range c.System.DNSServers {
			if d.Address == addr {
				c.System.DNSServers = append(c.System.DNSServers[:i], c.System.DNSServers[i+1:]...)
				return nil
			}
		}
		return errors.New("dns server not found")
	})
	redirect(w, r, "/interfaces", err)
}

func (s *Server) handleNTPServerAdd(w http.ResponseWriter, r *http.Request) {
	server := strings.TrimSpace(r.FormValue("server"))
	err := s.store.Update(func(c *config.Config) error {
		c.System.NTPServers = append(c.System.NTPServers, server)
		return nil
	})
	redirect(w, r, "/system", err)
}

func (s *Server) handleNTPServerDelete(w http.ResponseWriter, r *http.Request) {
	server := r.FormValue("server")
	err := s.store.Update(func(c *config.Config) error {
		for i, n := range c.System.NTPServers {
			if n == server {
				c.System.NTPServers = append(c.System.NTPServers[:i], c.System.NTPServers[i+1:]...)
				return nil
			}
		}
		return errors.New("ntp server not found")
	})
	redirect(w, r, "/system", err)
}

// handleDNSTest probes an upstream resolver live and returns an HTML fragment
// htmx swaps into the row. With a hostname it times a DNS-over-TLS handshake
// (and verifies the cert); otherwise it times a plain UDP query round trip.
func (s *Server) handleDNSTest(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimSpace(r.URL.Query().Get("address"))
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))
	d, note, err := probeDNS(address, hostname)
	writeProbeResult(w, d, note, err)
}

// handleNTPTest times an SNTP request/response round trip to the time source.
func (s *Server) handleNTPTest(w http.ResponseWriter, r *http.Request) {
	server := strings.TrimSpace(r.URL.Query().Get("server"))
	d, err := probeNTP(server)
	writeProbeResult(w, d, "", err)
}

// handleSMTPSettings saves the outbound mail relay. It lives on the System page
// because email is a shared facility: WireGuard client configs today, status
// and alert notifications later.
func (s *Server) handleSMTPSettings(w http.ResponseWriter, r *http.Request) {
	port := 0
	if v := strings.TrimSpace(r.FormValue("port")); v != "" {
		var err error
		if port, err = strconv.Atoi(v); err != nil {
			redirect(w, r, "/system", errors.New("smtp port must be a number"))
			return
		}
	}
	err := s.store.Update(func(c *config.Config) error {
		c.SMTP = config.SMTP{
			Host:     strings.TrimSpace(r.FormValue("host")),
			Port:     port,
			Username: strings.TrimSpace(r.FormValue("username")),
			Password: r.FormValue("password"),
			From:     strings.TrimSpace(r.FormValue("from")),
			Security: r.FormValue("security"),
		}
		return nil
	})
	redirect(w, r, "/system", err)
}

// handleShellToggle flips the web-shell master switch. It is a UI-service
// setting, not a packet-path one, so it takes effect immediately via
// Store.Update without the apply/rollback pipeline (docs/shell.md §3).
func (s *Server) handleShellToggle(w http.ResponseWriter, r *http.Request) {
	enable := r.FormValue("enabled") == "on"
	err := s.store.Update(func(c *config.Config) error {
		c.Shell.Enabled = enable
		return nil
	})
	if err == nil {
		state := "disabled"
		if enable {
			state = "enabled"
		}
		user, _ := r.Context().Value(userKey{}).(string)
		s.auditShell("config %s by user=%s from=%s", state, user, remoteIP(r))
	}
	redirect(w, r, "/system", err)
}

// handleBackup downloads the whole config document. The single JSON file is
// the complete appliance state (plan.md §7), so this is the entire backup
// story. It includes password hashes and WireGuard/TOTP secrets — the file
// deserves the same care as the appliance itself.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	data, err := json.MarshalIndent(s.store.Get(), "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="fw-config.json"`)
	w.Write(append(data, '\n'))
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	f, _, err := r.FormFile("backup")
	if err != nil {
		redirect(w, r, "/system", errors.New("choose a backup file to restore"))
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		redirect(w, r, "/system", err)
		return
	}
	var next config.Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields() // catches uploading the wrong JSON file
	if err := dec.Decode(&next); err != nil {
		redirect(w, r, "/system", fmt.Errorf("not a valid backup: %w", err))
		return
	}
	if err := s.store.Replace(next); err != nil {
		redirect(w, r, "/system", fmt.Errorf("restore rejected: %w", err))
		return
	}
	redirect(w, r, "/system", errors.New("restored — review and apply to take effect"))
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if len(password) < 8 {
		redirect(w, r, "/system", errors.New("password must be at least 8 characters"))
		return
	}
	hash := auth.HashPassword(password) // outside the store lock; ~50 ms
	err := s.store.Update(func(c *config.Config) error {
		c.Users = append(c.Users, config.User{Username: username, PasswordHash: hash})
		return nil
	})
	redirect(w, r, "/system", err)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.store.Update(func(c *config.Config) error {
		if len(c.Users) == 1 {
			return errors.New("cannot delete the last user")
		}
		for i, u := range c.Users {
			if u.Username == name {
				c.Users = append(c.Users[:i], c.Users[i+1:]...)
				return nil
			}
		}
		return errors.New("user not found")
	})
	redirect(w, r, "/system", err)
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	password := r.FormValue("password")
	if len(password) < 8 {
		redirect(w, r, "/system", errors.New("password must be at least 8 characters"))
		return
	}
	if r.FormValue("confirm") != password {
		redirect(w, r, "/system", errors.New("passwords do not match"))
		return
	}
	hash := auth.HashPassword(password)
	err := s.store.Update(updateUser(name, func(u *config.User) {
		u.PasswordHash = hash
	}))
	redirect(w, r, "/system", err)
}

// updateUser builds a Store.Update mutation targeting one user by name.
func updateUser(name string, fn func(*config.User)) func(*config.Config) error {
	return func(c *config.Config) error {
		for i := range c.Users {
			if c.Users[i].Username == name {
				fn(&c.Users[i])
				return nil
			}
		}
		return errors.New("user not found")
	}
}

// TOTP enrollment is two-step: begin stores a pending secret in memory and
// the page shows its QR; confirm proves the authenticator has it before the
// secret is committed to the config. Always for the logged-in user only.

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey{}).(string)
	s.totpMu.Lock()
	s.totpPending[user] = auth.NewTOTPSecret()
	s.totpMu.Unlock()
	redirect(w, r, "/system", nil)
}

func (s *Server) handleTOTPQR(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey{}).(string)
	s.totpMu.Lock()
	secret := s.totpPending[user]
	s.totpMu.Unlock()
	if secret == "" {
		http.Error(w, "no enrollment in progress", http.StatusNotFound)
		return
	}
	png, err := qrcode.Encode(auth.TOTPURL(secret, user, s.store.Get().System.Hostname), qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey{}).(string)
	s.totpMu.Lock()
	secret := s.totpPending[user]
	s.totpMu.Unlock()
	if secret == "" {
		redirect(w, r, "/system", errors.New("no enrollment in progress"))
		return
	}
	if !auth.VerifyTOTP(secret, r.FormValue("code")) {
		redirect(w, r, "/system", errors.New("code does not match — try again"))
		return
	}
	err := s.store.Update(updateUser(user, func(u *config.User) {
		u.TOTPSecret = secret
	}))
	if err == nil {
		s.totpMu.Lock()
		delete(s.totpPending, user)
		s.totpMu.Unlock()
	}
	redirect(w, r, "/system", err)
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userKey{}).(string)
	err := s.store.Update(updateUser(user, func(u *config.User) {
		u.TOTPSecret = ""
	}))
	redirect(w, r, "/system", err)
}
