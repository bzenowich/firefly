package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
