package server

import (
	"errors"
	"net/http"
	"strings"

	"firewall/ui/internal/config"
)

func (s *Server) routesDNS() {
	s.mux.HandleFunc("POST /dns/settings", s.handleDNSSettings)
	s.mux.HandleFunc("POST /dns/blocklists", s.handleBlocklistAdd)
	// The list URL travels in the form body: URLs don't fit path segments.
	s.mux.HandleFunc("POST /dns/blocklists/delete", s.handleBlocklistDelete)
	s.mux.HandleFunc("POST /dns/overrides", s.handleOverrideCreate)
	s.mux.HandleFunc("POST /dns/overrides/{host}", s.handleOverrideUpdate)
	s.mux.HandleFunc("POST /dns/overrides/{host}/delete", s.handleOverrideDelete)
}

func (s *Server) handleDNSSettings(w http.ResponseWriter, r *http.Request) {
	err := s.store.Update(func(c *config.Config) error {
		c.DNS.Enabled = r.FormValue("enabled") == "on"
		c.DNS.Adblock.Enabled = r.FormValue("adblock") == "on"
		return nil
	})
	redirect(w, r, "/dns", err)
}

func (s *Server) handleBlocklistAdd(w http.ResponseWriter, r *http.Request) {
	u := strings.TrimSpace(r.FormValue("url"))
	err := s.store.Update(func(c *config.Config) error {
		c.DNS.Adblock.Lists = append(c.DNS.Adblock.Lists, u)
		return nil
	})
	redirect(w, r, "/dns", err)
}

func (s *Server) handleBlocklistDelete(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("url")
	err := s.store.Update(func(c *config.Config) error {
		for i, l := range c.DNS.Adblock.Lists {
			if l == u {
				c.DNS.Adblock.Lists = append(c.DNS.Adblock.Lists[:i], c.DNS.Adblock.Lists[i+1:]...)
				return nil
			}
		}
		return errors.New("blocklist not found")
	})
	redirect(w, r, "/dns", err)
}

func parseOverride(r *http.Request) config.HostOverride {
	return config.HostOverride{
		Host: strings.TrimSpace(r.FormValue("host")),
		IP:   strings.TrimSpace(r.FormValue("ip")),
	}
}

func (s *Server) handleOverrideCreate(w http.ResponseWriter, r *http.Request) {
	o := parseOverride(r)
	err := s.store.Update(func(c *config.Config) error {
		c.DNS.Overrides = append(c.DNS.Overrides, o)
		return nil
	})
	redirect(w, r, "/dns", err)
}

func (s *Server) handleOverrideUpdate(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	o := parseOverride(r)
	err := s.store.Update(func(c *config.Config) error {
		for i := range c.DNS.Overrides {
			if c.DNS.Overrides[i].Host == host {
				c.DNS.Overrides[i] = o
				return nil
			}
		}
		return errors.New("override not found")
	})
	redirect(w, r, "/dns", err)
}

func (s *Server) handleOverrideDelete(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	err := s.store.Update(func(c *config.Config) error {
		for i, o := range c.DNS.Overrides {
			if o.Host == host {
				c.DNS.Overrides = append(c.DNS.Overrides[:i], c.DNS.Overrides[i+1:]...)
				return nil
			}
		}
		return errors.New("override not found")
	})
	redirect(w, r, "/dns", err)
}
