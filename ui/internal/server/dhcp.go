package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"firewall/ui/internal/config"
)

func (s *Server) routesDHCP() {
	s.mux.HandleFunc("POST /dhcp/settings", s.handleDHCPSettings)
	s.mux.HandleFunc("POST /dhcp/leases", s.handleLeaseCreate)
	s.mux.HandleFunc("POST /dhcp/leases/{mac}", s.handleLeaseUpdate)
	s.mux.HandleFunc("POST /dhcp/leases/{mac}/delete", s.handleLeaseDelete)
}

func (s *Server) handleDHCPSettings(w http.ResponseWriter, r *http.Request) {
	lease, err := strconv.Atoi(r.FormValue("lease_seconds"))
	if err != nil {
		redirect(w, r, "/dhcp", errors.New("lease must be a number of seconds"))
		return
	}
	err = s.store.Update(func(c *config.Config) error {
		c.DHCP.Enabled = r.FormValue("enabled") == "on"
		c.DHCP.RangeStart = strings.TrimSpace(r.FormValue("range_start"))
		c.DHCP.RangeEnd = strings.TrimSpace(r.FormValue("range_end"))
		c.DHCP.LeaseSeconds = lease
		return nil
	})
	redirect(w, r, "/dhcp", err)
}

func parseLease(r *http.Request) config.StaticLease {
	return config.StaticLease{
		MAC:      strings.TrimSpace(r.FormValue("mac")),
		IP:       strings.TrimSpace(r.FormValue("ip")),
		Hostname: strings.TrimSpace(r.FormValue("hostname")),
	}
}

func (s *Server) handleLeaseCreate(w http.ResponseWriter, r *http.Request) {
	lease := parseLease(r)
	err := s.store.Update(func(c *config.Config) error {
		c.DHCP.StaticLeases = append(c.DHCP.StaticLeases, lease)
		return nil
	})
	redirect(w, r, "/dhcp", err)
}

func (s *Server) handleLeaseUpdate(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	lease := parseLease(r)
	err := s.store.Update(func(c *config.Config) error {
		for i := range c.DHCP.StaticLeases {
			if c.DHCP.StaticLeases[i].MAC == mac {
				c.DHCP.StaticLeases[i] = lease
				return nil
			}
		}
		return errors.New("static lease not found")
	})
	redirect(w, r, "/dhcp", err)
}

func (s *Server) handleLeaseDelete(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	err := s.store.Update(func(c *config.Config) error {
		for i, l := range c.DHCP.StaticLeases {
			if l.MAC == mac {
				c.DHCP.StaticLeases = append(c.DHCP.StaticLeases[:i], c.DHCP.StaticLeases[i+1:]...)
				return nil
			}
		}
		return errors.New("static lease not found")
	})
	redirect(w, r, "/dhcp", err)
}
