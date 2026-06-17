package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"firewall/ui/internal/config"
)

func (s *Server) routesDHCP() {
	s.mux.HandleFunc("POST /dhcp/{iface}/settings", s.handleDHCPSettings)
	s.mux.HandleFunc("POST /dhcp/{iface}/leases", s.handleLeaseCreate)
	s.mux.HandleFunc("POST /dhcp/{iface}/leases/{mac}", s.handleLeaseUpdate)
	s.mux.HandleFunc("POST /dhcp/{iface}/leases/{mac}/delete", s.handleLeaseDelete)
}

// updateDHCP builds a Store.Update mutation against one interface's DHCP
// server, creating it if this interface has none yet so the first save from
// the page works without a separate "add server" step.
func updateDHCP(iface string, fn func(*config.DHCPServer)) func(*config.Config) error {
	return func(c *config.Config) error {
		for i := range c.DHCP {
			if c.DHCP[i].Interface == iface {
				fn(&c.DHCP[i])
				return nil
			}
		}
		d := config.DHCPServer{Interface: iface}
		fn(&d)
		c.DHCP = append(c.DHCP, d)
		return nil
	}
}

func (s *Server) handleDHCPSettings(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	lease, err := strconv.Atoi(r.FormValue("lease_seconds"))
	if err != nil {
		redirect(w, r, "/dhcp", errors.New("lease must be a number of seconds"))
		return
	}
	enabled := r.FormValue("enabled") == "on"
	err = s.store.Update(updateDHCP(iface, func(d *config.DHCPServer) {
		d.Enabled = enabled
		d.RangeStart = strings.TrimSpace(r.FormValue("range_start"))
		d.RangeEnd = strings.TrimSpace(r.FormValue("range_end"))
		d.LeaseSeconds = lease
	}))
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
	iface := r.PathValue("iface")
	lease := parseLease(r)
	err := s.store.Update(updateDHCP(iface, func(d *config.DHCPServer) {
		d.StaticLeases = append(d.StaticLeases, lease)
	}))
	redirect(w, r, "/dhcp", err)
}

func (s *Server) handleLeaseUpdate(w http.ResponseWriter, r *http.Request) {
	iface, mac := r.PathValue("iface"), r.PathValue("mac")
	lease := parseLease(r)
	err := s.store.Update(forDHCP(iface, func(d *config.DHCPServer) error {
		for i := range d.StaticLeases {
			if d.StaticLeases[i].MAC == mac {
				d.StaticLeases[i] = lease
				return nil
			}
		}
		return errors.New("static lease not found")
	}))
	redirect(w, r, "/dhcp", err)
}

func (s *Server) handleLeaseDelete(w http.ResponseWriter, r *http.Request) {
	iface, mac := r.PathValue("iface"), r.PathValue("mac")
	err := s.store.Update(forDHCP(iface, func(d *config.DHCPServer) error {
		for i, l := range d.StaticLeases {
			if l.MAC == mac {
				d.StaticLeases = append(d.StaticLeases[:i], d.StaticLeases[i+1:]...)
				return nil
			}
		}
		return errors.New("static lease not found")
	}))
	redirect(w, r, "/dhcp", err)
}

// forDHCP runs fn against an existing DHCP server, erroring if the interface
// has none. Used by lease edits, which must target a configured server.
func forDHCP(iface string, fn func(*config.DHCPServer) error) func(*config.Config) error {
	return func(c *config.Config) error {
		for i := range c.DHCP {
			if c.DHCP[i].Interface == iface {
				return fn(&c.DHCP[i])
			}
		}
		return errors.New("dhcp server not found")
	}
}
