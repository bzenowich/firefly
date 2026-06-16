package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"firewall/ui/internal/config"
)

func (s *Server) routesServices() {
	s.mux.HandleFunc("POST /services", s.handleServiceCreate)
	s.mux.HandleFunc("POST /services/{id}", s.handleServiceUpdate)
	s.mux.HandleFunc("POST /services/{id}/delete", s.handleServiceDelete)
}

// parseService reads the service form; semantic checks are config.Validate's job.
func parseService(r *http.Request) (config.Service, error) {
	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	if err != nil {
		return config.Service{}, errors.New("port must be a number")
	}
	return config.Service{
		Name:  strings.TrimSpace(r.FormValue("name")),
		IP:    strings.TrimSpace(r.FormValue("ip")),
		Port:  port,
		Proto: r.FormValue("proto"),
	}, nil
}

func (s *Server) handleServiceCreate(w http.ResponseWriter, r *http.Request) {
	svc, err := parseService(r)
	if err == nil {
		svc.ID = config.NewID()
		err = s.store.Update(func(c *config.Config) error {
			c.Services = append(c.Services, svc)
			return nil
		})
	}
	redirect(w, r, "/services", err)
}

func (s *Server) handleServiceUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	svc, err := parseService(r)
	if err == nil {
		svc.ID = id
		err = s.store.Update(func(c *config.Config) error {
			for i := range c.Services {
				if c.Services[i].ID == id {
					c.Services[i] = svc
					return nil
				}
			}
			return errors.New("service not found")
		})
	}
	redirect(w, r, "/services", err)
}

// handleServiceDelete removes a service. It refuses when a NAT port forward
// still references it (the destination would vanish), but prunes the softer
// WireGuard client grants automatically.
func (s *Server) handleServiceDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.Update(func(c *config.Config) error {
		idx := -1
		for i, svc := range c.Services {
			if svc.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return errors.New("service not found")
		}
		var users int
		for _, pf := range c.NAT.PortForwards {
			if pf.ServiceID == id {
				users++
			}
		}
		if users > 0 {
			return fmt.Errorf("in use by %d port forward(s); remove those first", users)
		}
		c.Services = append(c.Services[:idx], c.Services[idx+1:]...)
		for j := range c.WireGuard.Server.Clients {
			c.WireGuard.Server.Clients[j].ServiceIDs = without(c.WireGuard.Server.Clients[j].ServiceIDs, id)
		}
		return nil
	})
	redirect(w, r, "/services", err)
}

// without returns ids with v removed.
func without(ids []string, v string) []string {
	out := ids[:0]
	for _, id := range ids {
		if id != v {
			out = append(out, id)
		}
	}
	return out
}
