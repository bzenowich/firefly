package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"firewall/ui/internal/config"
	"firewall/ui/internal/mail"
	"firewall/ui/internal/render"
)

func (s *Server) routesWGServer() {
	s.mux.HandleFunc("POST /wireguard/server", s.handleWGServerSettings)
	s.mux.HandleFunc("POST /wireguard/server/services", s.handleWGServiceCreate)
	s.mux.HandleFunc("POST /wireguard/server/services/{id}/delete", s.handleWGServiceDelete)
	s.mux.HandleFunc("POST /wireguard/server/clients", s.handleWGClientCreate)
	s.mux.HandleFunc("POST /wireguard/server/clients/{id}", s.handleWGClientUpdate)
	s.mux.HandleFunc("POST /wireguard/server/clients/{id}/delete", s.handleWGClientDelete)
	s.mux.HandleFunc("POST /wireguard/server/clients/{id}/email", s.handleWGClientEmail)
	s.mux.HandleFunc("GET /wireguard/server/clients/{id}/config", s.handleWGClientConfig)
	s.mux.HandleFunc("GET /wireguard/server/clients/{id}/qr.png", s.handleWGClientQR)
	s.mux.HandleFunc("POST /wireguard/smtp", s.handleSMTPSettings)
}

// handleWGServerSettings toggles the server and edits its address/port/endpoint.
// The keypair is generated the first time the server is enabled and then kept.
func (s *Server) handleWGServerSettings(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") == "on"
	addr := strings.TrimSpace(r.FormValue("address"))
	endpoint := strings.TrimSpace(r.FormValue("endpoint_host"))
	port := 0
	if v := strings.TrimSpace(r.FormValue("listen_port")); v != "" {
		var err error
		if port, err = strconv.Atoi(v); err != nil {
			redirect(w, r, "/wireguard", errors.New("listen port must be a number"))
			return
		}
	}
	err := s.store.Update(func(c *config.Config) error {
		srv := &c.WireGuard.Server
		srv.Enabled = enabled
		if addr != "" {
			srv.Address = addr
		}
		if srv.Address == "" {
			srv.Address = "10.9.0.1/24" // sensible default subnet for new servers
		}
		srv.ListenPort = port
		srv.EndpointHost = endpoint
		if srv.PrivateKey == "" {
			priv, _, kerr := config.NewWGKeypair()
			if kerr != nil {
				return kerr
			}
			srv.PrivateKey = priv
		}
		return nil
	})
	redirect(w, r, "/wireguard", err)
}

func (s *Server) handleWGServiceCreate(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	if err != nil {
		redirect(w, r, "/wireguard", errors.New("service port must be a number"))
		return
	}
	svc := config.WGService{
		ID:    config.NewID(),
		Name:  strings.TrimSpace(r.FormValue("name")),
		IP:    strings.TrimSpace(r.FormValue("ip")),
		Port:  port,
		Proto: r.FormValue("proto"),
	}
	err = s.store.Update(func(c *config.Config) error {
		c.WireGuard.Server.Services = append(c.WireGuard.Server.Services, svc)
		return nil
	})
	redirect(w, r, "/wireguard", err)
}

func (s *Server) handleWGServiceDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.Update(func(c *config.Config) error {
		srv := &c.WireGuard.Server
		for i, svc := range srv.Services {
			if svc.ID == id {
				srv.Services = append(srv.Services[:i], srv.Services[i+1:]...)
				// Drop the now-dangling grant from every client.
				for j := range srv.Clients {
					srv.Clients[j].ServiceIDs = without(srv.Clients[j].ServiceIDs, id)
				}
				return nil
			}
		}
		return errors.New("service not found")
	})
	redirect(w, r, "/wireguard", err)
}

// handleWGClientCreate generates a keypair, assigns the next free tunnel IP,
// stores the client, and emails the config when a relay is configured.
func (s *Server) handleWGClientCreate(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	priv, pub, err := config.NewWGKeypair()
	if err != nil {
		redirect(w, r, "/wireguard", err)
		return
	}
	id := config.NewID()
	err = s.store.Update(func(c *config.Config) error {
		srv := &c.WireGuard.Server
		if !srv.Enabled {
			return errors.New("enable the server before adding clients")
		}
		addr, aerr := nextClientAddr(*srv)
		if aerr != nil {
			return aerr
		}
		srv.Clients = append(srv.Clients, config.WGClient{
			ID:         id,
			Email:      email,
			Address:    addr,
			PublicKey:  pub,
			PrivateKey: priv,
			ServiceIDs: r.Form["service_ids"],
			Created:    time.Now().UTC().Format(time.RFC3339),
		})
		return nil
	})
	if err != nil {
		redirect(w, r, "/wireguard", err)
		return
	}
	// Best-effort delivery; surface the mail error but keep the created client.
	redirect(w, r, "/wireguard", s.emailClient(id))
}

func (s *Server) handleWGClientUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.Update(updateClient(id, func(cl *config.WGClient) {
		cl.ServiceIDs = r.Form["service_ids"]
	}))
	redirect(w, r, "/wireguard", err)
}

func (s *Server) handleWGClientDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.Update(func(c *config.Config) error {
		srv := &c.WireGuard.Server
		for i, cl := range srv.Clients {
			if cl.ID == id {
				srv.Clients = append(srv.Clients[:i], srv.Clients[i+1:]...)
				return nil
			}
		}
		return errors.New("client not found")
	})
	redirect(w, r, "/wireguard", err)
}

func (s *Server) handleWGClientEmail(w http.ResponseWriter, r *http.Request) {
	redirect(w, r, "/wireguard", s.emailClient(r.PathValue("id")))
}

// emailClient renders and sends one client's config through the SMTP relay.
func (s *Server) emailClient(id string) error {
	cfg := s.store.Get()
	cl, ok := findClient(cfg, id)
	if !ok {
		return errors.New("client not found")
	}
	if !cfg.SMTP.Enabled() {
		return nil // no relay configured: created/updated, just not emailed
	}
	conf, err := render.WGServerClient(cfg, cl)
	if err != nil {
		return err
	}
	body := fmt.Sprintf("Your WireGuard VPN configuration is attached.\n\n"+
		"Import %s into the WireGuard app, or scan the QR code from the admin UI.\n", clientFile(cl))
	return mail.Send(cfg.SMTP, cl.Email, "Your VPN configuration", body,
		mail.Attachment{Name: clientFile(cl), Content: conf})
}

func (s *Server) handleWGClientConfig(w http.ResponseWriter, r *http.Request) {
	conf, cl, err := s.serverClientConfig(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", clientFile(cl)))
	fmt.Fprint(w, conf)
}

func (s *Server) handleWGClientQR(w http.ResponseWriter, r *http.Request) {
	conf, _, err := s.serverClientConfig(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	png, err := qrcode.Encode(conf, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

func (s *Server) handleSMTPSettings(w http.ResponseWriter, r *http.Request) {
	port := 0
	if v := strings.TrimSpace(r.FormValue("port")); v != "" {
		var err error
		if port, err = strconv.Atoi(v); err != nil {
			redirect(w, r, "/wireguard", errors.New("smtp port must be a number"))
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
	redirect(w, r, "/wireguard", err)
}

// serverClientConfig renders one remote-access client's config by id.
func (s *Server) serverClientConfig(id string) (string, config.WGClient, error) {
	cfg := s.store.Get()
	cl, ok := findClient(cfg, id)
	if !ok {
		return "", config.WGClient{}, fmt.Errorf("client %q not found", id)
	}
	conf, err := render.WGServerClient(cfg, cl)
	return conf, cl, err
}

// updateClient builds a Store.Update mutation targeting one client by id.
func updateClient(id string, fn func(*config.WGClient)) func(*config.Config) error {
	return func(c *config.Config) error {
		for i := range c.WireGuard.Server.Clients {
			if c.WireGuard.Server.Clients[i].ID == id {
				fn(&c.WireGuard.Server.Clients[i])
				return nil
			}
		}
		return errors.New("client not found")
	}
}

func findClient(cfg config.Config, id string) (config.WGClient, bool) {
	for _, cl := range cfg.WireGuard.Server.Clients {
		if cl.ID == id {
			return cl, true
		}
	}
	return config.WGClient{}, false
}

// clientFile is the attachment/download filename for a client, derived from the
// email local part so it is human-recognizable and filesystem-safe.
func clientFile(cl config.WGClient) string {
	local := cl.Email
	if i := strings.IndexByte(local, '@'); i >= 0 {
		local = local[:i]
	}
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, local)
	if safe == "" {
		safe = "client"
	}
	return "vpn-" + safe + ".conf"
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

// nextClientAddr picks the lowest free host address in the server subnet,
// skipping the network, broadcast, and the server's own address.
func nextClientAddr(srv config.WGServer) (string, error) {
	ip, ipNet, err := net.ParseCIDR(srv.Address)
	if err != nil {
		return "", fmt.Errorf("server address: %w", err)
	}
	used := map[string]bool{ip.String(): true}
	for _, cl := range srv.Clients {
		if cip, _, err := net.ParseCIDR(cl.Address); err == nil {
			used[cip.String()] = true
		}
	}
	for cand := nextIP(ipNet.IP); ipNet.Contains(cand); cand = nextIP(cand) {
		if cand.Equal(ipNet.IP) || isBroadcast(cand, ipNet) || used[cand.String()] {
			continue
		}
		return cand.String() + "/32", nil
	}
	return "", errors.New("no free addresses left in the server subnet")
}

func nextIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func isBroadcast(ip net.IP, n *net.IPNet) bool {
	bc := make(net.IP, len(n.IP))
	for i := range n.IP {
		bc[i] = n.IP[i] | ^n.Mask[i]
	}
	return ip.Equal(bc)
}

// wgSessions maps each client ID to a human "last seen" string for the UI,
// resolving public keys against the live handshake table.
func (s *Server) wgSessions(cfg config.Config) map[string]string {
	if !cfg.WireGuard.Enabled || !cfg.WireGuard.Server.Enabled || len(cfg.WireGuard.Server.Clients) == 0 {
		return nil
	}
	hs := s.wgHandshakes()
	out := map[string]string{}
	for _, cl := range cfg.WireGuard.Server.Clients {
		if t, ok := hs[cl.PublicKey]; ok {
			out[cl.ID] = humanSince(time.Since(t))
		} else {
			out[cl.ID] = "never"
		}
	}
	return out
}

// humanSince renders a coarse duration for the last-session column.
func humanSince(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// wgHandshakes reads each client's last handshake time from the running
// interface (wg show <dev> latest-handshakes). Best-effort: any error (no wg,
// dev down, dev box) yields an empty map and the UI shows "never". Keyed by
// public key.
func (s *Server) wgHandshakes() map[string]time.Time {
	out := map[string]time.Time{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wg", "show", render.WGServerDevice, "latest-handshakes")
	data, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		secs, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || secs == 0 {
			continue
		}
		out[fields[0]] = time.Unix(secs, 0)
	}
	return out
}
