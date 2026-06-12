package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"firewall/ui/internal/config"
	"firewall/ui/internal/render"
)

func (s *Server) routesWireGuard() {
	s.mux.HandleFunc("POST /wireguard/settings", s.handleWGSettings)
	s.mux.HandleFunc("POST /wireguard/tunnels", s.handleWGTunnelCreate)
	s.mux.HandleFunc("POST /wireguard/tunnels/{name}", s.handleWGTunnelUpdate)
	s.mux.HandleFunc("POST /wireguard/tunnels/{name}/delete", s.handleWGTunnelDelete)
	s.mux.HandleFunc("POST /wireguard/tunnels/{name}/peers", s.handleWGPeerCreate)
	s.mux.HandleFunc("POST /wireguard/tunnels/{name}/peers/{peer}/delete", s.handleWGPeerDelete)
	s.mux.HandleFunc("GET /wireguard/tunnels/{name}/peers/{peer}/config", s.handleWGPeerConfig)
	s.mux.HandleFunc("GET /wireguard/tunnels/{name}/peers/{peer}/qr.png", s.handleWGPeerQR)
}

func (s *Server) handleWGSettings(w http.ResponseWriter, r *http.Request) {
	err := s.store.Update(func(c *config.Config) error {
		c.WireGuard.Enabled = r.FormValue("enabled") == "on"
		return nil
	})
	redirect(w, r, "/wireguard", err)
}

// updateTunnel builds a Store.Update mutation targeting one tunnel by name.
func updateTunnel(name string, fn func(*config.WGTunnel) error) func(*config.Config) error {
	return func(c *config.Config) error {
		for i := range c.WireGuard.Tunnels {
			if c.WireGuard.Tunnels[i].Name == name {
				return fn(&c.WireGuard.Tunnels[i])
			}
		}
		return fmt.Errorf("tunnel %q not found", name)
	}
}

// parseTunnelForm reads the shared tunnel fields (address, port, endpoint).
func parseTunnelForm(r *http.Request) (addr string, port int, endpoint string, err error) {
	port, err = strconv.Atoi(r.FormValue("listen_port"))
	if err != nil {
		return "", 0, "", errors.New("listen port must be a number")
	}
	return strings.TrimSpace(r.FormValue("address")), port,
		strings.TrimSpace(r.FormValue("endpoint_host")), nil
}

func (s *Server) handleWGTunnelCreate(w http.ResponseWriter, r *http.Request) {
	addr, port, endpoint, err := parseTunnelForm(r)
	if err == nil {
		var private string
		private, _, err = config.NewWGKeypair()
		if err == nil {
			err = s.store.Update(func(c *config.Config) error {
				c.WireGuard.Tunnels = append(c.WireGuard.Tunnels, config.WGTunnel{
					Name:         strings.TrimSpace(r.FormValue("name")),
					Address:      addr,
					ListenPort:   port,
					EndpointHost: endpoint,
					PrivateKey:   private,
				})
				return nil
			})
		}
	}
	redirect(w, r, "/wireguard", err)
}

func (s *Server) handleWGTunnelUpdate(w http.ResponseWriter, r *http.Request) {
	addr, port, endpoint, err := parseTunnelForm(r)
	if err == nil {
		err = s.store.Update(updateTunnel(r.PathValue("name"), func(t *config.WGTunnel) error {
			t.Address, t.ListenPort, t.EndpointHost = addr, port, endpoint
			return nil
		}))
	}
	redirect(w, r, "/wireguard", err)
}

func (s *Server) handleWGTunnelDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.store.Update(func(c *config.Config) error {
		for i, t := range c.WireGuard.Tunnels {
			if t.Name == name {
				c.WireGuard.Tunnels = append(c.WireGuard.Tunnels[:i], c.WireGuard.Tunnels[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("tunnel %q not found", name)
	})
	redirect(w, r, "/wireguard", err)
}

func (s *Server) handleWGPeerCreate(w http.ResponseWriter, r *http.Request) {
	keepalive := 0
	if v := strings.TrimSpace(r.FormValue("keepalive")); v != "" {
		var err error
		if keepalive, err = strconv.Atoi(v); err != nil {
			redirect(w, r, "/wireguard", errors.New("keepalive must be a number of seconds"))
			return
		}
	}
	peer := config.WGPeer{
		Name:       strings.TrimSpace(r.FormValue("name")),
		PublicKey:  strings.TrimSpace(r.FormValue("public_key")),
		AllowedIPs: strings.TrimSpace(r.FormValue("allowed_ips")),
		Endpoint:   strings.TrimSpace(r.FormValue("endpoint")),
		Keepalive:  keepalive,
	}
	// No public key supplied: generate the keypair here and keep the private
	// key so the client config/QR can be served.
	var err error
	if peer.PublicKey == "" {
		peer.PrivateKey, peer.PublicKey, err = config.NewWGKeypair()
	}
	if err == nil {
		err = s.store.Update(updateTunnel(r.PathValue("name"), func(t *config.WGTunnel) error {
			t.Peers = append(t.Peers, peer)
			return nil
		}))
	}
	redirect(w, r, "/wireguard", err)
}

func (s *Server) handleWGPeerDelete(w http.ResponseWriter, r *http.Request) {
	peer := r.PathValue("peer")
	err := s.store.Update(updateTunnel(r.PathValue("name"), func(t *config.WGTunnel) error {
		for i, p := range t.Peers {
			if p.Name == peer {
				t.Peers = append(t.Peers[:i], t.Peers[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("peer %q not found", peer)
	}))
	redirect(w, r, "/wireguard", err)
}

// clientConfig resolves the rendered client config for one tunnel/peer pair.
func (s *Server) clientConfig(r *http.Request) (string, error) {
	cfg := s.store.Get()
	name, peer := r.PathValue("name"), r.PathValue("peer")
	for _, t := range cfg.WireGuard.Tunnels {
		if t.Name != name {
			continue
		}
		for _, p := range t.Peers {
			if p.Name == peer {
				return render.WGClient(cfg, t, p)
			}
		}
	}
	return "", fmt.Errorf("peer %q not found", peer)
}

func (s *Server) handleWGPeerConfig(w http.ResponseWriter, r *http.Request) {
	conf, err := s.clientConfig(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, conf)
}

func (s *Server) handleWGPeerQR(w http.ResponseWriter, r *http.Request) {
	conf, err := s.clientConfig(r)
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
