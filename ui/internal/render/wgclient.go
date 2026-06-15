package render

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"firewall/ui/internal/config"
)

// WGClient renders the config a peer's device imports (file or QR). Only
// possible for peers whose keypair the appliance generated — otherwise the
// private key is not ours to know.
func WGClient(cfg config.Config, t config.WGTunnel, p config.WGPeer) (string, error) {
	if p.PrivateKey == "" {
		return "", errors.New("peer keypair was not generated here; no client config available")
	}
	serverPub, err := config.WGPublicKey(t.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("tunnel public key: %w", err)
	}

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("[Interface]")
	w("PrivateKey = %s", p.PrivateKey)
	// The peer's first allowed-IP is its tunnel address by convention.
	addr := strings.TrimSpace(strings.Split(p.AllowedIPs, ",")[0])
	w("Address = %s", addr)
	if cfg.DNS.Enabled {
		if lan := cfg.LAN(); lan.IPv4 != "" {
			ip, _, _ := net.ParseCIDR(lan.IPv4)
			w("DNS = %s", ip)
		}
	}

	w("")
	w("[Peer]")
	w("PublicKey = %s", serverPub)
	endpoint := t.EndpointHost
	if endpoint != "" && !strings.Contains(endpoint, ":") {
		endpoint = fmt.Sprintf("%s:%d", endpoint, t.ListenPort)
	}
	if endpoint != "" {
		w("Endpoint = %s", endpoint)
	}
	w("AllowedIPs = 0.0.0.0/0")
	w("PersistentKeepalive = 25")
	return b.String(), nil
}

// WGServerClient renders the config a remote-access client imports. Unlike the
// site-to-site peer config it is split-tunnel: AllowedIPs covers only the
// appliance's internal networks (plus the VPN subnet), so the client routes
// just LAN-bound traffic through the tunnel. The firewall still enforces which
// services that client may actually reach.
func WGServerClient(cfg config.Config, c config.WGClient) (string, error) {
	s := cfg.WireGuard.Server
	if c.PrivateKey == "" {
		return "", errors.New("client keypair missing; cannot build config")
	}
	serverPub, err := config.WGPublicKey(s.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("server public key: %w", err)
	}

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("[Interface]")
	w("PrivateKey = %s", c.PrivateKey)
	w("Address = %s", c.Address)
	if lan := cfg.LAN(); lan.IPv4 != "" {
		ip, _, _ := net.ParseCIDR(lan.IPv4)
		w("DNS = %s", ip) // the appliance gateway resolves names for the client
	}

	w("")
	w("[Peer]")
	w("PublicKey = %s", serverPub)
	endpoint := s.EndpointHost
	if endpoint != "" && !strings.Contains(endpoint, ":") {
		endpoint = fmt.Sprintf("%s:%d", endpoint, s.Port())
	}
	if endpoint != "" {
		w("Endpoint = %s", endpoint)
	}
	w("AllowedIPs = %s", strings.Join(serverClientNets(cfg), ", "))
	w("PersistentKeepalive = 25")
	return b.String(), nil
}

// serverClientNets is the set of networks a remote-access client routes through
// the tunnel: every internal (non-wan) interface network plus the VPN subnet.
func serverClientNets(cfg config.Config) []string {
	var nets []string
	seen := map[string]bool{}
	add := func(cidr string) {
		if _, n, err := net.ParseCIDR(cidr); err == nil && !seen[n.String()] {
			seen[n.String()] = true
			nets = append(nets, n.String())
		}
	}
	for _, ifc := range cfg.Interfaces {
		if ifc.Role != "wan" && ifc.IPv4 != "" {
			add(ifc.IPv4)
		}
	}
	add(cfg.WireGuard.Server.Address)
	return nets
}
