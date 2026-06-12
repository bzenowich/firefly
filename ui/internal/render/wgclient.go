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
