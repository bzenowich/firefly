package apply

import (
	"io/fs"
	"path"

	"firewall/ui/internal/config"
	"firewall/ui/internal/render"
)

// Appliance paths for rendered service configs.
const (
	PFConfPath      = "/etc/pf.conf"
	KeaConfPath     = "/usr/local/etc/kea/kea-dhcp4.conf"
	UnboundConfPath = "/usr/local/etc/unbound/unbound.conf"
	WGConfDir       = "/usr/local/etc/wireguard"
)

// file is one managed config file with its validation and reload commands.
type file struct {
	path    string
	mode    fs.FileMode
	content string
	// check validates the staged copy before install; nil = no validator.
	check func(staged string) []string
	// reload takes the installed file live. Deduplicated across files.
	reload []string
}

// plan renders the config into the full managed file set. Pure: no I/O.
func plan(cfg config.Config) ([]file, error) {
	pfConf, err := render.PF(cfg)
	if err != nil {
		return nil, err
	}
	keaConf, err := render.KeaDHCP4(cfg)
	if err != nil {
		return nil, err
	}
	unboundConf, err := render.Unbound(cfg)
	if err != nil {
		return nil, err
	}
	wgFiles, err := render.WireGuard(cfg)
	if err != nil {
		return nil, err
	}

	files := []file{
		{
			path: PFConfPath, mode: 0o644, content: pfConf,
			check:  func(staged string) []string { return []string{"pfctl", "-nf", staged} },
			reload: []string{"pfctl", "-f", PFConfPath},
		},
		{
			path: KeaConfPath, mode: 0o644, content: keaConf,
			check:  func(staged string) []string { return []string{"kea-dhcp4", "-t", staged} },
			reload: []string{"service", "kea", "restart"},
		},
		{
			path: UnboundConfPath, mode: 0o644, content: unboundConf,
			check:  func(staged string) []string { return []string{"unbound-checkconf", staged} },
			reload: []string{"service", "unbound", "restart"},
		},
	}
	for _, wg := range wgFiles {
		files = append(files, file{
			// 0600: contains the tunnel private key.
			path: path.Join(WGConfDir, wg.Name), mode: 0o600, content: wg.Content,
			reload: []string{"service", "wireguard", "restart"},
		})
	}
	return files, nil
}
