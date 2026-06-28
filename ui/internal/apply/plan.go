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
	NtopngConfPath  = "/usr/local/etc/ntopng/ntopng.conf"
	PflowConfPath   = "/etc/rc.conf.d/pflow"
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
	ntopngConf, err := render.Ntopng(cfg)
	if err != nil {
		return nil, err
	}
	pflowConf, err := render.Pflow(cfg)
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
		{
			// No offline syntax checker for ntopng; the daemon validates on
			// start. Reload restarts when enabled, stops when disabled so a
			// turned-off feature leaves nothing capturing.
			path: NtopngConfPath, mode: 0o644, content: ntopngConf,
			reload: ntopngReload(cfg),
		},
		{
			// pflow0 is recreated from this rc.conf.d fragment on apply. No
			// offline checker; the kernel validates the create args. Destroy
			// first so changed flowdst/port take effect; tolerate absence.
			path: PflowConfPath, mode: 0o644, content: pflowConf,
			reload: pflowReload(cfg),
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

// ntopngReload picks the service action for a changed ntopng.conf: bring it up
// when visibility is on, take it down when off.
func ntopngReload(cfg config.Config) []string {
	if cfg.Visibility.Enabled {
		return []string{"service", "ntopng", "restart"}
	}
	return []string{"service", "ntopng", "stop"}
}

// pflowReload recreates pflow0 from the rendered rc.conf.d fragment when
// baseline flow is on, or destroys it when off. The destroy tolerates a missing
// interface so a no-op apply (already off) doesn't fail.
func pflowReload(cfg config.Config) []string {
	if cfg.Flow.Enabled {
		return []string{"sh", "-c", "ifconfig pflow0 destroy 2>/dev/null; service netif cloneup"}
	}
	return []string{"sh", "-c", "ifconfig pflow0 destroy 2>/dev/null || true"}
}
