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
			// pflow is configured imperatively via pflowctl(8) wrapped in an
			// rc.d service (render.Pflow). The script is executable; its start
			// is idempotent. No offline checker — the kernel validates pflowctl.
			path: render.PflowRcPath, mode: 0o755, content: pflowConf,
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
// when visibility is on, take it down when off. The stop is tolerant — a
// feature that is off (and so already stopped) must not fail the whole apply.
func ntopngReload(cfg config.Config) []string {
	if cfg.Visibility.Enabled {
		return []string{"service", "ntopng", "restart"}
	}
	return tolerantStop("ntopng")
}

// tolerantStop stops a service without failing when it is already stopped, so an
// off-by-default feature doesn't roll back an otherwise-good apply.
func tolerantStop(svc string) []string {
	return []string{"sh", "-c", "service " + svc + " onestop 2>/dev/null || true"}
}

// pflowReload (re)applies the rendered pflow service: a restart reconfigures the
// exporter when baseline flow is on; a stop tears it down when off. `one*`
// bypasses the rcvar so apply works whether or not the image enabled the service
// (boot persistence is the image's job via fwpflow_enable=YES).
func pflowReload(cfg config.Config) []string {
	if cfg.Flow.Enabled {
		return []string{"service", render.PflowService, "onerestart"}
	}
	return tolerantStop(render.PflowService)
}
