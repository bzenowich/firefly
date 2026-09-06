package apply

import (
	"fmt"
	"io/fs"
	"path"
	"strings"

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
	networkConf, err := render.Network(cfg)
	if err != nil {
		return nil, err
	}
	ntpConf, err := render.NTP(cfg)
	if err != nil {
		return nil, err
	}
	wgFiles, err := render.WireGuard(cfg)
	if err != nil {
		return nil, err
	}

	files := []file{
		{
			// First in the list on purpose: reloads run in file order, and
			// pf's `$lan_if:network` macros resolve against the live
			// interface, so addressing has to land before pf is loaded.
			path: render.NetworkRcPath, mode: 0o755, content: networkConf,
			reload: enableAndRun(render.NetworkService,
				"service "+render.NetworkService+" onerestart"),
		},
		{
			path: PFConfPath, mode: 0o644, content: pfConf,
			check: func(staged string) []string { return []string{"pfctl", "-nf", staged} },
			// pfctl -f rather than a service restart: it swaps the ruleset
			// without flushing state. `pfctl -e` is a no-op once pf is up but
			// is what actually turns filtering on for the first apply on a
			// box where pf has never run.
			reload: []string{"sh", "-c",
				"sysrc pf_enable=YES pflog_enable=YES >/dev/null; " +
					"service pflog onestart >/dev/null 2>&1; " +
					"pfctl -f " + PFConfPath + " && { pfctl -e 2>/dev/null || true; }"},
		},
		{
			path: KeaConfPath, mode: 0o644, content: keaConf,
			check:  func(staged string) []string { return []string{"kea-dhcp4", "-t", staged} },
			reload: enableAndRun("kea", "service kea onerestart"),
		},
		{
			path: UnboundConfPath, mode: 0o644, content: unboundConf,
			check:  func(staged string) []string { return []string{"unbound-checkconf", staged} },
			reload: enableAndRun("unbound", "service unbound onerestart"),
		},
		{
			path: render.NTPConfPath, mode: 0o644, content: ntpConf,
			reload: ntpReload(cfg),
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
	wgReload := wireguardReload(wgFiles)
	for _, wg := range wgFiles {
		files = append(files, file{
			// 0600: contains the tunnel private key.
			path: path.Join(WGConfDir, wg.Name), mode: 0o600, content: wg.Content,
			reload: wgReload,
		})
	}
	return files, nil
}

// prerequisites lists files a rendered config references but rendering does not
// produce, and which must merely exist for offline validation to pass.
//
// unbound.conf includes the compiled blocklist, which a runtime fetch job
// writes — so turning adblock on before that job has ever run made
// unbound-checkconf fail on the missing include and rejected every apply from
// then on, with an error pointing at a file the admin never heard of. An empty
// placeholder costs nothing and keeps the failure mode out of the config
// pipeline.
func prerequisites(cfg config.Config) []string {
	if cfg.DNS.Adblock.Enabled {
		return []string{render.AdblockInclude}
	}
	return nil
}

// enableAndRun sets a service's rcvar and then runs cmd.
//
// Both halves matter. `service X restart` *fails* when the rcvar is off, so on
// a stock FreeBSD install — where nothing has set kea_enable and friends — the
// first apply used to die in its reload and roll back; `one*` forms bypass the
// rcvar. And the rcvar is what makes the service come back after a reboot,
// which is why setting it belongs in apply rather than in a provisioning
// script that hardware installs never run (docs/design-review.md §3.2).
func enableAndRun(svc, cmd string) []string {
	return []string{"sh", "-c", fmt.Sprintf("sysrc %s_enable=YES >/dev/null; %s", svc, cmd)}
}

// disableAndStop clears a service's rcvar and stops it, tolerating a service
// that is already down so an off-by-default feature cannot fail an apply.
func disableAndStop(svc string) []string {
	return []string{"sh", "-c", fmt.Sprintf(
		"sysrc %s_enable=NO >/dev/null; service %s onestop 2>/dev/null || true", svc, svc)}
}

// wireguardReload restarts the WireGuard interfaces, first telling the rc
// script which ones exist.
//
// FreeBSD's wireguard rc script only acts on interfaces named in
// wireguard_interfaces. Nothing set it, so "service wireguard restart" brought
// up exactly nothing and an apply that enabled a tunnel reported success while
// no tunnel existed. The list is derived from the rendered files, so it tracks
// tunnels being added and removed.
func wireguardReload(files []render.WGFile) []string {
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, strings.TrimSuffix(f.Name, ".conf"))
	}
	if len(names) == 0 {
		return []string{"sh", "-c",
			"sysrc wireguard_enable=NO 'wireguard_interfaces=' >/dev/null; " +
				"service wireguard onestop 2>/dev/null || true"}
	}
	// Interface names are generated (wg0..wgN, wgsrv), so they are safe to
	// interpolate into the quoted sysrc assignment.
	return []string{"sh", "-c", fmt.Sprintf(
		"sysrc wireguard_enable=YES 'wireguard_interfaces=%s' >/dev/null; service wireguard onerestart",
		strings.Join(names, " "))}
}

// ntpReload starts ntpd when time sources are configured and stops it when
// they are not, so an appliance with no sources is not running a pointless
// daemon.
func ntpReload(cfg config.Config) []string {
	if len(cfg.System.NTPServers) == 0 {
		return disableAndStop("ntpd")
	}
	return enableAndRun("ntpd", "service ntpd onerestart")
}

// ntopngReload picks the service action for a changed ntopng.conf: bring it up
// when visibility is on, take it down when off. The stop is tolerant — a
// feature that is off (and so already stopped) must not fail the whole apply.
func ntopngReload(cfg config.Config) []string {
	if !cfg.Visibility.Enabled {
		// Leave redis alone on the way down: it is a shared service and the
		// admin may be running it for something else.
		return disableAndStop("ntopng")
	}
	// ntopng has no redis-less mode — redis is a hard runtime dependency, and
	// without this check a box that never installed it fails the reload and
	// rolls the whole apply back with nothing pointing at the cause.
	return []string{"sh", "-c",
		"command -v redis-server >/dev/null 2>&1 || " +
			"{ echo 'ntopng requires the redis package: pkg install redis' >&2; exit 1; }; " +
			"sysrc redis_enable=YES ntopng_enable=YES >/dev/null; " +
			"service redis onerestart && service ntopng onerestart"}
}

// pflowReload (re)applies the rendered pflow service: a restart reconfigures the
// exporter when baseline flow is on; a stop tears it down when off. Setting
// fwpflow_enable here is what makes flow export survive a reboot — it was
// previously left to an image build that does not exist, so the exporter died
// on every restart until someone applied again.
func pflowReload(cfg config.Config) []string {
	if cfg.Flow.Enabled {
		return enableAndRun(render.PflowService,
			"service "+render.PflowService+" onerestart")
	}
	return disableAndStop(render.PflowService)
}
