package render

import (
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

// guestCfg is the default config with OPT1 turned into a guest segment.
func trustCfg(t *testing.T, trust string) (config.Config, string) {
	t.Helper()
	cfg := config.Default()
	for i := range cfg.Interfaces {
		if cfg.Interfaces[i].Role == "opt" {
			cfg.Interfaces[i].IPv4 = "192.168.9.1/24"
			cfg.Interfaces[i].Trust = trust
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := PF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, out
}

// The S2 exit criterion: an OPT-segment host cannot reach the LAN or the admin
// UI (docs/security-plan.md SEC-5).
func TestGuestSegmentCannotReachLANOrAdmin(t *testing.T) {
	_, out := trustCfg(t, config.TrustGuest)

	// Blocked from the appliance itself and from the LAN subnet.
	want := "block in log quick on $opt1_if inet from $opt1_if:network to { (self) $lan_if:network }"
	if !strings.Contains(out, want) {
		t.Errorf("guest segment is not blocked from the LAN and the box:\n%s", out)
	}
	// ...and that block is quick, so the pass-to-any below cannot undo it.
	if !strings.Contains(out, "quick on $opt1_if inet from $opt1_if:network to { (self)") {
		t.Error("the guest block is not quick, so a later pass would win")
	}
	// Still gets DNS/DHCP/NTP from the appliance, or the segment is unusable.
	if !strings.Contains(out, "port { 53 67 123 }") {
		t.Error("guest segment cannot reach appliance DNS/DHCP/NTP")
	}
	// Still gets out.
	if !strings.Contains(out, "pass in on $opt1_if inet from $opt1_if:network to any") {
		t.Error("guest segment cannot reach the internet")
	}
	// The old blanket rule must be gone.
	if strings.Contains(out, "pass in on $opt1_if inet all") {
		t.Error("guest segment still has the blanket trusted pass")
	}
}

// An isolated segment additionally cannot reach its own peers.
func TestIsolatedSegmentBlocksPeers(t *testing.T) {
	_, out := trustCfg(t, config.TrustIsolated)

	if !strings.Contains(out, "block in quick on $opt1_if inet from $opt1_if:network to $opt1_if:network") {
		t.Errorf("isolated hosts can still reach each other:\n%s", out)
	}
	// DHCP must survive, or a host cannot obtain a lease and the segment is
	// dead rather than isolated.
	if !strings.Contains(out, "proto udp from any to (self) port 67") {
		t.Error("isolated segment cannot get a DHCP lease")
	}
	if strings.Contains(out, "port { 53 67 123 }") {
		t.Error("isolated segment was given the guest service set")
	}
}

// A trusted segment keeps its blanket pass: that is what "trusted" means, and
// an upgrade must not silently cut the LAN off.
func TestTrustedSegmentUnchanged(t *testing.T) {
	_, out := trustCfg(t, config.TrustTrusted)
	if !strings.Contains(out, "pass in on $opt1_if inet all") {
		t.Error("a trusted segment lost its pass")
	}
}

// An interface with no trust set behaves exactly as before, so restoring an
// older config document does not change the firewall's behaviour.
func TestUnsetTrustDefaultsToTrusted(t *testing.T) {
	cfg := config.Default()
	for i := range cfg.Interfaces {
		if cfg.Interfaces[i].Role == "opt" {
			cfg.Interfaces[i].IPv4 = "192.168.9.1/24"
			cfg.Interfaces[i].Trust = "" // as an older document would have it
		}
	}
	out, err := PF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pass in on $opt1_if inet all") {
		t.Error("an interface with no trust level lost access on upgrade")
	}
}

// The admin plane is closed everywhere it is not explicitly opened, and the
// block is ordered so a trusted-segment pass cannot admit it first.
func TestAdminPlaneIsClosedByDefault(t *testing.T) {
	cfg := config.Default()
	cfg.System.Management.Sources = []string{"192.168.1.0/24"}
	out, err := PF(cfg)
	if err != nil {
		t.Fatal(err)
	}

	passIdx := strings.Index(out, "management_sources")
	blockIdx := strings.Index(out, "block in log quick inet proto tcp to (self) port")
	lanIdx := strings.Index(out, "pass in on $lan_if inet all")
	switch {
	case passIdx < 0:
		t.Fatal("no management source rule emitted")
	case blockIdx < 0:
		t.Fatal("admin plane is never blocked")
	case blockIdx < passIdx:
		t.Error("the admin-plane block precedes its own allow, so management is unreachable")
	case lanIdx >= 0 && lanIdx < blockIdx:
		t.Error("the LAN blanket pass precedes the admin-plane block, which makes the block decorative")
	}
}

// A configured source list replaces the LAN default rather than adding to it.
func TestExplicitManagementSourcesReplaceTheDefault(t *testing.T) {
	cfg := config.Default()
	cfg.System.Management.Sources = []string{"192.168.1.10", "10.9.0.0/24"}
	out, err := PF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `management_sources = "{ 192.168.1.10 10.9.0.0/24 }"`) {
		t.Errorf("source list not rendered:\n%s", out)
	}
	if strings.Contains(out, "No explicit sources configured") {
		t.Error("the whole-LAN default is still emitted alongside an explicit list")
	}
}

// A custom port list must reach the ruleset: an operator who moves the WebUI
// and does not get the rule moved with it is locked out.
func TestManagementPortsAreConfigurable(t *testing.T) {
	cfg := config.Default()
	cfg.System.Management.Ports = []int{9443}
	out, err := PF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "port 9443") {
		t.Errorf("custom management port not rendered:\n%s", out)
	}
	if strings.Contains(out, "8443") {
		t.Error("the default port list is still emitted alongside the custom one")
	}
}

// The admin plane must never be reachable from the WAN, whatever the source
// list says.
//
// The first version of writeManagementRules emitted an interface-agnostic
// `pass in quick inet proto tcp from $management_sources ...`, so a list
// containing a public prefix — a mistake, or a restored backup — would have
// opened the WebUI on the internet. The ruleset does not offer that option.
func TestManagementIsNeverExposedOnTheWAN(t *testing.T) {
	cfg := config.Default()
	cfg.System.Management.Sources = []string{"0.0.0.0/0"} // the worst list an admin could write
	out, err := PF(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "management_sources") || strings.HasPrefix(line, "management_sources") {
			continue
		}
		if !strings.Contains(line, "pass in quick on $") {
			t.Errorf("management rule is not interface-scoped: %q", line)
		}
		if strings.Contains(line, "on $wan_if") {
			t.Errorf("management rule admits traffic on the wan: %q", line)
		}
	}

	// And the catch-all block still applies everywhere.
	if !strings.Contains(out, "block in log quick inet proto tcp to (self) port { 8443 22 }") {
		t.Error("admin plane is not blocked outside the permitted sources")
	}
}
