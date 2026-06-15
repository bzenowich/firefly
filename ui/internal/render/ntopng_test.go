package render

import (
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

func TestNtopngDisabled(t *testing.T) {
	out, err := Ntopng(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "default.ntopng.conf", out)
	if strings.Contains(out, "-i=") {
		t.Error("capture interface rendered while disabled")
	}
}

func TestNtopngFull(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces[2].IPv4 = "10.0.2.1/24" // OPT1 configured
	cfg.Visibility = config.Visibility{Enabled: true}
	out, err := Ntopng(cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "full.ntopng.conf", out)

	for _, want := range []string{
		"--disable-login=1",
		"--http-prefix=" + NtopngHTTPPrefix,
		"--local-networks=192.168.1.0/24,10.0.2.0/24",
		"-i=igc0", // WAN device, captured for north-south
		"-i=igc1",
		"-i=igc2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestNtopngInterfaceSubset(t *testing.T) {
	cfg := config.Default()
	cfg.Visibility = config.Visibility{Enabled: true, Interfaces: []string{"LAN"}, HTTPPort: 3001}
	out, err := Ntopng(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "--http-port=127.0.0.1:3001") {
		t.Errorf("custom port not rendered:\n%s", out)
	}
	if strings.Count(out, "-i=") != 1 || !strings.Contains(out, "-i=igc1") {
		t.Errorf("want only the LAN device captured:\n%s", out)
	}
}

func TestNtopngEnabledNoDevice(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces[1].Device = "" // LAN device cleared
	cfg.Visibility = config.Visibility{Enabled: true, Interfaces: []string{"LAN"}}
	if _, err := Ntopng(cfg); err == nil {
		t.Fatal("want error when a monitored interface has no device")
	}
}
