package render

import (
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

func TestPflowDefaultEnabled(t *testing.T) {
	// Baseline visibility ships on, so the default config renders an exporter.
	out, err := Pflow(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`cloned_interfaces="pflow0"`,
		"pflowproto 10",
		"pflowdst 127.0.0.1:9996",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPflowCustomPort(t *testing.T) {
	cfg := config.Default()
	cfg.Flow.Port = 9000
	out, err := Pflow(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pflowdst 127.0.0.1:9000") {
		t.Errorf("custom port not rendered:\n%s", out)
	}
}

func TestPflowDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Flow.Enabled = false
	out, err := Pflow(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "cloned_interfaces") {
		t.Errorf("exporter rendered while disabled:\n%s", out)
	}
}
