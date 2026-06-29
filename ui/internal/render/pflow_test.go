package render

import (
	"strings"
	"testing"

	"firewall/ui/internal/config"
)

func TestPflowDefaultEnabled(t *testing.T) {
	// Baseline visibility ships on, so the default config configures an exporter
	// via pflowctl.
	out, err := Pflow(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"#!/bin/sh",
		"# PROVIDE: fwpflow",
		"pflowctl -c",
		"pflowctl -s pflow0 src 127.0.0.1 dst 127.0.0.1:9996 proto 10",
		"run_rc_command",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// It must not use the OpenBSD-style ifconfig clone (the bug this replaced).
	if strings.Contains(out, "cloned_interfaces") || strings.Contains(out, "pflowproto") {
		t.Errorf("rendered OpenBSD-style cloning instead of pflowctl:\n%s", out)
	}
}

func TestPflowCustomPort(t *testing.T) {
	cfg := config.Default()
	cfg.Flow.Port = 9000
	out, err := Pflow(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "dst 127.0.0.1:9000 proto 10") {
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
	// Disabled: the script only tears down, never creates an exporter.
	if strings.Contains(out, "pflowctl -c") {
		t.Errorf("exporter created while disabled:\n%s", out)
	}
	if !strings.Contains(out, "fwpflow_clear") {
		t.Errorf("disabled script should still clear exporters:\n%s", out)
	}
}

func TestPFRulesFlaggedForPflow(t *testing.T) {
	// Each state-creating rule must carry "(pflow)" when baseline flow is on, so
	// pflow(4) exports its states. A global "set state-defaults pflow" does NOT
	// work here — an explicit "keep state" on a rule suppresses it — so the
	// option must be per-rule.
	on, err := PF(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(on, "set state-defaults pflow") {
		t.Errorf("global state-default is ineffective with explicit keep state; use per-rule (pflow):\n%s", on)
	}
	if !strings.Contains(on, "keep state (pflow)") {
		t.Errorf("pass rules not flagged for pflow while flow enabled:\n%s", on)
	}
	// The trusted-LAN pass rule specifically must be flagged (that's the bulk of
	// the visible traffic).
	if !strings.Contains(on, "pass in on $lan_if inet all keep state (pflow)") {
		t.Errorf("LAN pass rule missing (pflow):\n%s", on)
	}

	cfg := config.Default()
	cfg.Flow.Enabled = false
	off, err := PF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off, "(pflow)") {
		t.Errorf("pf.conf flagged states for pflow while flow disabled:\n%s", off)
	}
}
