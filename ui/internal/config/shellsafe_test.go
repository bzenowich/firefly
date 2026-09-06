package config

import (
	"strings"
	"testing"

	"firewall/ui/internal/auth"
)

// shellPayloads are the metacharacter shapes that validConfigValue lets through
// (it only rejects newline, quote, backslash and control characters) and that a
// generated rc.d script would execute as root (docs/security-plan.md SEC-1).
var shellPayloads = []string{
	"igc1; touch /tmp/pwned",
	"igc1 && touch /tmp/pwned",
	"igc1|sh",
	"igc1$(id)",
	"igc1`id`",
	"igc1 -x",
	"igc1'",
	"igc1\n",
	"$IFS",
	"../../etc/passwd",
	"",
}

func TestValidateRejectsShellMetacharactersInDevice(t *testing.T) {
	for _, payload := range shellPayloads {
		cfg := Default()
		for i := range cfg.Interfaces {
			if cfg.Interfaces[i].Role == "lan" {
				cfg.Interfaces[i].Device = payload
			}
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted device %q", payload)
		}
	}
}

func TestValidDeviceName(t *testing.T) {
	for _, ok := range []string{"igc0", "igc10", "vtnet1", "lagg0", "wg0", "igc0.100", "bridge0"} {
		if err := validDeviceName(ok); err != nil {
			t.Errorf("validDeviceName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "igc", "IGC0", "igc 0", "igc0 ", "0igc", "igc0.", "igc0.abc", "igc0;x"} {
		if err := validDeviceName(bad); err == nil {
			t.Errorf("validDeviceName(%q) = nil, want error", bad)
		}
	}
}

// The web terminal's shell binary and target account are not settable from any
// form, but POST /system/restore accepts a whole config document. Without these
// checks an uploaded backup is an arbitrary-command-as-any-user channel
// (docs/security-plan.md SEC-3a).
func TestValidateRejectsShellEscapeViaRestore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"arbitrary shell binary", func(c *Config) { c.Shell.Shell = "/usr/bin/env" }},
		{"relative shell binary", func(c *Config) { c.Shell.Shell = "sh" }},
		{"shell with arguments", func(c *Config) { c.Shell.Shell = "/bin/sh -c id" }},
		{"invalid account name", func(c *Config) { c.Shell.User = "root; id" }},
		{"uppercase account name", func(c *Config) { c.Shell.User = "Root" }},
		{"negative idle timeout", func(c *Config) { c.Shell.IdleTimeout = -1 }},
	} {
		cfg := Default()
		tc.mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", tc.name, cfg.Shell)
		}
	}
	// root stays reachable — it is a deliberate, spelled-out choice, not a
	// silent default (config.Shell's doc comment).
	cfg := Default()
	cfg.Shell = Shell{Enabled: true, User: "root", Shell: "/bin/sh", MaxSessions: 1}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected an explicit root shell: %v", err)
	}
}

func TestValidateUsernameShape(t *testing.T) {
	hash := auth.HashPassword("a reasonable password")
	for _, bad := range []string{"a b", "a\tb", "-admin", ".admin", strings.Repeat("a", 33), "admin/../root"} {
		cfg := Default()
		cfg.Users = []User{{Username: bad, PasswordHash: hash}}
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted username %q", bad)
		}
	}
	cfg := Default()
	cfg.Users = []User{{Username: "admin.1_x-y", PasswordHash: hash}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected a reasonable username: %v", err)
	}
}

func TestValidHostname(t *testing.T) {
	for _, ok := range []string{"pool.ntp.org", "time1", "192.168.1.1", "2001:db8::1", "a-b.example.com", "x.y."} {
		if err := validHostname(ok); err != nil {
			t.Errorf("validHostname(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "-a.example.com", "a-.example.com", "a b", "a_b.example.com", strings.Repeat("a", 64) + ".com"} {
		if err := validHostname(bad); err == nil {
			t.Errorf("validHostname(%q) = nil, want error", bad)
		}
	}
}

// A config document arrives wholesale from POST /system/restore. A hash with
// absurd parameters is an account that can never be logged into, so it is a
// restore error rather than a silent lockout (docs/security-plan.md SEC-4a).
func TestValidateRejectsHostilePasswordHash(t *testing.T) {
	good := auth.HashPassword("a reasonable password")
	for _, bad := range []string{
		strings.Replace(good, "m=65536", "m=16777216", 1), // 16 GiB per attempt
		strings.Replace(good, "t=1", "t=9999", 1),
		"$argon2id$stub",
		"not a hash at all",
		"",
	} {
		cfg := Default()
		cfg.Users = []User{{Username: "admin", PasswordHash: bad}}
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted password hash %q", bad)
		}
	}
	cfg := Default()
	cfg.Users = []User{{Username: "admin", PasswordHash: good}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected a genuine hash: %v", err)
	}
}
