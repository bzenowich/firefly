package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func validService() Service {
	return Service{ID: "svc-web", Name: "web", IP: "192.168.1.10", Port: 443, Proto: "tcp"}
}

func validForward() PortForward {
	return PortForward{ID: NewID(), Name: "web", ServiceID: "svc-web", WANPort: 443, Enabled: true}
}

// withForward returns a Default config carrying the web service and pf.
func withForward(pf PortForward) Config {
	cfg := Default()
	cfg.Services = []Service{validService()}
	cfg.NAT.PortForwards = []PortForward{pf}
	return cfg
}

func TestValidateServices(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Service)
		wantErr string
	}{
		{"valid", func(s *Service) {}, ""},
		{"missing id", func(s *Service) { s.ID = "" }, "missing id"},
		{"missing name", func(s *Service) { s.Name = "" }, "name is required"},
		{"bad proto", func(s *Service) { s.Proto = "icmp" }, "proto must be"},
		{"port zero", func(s *Service) { s.Port = 0 }, "port must be"},
		{"bad ip", func(s *Service) { s.IP = "not-an-ip" }, "invalid ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			svc := validService()
			tc.mutate(&svc)
			cfg.Services = []Service{svc}
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidatePortForwards(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*PortForward)
		wantErr string
	}{
		{"valid", func(pf *PortForward) {}, ""},
		{"missing id", func(pf *PortForward) { pf.ID = "" }, "missing id"},
		{"missing name", func(pf *PortForward) { pf.Name = "" }, "name is required"},
		{"unknown service", func(pf *PortForward) { pf.ServiceID = "nope" }, "unknown service"},
		{"wan port zero", func(pf *PortForward) { pf.WANPort = 0 }, "wan port must be"},
		{"wan port too big", func(pf *PortForward) { pf.WANPort = 70000 }, "wan port must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pf := validForward()
			tc.mutate(&pf)
			cfg := withForward(pf)
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateDuplicateWANPort(t *testing.T) {
	cfg := Default()
	cfg.Services = []Service{
		validService(),
		{ID: "svc-udp", Name: "game", IP: "192.168.1.20", Port: 443, Proto: "udp"},
	}
	a, b := validForward(), validForward()
	cfg.NAT.PortForwards = []PortForward{a, b}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "already forwarded") {
		t.Fatalf("want duplicate wan port error, got %v", err)
	}
	b.ServiceID = "svc-udp" // same wan port, different proto is fine
	cfg.NAT.PortForwards = []PortForward{a, b}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDHCP(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"default ok", func(c *Config) {}, ""},
		{"disabled skips checks", func(c *Config) {
			c.DHCP.Enabled = false
			c.DHCP.RangeStart = "garbage"
		}, ""},
		{"pool outside lan", func(c *Config) { c.DHCP.RangeEnd = "10.9.9.9" }, "inside"},
		{"bad range ip", func(c *Config) { c.DHCP.RangeStart = "nope" }, "invalid pool"},
		{"lease too short", func(c *Config) { c.DHCP.LeaseSeconds = 5 }, "at least 60"},
		{"lan needs static ip", func(c *Config) {
			c.Interfaces[1].IPv4 = ""
			c.Interfaces[1].DHCPClient = true
		}, "static address"},
		{"bad lease mac", func(c *Config) {
			c.DHCP.StaticLeases = []StaticLease{{MAC: "zz:zz", IP: "192.168.1.5", Hostname: "x"}}
		}, "invalid mac"},
		{"lease ip outside lan", func(c *Config) {
			c.DHCP.StaticLeases = []StaticLease{{MAC: "00:0d:b9:51:ab:cd", IP: "10.1.1.1", Hostname: "x"}}
		}, "inside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.json")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pf := validForward()
	err = s.Update(func(c *Config) error {
		c.Services = append(c.Services, validService())
		c.NAT.PortForwards = append(c.NAT.PortForwards, pf)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Reopen from disk and verify persistence.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Get().NAT.PortForwards
	if len(got) != 1 || got[0] != pf {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestStoreUpdateRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Update(func(c *Config) error {
		c.System.Hostname = ""
		return nil
	})
	if err == nil {
		t.Fatal("want validation error")
	}
	if s.Get().System.Hostname != "firewall" {
		t.Fatal("failed update must not change in-memory config")
	}
}

func TestValidateInterfaces(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"valid", func(c *Config) {}, ""},
		{"missing device", func(c *Config) { c.Interfaces[0].Device = "" }, "device is required"},
		{"duplicate device", func(c *Config) { c.Interfaces[2].Device = c.Interfaces[1].Device }, "already assigned"},
		{"dhcp and static", func(c *Config) { c.Interfaces[0].IPv4 = "10.0.0.2/24" }, "exclusive"},
		{"bad cidr", func(c *Config) { c.Interfaces[1].IPv4 = "192.168.1.1" }, "must be CIDR"},
		{"lan without address", func(c *Config) {
			c.Interfaces[1].IPv4 = ""
			c.DHCP.Enabled = false
		}, "lan needs a static address"},
		{"wan without address or dhcp", func(c *Config) { c.Interfaces[0].DHCPClient = false }, "wan needs dhcp"},
		{"wan static ok", func(c *Config) {
			c.Interfaces[0].DHCPClient = false
			c.Interfaces[0].IPv4 = "203.0.113.2/24"
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestUpdateRejectionLeavesNoTrace(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatal(err)
	}
	// In-place slice-element mutation that fails validation must not leak
	// into the live config (regression: shallow copy shared backing arrays).
	err = store.Update(func(c *Config) error {
		for i := range c.Interfaces {
			if c.Interfaces[i].Role == "lan" {
				c.Interfaces[i].IPv4 = "10.0.2.15/24" // pool now outside subnet
			}
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected validation failure")
	}
	for _, ifc := range store.Get().Interfaces {
		if ifc.Role == "lan" && ifc.IPv4 != "192.168.1.1/24" {
			t.Fatalf("rejected mutation leaked: lan = %+v", ifc)
		}
	}
}

func TestGetIsDeepCopy(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := store.Get()
	got.Interfaces[0].Device = "tampered"
	if store.Get().Interfaces[0].Device == "tampered" {
		t.Fatal("Get returned shared slice memory")
	}
}
