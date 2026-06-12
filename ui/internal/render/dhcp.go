package render

import (
	"encoding/json"
	"fmt"
	"net"

	"firewall/ui/internal/config"
)

// Kea config file structure, minimal subset. Rendered through structs (not
// maps) so field order is stable for golden tests.
type kea struct {
	Dhcp4 keaDhcp4 `json:"Dhcp4"`
}

type keaDhcp4 struct {
	InterfacesConfig keaInterfaces `json:"interfaces-config"`
	LeaseDatabase    keaLeaseDB    `json:"lease-database"`
	ValidLifetime    int           `json:"valid-lifetime"`
	OptionData       []keaOption   `json:"option-data"`
	Subnet4          []keaSubnet   `json:"subnet4"`
}

type keaInterfaces struct {
	Interfaces []string `json:"interfaces"`
}

type keaLeaseDB struct {
	Type    string `json:"type"`
	Persist bool   `json:"persist"`
}

type keaOption struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type keaSubnet struct {
	ID           int              `json:"id"`
	Subnet       string           `json:"subnet"`
	Pools        []keaPool        `json:"pools"`
	Reservations []keaReservation `json:"reservations,omitempty"`
}

type keaPool struct {
	Pool string `json:"pool"`
}

type keaReservation struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
	Hostname  string `json:"hostname,omitempty"`
}

// KeaDHCP4 renders kea-dhcp4.conf for the LAN. The firewall's LAN address is
// handed out as both router and DNS (Unbound runs locally). Whether the
// service runs at all is rc.conf's decision at apply time, so a config is
// rendered even when DHCP is disabled.
func KeaDHCP4(cfg config.Config) (string, error) {
	lan := cfg.LAN()
	if lan.IPv4 == "" {
		return "", fmt.Errorf("kea: lan interface needs a static address")
	}
	lanIP, lanNet, err := net.ParseCIDR(lan.IPv4)
	if err != nil {
		return "", fmt.Errorf("kea: lan address: %w", err)
	}

	k := kea{Dhcp4: keaDhcp4{
		InterfacesConfig: keaInterfaces{Interfaces: []string{lan.Device}},
		LeaseDatabase:    keaLeaseDB{Type: "memfile", Persist: true},
		ValidLifetime:    cfg.DHCP.LeaseSeconds,
		OptionData: []keaOption{
			{Name: "routers", Data: lanIP.String()},
			{Name: "domain-name-servers", Data: lanIP.String()},
			{Name: "domain-name", Data: cfg.System.Domain},
		},
		Subnet4: []keaSubnet{{
			ID:     1,
			Subnet: lanNet.String(),
			Pools:  []keaPool{{Pool: cfg.DHCP.RangeStart + " - " + cfg.DHCP.RangeEnd}},
		}},
	}}
	for _, l := range cfg.DHCP.StaticLeases {
		k.Dhcp4.Subnet4[0].Reservations = append(k.Dhcp4.Subnet4[0].Reservations, keaReservation{
			HWAddress: l.MAC,
			IPAddress: l.IP,
			Hostname:  l.Hostname,
		})
	}

	out, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}
