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
	ID            int              `json:"id"`
	Subnet        string           `json:"subnet"`
	Pools         []keaPool        `json:"pools"`
	ValidLifetime int              `json:"valid-lifetime"`
	OptionData    []keaOption      `json:"option-data"`
	Reservations  []keaReservation `json:"reservations,omitempty"`
}

type keaPool struct {
	Pool string `json:"pool"`
}

type keaReservation struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
	Hostname  string `json:"hostname,omitempty"`
}

// KeaDHCP4 renders kea-dhcp4.conf. Each enabled per-interface DHCP server
// becomes its own subnet; that interface's address is handed out as both
// router and DNS (Unbound runs locally). Disabled servers and the WAN are
// skipped. Whether the service runs at all is rc.conf's decision at apply
// time, so a config is rendered even when no server is enabled.
func KeaDHCP4(cfg config.Config) (string, error) {
	byName := map[string]config.Interface{}
	for _, ifc := range cfg.Interfaces {
		byName[ifc.Name] = ifc
	}

	k := kea{Dhcp4: keaDhcp4{
		LeaseDatabase: keaLeaseDB{Type: "memfile", Persist: true},
	}}
	id := 1
	for _, d := range cfg.DHCP {
		if !d.Enabled {
			continue
		}
		ifc, ok := byName[d.Interface]
		if !ok {
			return "", fmt.Errorf("kea: dhcp server references unknown interface %q", d.Interface)
		}
		if ifc.IPv4 == "" {
			return "", fmt.Errorf("kea: interface %q needs a static address", d.Interface)
		}
		ifcIP, ifcNet, err := net.ParseCIDR(ifc.IPv4)
		if err != nil {
			return "", fmt.Errorf("kea: %q address: %w", d.Interface, err)
		}
		k.Dhcp4.InterfacesConfig.Interfaces = append(k.Dhcp4.InterfacesConfig.Interfaces, ifc.Device)
		sub := keaSubnet{
			ID:            id,
			Subnet:        ifcNet.String(),
			Pools:         []keaPool{{Pool: d.RangeStart + " - " + d.RangeEnd}},
			ValidLifetime: d.LeaseSeconds,
			OptionData: []keaOption{
				{Name: "routers", Data: ifcIP.String()},
				{Name: "domain-name-servers", Data: ifcIP.String()},
				{Name: "domain-name", Data: cfg.System.Domain},
			},
		}
		for _, l := range d.StaticLeases {
			sub.Reservations = append(sub.Reservations, keaReservation{
				HWAddress: l.MAC,
				IPAddress: l.IP,
				Hostname:  l.Hostname,
			})
		}
		k.Dhcp4.Subnet4 = append(k.Dhcp4.Subnet4, sub)
		id++
	}

	out, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}
