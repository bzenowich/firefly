# Open Firewall Appliance

A spiritual successor to the PC Engines APU2: an open, fanless, serial-console-first
3-port firewall appliance. Coreboot firmware, FreeBSD-based OS, purpose-built WebUI.

See [plan.md](plan.md) for the full design plan. Current status: **Phase 0** —
OS image and WebUI development on COTS hardware.

## Layout

| Path | Contents |
|------|----------|
| `ui/` | Go WebUI + declarative config engine (single static binary, htmx frontend) |
| `os/` | FreeBSD image build: poudriere, mkimg, CI |
| `fw/` | coreboot configs, build scripts, blob policy |
| `hw/carrier/` | Phase 2 KiCad project (SMARC/COMe carrier board) |
| `hw/sbc/` | Phase 4 KiCad project (custom single-board design) |
| `case/` | Enclosure CAD, DXF flat patterns |
| `docs/` | User manual, build guides |

## WebUI quickstart

```sh
cd ui
go run ./cmd/fwd
# open http://127.0.0.1:8080
```

Writes a default config to `./fw.json` on first run. Linux is supported as a
dev host (dashboard stats via /proc); FreeBSD is the deployment target.
