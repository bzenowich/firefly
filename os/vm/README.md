# os/vm — FreeBSD test VM

QEMU/KVM VM on the plan.md §6 target OS (FreeBSD 15.x, ZFS) for testing the
`fwd` daemon and, later, the image-build pipeline output. 15.x is required for
native `pflow(4)` — the §8 baseline visibility exporter, absent from 14.x.

```
./fetch.sh      # download base image (once), create disk overlay
./provision.sh  # one-time: install SSH key via serial console, headless
./run.sh        # boot; serial console on stdio (exit: C-a x)
./ssh.sh        # root shell, or ./ssh.sh <command>
./deploy.sh     # cross-compile fwd and scp it to the VM
./reset.sh      # discard VM state, fresh overlay (re-provision after)
```

Provisioning drives the serial console (passwordless root, standard on the
official VM images) via `serial_expect.py` — no cloud-init seed tooling
needed on the host. The image's nuageinit prints a harmless "Impossible to
find a cloud init provider" at boot; it never finds a datasource.

It installs `~/.ssh/id_ed25519.pub` for root and enables sshd.

Ports: SSH `localhost:2222`, WebUI `localhost:8444` → guest `:8443` (HTTPS,
self-signed).

The disk is a qcow2 overlay on the pristine release image, so `reset.sh` is
cheap and the base never gets dirtied.

## NICs and the pf test layout

Three NICs: `vtnet0` is the QEMU user net carrying the SSH/WebUI host
forwards; `vtnet1`/`vtnet2` are peerless socket backends. The roles map
**LAN → vtnet0**, WAN → vtnet1, OPT → vtnet2: the rendered ruleset passes LAN
traffic, so management over the host forwards survives the applied default-deny
ruleset. (Host forwards arrive as inbound connections on vtnet0.) provision.sh
seeds this mapping into `/root/fw.json` and aliases the LAN IP (192.168.1.1)
onto vtnet0, so the first `apply` validates with no manual remap.

Gotchas learned the hard way (provision.sh handles both):

- **Disable offloads on vtnet0** (`-txcsum -rxcsum -tso -lro`): pf +
  vtnet hardware offload corrupts large TCP segments — SSH stays up while
  every TLS handshake dies, which looks exactly like flaky qemu forwarding.
- The cloud image DHCP-probes every NIC at boot; `ifconfig_vtnetN="up"` on
  the dead NICs avoids a ~2 minute boot stall.

## Running fwd on the VM

```
./deploy.sh
./ssh.sh 'daemon -o /root/fwd.log /root/fwd -listen 0.0.0.0:8443 -config /root/fw.json'
```

First apply needs in the guest: `pkg install kea unbound wireguard-tools
ntopng`, `sysrc pf_enable=YES pflog_enable=YES kea_enable=YES
unbound_enable=YES wireguard_enable=YES ntopng_enable=YES`, a permissive seed
`/etc/pf.conf` (`pass all`), the seed `/root/fw.json` (role→vtnet mapping) and
the LAN-IP alias. provision.sh does all of it, so `./deploy.sh` then start fwd,
create the admin in the WebUI, and Apply works out of the box — baseline
visibility included (native `pflow(4)`, FreeBSD 15+).

The ntopng web UI is reverse-proxied by `fwd` under `/visibility/app/` (it
binds localhost only); enable it on the Visibility page and apply.
