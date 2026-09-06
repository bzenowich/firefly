# os/vm — FreeBSD test VM

QEMU/KVM VM on the plan.md §6 target OS (FreeBSD 15.x, ZFS) for testing the
`fwd` daemon and, later, the image-build pipeline output. 15.x is required for
native `pflow(4)` — the §8 baseline visibility exporter, absent from 14.x.

```
./fetch.sh      # download base image (once), create disk overlay
./provision.sh  # one-time: install SSH key via serial console, headless
./run.sh        # boot; serial console on stdio (exit: C-a x)
./ssh.sh        # root shell, or ./ssh.sh <command>
./deploy.sh     # cross-compile fwd + fwd-helper, push them and the rc.d scripts
./reset.sh      # discard VM state, fresh overlay (re-provision after)
```

**No KVM?** `run.sh` and `provision.sh` fall back to TCG software emulation
automatically (`qemu-accel.sh`). It boots FreeBSD in minutes rather than
seconds, which is slow but is the difference between testing on the target OS
and not testing at all — sandboxes and CI runners routinely have no `/dev/kvm`.

**Boot appears to hang at "Obtaining a trust anchor..."** on a host with no
outbound DNS: that is `local_unbound` waiting out its DNS timeouts. It clears
on its own after a few minutes. Under TCG expect roughly 8-10 minutes from
`./run.sh` to a working `./ssh.sh`; `until ./ssh.sh 'echo UP'; do sleep 15;
done` is the polite way to wait.

**SSH identity** (`vmkey.sh`): your `~/.ssh/id_ed25519` when you have one,
otherwise a VM-local key generated into `os/vm/` (gitignored). The tooling never
creates keys in your personal `~/.ssh`.

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

fwd needs fwd-helper: it holds no privilege and has no in-process fallback, so
on its own it serves pages and can change nothing. Run both.

```
./deploy.sh
./ssh.sh 'service fwd-helper start </dev/null && service fwd start </dev/null'
```

By hand, without the rc.d scripts:

```
./ssh.sh 'daemon -o /root/helper.log /usr/local/sbin/fwd-helper -socket /var/run/fwd-helper.sock'
./ssh.sh 'daemon -o /root/fwd.log /usr/local/sbin/fwd -listen 0.0.0.0:8443 \
             -config /root/fw.json -helper-socket /var/run/fwd-helper.sock'
```

### Testing the privilege split

The VM is the only place the split (docs/security-plan.md §3) can actually be
exercised: it needs FreeBSD accounts, `devfs.rules` and `setusercontext(3)`.

```
./deploy.sh                                              # both binaries + rc.d
./ssh.sh 'NO_PKG=1 sh /root/provision-appliance.sh'      # accounts, devfs, sysctls
./ssh.sh 'service fwd-helper start && service fwd start'
./ssh.sh 'ps -axo user,command | grep -E "fwd|ndpi" | grep -v grep'
```

`NO_PKG=1` matters here: the packages are already installed in the image, and
skipping the repo refresh keeps this working on a host with no outbound DNS.
The checks to run afterwards are in `docs/hw-bringup.md` §8a.

Two things that will otherwise waste an hour:

- **`service X start` over ssh appears to hang.** `daemon(8)` inherits the ssh
  session's stdin, so ssh will not return even though the service started fine.
  Redirect it: `./ssh.sh 'service fwd start </dev/null'`.
- **Under TCG an apply takes minutes**, which is longer than the default 60 s
  confirm window — so it applies, the window expires, and the auto-rollback
  puts everything back before you can confirm. That is the lock-out guard
  working correctly, not a failure. For testing, either confirm from a second
  shell or set `sysrc fwd_helper_window=0` to auto-confirm.

First apply needs in the guest: `pkg install kea unbound wireguard-tools redis
ntopng`, `sysrc pf_enable=YES pflog_enable=YES kea_enable=YES
unbound_enable=YES wireguard_enable=YES redis_enable=YES ntopng_enable=YES`, a
permissive seed `/etc/pf.conf` (`pass all`), the seed `/root/fw.json`
(role→vtnet mapping) and the LAN-IP alias. provision.sh does all of it, so
`./deploy.sh` then start fwd, create the admin in the WebUI, and Apply works out
of the box — flow visibility included (native `pflow(4)`, FreeBSD 15+).

**`redis` is not optional gear.** ntopng requires it as a live store, and apply
does not check for it: enable Visibility on a box without redis installed and
running and the apply fails its reload and rolls back with no obvious cause.
It is in provision.sh's package set for exactly that reason.

**App labels need a second binary that `deploy.sh` does not build.** The flow
pipeline (`pflow(4)` → collector → SQLite → Flows UI) is pure Go and ships with
`fwd`; the `app` column stays empty until `cmd/ndpi-helper` is built *with*
`-tags "pcap ndpi"` and placed on the guest's `PATH`. That needs cgo against
libpcap + libnDPI, so it cannot ride the `GOOS=freebsd` cross-compile — build it
natively in the guest (`pkg install go ndpi`) and copy it into place. Without
it fwd's supervisor fails its `LookPath`, logs one line at startup, and disables
app labels — the Flows UI then just shows an empty app column with no
explanation, which is exactly how you waste an afternoon.

The ntopng web UI is reverse-proxied by `fwd` under `/visibility/app/` (it
binds localhost only); enable it on the Visibility page and apply.
