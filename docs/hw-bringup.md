# Hardware bring-up

Getting Luciola running on a COTS x86 box — the Phase 0 target (`plan.md` §10).
Written against the reference dev unit: **Intel N150, 16 GB RAM, 256 GB NVMe,
4× Intel i226 (`igc0`–`igc3`)**, which is deliberately the same silicon class as
the eventual custom board.

Nothing here is VM-specific. `os/vm/README.md` covers the QEMU test VM; this
covers real metal, and the provisioning script is shared.

## 0. What differs from the VM

The VM has been the only target so far, and it hid four things:

| | VM | Hardware |
|---|---|---|
| Console | serial on stdio | HDMI + USB keyboard; these boxes have no DB9 |
| Provisioning | `os/vm/provision.sh` over a serial socket | `os/provision-appliance.sh` over SSH |
| NICs | 3× `vtnet` | 4× `igc`, and **which jack is `igc0` is a board decision, not a convention** |
| Base image | cloud-init image, root passwordless on console | stock installer; you create the accounts |

Serial-console-first is a goal for the *custom board*, not a Phase 0 constraint.
Don't spend time on it now.

## 1. Install FreeBSD

Use the **15.1-RELEASE memstick** installer. 15.x is not optional: `pflow(4)`,
the flow exporter the whole visibility baseline hangs off, is absent from every
14.x release (`plan.md` §6).

At the partitioning step choose **Auto (ZFS)**. Boot environments (`bectl`) are
the appliance's update and rollback story, and they only exist on ZFS root.

Enable `sshd` in the installer's service list, create a user, and note the DHCP
address it picks up on whichever port you plugged into.

## 2. Provision

From your workstation:

```sh
scp os/provision-appliance.sh os/rc.d/fwd root@<box>:/tmp/
ssh root@<box> 'cd /tmp && mkdir -p rc.d && mv fwd rc.d/ && sh provision-appliance.sh'
```

It installs the service packages (Kea, Unbound, wireguard-tools, `ca_root_nss`),
installs fwd's rc.d script, seeds a permissive `/etc/pf.conf` so the box stays
reachable before the first apply, and writes a seed `/conf/config.json` mapping
the NICs it actually finds: first port WAN (DHCP), second port LAN, the rest
`OPT1..OPTn`. It is idempotent and never overwrites an existing config.

**If your existing home LAN is also `192.168.1.0/24`**, seed a different one —
identical subnets either side of a router is a confusing way to lose an
afternoon:

```sh
LAN_CIDR=192.168.77.1/24 sh provision-appliance.sh
```

Apply enables and starts pf, Kea, Unbound, WireGuard and the flow exporter
itself, and sets their rcvars so they survive a reboot. Provisioning
deliberately does not pre-enable them.

## 3. Deploy fwd

`fwd` is pure Go — no cgo, `modernc.org/sqlite` — so it cross-compiles from any
host:

```sh
cd ui && GOOS=freebsd GOARCH=amd64 go build -o /tmp/fwd ./cmd/fwd
scp /tmp/fwd root@<box>:/usr/local/sbin/fwd
ssh root@<box> 'chmod 0755 /usr/local/sbin/fwd && sysrc fwd_enable=YES && service fwd start'
```

Browse to `https://<lan-address>:8443` (self-signed cert) and create the admin
account. The setup page is open until that first account exists, so do it now
rather than later.

## 4. Confirm the port mapping *before* the first apply

This is the one step that has no VM equivalent and the one most likely to waste
your time. Which physical jack enumerates as `igc0` depends on the vendor's
PCIe lane wiring — it is frequently *not* left-to-right.

Plug a cable into one port at a time and watch:

```sh
ssh root@<box> 'ifconfig igc0 igc1 igc2 igc3 | grep -E "^igc|status:"'
```

Then fix the roles on the **Interfaces** page so WAN is the jack facing your
upstream router. Getting this wrong means the first apply NATs the wrong
direction and you lose the management path.

## 5. First apply

Hit **Apply**. The engine stages every rendered file, validates offline
(`pfctl -nf`, `kea-dhcp4 -t`, `unbound-checkconf`), installs atomically, reloads,
and then waits 60 s for you to **Confirm** — if you don't, it rolls everything
back. That window exists precisely for the mistake in step 4.

Order matters and is handled for you: interface addressing lands before pf
loads, because pf's `$lan_if:network` macros resolve against the live interface.

Then check, in order:

```sh
ssh root@<box> 'pfctl -si | head -3'                  # pf enabled, rules loaded
ssh root@<box> 'ifconfig igc1 | grep inet'            # LAN address applied
ssh root@<box> 'service kea status; service unbound status'
ssh root@<box> 'pflowctl -l'                          # one exporter, to 127.0.0.1:9996
```

Plug a client into the LAN port: it should get a lease, resolve names, and
reach the internet. The **Flows** view should start filling within a minute.

## 6. Optional extras

**App labels on flows.** The `app` column stays empty until `ndpi-helper` is
built — it needs cgo against libpcap and libnDPI, so it is built on the box, not
cross-compiled:

```sh
./os/build-ndpi-helper.sh root@<box>
ssh root@<box> 'service fwd restart'
```

**Visibility power tier (ntopng).** `pkg install redis ntopng`, then enable it on
the Visibility page. Redis is a hard dependency — ntopng has no Redis-less mode —
and apply now refuses with a clear message rather than an opaque rollback if it
is missing.

## 7. NIC tuning, and why it is in the config

The engine renders an rc.d script (`fwnetwork`) that owns interface addressing
and link tuning. On every port it disables TSO/LRO and checksum offload and pins
`dev.igc.N.eee_control=0`:

- **TSO/LRO** coalesce segments in the NIC. That is wrong for a box that forwards
  and firewalls other people's packets, and it hands the flow classifier merged
  super-frames that break dissection.
- **EEE** is a link-stability liability on i225/i226 and buys nothing on a
  mains-powered appliance. `igc(4)` already defaults it off; pinning it means a
  driver default change can't quietly turn it back on.

If a port is a plain host interface and isn't being captured, `hardware_offload`
in its config entry re-enables offloads.

**If links stall under load**, the other i226 suspect is ASPM L1.2 (there is an
upstream FreeBSD fix for RX stalls). Try `hw.igc.disable_aspm=1` in
`/boot/loader.conf` before blaming anything else.

## 8. Verify on the box (things unit tests cannot reach)

These are the open items from `design-review.md` §7 — all cheap, all recurring
on hardware, and none provable off a FreeBSD box:

1. **Web shell survives >60 s.** The HTTP server's write deadline used to kill
   the hijacked websocket; HTTP/2 negotiation would have broken the hijack
   outright. Both are addressed — confirm by leaving a shell session idle.
2. **`/bin/sh -l`** — confirm FreeBSD's `sh` accepts `-l`, and that the shell
   works now that it runs as an unprivileged user rather than root (the PTY is
   opened by root and inherited; that path was near-dead code before).
3. **pflow NAT tuple.** Does `pflow(4)` export the pre-NAT (LAN) or post-NAT
   (WAN) tuple for a NATed state? This decides whether app labels can attach to
   a LAN device at all. Check a known flow in the Flows view against `pfctl -ss`.
4. **`keep state (pflow)` grammar** on a stock 15.1 kernel — the one generated
   pf construct not verifiable from source. A mismatch fails loudly at
   `pfctl -nf`, so the apply gate catches it.
5. **Base `local_unbound`** may already hold port 53 on a stock install; nothing
   detects it. `sockstat -l | grep :53` before blaming the rendered config.
6. **`net.bpf.maxbufsize`** clamps the capture buffer ndpi-helper asks for; raise
   it if the drop counters in fwd's log are non-zero. Provisioning now sets it.

## 8a. Verify the privilege split (docs/security-plan.md §3)

None of this can be checked off FreeBSD — the accounts, `devfs.rules` and
`setusercontext(3)` all need the box. Run it after provisioning and after every
image update; the whole point of the split is that it is either true or it is
decoration.

```sh
# 1. Exactly one root process from this project.
ps -axo user,command | grep -E 'fwd|ndpi' | grep -v grep
#    want: root ... fwd-helper
#          _fwd ... fwd
#    a root fwd means fwd_runas or the helper socket is unset.

# 2. The channel to root, and the state fwd owns.
ls -l  /var/run/fwd-helper.sock   # srw-rw----  root  _fwd
ls -ld /conf /var/db/fwd          # drwx------  _fwd  _fwd
ls -l  /conf/config.json          # -rw-------  _fwd  _fwd

# 3. bpf by group, not by uid — this is what keeps the log collector and the
#    flow classifier out of root.
ls -l /dev/bpf0                   # crw-r-----  root  _fwdbpf
id _fwd                           # ... groups=...(_fwdbpf)

# 4. Process visibility is actually restricted.
sysctl security.bsd.see_other_uids security.bsd.see_other_gids   # both 0
su -m _fwd -c 'ps -axo user,command' 2>/dev/null | grep fwd-helper
#    want: nothing. If _fwd can see the helper's argv, the sysctls did not take.

# 5. The functions that need the helper still work, as _fwd:
#    - Apply/Confirm/Rollback from the System page
#    - the WireGuard page shows a real "last seen" for a connected client
#      (that is `wg show` crossing the boundary)
#    - the Logs page fills with pf entries (tcpdump on pflog0, via the bpf grant)

# 6. The web terminal is off at the privileged layer regardless of the UI.
grep fwd_helper_shell_users /etc/rc.conf || echo 'not set: no terminal, as intended'

# 7. The flow classifier — the most likely thing here to be exploitable, since
#    it points libnDPI at raw frames off the WAN — is not root.
ps -axo user,command | grep ndpi-helper | grep -v grep    # want: _fwdpcap
ls -l /var/run/fwd/ndpi.sock                               # srw-rw---- _fwd _fwdpcap
#    It opens bpf as root and drops before parsing anything, so a root
#    ndpi-helper in that output means the drop failed and the log will say why:
tail /var/log/ndpi-helper.log
```

**Deliberate consequence:** a root web terminal is now a console action, not a
checkbox. `sysrc fwd_helper_shell_users=root && service fwd-helper restart`.
Enabling the toggle in the UI without that gets a refusal naming both sides.

## 9. Known gaps

- **The 4th NIC needs a hand edit for now.** The config model and validation
  accept any number of `opt` interfaces, and provisioning seeds all four, but
  the Interfaces page can only edit the existing set — it has no add/remove
  affordance yet.
- **Dashboard temperature** is promised in `plan.md` §7 but not implemented;
  `stats_freebsd.go` reads load, memory and uptime only. On the N150 it needs
  `coretemp(4)` loaded and `dev.cpu.N.temperature` read.
- **fwd runs as root.** `plan.md` §7's privilege split (unprivileged daemon plus
  a narrow root helper) is not built. Fine for a bench box on your own LAN;
  it is a Phase 0 exit criterion before this goes anywhere else.
