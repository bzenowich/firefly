# os/vm — FreeBSD test VM

QEMU/KVM VM on the plan.md §6 target OS (FreeBSD 14.x, ZFS) for testing the
`fwd` daemon and, later, the image-build pipeline output.

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

Ports: SSH `localhost:2222`, WebUI `localhost:8080` → guest `:8080`.

The disk is a qcow2 overlay on the pristine release image, so `reset.sh` is
cheap and the base never gets dirtied. Single NIC for now; pf/multi-NIC
testing will need two more (LAN/OPT as socket or tap) plus the real apply
path — `fwd` currently runs in devroot mode off-appliance until the image
has the expected service layout.
