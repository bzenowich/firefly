#!/bin/sh -e
# Boot the FreeBSD test VM. Serial console on stdio (exit: C-a x), SSH on
# localhost:2222, WebUI forwarded on localhost:8444 (8443 tends to be taken
# on dev boxes). First time: ./fetch.sh
# then ./provision.sh.
#
# Three NICs to mirror the appliance: vtnet0 is the management/user net
# (SSH + WebUI host forwards; maps to the LAN role so pf keeps it open),
# vtnet1/vtnet2 are peerless socket backends standing in for WAN and OPT.
cd "$(dirname "$0")"

[ -f fwtest.qcow2 ] || { echo "no fwtest.qcow2 — run ./fetch.sh first" >&2; exit 1; }

. ./qemu-accel.sh

exec qemu-system-x86_64 \
	-machine "q35,$QEMU_ACCEL" -cpu "$QEMU_CPU" -smp 2 -m 2048 \
	-drive file=fwtest.qcow2,if=virtio,format=qcow2 \
	-nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8444-:8443" \
	-nic socket,model=virtio-net-pci,listen=127.0.0.1:9101 \
	-nic socket,model=virtio-net-pci,listen=127.0.0.1:9102 \
	-nographic "$@"
