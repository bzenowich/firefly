#!/bin/sh -e
# Boot the FreeBSD test VM. Serial console on stdio (exit: C-a x), SSH on
# localhost:2222, WebUI forwarded on localhost:8080. First time: ./fetch.sh
# then ./provision.sh.
cd "$(dirname "$0")"

[ -f fwtest.qcow2 ] || { echo "no fwtest.qcow2 — run ./fetch.sh first" >&2; exit 1; }

exec qemu-system-x86_64 \
	-machine q35,accel=kvm -cpu host -smp 2 -m 2048 \
	-drive file=fwtest.qcow2,if=virtio,format=qcow2 \
	-nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8080-:8080" \
	-nographic "$@"
