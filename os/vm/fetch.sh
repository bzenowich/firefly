#!/bin/sh -e
# Fetch the FreeBSD VM base image (plan.md §6: 14.x, ZFS for boot
# environments) and create the working overlay. The BASIC-CLOUDINIT variant
# lets first-boot provisioning run via cloud-init instead of console scripting.
cd "$(dirname "$0")"

REL=14.4-RELEASE
BASE=FreeBSD-$REL-amd64-BASIC-CLOUDINIT-zfs.qcow2
URL=https://download.freebsd.org/releases/VM-IMAGES/$REL/amd64/Latest

if [ ! -f "$BASE" ]; then
	curl -O "$URL/CHECKSUM.SHA256"
	curl -o "$BASE.xz" "$URL/$BASE.xz"
	grep "($BASE.xz)" CHECKSUM.SHA256 | sed 's/SHA256 (\(.*\)) = \(.*\)/\2  \1/' | sha256sum -c -
	unxz "$BASE.xz"
fi

# Working disk is a qcow2 overlay; reset the VM with ./reset.sh.
[ -f fwtest.qcow2 ] || qemu-img create -f qcow2 -b "$BASE" -F qcow2 fwtest.qcow2
echo "ok: fwtest.qcow2 ready"
