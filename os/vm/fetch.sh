#!/bin/sh -e
# Fetch the FreeBSD VM base image (plan.md §6: 15.x, ZFS for boot
# environments) and create the working overlay. The BASIC-CLOUDINIT variant
# lets first-boot provisioning run via cloud-init instead of console scripting.
#
# 15.x is the appliance target: it carries native pflow(4) for the §8 baseline
# visibility exporter, which is absent from all 14.x (see plan.md §6).
cd "$(dirname "$0")"

REL=15.1-RELEASE
BASE=FreeBSD-$REL-amd64-BASIC-CLOUDINIT-zfs.qcow2
URL=https://download.freebsd.org/releases/VM-IMAGES/$REL/amd64/Latest

if [ ! -f "$BASE" ]; then
	curl -O "$URL/CHECKSUM.SHA256"
	curl -o "$BASE.xz" "$URL/$BASE.xz"
	grep "($BASE.xz)" CHECKSUM.SHA256 | sed 's/SHA256 (\(.*\)) = \(.*\)/\2  \1/' | sha256sum -c -
	unxz "$BASE.xz"
fi

# Working disk is a qcow2 overlay; reset the VM with ./reset.sh. The base
# image is ~6 GB, too small for the appliance package set (ntopng alone pulls
# glib/python/font deps); size the overlay to 20 GB and let FreeBSD's firstboot
# growfs expand the ZFS pool to fill it.
[ -f fwtest.qcow2 ] || qemu-img create -f qcow2 -b "$BASE" -F qcow2 fwtest.qcow2 20G
echo "ok: fwtest.qcow2 ready"
