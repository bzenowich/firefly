#!/bin/sh -e
# Throw away VM state: disk overlay and host key. Base image stays; rerun
# ./provision.sh afterwards.
cd "$(dirname "$0")"
rm -f fwtest.qcow2 known_hosts console.sock qemu.pid
./fetch.sh
