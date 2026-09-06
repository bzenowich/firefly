# Shared QEMU acceleration choice, sourced by run.sh and provision.sh.
#
# KVM when the host offers it, software emulation when it does not. TCG is
# perhaps 10x slower but it is the difference between testing on a FreeBSD
# guest and not testing at all — CI runners and sandboxes routinely have no
# /dev/kvm.
if [ -w /dev/kvm ]; then
	QEMU_ACCEL="accel=kvm"
	QEMU_CPU="host"
else
	echo "note: no /dev/kvm — using TCG software emulation (slow)" >&2
	QEMU_ACCEL="accel=tcg"
	QEMU_CPU="qemu64"
fi
