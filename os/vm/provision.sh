#!/bin/sh -e
# One-time VM setup: boot headless, configure SSH access over the serial
# console (FreeBSD VM images allow passwordless root there), shut down.
# After this, ./run.sh + ./ssh.sh are the daily drivers.
cd "$(dirname "$0")"

[ -f fwtest.qcow2 ] || { echo "no fwtest.qcow2 — run ./fetch.sh first" >&2; exit 1; }

KEY=$(cat "$HOME/.ssh/id_ed25519.pub")
cat > provision.cmds <<EOF
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo '$KEY' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
sed -i '' -E 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sysrc hostname=fwtest sshd_enable=YES
hostname fwtest
service sshd restart || service sshd start
poweroff
EOF

qemu-system-x86_64 \
	-machine q35,accel=kvm -cpu host -smp 2 -m 2048 \
	-drive file=fwtest.qcow2,if=virtio,format=qcow2 \
	-nic user,model=virtio-net-pci \
	-display none -serial unix:console.sock,server,nowait \
	-pidfile qemu.pid -daemonize

python3 serial_expect.py provision.cmds
rm -f provision.cmds

# poweroff in the command script stops the VM; wait for QEMU to exit, with
# a SIGTERM fallback — everything important is already synced to disk.
PID=$(cat qemu.pid 2>/dev/null)
n=0
while [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; do
	n=$((n + 1))
	[ "$n" -gt 90 ] && { echo "poweroff timed out; terminating qemu" >&2; kill "$PID"; break; }
	sleep 1
done
rm -f console.sock qemu.pid
echo "ok: provisioned — ./run.sh to boot, ./ssh.sh to connect"
