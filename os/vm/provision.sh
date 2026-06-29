#!/bin/sh -e
# One-time VM setup: boot headless, configure SSH access over the serial
# console (FreeBSD VM images allow passwordless root there), shut down.
# After this, ./run.sh + ./ssh.sh are the daily drivers.
#
# It also seeds /root/fw.json with the role->NIC mapping this VM actually has
# (LAN->vtnet0 so management survives default-deny, WAN->vtnet1, OPT->vtnet2)
# and aliases the LAN IP onto vtnet0, so the first `apply` validates without a
# manual device remap. See os/vm/README.md "NICs and the pf test layout".
cd "$(dirname "$0")"

[ -f fwtest.qcow2 ] || { echo "no fwtest.qcow2 — run ./fetch.sh first" >&2; exit 1; }

KEY=$(cat "$HOME/.ssh/id_ed25519.pub")

# Seed config: config.Default() with the three igc* devices remapped to this
# VM's vtnet* NICs. Kept in sync with internal/config.Default() by hand — a test
# fixture, not the product default. Compacted + validated through python (also
# fails provisioning early on a malformed edit), then shipped as one base64 line
# because serial_expect drives the console a line at a time (no heredocs).
FW_JSON=$(cat <<'JSON'
{
  "version": 1,
  "system": {
    "hostname": "firewall", "domain": "lan", "timezone": "UTC+00:00",
    "dns_servers": [{"address": "1.1.1.1", "hostname": "cloudflare-dns.com"}],
    "ntp_servers": ["pool.ntp.org"]
  },
  "interfaces": [
    {"name": "WAN", "role": "wan", "device": "vtnet1", "dhcp_client": true},
    {"name": "LAN", "role": "lan", "device": "vtnet0", "ipv4": "192.168.1.1/24"},
    {"name": "OPT1", "role": "opt", "device": "vtnet2"}
  ],
  "nat": {"outbound_mode": "automatic"},
  "dhcp": [{"interface": "LAN", "enabled": true, "range_start": "192.168.1.100", "range_end": "192.168.1.199", "lease_seconds": 7200}],
  "dns": {"enabled": true},
  "flow": {"enabled": true}
}
JSON
)
FW_B64=$(printf '%s' "$FW_JSON" | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)),end="")' | base64 | tr -d '\n')
# The console is line-at-a-time with a ~255-char canonical limit, so a single
# echo of the full base64 overruns it. Append it in short chunks, then decode.
FW_WRITE=$(printf '%s\n' "$FW_B64" | fold -w 100 | while read -r c; do
	[ -n "$c" ] && printf "printf %%s '%s' >> /root/fw.b64\n" "$c"
done)
cat > provision.cmds <<EOF
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo '$KEY' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
sed -i '' -E 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sysrc hostname=fwtest sshd_enable=YES
hostname fwtest
service sshd restart || service sshd start
sysrc ifconfig_vtnet0="SYNCDHCP -txcsum -rxcsum -tso -lro"
sysrc ifconfig_vtnet1="up" ifconfig_vtnet2="up"
# Alias the seed LAN IP onto vtnet0 (which also keeps its DHCP mgmt address), so
# unbound/kea can bind it and pf \$lan_if:network resolves on first apply.
sysrc ifconfig_vtnet0_alias0="inet 192.168.1.1/24"
sysrc pf_enable=YES pflog_enable=YES kea_enable=YES unbound_enable=YES wireguard_enable=YES redis_enable=YES ntopng_enable=YES
# The rc.d/ntopng script never reads ntopng.conf; point ntopng_flags at the
# file fwd renders so the appliance config (interfaces, http-prefix, localhost
# bind, disable-login) is actually applied. ntopng loads a bare path as a
# config file.
sysrc ntopng_flags="/usr/local/etc/ntopng/ntopng.conf"
printf 'pass all\n' > /etc/pf.conf
rm -f /root/fw.b64
$FW_WRITE
openssl base64 -d -A < /root/fw.b64 > /root/fw.json && rm -f /root/fw.b64
pkg install -y kea unbound wireguard-tools redis ntopng
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
