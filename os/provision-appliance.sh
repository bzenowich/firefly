#!/bin/sh -e
#
# Provision a FreeBSD 15.x host into a Luciola appliance.
#
# Runs ON the target (hardware or VM), as root, against a stock install:
#
#   scp os/provision-appliance.sh root@box:/tmp/ && ssh root@box sh /tmp/provision-appliance.sh
#
# It is idempotent — re-run it after an upgrade or a botched experiment.
#
# What it does NOT do: it installs no addressing, no pf rules, no service
# configs. Those are fwd's job, rendered from the config document and applied
# through the confirm-or-rollback pipeline. This script only creates the
# preconditions fwd cannot create for itself — packages, its own rc.d script,
# a seed config matching this box's actual NICs, and a permissive pf.conf so
# the box is reachable before the first apply.
#
# Environment overrides:
#   LAN_CIDR   LAN address for the seed config (default 192.168.1.1/24).
#              Change it if the network the WAN port plugs into is also
#              192.168.1.0/24 — two identical subnets either side of a router
#              is a confusing way to lose an afternoon.
#   PKGS_EXTRA Extra packages, e.g. "redis ntopng" for the visibility power
#              tier or "go ndpi" to build the flow classifier on the box.
#   NO_PKG=1   Skip package installation (offline / already provisioned).

LAN_CIDR=${LAN_CIDR:-192.168.1.1/24}
CONF_DIR=/conf
CONF=$CONF_DIR/config.json
SEED_PF=/etc/pf.conf

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
[ "$(uname -s)" = FreeBSD ] || die "this provisions FreeBSD, not $(uname -s)"

# 15.x is the appliance target: pflow(4), the baseline flow exporter, is
# absent from every 14.x release (plan.md §6).
case "$(uname -r)" in
15.*) ;;
*) echo "warning: FreeBSD $(uname -r); 15.x is required for pflow(4) flow export" >&2 ;;
esac

# ---------------------------------------------------------------- packages
# ca_root_nss is not optional: unbound verifies DNS-over-TLS upstreams against
# the bundle it installs, and the default config ships a DoT upstream.
PKGS="kea unbound wireguard-tools ca_root_nss"
if [ "${NO_PKG:-0}" != 1 ]; then
	log "installing packages: $PKGS ${PKGS_EXTRA:-}"
	ASSUME_ALWAYS_YES=yes pkg bootstrap >/dev/null 2>&1 || true
	# shellcheck disable=SC2086
	pkg install -y $PKGS ${PKGS_EXTRA:-}
else
	log "NO_PKG=1: skipping package installation"
fi

# --------------------------------------------------------------- accounts
# The privilege split (docs/security-plan.md §3). fwd runs as _fwd and holds no
# privilege of its own; fwd-helper stays root and is the only thing that writes
# /etc, runs pfctl and service(8), or forks a terminal. _fwdpcap is for
# ndpi-helper, which parses hostile packets with libnDPI and has no business
# being root.
#
# Both are nologin service accounts with no home. _fwdbpf is the group that
# carries the bpf grant below: membership, not uid 0, is what lets the log
# collector run tcpdump on pflog0 and the classifier capture from the NICs.
for grp in _fwd _fwdpcap _fwdbpf; do
	pw groupshow "$grp" >/dev/null 2>&1 || {
		log "creating group $grp"
		pw groupadd "$grp"
	}
done
for acct in _fwd _fwdpcap; do
	pw usershow "$acct" >/dev/null 2>&1 || {
		log "creating account $acct"
		pw useradd "$acct" -g "$acct" -d /nonexistent -s /usr/sbin/nologin -c "Luciola $acct"
	}
	pw groupmod _fwdbpf -m "$acct"
done

# ------------------------------------------------------------------ devfs
# bpf access by group rather than by uid. This is what makes the split
# affordable: without it the log collector (tcpdump on pflog0) and the flow
# classifier (libpcap on the NICs) would both need root, and there would be
# little left to separate.
DEVFS_RULES=/etc/devfs.rules
if ! grep -q 'fwd_bpf' $DEVFS_RULES 2>/dev/null; then
	log "granting bpf to the _fwdbpf group via devfs.rules"
	cat >> $DEVFS_RULES <<'DEVFS'

# Luciola: bpf readable by the _fwdbpf group (docs/security-plan.md §3.3).
# fwd's log collector and ndpi-helper both open bpf devices; neither needs
# root for anything else.
[fwd_bpf=10]
add path 'bpf*' mode 0640 group _fwdbpf
DEVFS
fi
sysrc devfs_system_ruleset=fwd_bpf >/dev/null
service devfs restart >/dev/null 2>&1 || true

# BPF's default kernel buffer is a small fraction of a second on a routed
# 2.5GbE path, so bursts are dropped in the kernel, silently. ndpi-helper asks
# for 8 MiB per device; without raising this it cannot get it
# (ui/cmd/ndpi-helper/source_pcap.go).
sysctl net.bpf.maxbufsize=16777216 >/dev/null 2>&1 || true
grep -q '^net.bpf.maxbufsize=' /etc/sysctl.conf 2>/dev/null || \
	echo 'net.bpf.maxbufsize=16777216' >> /etc/sysctl.conf

# ---------------------------------------------------------------- sysctls
# Without these the split buys much less: a compromised _fwd could read the
# helper's and the terminal user's process state, arguments and environment.
for kv in security.bsd.see_other_uids=0 security.bsd.see_other_gids=0; do
	key=${kv%%=*}
	sysctl "$kv" >/dev/null 2>&1 || true
	grep -q "^$key=" /etc/sysctl.conf 2>/dev/null || echo "$kv" >> /etc/sysctl.conf
done

# ------------------------------------------------------------------- sshd
# The appliance is managed over the WebUI, but SSH is the recovery path and
# the only way in before the first apply.
sysrc sshd_enable=YES >/dev/null

# Key-only, no root login (docs/security-plan.md SEC-18). Written as a drop-in
# rather than by editing sshd_config, so a base-system upgrade does not fight
# us and the change is one file to inspect or delete.
#
# Deliberately NOT applied when no key is installed yet: locking password auth
# on a box whose only account has no authorized_keys is how a bring-up ends
# with a serial cable. The provisioning output says so plainly.
SSHD_DROPIN=/etc/ssh/sshd_config.d/luciola.conf
if grep -rqs . /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null; then
	install -d -m 0755 /etc/ssh/sshd_config.d
	cat > $SSHD_DROPIN <<'SSHD'
# Luciola appliance hardening (docs/security-plan.md SEC-18).
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
SSHD
	log "sshd: key-only, root login disabled"
else
	log "sshd: leaving password auth enabled — no authorized_keys found"
	log "      install a key, then re-run this script to lock it down"
fi
service sshd restart >/dev/null 2>&1 || service sshd start >/dev/null 2>&1 || true

# --------------------------------------------------------------- seed pf
# fwd renders the real ruleset. This placeholder exists so that pf can be
# enabled and the box stays reachable in the window before the first apply;
# the first apply overwrites it.
if [ ! -f $SEED_PF ]; then
	log "seeding a permissive $SEED_PF (replaced by the first apply)"
	printf '# Placeholder until fwd applies a rendered ruleset.\npass all\n' > $SEED_PF
fi

# ------------------------------------------------------- interface discovery
# Physical ports only: drop loopback, pf's logging clone, wireguard, bridges
# and anything else fwd or the kernel creates.
nics=$(ifconfig -l | tr ' ' '\n' | grep -vE '^(lo|pflog|pfsync|wg|bridge|tap|tun|gif|epair|vlan|enc|ipfw)' | grep -v '^$')
[ -n "$nics" ] || die "no physical network interfaces found"

set -- $nics
count=$#
log "found $count interface(s): $nics"
[ "$count" -ge 2 ] || die "need at least two interfaces (wan + lan), found $count"

# ------------------------------------------------------------- seed config
# Written only when absent: re-running this script must never clobber a
# configured appliance.
if [ -f "$CONF" ]; then
	log "$CONF exists; leaving it alone"
else
	log "writing seed config $CONF (wan=$1, lan=$2, lan address $LAN_CIDR)"
	install -d -m 0700 $CONF_DIR

	lan_ip=${LAN_CIDR%%/*}
	# DHCP pool: .100-.199 of the LAN's /24. Derived from the configured
	# address so overriding LAN_CIDR does not leave a pool in a foreign
	# subnet — validation would reject that.
	lan_prefix=$(echo "$lan_ip" | cut -d. -f1-3)

	wan=$1
	lan=$2
	shift 2

	opts=""
	n=1
	for dev in "$@"; do
		opts="$opts,
    {\"name\": \"OPT$n\", \"role\": \"opt\", \"device\": \"$dev\"}"
		n=$((n + 1))
	done

	cat > "$CONF" <<EOF
{
  "version": 1,
  "system": {
    "hostname": "firewall",
    "domain": "lan",
    "timezone": "UTC+00:00",
    "dns_servers": [{"address": "1.1.1.1", "hostname": "cloudflare-dns.com"}],
    "ntp_servers": ["pool.ntp.org"]
  },
  "interfaces": [
    {"name": "WAN", "role": "wan", "device": "$wan", "dhcp_client": true},
    {"name": "LAN", "role": "lan", "device": "$lan", "ipv4": "$LAN_CIDR"}$opts
  ],
  "nat": {"outbound_mode": "automatic"},
  "dhcp": [{"interface": "LAN", "enabled": true,
            "range_start": "$lan_prefix.100", "range_end": "$lan_prefix.199",
            "lease_seconds": 7200}],
  "dns": {"enabled": true},
  "flow": {"enabled": true}
}
EOF
	chmod 0600 "$CONF"
fi

# ----------------------------------------------------------------- fwd rc.d
# fwd renders the other services' rc scripts but cannot install its own.
for svc in fwd fwd-helper ndpi-helper; do
	if [ -f "$(dirname "$0")/rc.d/$svc" ]; then
		log "installing the $svc rc.d script"
		install -m 0755 "$(dirname "$0")/rc.d/$svc" "/usr/local/etc/rc.d/$svc"
	else
		echo "note: rc.d/$svc not found next to this script; copy it to" >&2
		echo "      /usr/local/etc/rc.d/$svc by hand to run $svc as a service" >&2
	fi
done
# ------------------------------------------------------- state ownership
# fwd runs as _fwd and owns its own state: the config document (every secret on
# the box), the TLS identity, and the SQLite stores. fwd-helper never reads any
# of it — the config document reaches it over the socket, where it is
# re-validated (docs/security-plan.md §3.3).
#
# chown unconditionally, not just on create: a box provisioned before the split
# has these owned by root, and the first thing fwd does after dropping is fail
# to write them.
install -d -m 0700 -o _fwd -g _fwd /var/db/fwd
install -d -m 0700 -o _fwd -g _fwd $CONF_DIR
[ -f "$CONF" ] && chown _fwd:_fwd "$CONF" && chmod 0600 "$CONF"
for f in $CONF_DIR/fw-cert.pem $CONF_DIR/fw-key.pem; do
	[ -f "$f" ] && chown _fwd:_fwd "$f"
done
chown -R _fwd:_fwd /var/db/fwd 2>/dev/null || true

# Log files must exist and be writable before the services start; daemon(8)
# appends as the target user and will not create them.
for lf in /var/log/fwd.log:_fwd /var/log/fwd-helper.log:root; do
	path=${lf%%:*}; owner=${lf##*:}
	[ -f "$path" ] || : > "$path"
	chown "$owner" "$path"
	chmod 0640 "$path"
done

# newsyslog so neither log grows without bound.
NEWSYSLOG=/etc/newsyslog.conf.d/luciola.conf
install -d -m 0755 /etc/newsyslog.conf.d
cat > $NEWSYSLOG <<'NEWSYSLOG'
# Luciola appliance logs.
/var/log/fwd.log		_fwd:_fwd	640  7	  1000	*	JC
/var/log/fwd-helper.log		root:wheel	640  7	  1000	*	JC
NEWSYSLOG

# fwd-helper is the privileged half (docs/security-plan.md §3). It is enabled
# whenever its binary is present; fwd only routes through it once fwd_args
# names the socket, so installing the helper is safe on its own and the two can
# be rolled out separately.
# fwd-helper is not optional any more: fwd has no in-process fallback, so a box
# with only the fwd binary serves pages and can change nothing
# (docs/security-plan.md §3.5 step 6).
if [ -x /usr/local/sbin/fwd-helper ]; then
	sysrc fwd_helper_enable=YES >/dev/null
	# The socket is root-owned, group _fwd, mode 0660 — so only fwd can reach
	# it — and the helper additionally takes the caller's uid from the kernel
	# and checks it. Two controls, because socket permissions alone are one
	# botched umask away from being none.
	sysrc fwd_helper_peer=_fwd >/dev/null
	sysrc fwd_helper_group=_fwd >/dev/null
	log "fwd-helper binary present; fwd_helper_enable=YES (peer=_fwd, socket group=_fwd)"
	HAVE_HELPER=1
else
	log "no /usr/local/sbin/fwd-helper yet — fwd will refuse to start without it"
	HAVE_HELPER=0
fi

if [ -x /usr/local/sbin/fwd ]; then
	sysrc fwd_enable=YES >/dev/null
	if [ "$HAVE_HELPER" = 1 ]; then
		# This is the drop. Both must be set together: fwd as _fwd with no
		# helper socket is a web daemon that cannot apply anything, and the
		# failure would look like a permissions bug rather than a missing
		# setting.
		sysrc fwd_runas=_fwd >/dev/null
		sysrc fwd_helper_socket=/var/run/fwd-helper.sock >/dev/null
		# The label socket moves out of the state directory (mode 0700) so the
		# classifier, which runs as a different account, can reach it. fwd owns
		# it, _fwdpcap is its group, and fwd refuses connections from anything
		# else.
		sysrc fwd_label_socket=/var/run/fwd/ndpi.sock >/dev/null
		sysrc fwd_label_peer=_fwdpcap >/dev/null
		log "fwd runs as _fwd; privileged operations go to fwd-helper"
	else
		# No helper: leave fwd disabled rather than configure a daemon whose
		# rc.d script will refuse to start. Saying so here beats a confusing
		# failure at the next boot.
		sysrc fwd_enable=NO >/dev/null
		log "fwd_enable=NO — deploy fwd-helper and re-run this script"
	fi
else
	log "no /usr/local/sbin/fwd yet — deploy the binary, then re-run this script"
fi

# --------------------------------------------------------- flow classifier
# ndpi-helper is its own service, not a child of fwd: fwd is unprivileged and
# cannot fork as another account, and a libnDPI process handling hostile frames
# should not inherit the web daemon's identity either (SEC-2a). It is built on
# the box (cgo), so it is frequently absent.
if [ -x /usr/local/sbin/ndpi-helper ]; then
	sysrc ndpi_helper_enable=YES >/dev/null
	sysrc ndpi_helper_user=_fwdpcap >/dev/null
	sysrc ndpi_helper_socket=/var/run/fwd/ndpi.sock >/dev/null
	# Capture devices are not guessed: capturing on the wrong interface is a
	# silent wrong answer. Seed from the NICs this box actually has.
	if [ -z "$(sysrc -n ndpi_helper_devices 2>/dev/null)" ]; then
		sysrc ndpi_helper_devices="$(printf '%s' "$nics" | tr '\n' ',' | sed 's/,$//')" >/dev/null
	fi
	log "ndpi-helper present; runs as _fwdpcap on: $(sysrc -n ndpi_helper_devices)"
else
	log "no /usr/local/sbin/ndpi-helper — app labels stay empty (os/build-ndpi-helper.sh)"
fi

cat <<'EOF'

==> provisioning done.

Next:
  1. Copy BOTH binaries to /usr/local/sbin (os/vm/deploy.sh cross-compiles them):
       fwd          the web daemon, runs as _fwd, holds no privilege
       fwd-helper   the privileged half; without it fwd cannot apply anything
     Then re-run this script so it sets fwd_runas and the helper socket.
  2. service fwd-helper start && service fwd start
  3. Browse to https://<lan-address>:8443 and create the admin account.
  4. Check the interface roles on the Interfaces page before the first Apply —
     which physical jack is which device depends on the board's lane wiring,
     so confirm with a cable rather than trusting the seed order.

Verify the privilege split took (docs/security-plan.md §3.5):
  ps -axo user,command | grep -E "fwd|ndpi" | grep -v grep
     -> fwd-helper is the ONLY root process from this project.
  ls -l /var/run/fwd-helper.sock     -> srw-rw---- root:_fwd
  ls -ld /conf /var/db/fwd           -> drwx------ _fwd:_fwd

The web terminal is off at the privileged layer regardless of the UI toggle.
To permit one, name the accounts it may run as — a deliberate console action,
which is the point:
  sysrc fwd_helper_shell_users=nobody && service fwd-helper restart

Apply enables and starts pf, kea, unbound, wireguard and the flow exporter
itself; nothing above pre-enables them.

Optional:
  Visibility power tier   pkg install redis ntopng
  Flow app labels         see os/build-ndpi-helper.sh (needs cgo on the box)
EOF
