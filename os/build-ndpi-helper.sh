#!/bin/sh -e
#
# Build ndpi-helper on a FreeBSD target and install it there.
#
#   ./os/build-ndpi-helper.sh                    # the QEMU test VM
#   ./os/build-ndpi-helper.sh root@10.0.0.1      # a real appliance
#
# Why this is not part of deploy.sh: fwd is pure Go and cross-compiles from
# any host with GOOS=freebsd, but ndpi-helper links libpcap and libnDPI
# through cgo, and cross-compiling cgo needs a FreeBSD sysroot and a
# cross-clang that we deliberately do not carry. Building on the target is
# simpler and matches what the appliance image build will do.
#
# Without this binary the flow pipeline still works — pflow(4) to the
# collector to the Flows UI is all pure Go — but every flow's app column stays
# empty, because fwd's supervisor fails its PATH lookup and disables app
# labels with a single log line.

DEST=${1:-}
SRC=$(cd "$(dirname "$0")/../ui" && pwd)

if [ -z "$DEST" ]; then
	# Default to the test VM's ssh settings (see os/vm/ssh.sh).
	VMDIR=$(cd "$(dirname "$0")/vm" && pwd)
	SSH="ssh -p 2222 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$VMDIR/known_hosts root@127.0.0.1"
	SCP="scp -P 2222 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$VMDIR/known_hosts"
	TARGET=root@127.0.0.1
else
	SSH="ssh $DEST"
	SCP="scp"
	TARGET=$DEST
fi

echo "==> installing build dependencies on $TARGET"
# go: the compiler, on the target because of cgo.
# ndpi: libnDPI. The FreeBSD port tracks a 5.x snapshot; classifier_ndpi.go is
#   written against the nDPI 5.0 C API, which breaks across major versions —
#   if this build fails on unknown symbols, check the installed version first.
# libpcap is in the base system.
$SSH 'pkg install -y go ndpi'

echo "==> copying the ui source tree"
$SSH 'rm -rf /root/build-ui && mkdir -p /root/build-ui'
tar -C "$SRC" -cf - \
	--exclude .git --exclude ndpi-helper --exclude fwd-freebsd \
	. | $SSH 'tar -C /root/build-ui -xf -'

echo "==> building ndpi-helper with -tags \"pcap ndpi\""
# CGO_ENABLED=1 is the default on a native build, but the tags are what select
# source_pcap.go and classifier_ndpi.go over their no-op stubs — without them
# this silently produces a helper that captures nothing.
$SSH 'cd /root/build-ui && CGO_ENABLED=1 go build -tags "pcap ndpi" -o /usr/local/sbin/ndpi-helper ./cmd/ndpi-helper'

echo "==> verifying"
$SSH '/usr/local/sbin/ndpi-helper -version 2>/dev/null || ldd /usr/local/sbin/ndpi-helper | head -5'

cat <<'EOF'

==> ndpi-helper installed to /usr/local/sbin/ndpi-helper

fwd supervises it and finds it on PATH, so restart fwd to pick it up:
    service fwd restart      (or restart the process you started by hand)

Then confirm the app column fills in on the Flows view. If it stays empty,
check fwd's log for the supervisor's LookPath line.
EOF
