#!/bin/sh -e
# Cross-compile fwd for FreeBSD and push it to the running test VM.
#
# fwd and fwd-helper: both pure Go (modernc sqlite, no cgo), so they
# cross-compile from any host. They are deployed together on purpose — fwd
# running as _fwd with no helper cannot apply anything, and its rc.d script
# refuses to start in that state (docs/security-plan.md §3.5).
#
# ndpi-helper links libpcap and libnDPI through cgo and has to be built on the
# target — see os/build-ndpi-helper.sh. Without it the app column in the Flows
# view stays empty.
cd "$(dirname "$0")"

. ./vmkey.sh
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$PWD/known_hosts -i $VM_KEY -o IdentitiesOnly=yes"

for bin in fwd fwd-helper; do
	# $$ in the staging name: two concurrent deploys otherwise race over one
	# fixed filename and one deletes the other's binary mid-copy.
	local_bin="$bin-freebsd.$$"
	(cd ../../ui && GOOS=freebsd GOARCH=amd64 go build -o "../os/vm/$local_bin" "./cmd/$bin")
	# Copy to a staging path and rename into place. Writing the destination
	# directly fails with ETXTBSY whenever the service is running, which is the
	# normal case when redeploying; rename(2) over a busy executable is allowed
	# and leaves the running process on the old inode until it restarts.
	# shellcheck disable=SC2086
	scp -P 2222 $SSH_OPTS "$local_bin" "root@127.0.0.1:/usr/local/sbin/.$bin.new"
	rm "$local_bin"
	# shellcheck disable=SC2086
	ssh -p 2222 $SSH_OPTS root@127.0.0.1 \
		"chmod 0755 /usr/local/sbin/.$bin.new && mv /usr/local/sbin/.$bin.new /usr/local/sbin/$bin"
done

# The rc.d scripts and provisioning are what wire the privilege split together.
# shellcheck disable=SC2086
scp -P 2222 $SSH_OPTS ../rc.d/fwd ../rc.d/fwd-helper ../rc.d/ndpi-helper \
	root@127.0.0.1:/usr/local/etc/rc.d/
# shellcheck disable=SC2086
scp -P 2222 $SSH_OPTS ../provision-appliance.sh root@127.0.0.1:/root/
# shellcheck disable=SC2086
ssh -p 2222 $SSH_OPTS root@127.0.0.1 'chmod 0755 /usr/local/etc/rc.d/fwd /usr/local/etc/rc.d/fwd-helper /usr/local/etc/rc.d/ndpi-helper'

echo "deployed fwd + fwd-helper to /usr/local/sbin, rc.d scripts to /usr/local/etc/rc.d"
echo "  apply the privilege split: ./ssh.sh 'NO_PKG=1 sh /root/provision-appliance.sh'"
echo "  then:                      ./ssh.sh 'service fwd-helper start && service fwd start'"
