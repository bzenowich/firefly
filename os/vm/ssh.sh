#!/bin/sh
# SSH into the test VM. Extra args pass through: ./ssh.sh uname -a
cd "$(dirname "$0")"
. ./vmkey.sh
exec ssh -p 2222 -o StrictHostKeyChecking=accept-new \
	-o UserKnownHostsFile="$PWD/known_hosts" -i "$VM_KEY" \
	-o IdentitiesOnly=yes root@127.0.0.1 "$@"
