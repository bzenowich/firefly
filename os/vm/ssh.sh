#!/bin/sh
# SSH into the test VM. Extra args pass through: ./ssh.sh uname -a
cd "$(dirname "$0")"
exec ssh -p 2222 -o StrictHostKeyChecking=accept-new \
	-o UserKnownHostsFile="$PWD/known_hosts" root@127.0.0.1 "$@"
