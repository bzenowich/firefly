#!/bin/sh -e
# Cross-compile fwd for FreeBSD and push it to the running test VM.
cd "$(dirname "$0")"

(cd ../../ui && GOOS=freebsd GOARCH=amd64 go build -o ../os/vm/fwd-freebsd ./cmd/fwd)
scp -P 2222 -o StrictHostKeyChecking=accept-new \
	-o UserKnownHostsFile="$PWD/known_hosts" fwd-freebsd root@127.0.0.1:/root/fwd
rm fwd-freebsd
echo "deployed: ./ssh.sh '/root/fwd -listen 0.0.0.0:8443 -config /root/fw.json'"
