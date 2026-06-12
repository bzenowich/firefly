#!/usr/bin/env python3
"""Drive the VM serial console over QEMU's unix-socket chardev.

Used by provision.sh for first-boot setup: the official FreeBSD VM images
allow passwordless root login on the console, and provisioning there avoids
any cloud-init/seed-image tooling on the host. Commands come from a script
file: lines are sent in order, waiting for the shell prompt between each.

First boot is slow and noisy: the image's firstboot rc script runs
freebsd-update before getty, so the login prompt can take many minutes.
"""

import socket
import sys
import time

SOCK = "console.sock"
LOGIN_TIMEOUT = 20 * 60


def main():
    script = open(sys.argv[1], "rb").read().splitlines()
    s = socket.socket(socket.AF_UNIX)
    deadline = time.time() + 30
    while True:
        try:
            s.connect(SOCK)
            break
        except (FileNotFoundError, ConnectionRefusedError):
            if time.time() > deadline:
                raise
            time.sleep(1)
    s.settimeout(2)

    buf = b""

    def expect(token, timeout):
        """Wait until token appears in console output since the last send."""
        nonlocal buf
        end = time.time() + timeout
        while time.time() < end:
            if token in buf:
                buf = b""
                return True
            try:
                data = s.recv(4096)
            except socket.timeout:
                continue
            if not data:
                raise EOFError("console closed")
            buf += data
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        return False

    def send(line):
        nonlocal buf
        buf = b""
        s.sendall(line + b"\r")

    # Poke until getty answers; quiet stretches during firstboot are normal.
    end = time.time() + LOGIN_TIMEOUT
    while True:
        send(b"")
        if expect(b"login: ", 10):
            break
        if time.time() > end:
            sys.exit("no login prompt")
    send(b"root")
    if not expect(b"# ", 30):
        sys.exit("no shell after root login")

    for line in script:
        if not line or line.startswith(b"#"):
            continue
        send(line)
        if line == b"poweroff":
            break  # no prompt comes back; provision.sh waits for QEMU exit
        if not expect(b"# ", 120):
            sys.exit(f"no prompt after: {line.decode()}")

    print("\nprovisioned")


if __name__ == "__main__":
    main()
