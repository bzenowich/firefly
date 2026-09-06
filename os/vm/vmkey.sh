# Shared SSH identity for the test VM, sourced by provision.sh and ssh.sh.
#
# Prefers the developer's own key when there is one, and otherwise generates a
# VM-local one. That keeps the tooling self-contained — a fresh checkout on a
# machine with no ~/.ssh (a container, a CI runner) can still bring the VM up —
# without silently creating keys in someone's personal ~/.ssh.
VM_KEY="$PWD/id_ed25519"
if [ -f "$HOME/.ssh/id_ed25519" ] && [ -f "$HOME/.ssh/id_ed25519.pub" ]; then
	VM_KEY="$HOME/.ssh/id_ed25519"
elif [ ! -f "$VM_KEY" ]; then
	echo "note: no ~/.ssh/id_ed25519 — generating a VM-local key at $VM_KEY" >&2
	ssh-keygen -t ed25519 -N '' -C 'luciola-vm' -f "$VM_KEY" >/dev/null
fi
VM_PUBKEY="${VM_KEY}.pub"
