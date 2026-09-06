// Command fwd-helper is the privileged half of the appliance daemon.
//
// It owns everything that needs root — writing /etc and /usr/local/etc,
// running pfctl and service(8), and the confirm-or-rollback window — and
// exposes exactly four operations over a unix socket to the unprivileged fwd
// process (internal/privsep). fwd itself holds no privilege and can name no
// path, no file content and no command: the only thing that crosses the socket
// is a config document, which this side re-validates before acting on it.
//
// See docs/security-plan.md §3 for why the boundary is drawn there and not at
// the file-and-argv level.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"firewall/ui/internal/apply"
	"firewall/ui/internal/privsep"
	"firewall/ui/internal/ptyspawn"
	"firewall/ui/internal/render"
	"firewall/ui/internal/wgstat"
)

// DefaultSocket is where fwd looks for the helper. /var/run is root-owned, so
// only root can create the socket there — which is what makes fwd's
// owner check on the far end meaningful.
const DefaultSocket = "/var/run/fwd-helper.sock"

func main() {
	socket := flag.String("socket", DefaultSocket, "unix socket to listen on")
	peerUsers := flag.String("peer-user", "", "comma-separated accounts allowed to connect (root is always allowed)")
	socketGroup := flag.String("socket-group", "", "group to own the socket; with it the mode is 0660, without it 0600")
	window := flag.Duration("confirm-window", time.Minute, "auto-rollback window after apply (0 = no confirmation step)")
	shellUsers := flag.String("shell-user", "", "accounts a web terminal may run as (comma-separated); empty disables the web terminal entirely")
	shellSessions := flag.Int("shell-sessions", 1, "maximum concurrent web terminals")
	root := flag.String("root", "", "prefix every managed path with this directory (development)")
	noexec := flag.Bool("noexec", false, "log service commands instead of running them (development)")
	flag.Parse()

	log.SetPrefix("fwd-helper: ")

	if err := os.Setenv("PATH", appliancePath); err != nil {
		log.Fatalf("setting PATH: %v", err)
	}

	// Refuse to pretend. In appliance mode this process is the only thing on
	// the box that can write /etc/pf.conf; if it is not root it cannot do its
	// job, and starting anyway would mean fwd's applies fail with confusing
	// per-file permission errors instead of one clear message here.
	devMode := *root != "" || *noexec
	if !devMode && os.Geteuid() != 0 {
		log.Fatalf("must run as root (or pass -root/-noexec for development)")
	}
	if devMode {
		log.Printf("development mode: root=%q noexec=%v", *root, *noexec)
	}

	allow, err := resolveUIDs(*peerUsers)
	if err != nil {
		log.Fatalf("peer-user: %v", err)
	}
	gid, mode, err := resolveSocketOwner(*socketGroup)
	if err != nil {
		log.Fatalf("socket-group: %v", err)
	}

	mgr := apply.New(apply.OSSystem{Root: *root, NoExec: *noexec}, *window)
	svc := privsep.NewService(mgr, allow)

	// Live WireGuard peer state: a root-only ioctl, so the web daemon asks for
	// it rather than running wg(8) itself. The interface name is a constant
	// here, not something the caller names.
	svc.WithWG(wgPeers{})

	// The web terminal is opt-in *here*, not in the config document. fwd names
	// an account when it asks; this list decides whether it gets one, and fwd
	// cannot widen it — which is what stops a compromised web daemon from
	// asking for root and getting it (internal/ptyspawn). The practical
	// consequence is deliberate: a root web terminal takes a console action.
	if users := splitList(*shellUsers); len(users) > 0 {
		svc.WithShell(&ptyspawn.Spawner{
			AllowedUsers: users,
			MaxSessions:  *shellSessions,
		})
		log.Printf("web terminal permitted as: %s (max %d concurrent)",
			strings.Join(users, ", "), *shellSessions)
	} else {
		log.Printf("web terminal disabled (no -shell-user given)")
	}

	ln, err := svc.Listen(*socket, mode, gid)
	if err != nil {
		log.Fatalf("listen on %s: %v", *socket, err)
	}
	defer os.Remove(*socket)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("listening on %s (mode %04o, uid %d, %s)", *socket, mode, os.Geteuid(), describeAllowed(allow))
	if err := svc.Serve(ctx, ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
	log.Printf("shutting down")
}

// splitList parses a comma-separated flag value, dropping empties.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// resolveUIDs turns a comma-separated account list into uids. An account that
// does not exist is fatal rather than skipped: silently allowing fewer peers
// than intended shows up later as an unexplained refusal.
func resolveUIDs(list string) ([]uint32, error) {
	var out []uint32
	for _, name := range splitList(list) {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, err
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, err
		}
		out = append(out, uint32(uid))
	}
	return out, nil
}

// resolveSocketOwner picks the socket's group and mode. Without a group the
// socket is root-only (0600), which is correct while fwd still runs as root;
// the group grant is what opens it to the _fwd account at step 4 of
// docs/security-plan.md §3.5.
func resolveSocketOwner(group string) (gid int, mode os.FileMode, err error) {
	if strings.TrimSpace(group) == "" {
		return -1, 0o600, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, 0, err
	}
	id, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, err
	}
	return id, 0o660, nil
}

func describeAllowed(uids []uint32) string {
	if len(uids) == 0 {
		return "peers: root only"
	}
	parts := make([]string, 0, len(uids))
	for _, u := range uids {
		parts = append(parts, strconv.FormatUint(uint64(u), 10))
	}
	return "peers: root, uid " + strings.Join(parts, ", ")
}

// appliancePath is the PATH this daemon runs external commands with.
//
// rc.d starts services through daemon(8), which passes on the boot environment:
// PATH=/sbin:/bin:/usr/sbin:/usr/bin. Every package-installed tool the appliance
// depends on lives outside that — kea-dhcp4 and unbound-checkconf in
// /usr/local/sbin, wg in /usr/local/bin — so with the inherited PATH the very
// first apply fails at the kea validator with "executable file not found", and
// the WireGuard page silently reports no handshakes.
//
// It is set here, once, rather than at each exec site, so a command added later
// cannot miss it. Found on the VM: it does not reproduce when the daemon is
// started by hand from a login shell, which is how it stayed hidden.
const appliancePath = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"

// wgPeers is this process's implementation of the WireGuard read. It lives here
// rather than in internal/privsep because that package holds the boundary and
// the unprivileged client only — no privileged implementations, so there is
// nothing in it that fwd could accidentally be wired to
// (docs/security-plan.md §3.5 step 6).
type wgPeers struct{}

func (wgPeers) WGPeers() (map[string]time.Time, error) {
	return wgstat.Peers(render.WGServerDevice)
}
