// Package ptyspawn opens PTY-backed login shells for the web terminal.
//
// It is the privileged half of the shell feature: forking a shell as another
// account needs root, which is why this runs in fwd-helper and not in the web
// daemon (docs/security-plan.md §3.5 step 3). The caller receives only the PTY
// master file descriptor; the process, its credentials and its reaping stay
// here.
//
// # Who decides which account
//
// This is the load-bearing question of the whole step, and the answer is not
// "whoever asked".
//
// The account a terminal runs as used to come from config.Shell.User, and the
// config document is sent by fwd. If fwd-helper simply honoured a requested
// account, a compromised or buggy fwd would ask for root and get it — which
// would make the privilege split decorative, since one stolen session cookie
// or one bug in the HTTP layer would again be the whole box.
//
// So the permitted set lives here, in the privileged process, configured
// out-of-band by the operator (fwd-helper's -shell-user flag, set from
// fwd_helper_shell_users in rc.conf). The request names an account; this
// package decides whether it is allowed. fwd cannot widen it, and neither can
// anything fwd is tricked into sending — including a restored backup.
//
// The practical consequence is deliberate: a root web terminal now requires a
// console action on the appliance, not a checkbox in a browser.
package ptyspawn

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// Request is what the unprivileged side asks for. It names an account and a
// login shell; it cannot name arguments, an environment, or a working
// directory, all of which are decided here.
type Request struct {
	User  string `json:"user,omitempty"`
	Shell string `json:"shell,omitempty"`
	Cols  uint16 `json:"cols,omitempty"`
	Rows  uint16 `json:"rows,omitempty"`
}

// DefaultUser is the account a terminal runs as when the request names none.
// nobody exists on every FreeBSD install, so the default never fails to
// resolve, and it is unprivileged, so an unconfigured appliance cannot hand out
// anything dangerous.
const DefaultUser = "nobody"

// PermittedShells is the closed set of login shells that may be exec'd. It
// mirrors config's list; both exist because both boundaries are crossed
// independently — the config document on its way in, and the shell request
// here.
var PermittedShells = []string{
	"/bin/sh", "/bin/csh", "/bin/tcsh",
	"/usr/local/bin/bash", "/usr/local/bin/zsh", "/usr/local/bin/fish",
}

// Spawner opens shell sessions under a fixed policy.
type Spawner struct {
	// AllowedUsers is the set of accounts a terminal may run as. A nil slice
	// means "no allowlist": the request decides, which is the pre-split
	// behaviour used while fwd is still root and doing this in-process. Once
	// the spawn moves behind fwd-helper this is always set, and an empty
	// non-nil slice means the web terminal is refused outright.
	AllowedUsers []string

	// MaxSessions bounds concurrently live terminals. The unprivileged side
	// has its own cap, but this one is what actually bounds the number of
	// processes on the box, since a compromised fwd would simply not apply
	// its own. Zero means one.
	MaxSessions int

	mu   sync.Mutex
	live int
}

// Session is one running terminal. The caller takes PTY; everything else here
// belongs to the spawner.
type Session struct {
	// PTY is the master side. Whoever holds it drives the terminal; closing it
	// hangs up the shell.
	PTY *os.File
	// RunAs is the account the shell actually got, for the audit line.
	RunAs string
	// Pid is the shell's process id, which is also its process group id
	// (pty.Start sets Setsid).
	Pid int

	cmd     *exec.Cmd
	release func()
	once    sync.Once
}

// ErrShellNotPermitted is returned when policy refuses the request outright,
// as distinct from a request that is merely malformed.
var ErrShellNotPermitted = errors.New("the web terminal is not permitted on this appliance")

// Open starts a login shell on a new PTY and returns the master side.
func (s *Spawner) Open(req Request) (*Session, error) {
	name := strings.TrimSpace(req.User)
	if name == "" {
		name = DefaultUser
	}
	if err := s.permit(name); err != nil {
		return nil, err
	}

	shell := strings.TrimSpace(req.Shell)
	if shell == "" {
		shell = "/bin/sh"
	}
	if !slices.Contains(PermittedShells, shell) {
		return nil, fmt.Errorf("%q is not one of the permitted login shells (%s)",
			shell, strings.Join(PermittedShells, ", "))
	}

	if !s.acquire() {
		return nil, fmt.Errorf("too many terminal sessions (limit %d)", s.sessions())
	}

	cmd, runAs, err := buildCmd(shell, name)
	if err != nil {
		s.release()
		return nil, err
	}

	size := &pty.Winsize{Cols: req.Cols, Rows: req.Rows}
	if size.Cols == 0 || size.Rows == 0 {
		size = &pty.Winsize{Cols: 80, Rows: 24}
	}
	ptmx, err := pty.StartWithSize(cmd, size)
	if err != nil {
		s.release()
		return nil, err
	}

	sess := &Session{PTY: ptmx, RunAs: runAs, Pid: cmd.Process.Pid, cmd: cmd, release: s.release}
	return sess, nil
}

// permit applies the account policy.
func (s *Spawner) permit(name string) error {
	if s.AllowedUsers == nil {
		return nil // pre-split: the config document decides
	}
	if len(s.AllowedUsers) == 0 {
		return ErrShellNotPermitted
	}
	if !slices.Contains(s.AllowedUsers, name) {
		return fmt.Errorf("%w: %q is not among the accounts this appliance permits a terminal as (%s)",
			ErrShellNotPermitted, name, strings.Join(s.AllowedUsers, ", "))
	}
	return nil
}

func (s *Spawner) sessions() int {
	if s.MaxSessions <= 0 {
		return 1
	}
	return s.MaxSessions
}

func (s *Spawner) acquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live >= s.sessions() {
		return false
	}
	s.live++
	return true
}

func (s *Spawner) release() {
	s.mu.Lock()
	if s.live > 0 {
		s.live--
	}
	s.mu.Unlock()
}

// Wait reaps the shell and everything it spawned, returning its exit code. It
// is safe to call once; later calls return the same code.
//
// pty.Start sets Setsid, so the child leads its own process group and signalling
// the negated pid reaches everything it started — SIGHUP first, then SIGKILL for
// anything that ignored it. Without this a dropped browser leaves an orphan
// shell behind.
func (sess *Session) Wait() int {
	code := -1
	sess.once.Do(func() {
		code = exitCode(sess.cmd.Wait())
		if sess.cmd.Process != nil {
			_ = syscall.Kill(-sess.Pid, syscall.SIGHUP)
			time.AfterFunc(2*time.Second, func() { _ = syscall.Kill(-sess.Pid, syscall.SIGKILL) })
		}
		sess.PTY.Close()
		if sess.release != nil {
			sess.release()
		}
	})
	return code
}

// Hangup closes the master side, which sends SIGHUP to the session and makes
// Wait return. It is how the holder of the PTY ends a session.
func (sess *Session) Hangup() { sess.PTY.Close() }

// buildCmd constructs the login-shell command with a clean environment and
// returns it alongside the account it will run as.
//
// On the appliance this process is root, so it drops to the target account's
// credentials. On a non-root dev box credentials cannot be changed at all, so
// the terminal inherits ours — which is the same privilege the caller already
// had, and is why that case is not an error.
func buildCmd(shell, name string) (*exec.Cmd, string, error) {
	cmd := exec.Command(shell, "-l")
	env := []string{
		"TERM=xterm-256color",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}

	if os.Geteuid() != 0 {
		u, err := user.Current()
		if err != nil {
			return nil, "", err
		}
		return withEnv(cmd, env, u), u.Username, nil
	}

	u, err := user.Lookup(name)
	if err != nil {
		// Fail loudly. Falling back to the current user here would hand out
		// the root shell every other check exists to prevent.
		return nil, "", fmt.Errorf("account %q does not exist on this system", name)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, "", fmt.Errorf("account %q: unusable uid %q", name, u.Uid)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, "", fmt.Errorf("account %q: unusable gid %q", name, u.Gid)
	}
	// A Credential with no Groups also drops the supplementary groups this
	// process holds, which on the appliance include the bpf grant.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}
	return withEnv(cmd, env, u), u.Username, nil
}

// withEnv fills in the environment and working directory. Service accounts like
// nobody have a home directory that does not exist; chdir would fail and kill
// the session before it started, so fall back to /.
func withEnv(cmd *exec.Cmd, env []string, u *user.User) *exec.Cmd {
	home := u.HomeDir
	if st, err := os.Stat(home); err != nil || !st.IsDir() {
		home = "/"
	}
	cmd.Env = append(env, "USER="+u.Username, "HOME="+home)
	cmd.Dir = home
	return cmd
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
