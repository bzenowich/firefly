// Package apply takes the rendered file set live: stage, validate, install
// atomically, reload services, and arm a confirm-or-rollback window so a bad
// firewall rule can't lock the admin out permanently (plan.md §7).
package apply

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// System abstracts the host so the pipeline is testable off-FreeBSD.
type System interface {
	// ReadFile returns fs.ErrNotExist for absent files.
	ReadFile(path string) ([]byte, error)
	// WriteFile installs content atomically (temp + rename), creating
	// parent directories as needed.
	WriteFile(path string, data []byte, mode fs.FileMode) error
	Remove(path string) error
	Glob(pattern string) ([]string, error)
	// Run executes a command and returns an error on non-zero exit,
	// with stderr included in the message.
	Run(name string, args ...string) error
}

// OSSystem is the real host. Root prefixes all paths ("" = real root) and
// NoExec logs commands instead of running them — together they make a dev
// box render into ./devroot without touching the system or needing pfctl.
type OSSystem struct {
	Root   string
	NoExec bool
}

func (s OSSystem) abs(path string) string {
	if s.Root == "" {
		return path
	}
	return filepath.Join(s.Root, path)
}

func (s OSSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(s.abs(path))
}

func (s OSSystem) WriteFile(path string, data []byte, mode fs.FileMode) error {
	path = s.abs(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".apply-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s OSSystem) Remove(path string) error {
	return os.Remove(s.abs(path))
}

func (s OSSystem) Glob(pattern string) ([]string, error) {
	matches, err := filepath.Glob(s.abs(pattern))
	if err != nil || s.Root == "" {
		return matches, err
	}
	// Strip the root prefix so callers always see appliance paths.
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if rel, err := filepath.Rel(s.Root, m); err == nil {
			out = append(out, "/"+rel)
		}
	}
	return out, nil
}

func (s OSSystem) Run(name string, args ...string) error {
	if s.NoExec {
		log.Printf("apply (noexec): %s %s", name, strings.Join(args, " "))
		return nil
	}
	// Hard ceiling on any single command; a wedged rc script must not pin
	// the apply mutex (and with it every page render) forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	// rc scripts hand our output pipe to the daemons they start (kea,
	// unbound); without WaitDelay, Wait blocks on that inherited fd until
	// the daemon exits — the live-lock found in VM testing.
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	// ErrWaitDelay means the command itself exited 0 and only the inherited
	// pipe stayed open — success for our purposes.
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		return &CmdError{Cmd: name + " " + strings.Join(args, " "), Output: out.String(), Err: err}
	}
	return nil
}

// CmdError carries command output so validation failures (pfctl -nf etc.)
// surface their actual diagnostics to the UI.
type CmdError struct {
	Cmd    string
	Output string
	Err    error
}

func (e *CmdError) Error() string {
	msg := e.Cmd + ": " + e.Err.Error()
	if o := strings.TrimSpace(e.Output); o != "" {
		msg += ": " + o
	}
	return msg
}

func (e *CmdError) Unwrap() error { return e.Err }
