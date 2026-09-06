package apply

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path"
	"strings"
	"sync"
	"time"

	"firewall/ui/internal/config"
	"firewall/ui/internal/privsep"
)

// Manager owns the apply lifecycle. One apply may be pending at a time;
// until it is confirmed, the previous files are kept and restored if the
// window expires — the remote-firewall lock-out guard.
type Manager struct {
	sys    System
	window time.Duration // 0 = auto-confirm immediately

	// applyMu serializes the apply lifecycle. It is held for the whole of an
	// apply, which includes service reloads that can take minutes.
	applyMu sync.Mutex

	// stateMu guards pending alone, so Pending() — which every page render
	// calls — never waits behind a running apply. That mattered: the confirm
	// button lives on a page that could not render while the apply it was
	// meant to confirm was still reloading. Lock order is applyMu then
	// stateMu, never the reverse.
	stateMu sync.Mutex
	pending *pending
}

// backup is the pre-apply state of one managed file.
type backup struct {
	content []byte
	// existed distinguishes "was empty" from "was absent"; rollback removes
	// a file that was not there before.
	existed bool
	// mode is the mode the file is managed with, carried so a restore does
	// not silently change it. Restoring everything as 0600 used to strip the
	// executable bit from the generated rc.d scripts, which then failed to
	// start and never healed — the next apply compares content, not mode.
	mode fs.FileMode
}

type pending struct {
	backups  map[string]backup
	reloads  [][]string
	timer    *time.Timer
	deadline time.Time
}

// Manager is the in-process implementation of the privileged boundary, used
// while fwd still runs as root. When the split lands (docs/security-plan.md
// §3.5) this package moves into fwd-helper and a socket client takes its place
// on the fwd side; the assertion is here so that the day one of the four
// methods changes shape, both sides fail to compile together.
var _ privsep.Ops = (*Manager)(nil)

func New(sys System, window time.Duration) *Manager {
	return &Manager{sys: sys, window: window}
}

// Pending reports the rollback deadline of an unconfirmed apply.
func (m *Manager) Pending() (time.Time, bool) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.pending == nil {
		return time.Time{}, false
	}
	return m.pending.deadline, true
}

// Apply stages and validates the rendered files, installs them, reloads the
// affected services, and arms the rollback timer. Nothing is installed if
// any validator rejects its staged file.
func (m *Manager) Apply(cfg config.Config) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if _, ok := m.Pending(); ok {
		return errors.New("an apply is already pending: confirm or roll back first")
	}

	// Never render a document that has not passed validation. The store
	// validates on every write, but a hand-edited or restored-by-hand
	// fw.json reaches here unchecked, and the renderers assume invariants
	// (exactly one wan and lan, resolvable service references) that it may
	// not hold.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("refusing to apply an invalid configuration: %w", err)
	}

	files, err := plan(cfg)
	if err != nil {
		return err
	}

	// Create any referenced-but-not-rendered file before validating. Never
	// truncate: the real content belongs to whatever job produces it.
	for _, p := range prerequisites(cfg) {
		if _, err := m.sys.ReadFile(p); errors.Is(err, fs.ErrNotExist) {
			if err := m.sys.WriteFile(p, nil, 0o644); err != nil {
				return fmt.Errorf("creating %s: %w", p, err)
			}
		}
	}

	// Stage and validate everything before touching any live file.
	for _, f := range files {
		if f.check == nil {
			continue
		}
		staged := f.path + ".staged"
		if err := m.sys.WriteFile(staged, []byte(f.content), f.mode); err != nil {
			return err
		}
		err := m.sys.Run(f.check(staged)[0], f.check(staged)[1:]...)
		m.sys.Remove(staged)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	// Back up and install, collecting reloads for changed files only.
	p := &pending{backups: map[string]backup{}}
	seen := map[string]bool{}
	addReload := func(cmd []string) {
		key := fmt.Sprint(cmd)
		if !seen[key] {
			seen[key] = true
			p.reloads = append(p.reloads, cmd)
		}
	}
	managed := map[string]bool{}
	var wgReload []string
	for _, f := range files {
		managed[f.path] = true
		if path.Dir(f.path) == WGConfDir {
			wgReload = f.reload
		}
		old, err := m.sys.ReadFile(f.path)
		existed := true
		switch {
		case errors.Is(err, fs.ErrNotExist):
			old, existed = nil, false
		case err != nil:
			return err
		}
		if existed && string(old) == f.content {
			continue
		}
		p.backups[f.path] = backup{content: old, existed: existed, mode: f.mode}
		if err := m.sys.WriteFile(f.path, []byte(f.content), f.mode); err != nil {
			m.restore(p) // best effort
			return err
		}
		addReload(f.reload)
	}

	// Tunnels removed from config leave stale wg files behind; they are
	// part of the managed set, so remove (and back up for rollback).
	stale, err := m.sys.Glob(path.Join(WGConfDir, "*.conf"))
	if err == nil {
		for _, s := range stale {
			if managed[s] {
				continue
			}
			if old, err := m.sys.ReadFile(s); err == nil {
				p.backups[s] = backup{content: old, existed: true, mode: 0o600}
				m.sys.Remove(s)
				// Use the same reload the managed tunnel files carry so the
				// two dedupe to one restart. When the last tunnel is deleted
				// there are no managed files left to borrow it from, so fall
				// back to the empty-set form, which clears
				// wireguard_interfaces and stops the service.
				if wgReload != nil {
					addReload(wgReload)
				} else {
					addReload(wireguardReload(nil))
				}
			}
		}
	}

	if len(p.backups) == 0 {
		return errors.New("no changes to apply")
	}

	if err := m.runReloads(p.reloads); err != nil {
		m.restore(p)
		m.runReloadsBestEffort(p.reloads) // bring the old config back up
		return fmt.Errorf("reload failed, rolled back: %w", err)
	}

	if m.window == 0 {
		return nil // auto-confirm
	}
	p.deadline = time.Now().Add(m.window)
	p.timer = time.AfterFunc(m.window, func() {
		// This is the lock-out guard firing: nobody is watching a return
		// value, so a failure here has to reach the log or it is invisible.
		if err := m.Rollback(); err != nil {
			log.Printf("apply: automatic rollback after the confirm window failed: %v", err)
		}
	})
	m.stateMu.Lock()
	m.pending = p
	m.stateMu.Unlock()
	return nil
}

// take removes and returns the pending apply, or nil when there is none.
func (m *Manager) take() *pending {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	p := m.pending
	m.pending = nil
	return p
}

// Confirm keeps the applied configuration and disarms the rollback timer.
func (m *Manager) Confirm() error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	p := m.take()
	if p == nil {
		return errors.New("nothing to confirm")
	}
	p.timer.Stop()
	return nil
}

// Rollback restores the pre-apply files and reloads. Called manually or by
// the window timer.
func (m *Manager) Rollback() error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	p := m.take()
	if p == nil {
		return errors.New("nothing to roll back")
	}
	p.timer.Stop()
	m.restore(p)
	return m.runReloadsBestEffort(p.reloads)
}

// restore puts the pre-apply files back, each with the mode it is managed
// with. Failures are logged and do not stop the remaining files: a rollback
// that gives up halfway leaves the box in a state that is neither the old
// config nor the new one.
func (m *Manager) restore(p *pending) {
	for path, b := range p.backups {
		if !b.existed {
			if err := m.sys.Remove(path); err != nil {
				log.Printf("apply: rollback could not remove %s: %v", path, err)
			}
			continue
		}
		if err := m.sys.WriteFile(path, b.content, b.mode); err != nil {
			log.Printf("apply: rollback could not restore %s: %v", path, err)
		}
	}
}

func (m *Manager) runReloads(reloads [][]string) error {
	for _, cmd := range reloads {
		if err := m.sys.Run(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// runReloadsBestEffort runs every reload, continuing past failures, and
// returns the first error.
//
// Rollback must not stop at the first failure. A first apply on a stock box
// backs up files that did not exist, so rollback deletes them — and then
// `pfctl -f /etc/pf.conf` on the file it just removed fails, which used to
// abort the loop and leave unbound and wireguard still running the config
// that was being rolled back.
func (m *Manager) runReloadsBestEffort(reloads [][]string) error {
	var first error
	for _, cmd := range reloads {
		if err := m.sys.Run(cmd[0], cmd[1:]...); err != nil {
			log.Printf("apply: reload %q failed during rollback: %v", strings.Join(cmd, " "), err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}
