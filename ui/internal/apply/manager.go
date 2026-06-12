package apply

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sync"
	"time"

	"firewall/ui/internal/config"
)

// Manager owns the apply lifecycle. One apply may be pending at a time;
// until it is confirmed, the previous files are kept and restored if the
// window expires — the remote-firewall lock-out guard.
type Manager struct {
	sys    System
	window time.Duration // 0 = auto-confirm immediately

	mu      sync.Mutex
	pending *pending
}

type pending struct {
	// backups holds pre-apply content per path; nil content = file was
	// absent and rollback removes it.
	backups  map[string][]byte
	reloads  [][]string
	timer    *time.Timer
	deadline time.Time
}

func New(sys System, window time.Duration) *Manager {
	return &Manager{sys: sys, window: window}
}

// Pending reports the rollback deadline of an unconfirmed apply.
func (m *Manager) Pending() (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return time.Time{}, false
	}
	return m.pending.deadline, true
}

// Apply stages and validates the rendered files, installs them, reloads the
// affected services, and arms the rollback timer. Nothing is installed if
// any validator rejects its staged file.
func (m *Manager) Apply(cfg config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != nil {
		return errors.New("an apply is already pending: confirm or roll back first")
	}

	files, err := plan(cfg)
	if err != nil {
		return err
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
	p := &pending{backups: map[string][]byte{}}
	seen := map[string]bool{}
	addReload := func(cmd []string) {
		key := fmt.Sprint(cmd)
		if !seen[key] {
			seen[key] = true
			p.reloads = append(p.reloads, cmd)
		}
	}
	managed := map[string]bool{}
	for _, f := range files {
		managed[f.path] = true
		old, err := m.sys.ReadFile(f.path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			old = nil
		case err != nil:
			return err
		}
		if string(old) == f.content {
			continue
		}
		p.backups[f.path] = old
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
				p.backups[s] = old
				m.sys.Remove(s)
				addReload([]string{"service", "wireguard", "restart"})
			}
		}
	}

	if len(p.backups) == 0 {
		return errors.New("no changes to apply")
	}

	if err := m.runReloads(p.reloads); err != nil {
		m.restore(p)
		m.runReloads(p.reloads) // best effort: bring old config back up
		return fmt.Errorf("reload failed, rolled back: %w", err)
	}

	if m.window == 0 {
		return nil // auto-confirm
	}
	p.deadline = time.Now().Add(m.window)
	p.timer = time.AfterFunc(m.window, func() { m.Rollback() })
	m.pending = p
	return nil
}

// Confirm keeps the applied configuration and disarms the rollback timer.
func (m *Manager) Confirm() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return errors.New("nothing to confirm")
	}
	m.pending.timer.Stop()
	m.pending = nil
	return nil
}

// Rollback restores the pre-apply files and reloads. Called manually or by
// the window timer.
func (m *Manager) Rollback() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return errors.New("nothing to roll back")
	}
	p := m.pending
	p.timer.Stop()
	m.pending = nil
	m.restore(p)
	return m.runReloads(p.reloads)
}

func (m *Manager) restore(p *pending) {
	for path, old := range p.backups {
		if old == nil {
			m.sys.Remove(path)
			continue
		}
		// Mode detail is lost in backup; 0600 is safe for every managed
		// file and right for the wireguard ones.
		m.sys.WriteFile(path, old, 0o600)
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
