package privsep

import (
	"go/build"
	"strings"
	"testing"
)

// The split is only real while the unprivileged binary cannot perform
// privileged work itself. An in-process fallback existed while the split was
// being brought up and was deleted in step 6 of docs/security-plan.md §3.5 —
// a fallback is a way for a misconfiguration to silently produce a root web
// daemon, which is the exact outcome the split exists to prevent.
//
// This asserts the property structurally, because "we removed it" is not a
// property: a future edit that reintroduces an apply.Manager into cmd/fwd, or
// an in-process PTY spawner, would compile and pass every other test.
func TestUnprivilegedBinaryCannotDoPrivilegedWork(t *testing.T) {
	// Packages that only make sense on the privileged side of the boundary.
	privileged := map[string]string{
		"firewall/ui/internal/apply":    "renders and installs config as root",
		"firewall/ui/internal/ptyspawn": "forks shells as other accounts",
		"firewall/ui/internal/wgstat":   "reads WireGuard state via a root-only ioctl",
	}

	pkg, err := build.ImportDir("../../cmd/fwd", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Imports) == 0 {
		t.Fatal("no imports resolved; the check would pass vacuously")
	}
	for _, imp := range pkg.Imports {
		if why, bad := privileged[imp]; bad {
			t.Errorf("cmd/fwd imports %s, which %s.\n"+
				"fwd holds no privilege: privileged work goes to fwd-helper over "+
				"internal/privsep. See docs/security-plan.md §3.5 step 6.", imp, why)
		}
	}
}

// This package is the boundary and the unprivileged client. It must not grow a
// privileged implementation, because anything here is linked into fwd.
func TestPrivsepHasNoPrivilegedImplementation(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Imports) == 0 {
		t.Fatal("no imports resolved; the check would pass vacuously")
	}
	for _, imp := range pkg.Imports {
		switch imp {
		case "firewall/ui/internal/apply", "firewall/ui/internal/wgstat":
			t.Errorf("internal/privsep imports %s; this package is linked into fwd, "+
				"so a privileged implementation here is a privileged implementation "+
				"in the unprivileged daemon", imp)
		}
	}
	// ptyspawn is permitted: only its Request and Session *types* cross the
	// boundary in signatures. Spawning is behind the Spawner interface, which
	// fwd never implements and fwd-helper supplies.
	if !contains(pkg.Imports, "firewall/ui/internal/ptyspawn") {
		t.Log("note: ptyspawn no longer imported; the type-only exception can go")
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// A stale doc reference is a real cost on a security boundary: it is how the
// reasoning gets lost. Cheap to check.
func TestBoundaryDocsMentionTheHelper(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pkg.Doc, "privileged") {
		t.Errorf("package doc no longer explains the boundary: %q", pkg.Doc)
	}
}
