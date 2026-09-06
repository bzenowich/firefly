package render

import "strings"

// shellQuote renders s as a single POSIX shell word, safe to interpolate into a
// generated rc.d script.
//
// The generated scripts (render.Network, render.Pflow) are installed mode 0755
// and executed by root at every apply and every boot, so a value interpolated
// into one is code, not data. config.validateShellSafe is the primary defense —
// it constrains those fields to grammars with no metacharacters in them — and
// this is the second, because the primary is one forgotten field away from
// failing and the cost of being wrong here is root (docs/security-plan.md
// SEC-1).
//
// Single quotes are the only shell quoting with no interior escapes at all:
// everything between them is literal. A single quote in the input therefore has
// to end the string, emit an escaped quote, and start a new one — the standard
// '\” dance.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
