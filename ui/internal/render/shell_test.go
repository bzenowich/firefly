package render

import "testing"

func TestShellQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{"igc0", "'igc0'"},
		{"", "''"},
		{"igc0; touch /tmp/pwned", "'igc0; touch /tmp/pwned'"},
		{"a'b", `'a'\''b'`},
		{"$(id)", "'$(id)'"},
		{"`id`", "'`id`'"},
	}
	for _, tt := range tests {
		if got := shellQuote(tt.in); got != tt.want {
			t.Errorf("shellQuote(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}
