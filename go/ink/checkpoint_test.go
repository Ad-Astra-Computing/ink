package ink

import (
	"strings"
	"testing"
)

const cpTestRoot = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func TestParseCheckpointAccepts(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		origin    string
		treeSize  int64
		rootHash  string
		canonical string
	}{
		{"valid", "example.com/ink-log\n5\n" + cpTestRoot + "\n", "example.com/ink-log", 5, cpTestRoot, "example.com/ink-log\n5\n" + cpTestRoot + "\n"},
		{"tree-size-zero", "log\n0\n" + cpTestRoot + "\n", "log", 0, cpTestRoot, "log\n0\n" + cpTestRoot + "\n"},
		{"max-safe-integer", "log\n9007199254740991\n" + cpTestRoot + "\n", "log", 9007199254740991, cpTestRoot, "log\n9007199254740991\n" + cpTestRoot + "\n"},
		{"leading-zero-normalizes", "log\n05\n" + cpTestRoot + "\n", "log", 5, cpTestRoot, "log\n5\n" + cpTestRoot + "\n"},
		{"utf16-boundary-origin", strings.Repeat("é", 256) + "\n5\n" + cpTestRoot + "\n", strings.Repeat("é", 256), 5, cpTestRoot, strings.Repeat("é", 256) + "\n5\n" + cpTestRoot + "\n"},
	}
	for _, c := range cases {
		parsed, ok := ParseCheckpoint(c.body)
		if !ok {
			t.Errorf("%s: expected accept, got reject", c.name)
			continue
		}
		if parsed.Origin != c.origin || parsed.TreeSize != c.treeSize || parsed.RootHash != c.rootHash {
			t.Errorf("%s: parsed = %+v", c.name, parsed)
		}
		if got := FormatCheckpoint(parsed); got != c.canonical {
			t.Errorf("%s: canonical = %q, want %q", c.name, got, c.canonical)
		}
	}
}

func TestParseCheckpointRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"missing-trailing-newline", "log\n5\n" + cpTestRoot},
		{"extra-trailing-line", "log\n5\n" + cpTestRoot + "\n\n"},
		{"trailing-junk", "log\n5\n" + cpTestRoot + "\nx"},
		{"empty-origin", "\n5\n" + cpTestRoot + "\n"},
		{"non-numeric-tree-size", "log\nabc\n" + cpTestRoot + "\n"},
		{"negative-tree-size", "log\n-5\n" + cpTestRoot + "\n"},
		{"leading-plus-tree-size", "log\n+5\n" + cpTestRoot + "\n"},
		{"tree-size-above-safe-integer", "log\n9007199254740992\n" + cpTestRoot + "\n"},
		{"uppercase-root-hash", "log\n5\n" + strings.ToUpper(cpTestRoot) + "\n"},
		{"short-root-hash", "log\n5\n" + cpTestRoot[:63] + "\n"},
		{"long-root-hash", "log\n5\n" + cpTestRoot + "a\n"},
		{"non-hex-root-hash", "log\n5\n" + strings.Repeat("z", 64) + "\n"},
		{"trailing-cr-root-hash", "log\n5\n" + cpTestRoot + "\r\n"},
		{"oversized-body", strings.Repeat("a", 1025)},
		{"origin-line-too-long", strings.Repeat("a", 257) + "\n5\n" + cpTestRoot + "\n"},
		{"astral-origin-over-utf16-cap", strings.Repeat("\U0001D400", 200) + "\n5\n" + cpTestRoot + "\n"},
	}
	for _, c := range cases {
		if _, ok := ParseCheckpoint(c.body); ok {
			t.Errorf("%s: expected reject, got accept", c.name)
		}
	}
}
