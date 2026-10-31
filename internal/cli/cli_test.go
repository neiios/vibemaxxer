package cli

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestFlagPolicy(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(rules, []byte("block example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("allow example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"nope"},
		{"client"},
		{"client", "-rules", filepath.Join(dir, "missing")},
		{"client", "-rules", bad},
		{"client", "-rules", rules, "-listen", "0.0.0.0:8080"},
		{"client", "-rules", rules, "-listen", "127.0.0.1:0"},
		{"client", "-rules", rules, "-upstream", "192.0.2.1:18080"},
		{"client", "-rules", rules, "extra"},
		{"server", "-rules", rules},
		{"server", "-rules", rules, "-upstream", "127.0.0.1:18080"},
		{"server", "-rules", rules, "-listen", "[::]:8081"},
	} {
		if err := Run(logger, args); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}
