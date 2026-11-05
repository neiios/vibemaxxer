package cli

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestClientWithoutUpstream(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)
	rules := filepath.Join(t.TempDir(), "client.rules")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, upstream := range [][]string{nil, {"--upstream", ""}, {"--upstream", "127.0.0.1:18080"}} {
		if err := os.WriteFile(rules, []byte("block .ads.example\n"), 0600); err != nil {
			t.Fatal(err)
		}
		args := append([]string{"client", "--rules", rules, "--listen", listener.Addr().String()}, upstream...)
		if err := Run(logger, args); !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("%v: want listener error after valid configuration, got %v", args, err)
		}
	}
	if err := os.WriteFile(rules, []byte("proxy .remote.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err = Run(logger, []string{"client", "--rules", rules})
	if err == nil || !strings.Contains(err.Error(), "proxy rules require --upstream") {
		t.Fatalf("proxy rules without upstream: %v", err)
	}
}

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
		{"client", "--rules", filepath.Join(dir, "missing")},
		{"client", "--rules", bad},
		{"client", "--rules", rules, "--listen", "0.0.0.0:8080"},
		{"client", "--rules", rules, "--listen", "127.0.0.1:0"},
		{"client", "--rules", rules, "--upstream", "192.0.2.1:18080"},
		{"client", "--rules", rules, "--upstream", "localhost:18080"},
		{"client", "--rules", rules, "--upstream", "127.0.0.1:0"},
		{"client", "--rules", rules, "extra"},
		{"server", "--rules", rules},
		{"server", "--rules", rules, "--upstream", "127.0.0.1:18080"},
		{"server", "--rules", rules, "--listen", "[::]:8081"},
	} {
		if err := Run(logger, args); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}

func TestSingleDashLongOptionsStillWork(t *testing.T) {
	err := Run(slog.New(slog.DiscardHandler), []string{"client", "-rules", ""})
	if err == nil || !strings.Contains(err.Error(), "--rules is required") {
		t.Fatalf("single-dash -rules not parsed: %v", err)
	}
}

func TestOptionErrorsUseGNUStyle(t *testing.T) {
	err := Run(slog.New(slog.DiscardHandler), []string{"client", "-bogus"})
	if err == nil || err.Error() != "unknown option --bogus; see vibemaxxer client --help" {
		t.Fatalf("got %v", err)
	}
}
