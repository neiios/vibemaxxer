package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

func TestCommandsRequireExplicitEncryptedFlow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, args := range [][]string{
		{"plain", "-listen", "invalid"},
		{"-listen", "invalid"},
		{"-allow", "127.0.0.1"},
		{"unknown"},
	} {
		if err := run(logger, args); err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("run(%q) = %v; want command rejection, not listener startup", args, err)
		}
	}
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"-help"}, {"--help"}} {
		if err := run(logger, args); err != nil {
			t.Errorf("run(%q): %v", args, err)
		}
	}
	for _, command := range []string{"serve", "bridge", "pair", "pair-code"} {
		if err := run(logger, []string{command, "-help"}); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%s -help: %v", command, err)
		}
	}
	var output bytes.Buffer
	printCommands(&output)
	if strings.Contains(output.String(), "plain") || strings.Contains(output.String(), "legacy") {
		t.Fatal("help still advertises the removed flow")
	}
}

func TestServerAllowlistDefaults(t *testing.T) {
	allowed, err := parseAllow(nil)
	if err != nil || len(allowed) != 2 || allowed[0] != netip.MustParsePrefix("0.0.0.0/0") || allowed[1] != netip.MustParsePrefix("::/0") {
		t.Fatalf("default IP policy must allow paired clients from either address family: %v, %v", allowed, err)
	}
	allowed, err = parseAllow([]string{"192.168.1.20"})
	if err != nil || len(allowed) != 1 || allowed[0] != netip.MustParsePrefix("192.168.1.20/32") {
		t.Fatalf("explicit allowlist must replace defaults: %v, %v", allowed, err)
	}
}
