package main

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFlagValidation(t *testing.T) {
	logger, _ := testLogger()
	key := filepath.Join(t.TempDir(), "id.pem")
	fp := strings.Repeat("ab", 32)
	closed, _ := closedPort(t)
	for _, args := range [][]string{
		{"serve"},
		{"serve", "-listen", "127.0.0.1:0"},
		{"serve", "-listen", "127.0.0.1:0", "-client-key", "nothex"},
		{"serve", "-listen", "127.0.0.1:0", "-client-key", fp, "-ports", "https"},
		{"serve", "-listen", "127.0.0.1:0", "-client-key", fp, "extra"},
		{"bridge"},
		{"bridge", "-server", "host", "-server-key", fp},
		{"bridge", "-server", "host:8443", "-server-key", "short"},
		{"bridge", "-server", "host:8443", "-server-key", fp, "-listen", "192.168.1.5:8888"},
		{"bridge", "-server", "host:8443", "-server-key", fp, "-blocklist", "/nonexistent", "-key", key},
		{"run"},
		{"run", "-bridge", closed, "true"},
		{"nonsense"},
	} {
		if err := run(logger, args); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}

func TestKeyCommand(t *testing.T) {
	key := filepath.Join(t.TempDir(), "id.pem")
	var first, second bytes.Buffer
	if err := runKey([]string{"-key", key}, &first); err != nil {
		t.Fatal(err)
	}
	if err := runKey([]string{"-key", key}, &second); err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(first.String(), "\n")
	if _, err := parseFingerprint(line); err != nil || first.String() != second.String() {
		t.Fatalf("key output:\n%s\n%s", first.String(), second.String())
	}
}

func TestProxyEnv(t *testing.T) {
	env := proxyEnv([]string{"PATH=/bin", "https_proxy=http://old:1", "ALL_PROXY=socks://x",
		"NO_PROXY=internal.example,localhost", "no_proxy=internal.example, 127.0.0.1", "TERM=xterm"}, "127.0.0.1:8888")
	want := []string{
		"PATH=/bin", "TERM=xterm",
		"HTTP_PROXY=http://127.0.0.1:8888", "http_proxy=http://127.0.0.1:8888",
		"HTTPS_PROXY=http://127.0.0.1:8888", "https_proxy=http://127.0.0.1:8888",
		"NO_PROXY=internal.example,localhost,127.0.0.1,::1", "no_proxy=internal.example,localhost,127.0.0.1,::1",
	}
	if !slices.Equal(env, want) {
		t.Fatalf("env:\n%v\nwant:\n%v", env, want)
	}
}
