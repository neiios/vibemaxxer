package cli

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/proxytest"
)

func TestFlagPolicy(t *testing.T) {
	logger, _ := proxytest.Logger()
	key := filepath.Join(t.TempDir(), "id.pem")
	fp := strings.Repeat("ab", 32)
	closed, _ := proxytest.ClosedPort(t)
	for _, args := range [][]string{
		{"serve", "-listen", "127.0.0.1:0", "-key", key},
		{"serve", "-listen", "127.0.0.1:0", "-client-key", "nothex", "-key", key},
		{"serve", "-listen", "0.0.0.0:0", "-client-key", fp, "-key", key},
		{"serve", "-listen", ":0", "-client-key", fp, "-key", key},
		{"serve", "-listen", "[::]:0", "-client-key", fp, "-key", key},
		{"bridge", "-server", "host:8443", "-server-key", fp, "-listen", "192.168.1.5:8888", "-key", key},
		{"bridge", "-server", "host:8443", "-server-key", fp, "-listen", "127.0.0.1:0", "-key", key},
		{"run", "-bridge", closed, "--", "true"},
		{"run", "-bridge", closed, "-server", "host:443", "-server-key", fp, "-key", key, "--", "true"},
		{"run", "-server-key", fp, "--", "true"},
		{"run", "-server", "host:443", "-server-key", fp, "-listen", "0.0.0.0:0", "-key", key, "--", "true"},
		{"run", "-server", "host:443", "-server-key", fp, "-grace", "0s", "-key", key, "--", "true"},
	} {
		if err := Run(logger, args); err == nil {
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
	if first.String() != second.String() {
		t.Fatalf("key output changed:\n%s\n%s", first.String(), second.String())
	}
	line, _, _ := strings.Cut(first.String(), "\n")
	if got, err := identity.ParseFingerprint("  " + strings.ToUpper(line) + "\n"); err != nil || got != line {
		t.Fatalf("fingerprint %q: %q, %v", line, got, err)
	}
	for _, bad := range []string{"", line[:63], line + "0", strings.Repeat("zz", 32)} {
		if _, err := identity.ParseFingerprint(bad); err == nil {
			t.Errorf("accepted fingerprint %q", bad)
		}
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
