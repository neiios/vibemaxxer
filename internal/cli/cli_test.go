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

func TestFlagValidation(t *testing.T) {
	logger, _ := proxytest.Logger()
	key := filepath.Join(t.TempDir(), "id.pem")
	fp := strings.Repeat("ab", 32)
	closed, _ := proxytest.ClosedPort(t)
	for _, args := range [][]string{
		{"serve"},
		{"serve", "-listen", "127.0.0.1:0"},
		{"serve", "-listen", "127.0.0.1:0", "-client-key", "nothex"},
		{"serve", "-listen", "127.0.0.1:0", "-client-key", fp, "-ports", "https"},
		{"serve", "-listen", "127.0.0.1:0", "-client-key", fp, "extra"},
		{"serve", "-listen", "0.0.0.0:0", "-client-key", fp, "-key", key},
		{"serve", "-listen", ":0", "-client-key", fp, "-key", key},
		{"serve", "-listen", "[::]:0", "-client-key", fp, "-key", key},
		{"bridge"},
		{"bridge", "-server", "host", "-server-key", fp},
		{"bridge", "-server", "host:8443", "-server-key", "short"},
		{"bridge", "-server", "host:8443", "-server-key", fp, "-listen", "192.168.1.5:8888"},
		{"bridge", "-server", "host:8443", "-server-key", fp, "-blocklist", "/nonexistent", "-key", key},
		{"run"},
		{"run", "-bridge", closed, "true"},
		{"run", "-bridge", closed, "-server", "host:443", "--", "true"},
		{"run", "-server-key", fp, "--", "true"},
		{"run", "-blocklist", "missing", "--", "true"},
		{"run", "-server", "host:443", "--", "true"},
		{"run", "-server", "host:443", "-server-key", fp, "-listen", "0.0.0.0:0", "--", "true"},
		{"run", "-server", "host:443", "-server-key", fp, "-grace", "0s", "--", "true"},
		{"nonsense"},
	} {
		if err := Run(logger, args); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}

func TestErrorsNameFlags(t *testing.T) {
	logger, _ := proxytest.Logger()
	key := filepath.Join(t.TempDir(), "id.pem")
	fp := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "-server", "host", "-server-key", fp, "--", "true"}, "-server"},
		{[]string{"run", "-server", "host:443", "-server-key", "short", "--", "true"}, "-server-key"},
		{[]string{"run", "-server", "host:443", "-server-key", fp, "-direct-ports", "https", "--", "true"}, "-direct-ports"},
		{[]string{"run", "-server", "host:443", "-server-key", fp, "-blocklist", "/nonexistent", "--", "true"}, "-blocklist"},
		{[]string{"run", "-server", "host:443", "-server-key", fp, "-proxy-domains", "/nonexistent", "--", "true"}, "-proxy-domains"},
		{[]string{"bridge", "-server", "host:8443", "-server-key", fp, "-blocklist", "/nonexistent", "-key", key}, "-blocklist"},
	} {
		err := Run(logger, tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.args, err, tc.want)
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
	if _, err := identity.ParseFingerprint(line); err != nil || first.String() != second.String() {
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
