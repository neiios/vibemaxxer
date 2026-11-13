package cli

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runnerCommand(t *testing.T, args ...string) (*exec.Cmd, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("runner test commands require bash")
	}
	dir := t.TempDir()
	for name, script := range map[string]string{
		"systemd-run": `set -euo pipefail
printf '%s\n' "$@" > "$SYSTEMD_ARGS"
while [[ $1 != -- ]]; do shift; done
shift
exec "$@"
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!"+bash+"\n"+script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "vibemaxxer")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/vibemaxxer")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, binary, append([]string{"run"}, args...)...)
	argsFile := filepath.Join(dir, "systemd-args")
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"VIBEMAXXER_RUN_SCOPE=", "SYSTEMD_ARGS="+argsFile,
		"HTTP_PROXY=http://old.invalid", "HTTPS_PROXY=http://old.invalid",
		"http_proxy=http://old.invalid", "https_proxy=http://old.invalid",
		"NO_PROXY=*", "no_proxy=*", "ALL_PROXY=socks5://old.invalid", "all_proxy=socks5://old.invalid")
	return cmd, argsFile
}

func runnerListener(t *testing.T) (*net.TCPListener, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener.(*net.TCPListener), listener.Addr().String()
}

func TestRunnerModes(t *testing.T) {
	_, proxy := runnerListener(t)
	upstream, tunnel := runnerListener(t)
	for _, remote := range []bool{false, true} {
		name, target := "local", "vibemaxxer.target"
		args := []string{"--proxy", proxy, "--tunnel", tunnel}
		if remote {
			name, target = "remote", "vibemaxxer-remote.target"
			args = append(args, "--remote")
		}
		t.Run(name, func(t *testing.T) {
			args = append(args, "--", "bash", "-c", `printf '%s\n' "$HTTP_PROXY" "$HTTPS_PROXY" "$http_proxy" "$https_proxy" "${NO_PROXY-unset}" "${no_proxy-unset}" "${ALL_PROXY-unset}" "${all_proxy-unset}" "${VIBEMAXXER_RUN_SCOPE-unset}" "$@"`,
				"command", "--remote", "argument with spaces", "literal $value")
			cmd, argsFile := runnerCommand(t, args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("runner: %v\n%s", err, out)
			}
			want := strings.Repeat("http://"+proxy+"\n", 4) +
				"unset\nunset\nunset\nunset\nunset\n--remote\nargument with spaces\nliteral $value\n"
			if string(out) != want {
				t.Fatalf("command environment/arguments = %q, want %q", out, want)
			}
			invocation, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			for _, property := range []string{"Wants=" + target, "After=" + target, "--proxy\n" + proxy, "--tunnel\n" + tunnel} {
				if !strings.Contains(string(invocation), "\n"+property+"\n") {
					t.Fatalf("missing %q in systemd-run arguments: %s", property, invocation)
				}
			}
			_ = upstream.SetDeadline(time.Now().Add(100 * time.Millisecond))
			conn, err := upstream.Accept()
			if conn != nil {
				conn.Close()
			}
			if remote && err != nil {
				t.Fatalf("remote mode did not check the upstream: %v", err)
			}
			if !remote && err == nil {
				t.Fatal("local mode checked the upstream")
			}
		})
	}
}

func TestRunnerLocalWithoutTunnel(t *testing.T) {
	_, proxy := runnerListener(t)
	upstream, tunnel := runnerListener(t)
	upstream.Close()
	cmd, _ := runnerCommand(t, "--proxy", proxy, "--tunnel", tunnel, "bash", "-c", "printf ran")
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "ran" {
		t.Fatalf("local runner without tunnel: %q, %v", out, err)
	}
	if err := waitForProxy(proxy, tunnel, 1, 0); err == nil || !strings.Contains(err.Error(), "proxy or tunnel is not up") {
		t.Fatalf("remote runner without tunnel: %v", err)
	}
}

func TestRunnerExitStatus(t *testing.T) {
	_, proxy := runnerListener(t)
	cmd, _ := runnerCommand(t, "--proxy", proxy, "bash", "-c", "exit 42")
	out, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 42 {
		t.Fatalf("exit status not preserved: %q, %v", out, err)
	}
}

func TestRunnerMissingProxy(t *testing.T) {
	listener, proxy := runnerListener(t)
	listener.Close()
	if err := waitForProxy(proxy, "", 1, 0); err == nil || !strings.Contains(err.Error(), "proxy is not up") {
		t.Fatalf("missing proxy: %v", err)
	}
}

func TestRunnerUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "see vibemaxxer run --help"},
		{[]string{"--remote"}, "see vibemaxxer run --help"},
		{[]string{"--"}, "see vibemaxxer run --help"},
		{[]string{"--unknown"}, "see vibemaxxer run --help"},
		{[]string{"--proxy", "192.0.2.1:9878", "true"}, "--proxy must be a loopback"},
		{[]string{"--tunnel", "localhost:19878", "true"}, "--tunnel must be a loopback"},
	} {
		cmd, argsFile := runnerCommand(t, tc.args...)
		out, err := cmd.CombinedOutput()
		if _, statErr := os.Stat(argsFile); !os.IsNotExist(statErr) {
			t.Errorf("invalid invocation started a scope: %v", statErr)
		}
		if err == nil || !strings.Contains(string(out), tc.want) {
			t.Errorf("%v: %q, %v", tc.args, out, err)
		}
	}
	cmd, _ := runnerCommand(t, "--help")
	out, err := cmd.CombinedOutput()
	for _, want := range []string{"--remote", "--proxy ADDR", "(default 127.0.0.1:9878)", "(default 127.0.0.1:19878)"} {
		if err != nil || !strings.Contains(string(out), want) {
			t.Errorf("help is missing %q: %q, %v", want, out, err)
		}
	}
}
