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
		"http_proxy=http://old.invalid", "https_proxy=http://old.invalid")
	return cmd, argsFile
}

func runnerListener(t *testing.T, address string) *net.TCPListener {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Skipf("runner uses fixed address %s: %v", address, err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener.(*net.TCPListener)
}

func TestRunnerModes(t *testing.T) {
	// Readiness checks only need a TCP listener, not an HTTP server or tunnel.
	runnerListener(t, "127.0.0.1:8080")
	upstream := runnerListener(t, "127.0.0.1:18080")
	for _, remote := range []bool{false, true} {
		name, target := "local", "vibemaxxer.target"
		var args []string
		if remote {
			name, target = "remote", "vibemaxxer-remote.target"
			args = append(args, "--remote")
		}
		t.Run(name, func(t *testing.T) {
			args = append(args, "--", "bash", "-c", `printf '%s\n' "$HTTP_PROXY" "$HTTPS_PROXY" "$http_proxy" "$https_proxy" "${VIBEMAXXER_RUN_SCOPE-unset}" "$@"`,
				"command", "--remote", "argument with spaces", "literal $value")
			cmd, argsFile := runnerCommand(t, args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("runner: %v\n%s", err, out)
			}
			want := strings.Repeat("http://127.0.0.1:8080\n", 4) + "unset\n--remote\nargument with spaces\nliteral $value\n"
			if string(out) != want {
				t.Fatalf("command environment/arguments = %q, want %q", out, want)
			}
			invocation, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			for _, property := range []string{"Wants=", "After="} {
				if !strings.Contains(string(invocation), "\n"+property+target+"\n") {
					t.Fatalf("missing %s%s in systemd-run arguments: %s", property, target, invocation)
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
	runnerListener(t, "127.0.0.1:8080")
	upstream := runnerListener(t, "127.0.0.1:18080")
	upstream.Close()
	cmd, _ := runnerCommand(t, "bash", "-c", "printf ran")
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "ran" {
		t.Fatalf("local runner without tunnel: %q, %v", out, err)
	}
	if err := waitForProxy(true, 1, 0); err == nil || !strings.Contains(err.Error(), "proxy or tunnel is not up") {
		t.Fatalf("remote runner without tunnel: %v", err)
	}
}

func TestRunnerExitStatus(t *testing.T) {
	runnerListener(t, "127.0.0.1:8080")
	cmd, _ := runnerCommand(t, "bash", "-c", "exit 42")
	out, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 42 {
		t.Fatalf("exit status not preserved: %q, %v", out, err)
	}
}

func TestRunnerMissingProxy(t *testing.T) {
	listener := runnerListener(t, "127.0.0.1:8080")
	listener.Close()
	if err := waitForProxy(false, 1, 0); err == nil || !strings.Contains(err.Error(), "proxy is not up") {
		t.Fatalf("missing proxy: %v", err)
	}
}

func TestRunnerUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"--remote"}, {"--"}, {"--unknown"}} {
		cmd, argsFile := runnerCommand(t, args...)
		out, err := cmd.CombinedOutput()
		if _, statErr := os.Stat(argsFile); !os.IsNotExist(statErr) {
			t.Errorf("invalid invocation started a scope: %v", statErr)
		}
		if err == nil || !strings.Contains(string(out), "usage:") {
			t.Errorf("%v: %q, %v", args, out, err)
		}
	}
	cmd, _ := runnerCommand(t, "--help")
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "[--remote]") {
		t.Errorf("help: %q, %v", out, err)
	}
}
