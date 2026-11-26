package cli

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var runnerBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "vibemaxxer-test")
	if err != nil {
		panic(err)
	}
	runnerBinary = filepath.Join(dir, "vibemaxxer")
	if out, err := exec.Command("go", "build", "-o", runnerBinary, "../../cmd/vibemaxxer").CombinedOutput(); err != nil {
		panic("build CLI: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type runner struct {
	dir   string
	rules string
	log   string
}

func newRunner(t *testing.T) runner {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("runner test commands require bash")
	}
	dir := t.TempDir()
	r := runner{dir: dir, rules: filepath.Join(dir, "rules"), log: filepath.Join(dir, "state", "run.log")}
	if err := os.WriteFile(r.rules, []byte("block .blocked.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r runner) command(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, runnerBinary, append([]string{"run"}, args...)...)
	cmd.Env = append(os.Environ(), "VIBEMAXXER_RUN=",
		"HTTP_PROXY=http://old.invalid", "HTTPS_PROXY=http://old.invalid",
		"http_proxy=http://old.invalid", "https_proxy=http://old.invalid",
		"NO_PROXY=*", "no_proxy=*", "ALL_PROXY=socks5://old.invalid", "all_proxy=socks5://old.invalid")
	return cmd
}

func (r runner) script(t *testing.T, script string, args ...string) *exec.Cmd {
	t.Helper()
	return r.command(t, append([]string{"--rules", r.rules, "--log", r.log, "--", "bash", "-c", script, "command"}, args...)...)
}

func start(t *testing.T, cmd *exec.Cmd) (*bufio.Reader, io.WriteCloser) {
	t.Helper()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	return bufio.NewReader(stdout), stdin
}

func line(t *testing.T, out *bufio.Reader) string {
	t.Helper()
	text, err := out.ReadString('\n')
	if err != nil {
		t.Fatalf("read command output: %v (%q)", err, text)
	}
	return strings.TrimSuffix(text, "\n")
}

func TestRunnerEnvironmentAndArguments(t *testing.T) {
	r := newRunner(t)
	cmd := r.script(t, `printf '%s\n' "$HTTP_PROXY" "$HTTPS_PROXY" "$http_proxy" "$https_proxy" "${NO_PROXY-unset}" "${no_proxy-unset}" "${ALL_PROXY-unset}" "${all_proxy-unset}" "$@"`,
		"--rules", "argument with spaces", "literal $value")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("runner: %v\n%s", err, out)
	}
	lines := strings.Split(string(out), "\n")
	if err := loopback("proxy", strings.TrimPrefix(lines[0], "http://")); err != nil {
		t.Fatalf("HTTP_PROXY = %q", lines[0])
	}
	want := strings.Repeat(lines[0]+"\n", 4) + "unset\nunset\nunset\nunset\n--rules\nargument with spaces\nliteral $value\n"
	if string(out) != want {
		t.Fatalf("command environment/arguments = %q, want %q", out, want)
	}
}

func TestRunnerProxyLivesWithCommand(t *testing.T) {
	r := newRunner(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	cmd := r.script(t, `echo "$HTTP_PROXY"; read -r _ || true`)
	out, stdin := start(t, cmd)
	proxy, err := url.Parse(line(t, out))
	if err != nil {
		t.Fatal(err)
	}
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 5 * time.Second}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "origin" {
		t.Fatalf("direct request: %d %q", resp.StatusCode, body)
	}
	resp, err = client.Get("http://www.blocked.example/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get("Proxy-Status"), "vibemaxxer-client; error=http_request_denied") {
		t.Fatalf("blocked request: %d %q", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}

	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", proxy.Host, time.Second); err == nil {
		conn.Close()
		t.Fatal("proxy outlived the command")
	}
	log, err := os.ReadFile(r.log)
	if err != nil {
		t.Fatal(err)
	}
	tag := "pid=" + strconv.Itoa(cmd.Process.Pid) + " command=bash "
	for _, want := range []string{
		tag + "method=GET host=www.blocked.example port=80 action=block rule=" + r.rules + ":1 status=403",
		tag + "method=GET host=localhost port=" + origin.Listener.Addr().(*net.TCPAddr).AddrPort().String()[len("127.0.0.1:"):] + " action=direct rule=default status=200",
	} {
		if !strings.Contains(string(log), want) {
			t.Errorf("log is missing %q:\n%s", want, log)
		}
	}
	for text := range strings.Lines(string(log)) {
		if !strings.Contains(text, tag) {
			t.Errorf("untagged log line %q", text)
		}
	}
}

func TestRunnerLogsConnectionsOpenAtExit(t *testing.T) {
	r := newRunner(t)
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, conn)
		}
	}()
	port := strconv.Itoa(origin.Addr().(*net.TCPAddr).Port)
	out, err := r.script(t, `exec 3<>/dev/tcp/127.0.0.1/"${HTTP_PROXY##*:}"; printf 'CONNECT localhost:%s HTTP/1.1\r\n\r\n' "$1" >&3; read -r status <&3; echo "${status%$'\r'}"`, port).Output()
	if err != nil || string(out) != "HTTP/1.1 200 Connection Established\n" {
		t.Fatalf("tunnel: %q, %v", out, err)
	}
	log, err := os.ReadFile(r.log)
	if err != nil {
		t.Fatal(err)
	}
	if want := "method=CONNECT host=localhost port=" + port + " action=direct rule=default status=200"; !strings.Contains(string(log), want) {
		t.Fatalf("log is missing %q:\n%s", want, log)
	}
}

func TestRunnerNesting(t *testing.T) {
	r := newRunner(t)
	other := filepath.Join(r.dir, "other")
	same := filepath.Join(r.dir, "same")
	if err := os.WriteFile(other, []byte("block .other.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(same, []byte("block .blocked.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inner := `echo "$HTTP_PROXY $$"`
	for _, tc := range []struct {
		name   string
		nested string
		shared bool
	}{
		{"same rules", `exec "$1" run --rules "$2" --log "$3" -- bash -c '` + inner + `'`, true},
		{"same rules in another file", `exec "$1" run --rules "$4" --log "$3" -- bash -c '` + inner + `'`, true},
		{"other rules", `"$1" run --rules "$5" --log "$3" -- bash -c '` + inner + `'`, false},
		{"other upstream", `"$1" run --rules "$2" --log "$3" --upstream 127.0.0.1:1 -- bash -c '` + inner + `'`, false},
		{"changed marker", `VIBEMAXXER_RUN=${VIBEMAXXER_RUN%?}x "$1" run --rules "$2" --log "$3" -- bash -c '` + inner + `'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := r.script(t, `echo "$HTTP_PROXY $$"; `+tc.nested, runnerBinary, r.rules, r.log, same, other)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("runner: %v\n%s", err, out)
			}
			outer, nested, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
			outerProxy, outerPID, _ := strings.Cut(outer, " ")
			nestedProxy, nestedPID, _ := strings.Cut(nested, " ")
			if shared := outerProxy == nestedProxy; shared != tc.shared || nestedProxy == "" {
				t.Fatalf("outer %q, nested %q, want shared = %v", outer, nested, tc.shared)
			}
			if tc.shared && outerPID != nestedPID {
				t.Fatalf("a shared run should exec the command in place: outer %q, nested %q", outer, nested)
			}
		})
	}
}

func TestRunnerStaleMarker(t *testing.T) {
	r := newRunner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stale := listener.Addr().String()
	listener.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer other.Close()
	for _, marker := range []string{stale + "/00", other.Listener.Addr().String() + "/00", "example.com:80/00", "garbage"} {
		cmd := r.script(t, `echo "$HTTP_PROXY"`)
		cmd.Env = append(cmd.Env, "VIBEMAXXER_RUN="+marker)
		out, err := cmd.Output()
		proxy := strings.TrimPrefix(strings.TrimSpace(string(out)), "http://")
		if err != nil || loopback("proxy", proxy) != nil || strings.HasPrefix(marker, proxy+"/") {
			t.Errorf("marker %q: command got proxy %q, %v", marker, proxy, err)
		}
	}
}

func TestRunnerExitStatus(t *testing.T) {
	r := newRunner(t)
	out, err := r.script(t, "exit 42").CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 42 || len(out) != 0 {
		t.Fatalf("exit status not preserved: %q, %v", out, err)
	}
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL, syscall.SIGUSR1} {
		out, err := r.script(t, "kill -"+strconv.Itoa(int(sig))+" $$").CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("%v: %q, %v", sig, out, err)
		}
		status := exit.Sys().(syscall.WaitStatus)
		if sig == syscall.SIGUSR1 {
			if status.ExitStatus() != 128+int(sig) {
				t.Errorf("%v: exit status %d", sig, status.ExitStatus())
			}
		} else if !status.Signaled() || status.Signal() != sig {
			t.Errorf("%v: runner did not die from the same signal: %v", sig, status)
		}
	}
}

func TestRunnerForwardsSignals(t *testing.T) {
	r := newRunner(t)
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2} {
		cmd := r.script(t, `trap 'echo got; exit 7' `+strconv.Itoa(int(sig))+`; echo ready; while :; do read -r -t 0.05 _; done`)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		out, _ := start(t, cmd)
		if got := line(t, out); got != "ready" {
			t.Fatalf("%v: %q", sig, got)
		}
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
		if got := line(t, out); got != "got" {
			t.Fatalf("%v: %q", sig, got)
		}
		if exit, ok := cmd.Wait().(*exec.ExitError); !ok || exit.ExitCode() != 7 {
			t.Fatalf("%v: runner exited with %v", sig, exit)
		}
	}
}

func TestRunnerStopsAndContinuesWithCommand(t *testing.T) {
	r := newRunner(t)
	cmd := r.script(t, `echo ready; kill -STOP $$; echo continued`)
	out, _ := start(t, cmd)
	if got := line(t, out); got != "ready" {
		t.Fatal(got)
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(cmd.Process.Pid, &status, syscall.WUNTRACED, nil); err != nil || !status.Stopped() {
		t.Fatalf("runner did not stop with its command: %v, %v", status, err)
	}
	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if got := line(t, out); got != "continued" {
		t.Fatal(got)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerStopsOnceForGroupStop(t *testing.T) {
	r := newRunner(t)
	cmd := r.script(t, `echo ready; while :; do read -r -t 0.05 _; echo tick; done`)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, _ := start(t, cmd)
	if got := line(t, out); got != "ready" {
		t.Fatal(got)
	}
	for range 5 {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTSTP); err != nil {
			t.Fatal(err)
		}
		var status syscall.WaitStatus
		if _, err := syscall.Wait4(cmd.Process.Pid, &status, syscall.WUNTRACED, nil); err != nil || !status.Stopped() {
			t.Fatalf("runner did not stop with its group: %v, %v", status, err)
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGCONT); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			if got := line(t, out); got != "tick" {
				t.Fatal(got)
			}
		}
		time.Sleep(100 * time.Millisecond)
		if pid, err := syscall.Wait4(cmd.Process.Pid, &status, syscall.WUNTRACED|syscall.WNOHANG, nil); err != nil || pid != 0 {
			t.Fatalf("runner stopped again after continuing: %v, %v", status, err)
		}
	}
}

func TestRunnerCommandDiesWithRunner(t *testing.T) {
	r := newRunner(t)
	cmd := r.script(t, `trap 'echo terminated; exit' TERM; echo ready; while :; do read -r -t 0.05 _; done`)
	out, _ := start(t, cmd)
	if got := line(t, out); got != "ready" {
		t.Fatal(got)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if got := line(t, out); got != "terminated" {
		t.Fatal(got)
	}
}

func TestRunnerLogRotation(t *testing.T) {
	r := newRunner(t)
	if err := os.MkdirAll(filepath.Dir(r.log), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.log, make([]byte, maxLogSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := r.script(t, "true").CombinedOutput(); err != nil {
		t.Fatalf("%q, %v", out, err)
	}
	old, err := os.Stat(r.log + ".1")
	if err != nil || old.Size() != maxLogSize+1 {
		t.Fatalf("old log was not rotated: %v, %v", old, err)
	}
	current, err := os.ReadFile(r.log)
	if err != nil || !strings.Contains(string(current), "msg=listening") || len(current) > 4096 {
		t.Fatalf("new log: %q, %v", current, err)
	}
}

func TestRunnerUsage(t *testing.T) {
	r := newRunner(t)
	marker := filepath.Join(r.dir, "ran")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "see vibemaxxer run --help"},
		{[]string{"--rules", r.rules}, "missing COMMAND"},
		{[]string{"--rules", r.rules, "--"}, "missing COMMAND"},
		{[]string{"--unknown"}, "see vibemaxxer run --help"},
		{[]string{"touch", marker}, "--rules is required"},
		{[]string{"--rules", filepath.Join(r.dir, "missing"), "touch", marker}, "no such file"},
		{[]string{"--rules", r.rules, "--upstream", "192.0.2.1:19878", "touch", marker}, "--upstream must be a loopback"},
		{[]string{"--rules", r.rules, "--log", r.log, "missing-command-" + filepath.Base(r.dir)}, "executable file not found"},
	} {
		out, err := r.command(t, tc.args...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), tc.want) {
			t.Errorf("%v: %q, %v", tc.args, out, err)
		}
	}
	if err := os.WriteFile(r.rules, []byte("proxy .remote.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := r.command(t, "--rules", r.rules, "--log", r.log, "touch", marker).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "proxy rules require --upstream") {
		t.Errorf("proxy rules without upstream: %q, %v", out, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("an invalid invocation ran its command: %v", err)
	}
	out, err = r.command(t, "--help").CombinedOutput()
	for _, want := range []string{"--rules FILE", "--log FILE", "--direct-shells", "--upstream ADDR", "--server HOST:PORT"} {
		if err != nil || !strings.Contains(string(out), want) {
			t.Errorf("help is missing %q: %q, %v", want, out, err)
		}
	}
}

func (r runner) direct(t *testing.T, env []string, command ...string) string {
	t.Helper()
	cmd := r.command(t, append([]string{"--direct-shells", "--rules", r.rules, "--log", r.log, "--"}, command...)...)
	cmd.Env = slices.DeleteFunc(cmd.Env, func(entry string) bool {
		name, _, _ := strings.Cut(entry, "=")
		return slices.Contains([]string{"BASH_ENV", "ZDOTDIR", "VIBEMAXXER_BASH_ENV", "VIBEMAXXER_ZDOTDIR"}, name)
	})
	cmd.Env = append(cmd.Env, "HOME="+filepath.Join(r.dir, "home"), "XDG_CACHE_HOME="+filepath.Join(r.dir, "cache"), "TMPDIR="+filepath.Join(r.dir, "tmp"))
	cmd.Env = append(cmd.Env, env...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v: %v\n%s", command, err, out)
	}
	return string(out)
}

func (r runner) write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(r.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func shells(t *testing.T, test func(t *testing.T, shell string)) {
	t.Helper()
	for _, shell := range []string{"bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			if _, err := exec.LookPath(shell); err != nil {
				t.Skip(shell + " is not installed")
			}
			test(t, shell)
		})
	}
}

const proxyState = `echo "${HTTP_PROXY-unset} ${HTTPS_PROXY-unset} ${http_proxy-unset} ${https_proxy-unset}"`

func TestRunnerDirectShells(t *testing.T) {
	r := newRunner(t)
	hooks := filepath.Join(r.dir, "cache", "vibemaxxer", "direct-shells")
	r.write(t, "tmp/.keep", "")

	env := r.direct(t, nil, "env")
	proxy := ""
	for _, name := range proxyVariables {
		_, value, _ := strings.Cut(env, "\n"+name+"=http://")
		value, _, _ = strings.Cut(value, "\n")
		if loopback("proxy", value) != nil || proxy != "" && value != proxy {
			t.Fatalf("command has %s = %q:\n%s", name, value, env)
		}
		proxy = value
	}
	for _, want := range []string{"\nBASH_ENV=" + hooks + "/bash_env\n", "\nZDOTDIR=" + hooks + "\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("command environment is missing %q:\n%s", want, env)
		}
	}
	if strings.Contains(env, "VIBEMAXXER_BASH_ENV=") || strings.Contains(env, "VIBEMAXXER_ZDOTDIR=") {
		t.Errorf("command environment saves startup files that were not set:\n%s", env)
	}

	shells(t, func(t *testing.T, shell string) {
		for _, options := range []string{"-c", "-euc"} {
			script := proxyState + `; echo "${BASH_ENV-unset} ${ZDOTDIR-unset}"; env | grep -c VIBEMAXXER_; ` + shell + ` -c '` + proxyState + `'`
			want := "unset unset unset unset\nunset unset\n1\nunset unset unset unset\n"
			if out := r.direct(t, nil, "env", shell, options, script); out != want {
				t.Errorf("%s %s printed %q, want %q", shell, options, out, want)
			}
		}
	})

	if out, err := r.script(t, proxyState).Output(); err != nil || strings.Contains(string(out), "unset") {
		t.Errorf("without --direct-shells a shell printed %q, %v", out, err)
	}
	for dir, want := range map[string][]string{hooks: {".zshenv", "bash_env"}, filepath.Join(r.dir, "tmp"): {".keep"}} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		if !slices.Equal(names, want) {
			t.Errorf("%s holds %q, want %q", dir, names, want)
		}
	}
}

func TestRunnerDirectShellsNesting(t *testing.T) {
	r := newRunner(t)
	shells(t, func(t *testing.T, shell string) {
		os.Remove(r.log)
		nested := `"$1" run --direct-shells --rules "$2" --log "$3" -- `
		out := r.direct(t, nil, shell, "-c", proxyState+`; echo "${VIBEMAXXER_RUN%%/*}"; `+nested+`env | grep -x "HTTP_PROXY=.*"; `+nested+shell+` -c '`+proxyState+`'`,
			"command", runnerBinary, r.rules, r.log)
		lines := strings.Split(out, "\n")
		if len(lines) != 5 || lines[0] != "unset unset unset unset" || loopback("proxy", lines[1]) != nil || lines[2] != "HTTP_PROXY=http://"+lines[1] || lines[3] != lines[0] {
			t.Fatalf("nested runs printed %q", out)
		}
		log, err := os.ReadFile(r.log)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(log), "msg=listening") != 1 {
			t.Fatalf("nested runs did not share one proxy:\n%s", log)
		}
	})
}

func TestRunnerDirectShellsKeepStartupFiles(t *testing.T) {
	r := newRunner(t)
	t.Run("bash", func(t *testing.T) {
		user := r.write(t, "user/bash_env", `echo "user ${HTTP_PROXY-unset}"`+"\n")
		script := `echo "$BASH_ENV ${VIBEMAXXER_BASH_ENV-unset}"; bash -c 'echo nested'`
		want := "user unset\n" + user + " unset\nuser unset\nnested\n"
		for _, command := range [][]string{
			{"bash", "-c", script},
			{runnerBinary, "run", "--direct-shells", "--rules", r.rules, "--log", r.log, "--", "bash", "-c", script},
		} {
			if out := r.direct(t, []string{"BASH_ENV=" + user}, command...); out != want {
				t.Errorf("%v printed %q, want %q", command, out, want)
			}
		}
		if out := r.direct(t, []string{"BASH_ENV=" + filepath.Join(r.dir, "missing")}, "bash", "-c", "echo ran"); out != "ran\n" {
			t.Errorf("a missing BASH_ENV printed %q", out)
		}
	})
	t.Run("zsh", func(t *testing.T) {
		if _, err := exec.LookPath("zsh"); err != nil {
			t.Skip("zsh is not installed")
		}
		r.write(t, "home/.zshenv", `echo "home zshenv ${HTTP_PROXY-unset}"`+"\n")
		r.write(t, "home/.zshrc", "echo home zshrc\n")
		dotdir := filepath.Dir(r.write(t, "dotdir/.zshenv", `echo "dotdir zshenv ${HTTP_PROXY-unset}"`+"\n"))
		r.write(t, "dotdir/.zshrc", "echo dotdir zshrc\n")
		moved := filepath.Dir(r.write(t, "moved/.zshrc", "echo moved zshrc\n"))
		script := `echo "${ZDOTDIR-unset} ${VIBEMAXXER_ZDOTDIR-unset}"; zsh -c 'echo nested'`
		for _, tc := range []struct {
			name    string
			env     []string
			command []string
			want    string
		}{
			{"home", nil, []string{"zsh", "-c", script}, "home zshenv unset\nunset unset\nhome zshenv unset\nnested\n"},
			{"interactive", nil, []string{"zsh", "-ic", script}, "home zshenv unset\nhome zshrc\nunset unset\nhome zshenv unset\nnested\n"},
			{"ZDOTDIR", []string{"ZDOTDIR=" + dotdir}, []string{"zsh", "-c", script}, "dotdir zshenv unset\n" + dotdir + " unset\ndotdir zshenv unset\nnested\n"},
			{"ZDOTDIR interactive", []string{"ZDOTDIR=" + dotdir}, []string{"zsh", "-ic", "true"}, "dotdir zshenv unset\ndotdir zshrc\n"},
			{"ZDOTDIR set in .zshenv", []string{"HOME=" + filepath.Dir(r.write(t, "sets/.zshenv", "ZDOTDIR="+moved+"\n"))}, []string{"zsh", "-ic", `echo "$ZDOTDIR"`}, "moved zshrc\n" + moved + "\n"},
			{"hooked twice", []string{"ZDOTDIR=" + dotdir}, []string{runnerBinary, "run", "--direct-shells", "--rules", r.rules, "--log", r.log, "--", "zsh", "-c", script}, "dotdir zshenv unset\n" + dotdir + " unset\ndotdir zshenv unset\nnested\n"},
		} {
			if out := r.direct(t, tc.env, tc.command...); out != tc.want {
				t.Errorf("%s: printed %q, want %q", tc.name, out, tc.want)
			}
		}
	})
}
