package cli

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/managed"
	"github.com/neiios/vibemaxxer/internal/proxytest"
)

// The test binary doubles as the vibemaxxer executable (via Main) and as the
// command that `run` supervises (via child), so these tests drive the real
// process tree: run → bridge → serve.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "_managed":
			os.Exit(Main(os.Args[1:]))
		case "_test-run":
			os.Exit(Main(os.Args[2:]))
		case "_test-child":
			os.Exit(child(os.Args[2:]))
		}
	}
	os.Exit(m.Run())
}

func child(args []string) int {
	switch args[0] {
	case "connect":
		// Check the environment `run` hands to agents, issue one CONNECT
		// through it and report the answer. Exit 7 so tests can verify that
		// exit statuses propagate.
		entries, _ := os.ReadDir("/proc/self/fd")
		for _, e := range entries {
			target, _ := os.Readlink("/proc/self/fd/" + e.Name())
			if strings.HasPrefix(target, "socket:") || strings.Contains(target, ".owner") || strings.Contains(target, ".lock") || strings.Contains(target, ".snapshot-") {
				fmt.Fprintln(os.Stderr, "leaked descriptor:", target)
				return 90
			}
		}
		proxy := os.Getenv("HTTPS_PROXY")
		if !strings.HasPrefix(proxy, "http://127.0.0.1:") || os.Getenv("https_proxy") != proxy || os.Getenv("HTTP_PROXY") != proxy || !strings.Contains(os.Getenv("NO_PROXY"), "localhost") {
			fmt.Fprintln(os.Stderr, "proxy environment not set")
			return 91
		}
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(proxy, "http://"), 2*time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 92
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", args[1], args[1])
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 93
		}
		fmt.Printf("status:%d\n", response.StatusCode)
		return 7
	case "wait":
		_ = os.WriteFile(args[1], []byte(os.Getenv("HTTPS_PROXY")), 0600)
	case "tty":
		terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return 92
		}
		terminal.Close()
		_ = os.WriteFile(args[1], []byte("ready"), 0600)
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return 93
		}
		fmt.Printf("received:%s", line)
	default:
		return 99
	}
	for {
		time.Sleep(time.Second)
	}
}

func runtimeRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "vmx-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if os.Getenv("VIBEMAXXER_TEST_NIX_SANDBOX") == "1" {
		if _, err := managed.RuntimeDir(root); err != nil {
			t.Skipf("Nix sandbox cannot provide a trusted runtime ancestry: %v", err)
		}
	}
	return root
}

func snapshot(t *testing.T, root, server, serverKey string) managed.Config {
	t.Helper()
	c, err := managed.Snapshot(server, serverKey, "127.0.0.1:0", filepath.Join(root, "identity.pem"), "", "", "443", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// managedFixture points the bridge at a dead server; use it for tests about
// supervision rather than the data path.
func managedFixture(t *testing.T) (managed.Config, string) {
	t.Helper()
	root := runtimeRoot(t)
	server, _ := proxytest.ClosedPort(t)
	return snapshot(t, root, server, strings.Repeat("ab", 32)), root
}

func managedRunArgs(c managed.Config, root string, child ...string) []string {
	args := []string{"_test-run", "run", "-server", c.Server, "-server-key", c.ServerKey, "-key", filepath.Join(root, "identity.pem"), "-runtime-dir", root, "-grace", c.Grace.String(), "--"}
	return append(args, child...)
}

func waitStopped(t *testing.T, c managed.Config, root string) {
	t.Helper()
	base := filepath.Join(root, c.Digest())
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(base + ".sock"); os.IsNotExist(err) {
			f, e := os.OpenFile(base+".owner", os.O_RDWR|os.O_CREATE, 0600)
			if e == nil {
				e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
				f.Close()
				if e == nil {
					return
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	logs, _ := os.ReadFile(base + ".log")
	t.Fatalf("bridge did not stop: %s", logs)
}

func waitFile(t *testing.T, path string) []byte {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if b, err := os.ReadFile(path); err == nil {
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for child")
	return nil
}

// fingerprint runs `vibemaxxer key`, creating the identity on first use.
func fingerprint(t *testing.T, keyPath string) string {
	t.Helper()
	exe, _ := os.Executable()
	output, err := exec.Command(exe, "_test-run", "key", "-key", keyPath).Output()
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(output), "\n")
	fp, err := identity.ParseFingerprint(line)
	if err != nil {
		t.Fatalf("key output %q: %v", output, err)
	}
	return fp
}

// startCommand runs a vibemaxxer subcommand in the background until the test
// ends and returns once its log contains ready.
func startCommand(t *testing.T, ready string, args ...string) *proxytest.LogBuffer {
	t.Helper()
	exe, _ := os.Executable()
	cmd := exec.Command(exe, append([]string{"_test-run"}, args...)...)
	logs := &proxytest.LogBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	proxytest.WaitForLog(t, logs, ready)
	return logs
}

var servingAddress = regexp.MustCompile(`address=(\S+)`)

func startServe(t *testing.T, keyPath, clientKey string) (address, serverKey string, logs *proxytest.LogBuffer) {
	t.Helper()
	serverKey = fingerprint(t, keyPath)
	logs = startCommand(t, "msg=serving", "serve", "-listen", "127.0.0.1:0", "-client-key", clientKey, "-key", keyPath)
	m := servingAddress.FindStringSubmatch(logs.String())
	if m == nil {
		t.Fatalf("serve did not report its address:\n%s", logs.String())
	}
	return m[1], serverKey, logs
}

func startBridge(t *testing.T, keyPath, server, serverKey string) (address string, logs *proxytest.LogBuffer) {
	t.Helper()
	address, _ = proxytest.ClosedPort(t)
	logs = startCommand(t, "bridge listening", "bridge", "-server", server, "-server-key", serverKey, "-listen", address, "-key", keyPath)
	return address, logs
}

// assertConnected checks the supervised command's view of the chain: proxy
// variables set, no leaked descriptors, exit status propagated, and a CONNECT
// that travelled bridge → TLS → serve and was refused there because the
// destination is loopback (serve never allows private destinations).
func assertConnected(t *testing.T, output []byte, err error, serveLogs *proxytest.LogBuffer) {
	t.Helper()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 7 {
		t.Fatalf("exit status: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "status:403") {
		t.Fatalf("command output:\n%s", output)
	}
	proxytest.WaitForLog(t, serveLogs, "private/local destination blocked")
}

// External mode: key on both sides, serve, a self-managed bridge, then
// `run -bridge` execs the command against it.
func TestExternalBridgeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	clientKey := filepath.Join(dir, "client.pem")
	server, serverKey, serveLogs := startServe(t, filepath.Join(dir, "server.pem"), fingerprint(t, clientKey))
	bridge, bridgeLogs := startBridge(t, clientKey, server, serverKey)
	exe, _ := os.Executable()
	output, err := exec.Command(exe, "_test-run", "run", "-bridge", bridge, "--", exe, "_test-child", "connect", "127.0.0.1:443").CombinedOutput()
	assertConnected(t, output, err, serveLogs)
	if strings.Contains(string(output), "log:") {
		t.Fatal("external mode launched a managed bridge")
	}
	proxytest.WaitForLog(t, bridgeLogs, "upstream verified")
}

// Managed mode: `run -server` starts a shared bridge on demand, supervises the
// command, and stops the bridge after the grace period.
func TestManagedEndToEnd(t *testing.T) {
	root := runtimeRoot(t)
	clientKey := filepath.Join(root, "identity.pem")
	server, serverKey, serveLogs := startServe(t, filepath.Join(root, "server.pem"), fingerprint(t, clientKey))
	c := snapshot(t, root, server, serverKey)
	exe, _ := os.Executable()
	output, err := exec.Command(exe, managedRunArgs(c, root, exe, "_test-child", "connect", "127.0.0.1:443")...).CombinedOutput()
	assertConnected(t, output, err, serveLogs)
	if !strings.Contains(string(output), "log:") {
		t.Fatalf("log path not printed:\n%s", output)
	}
	waitStopped(t, c, root)
	logs, _ := os.ReadFile(filepath.Join(root, c.Digest()) + ".log")
	for _, want := range []string{"upstream verified", "last lease released"} {
		if !strings.Contains(string(logs), want) {
			t.Fatalf("bridge log missing %q:\n%s", want, logs)
		}
	}
}

func TestManagedSupervisorSignalAndDeath(t *testing.T) {
	for _, kill := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		t.Run(kill.String(), func(t *testing.T) {
			c, root := managedFixture(t)
			exe, _ := os.Executable()
			ready := filepath.Join(root, "ready")
			cmd := exec.Command(exe, managedRunArgs(c, root, exe, "_test-child", "wait", ready)...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			waitFile(t, ready)
			cmd.Process.Signal(kill)
			err := cmd.Wait()
			if kill == syscall.SIGTERM {
				if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 143 {
					t.Fatalf("signal status: %v", err)
				}
			}
			waitStopped(t, c, root)
		})
	}
}

func TestManagedIndependentLaunchers(t *testing.T) {
	c, root := managedFixture(t)
	exe, _ := os.Executable()
	cmds := make([]*exec.Cmd, 2)
	ready := make([]string, 2)
	for i := range cmds {
		ready[i] = filepath.Join(root, []string{"first", "second"}[i])
		cmds[i] = exec.Command(exe, managedRunArgs(c, root, exe, "_test-child", "wait", ready[i])...)
		cmds[i].SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmds[i].Start(); err != nil {
			t.Fatal(err)
		}
		defer syscall.Kill(-cmds[i].Process.Pid, syscall.SIGKILL)
	}
	first, second := string(waitFile(t, ready[0])), string(waitFile(t, ready[1]))
	if first != second {
		t.Fatalf("independent launchers not sharing: %s %s", first, second)
	}
	cmds[0].Process.Kill()
	cmds[0].Wait()
	time.Sleep(2 * c.Grace)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(second, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	cmds[1].Process.Signal(syscall.SIGTERM)
	cmds[1].Wait()
	waitStopped(t, c, root)
}

func TestManagedInteractiveTerminal(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	defer master.Close()
	var zero, number uint32
	ioctl := func(request uintptr, value *uint32) {
		t.Helper()
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), request, uintptr(unsafe.Pointer(value))); errno != 0 {
			t.Fatal(errno)
		}
	}
	ioctl(syscall.TIOCSPTLCK, &zero)
	ioctl(syscall.TIOCGPTN, &number)
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	c, root := managedFixture(t)
	exe, _ := os.Executable()
	ready := filepath.Join(root, "tty-ready")
	cmd := exec.Command(exe, managedRunArgs(c, root, exe, "_test-child", "tty", ready)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	waitFile(t, ready)
	output := make(chan string, 1)
	go func() {
		var result strings.Builder
		data := make([]byte, 1024)
		for {
			n, err := master.Read(data)
			result.Write(data[:n])
			if strings.Contains(result.String(), "received:hello") || err != nil {
				output <- result.String()
				return
			}
		}
	}()
	master.Write([]byte("hello\n"))
	select {
	case got := <-output:
		if !strings.Contains(got, "received:hello") {
			t.Fatalf("terminal input failed: %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal input hung (background process group?)")
	}
	master.Write([]byte{3})
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 130 {
			t.Fatalf("Ctrl-C status: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ctrl-C did not terminate command")
	}
	waitStopped(t, c, root)
}
