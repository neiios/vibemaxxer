package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/neiios/vibemaxxer/internal/managed"
	"github.com/neiios/vibemaxxer/internal/proxytest"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "_managed":
			os.Exit(Main(os.Args[1:]))
		case "_test-run":
			os.Exit(Main(os.Args[2:]))
		case "_test-child":
			switch os.Args[2] {
			case "fds":
				entries, _ := os.ReadDir("/proc/self/fd")
				for _, e := range entries {
					target, _ := os.Readlink("/proc/self/fd/" + e.Name())
					if strings.HasPrefix(target, "socket:") || strings.Contains(target, ".owner") || strings.Contains(target, ".lock") || strings.Contains(target, ".snapshot-") {
						fmt.Fprintln(os.Stderr, "leaked descriptor:", target)
						os.Exit(90)
					}
				}
				if !strings.HasPrefix(os.Getenv("HTTPS_PROXY"), "http://127.0.0.1:") {
					os.Exit(91)
				}
				os.Exit(7)
			case "tty":
				terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
				if err != nil {
					os.Exit(92)
				}
				terminal.Close()
				_ = os.WriteFile(os.Args[3], []byte("ready"), 0600)
				line, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil {
					os.Exit(93)
				}
				fmt.Printf("received:%s", line)
				for {
					time.Sleep(time.Second)
				}
			case "wait":
				_ = os.WriteFile(os.Args[3], []byte(os.Getenv("HTTPS_PROXY")), 0600)
				for {
					time.Sleep(time.Second)
				}
			}
		}
	}
	os.Exit(m.Run())
}

func managedFixture(t *testing.T) (managed.Config, string) {
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
	key := filepath.Join(root, "identity.pem")
	server, _ := proxytest.ClosedPort(t)
	c, err := managed.Snapshot(server, strings.Repeat("ab", 32), "127.0.0.1:0", key, "", "", "443", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return c, root
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

func managedRunArgs(c managed.Config, root string, child ...string) []string {
	args := []string{"_test-run", "run", "-server", c.Server, "-server-key", c.ServerKey, "-key", filepath.Join(root, "identity.pem"), "-runtime-dir", root, "-grace", c.Grace.String(), "--"}
	return append(args, child...)
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

func TestExternalRunStillExecs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "_test-run", "run", "-bridge", listener.Addr().String(), "--", exe, "_test-child", "fds")
	output, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 7 {
		t.Fatalf("external mode: %v %s", err, output)
	}
	if strings.Contains(string(output), "log:") {
		t.Fatal("external mode launched managed bridge")
	}
}

func TestManagedSupervisorExitAndFDs(t *testing.T) {
	c, root := managedFixture(t)
	exe, _ := os.Executable()
	cmd := exec.Command(exe, managedRunArgs(c, root, exe, "_test-child", "fds")...)
	output, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 7 {
		t.Fatalf("exit/descriptor test: %v %s", err, output)
	}
	if !strings.Contains(string(output), "log:") {
		t.Fatal("log path not printed")
	}
	waitStopped(t, c, root)
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
