package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

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

func TestManagedDoesNotAdoptExistingTCPListener(t *testing.T) {
	c, root := managedFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c.Listen = listener.Addr().String()
	start := time.Now()
	if _, err := acquireBridge(c, root, 200*time.Millisecond); err == nil {
		t.Fatal("adopted unrelated TCP listener")
	}
	if time.Since(start) > time.Second {
		t.Fatal("unbounded bind failure")
	}
	conn, err := net.Dial("tcp", c.Listen)
	if err != nil {
		t.Fatalf("disturbed existing listener: %v", err)
	}
	conn.Close()
	data, _ := os.ReadFile(filepath.Join(root, c.digest()) + ".log")
	if !strings.Contains(string(data), "address already in use") {
		t.Fatalf("missing startup diagnosis: %s", data)
	}
	waitStopped(t, c, root)
}

func TestManagedDomainFilePresenceAndValidation(t *testing.T) {
	c, root := managedFixture(t)
	path := filepath.Join(root, "rules")
	os.WriteFile(path, nil, 0600)
	rules, contents, err := snapshotRules(path)
	if err != nil || rules == nil {
		t.Fatalf("empty file must mean direct-all: %v", err)
	}
	empty := c
	empty.Domains = rules
	empty.DomainContents = contents
	if empty.digest() == c.digest() {
		t.Fatal("empty file aliases absent file")
	}
	os.WriteFile(path, []byte("https://invalid.example\n"), 0600)
	if _, _, err := snapshotRules(path); err == nil {
		t.Fatal("accepted malformed rules")
	}
	if _, _, err := snapshotRules(path + "-missing"); err == nil {
		t.Fatal("accepted missing rules")
	}
}
