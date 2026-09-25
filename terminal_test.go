package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

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
