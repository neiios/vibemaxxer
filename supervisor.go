package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/neiios/vibemaxxer/internal/managed"
)

type commandExit struct{ code int }

func (e commandExit) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func supervise(args []string, lease *managed.Lease) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = proxyEnv(os.Environ(), lease.Address)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	lost := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, lease.Conn); close(lost) }()
	for {
		select {
		case sig := <-signals:
			_ = cmd.Process.Signal(sig)
		case <-lost:
			fmt.Fprintln(os.Stderr, "vibemaxxer: shared bridge disconnected; VPN requests will fail (no direct fallback)")
			lost = nil
		case err := <-done:
			if err == nil {
				return nil
			}
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				status := exit.Sys().(syscall.WaitStatus)
				if status.Signaled() {
					return commandExit{128 + int(status.Signal())}
				}
				return commandExit{exit.ExitCode()}
			}
			return err
		}
	}
}
