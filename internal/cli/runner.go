package cli

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const runnerUsage = "usage: vibemaxxer run [--remote] [--] COMMAND [ARG...]"

const runnerHelp = `Usage: vibemaxxer run [--remote] [--] COMMAND [ARG...]

Starts the proxy, runs COMMAND through it, and stops the proxy when
the last command exits. Needs the systemd user units from the docs.

Options:
  --remote     also start the SSH tunnel
  -h, --help   show this help`

func runCommand(args []string) error {
	remote := false
parse:
	for len(args) > 0 {
		switch args[0] {
		case "--remote":
			remote = true
			args = args[1:]
		case "--":
			args = args[1:]
			break parse
		case "-h", "-help", "--help":
			fmt.Fprintln(os.Stdout, runnerHelp)
			return flag.ErrHelp
		default:
			if strings.HasPrefix(args[0], "-") {
				return fmt.Errorf("unknown run option %q; %s", args[0], runnerUsage)
			}
			break parse
		}
	}
	if len(args) == 0 {
		return errors.New(runnerUsage)
	}

	if os.Getenv("VIBEMAXXER_RUN_SCOPE") == "" {
		target := "vibemaxxer.target"
		if remote {
			target = "vibemaxxer-remote.target"
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		command := []string{"systemd-run", "--user", "--scope", "--quiet",
			"-p", "Wants=" + target, "-p", "After=" + target, "--", self, "run"}
		if remote {
			command = append(command, "--remote")
		}
		command = append(command, "--")
		command = append(command, args...)
		if err := os.Setenv("VIBEMAXXER_RUN_SCOPE", "1"); err != nil {
			return err
		}
		return execCommand(command, os.Environ())
	}
	if err := os.Unsetenv("VIBEMAXXER_RUN_SCOPE"); err != nil {
		return err
	}

	if err := waitForProxy(remote, 100, 200*time.Millisecond); err != nil {
		return err
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if err := os.Setenv(name, "http://127.0.0.1:8080"); err != nil {
			return err
		}
	}
	return execCommand(args, os.Environ())
}

func waitForProxy(remote bool, attempts int, delay time.Duration) error {
	ready := func(address string) bool {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}
	for range attempts {
		if ready("127.0.0.1:8080") && (!remote || ready("127.0.0.1:18080")) {
			return nil
		}
		time.Sleep(delay)
	}
	if remote {
		return errors.New("proxy or tunnel is not up; see journalctl --user -u \"vibemaxxer-*\"")
	}
	return errors.New("proxy is not up; see journalctl --user -u vibemaxxer-client")
}

func execCommand(args, env []string) error {
	path, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, args, env)
}
