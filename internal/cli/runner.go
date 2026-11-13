package cli

import (
	"errors"
	"flag"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const runnerHeader = `Usage: vibemaxxer run [OPTION...] [--] COMMAND [ARG...]

Starts the proxy, runs COMMAND through it, and stops the proxy when
the last command exits. It needs the systemd user units described in
docs/run.md.`

func runCommand(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	remote := flags.Bool("remote", false, "also start the SSH tunnel")
	proxy := flags.String("proxy", "127.0.0.1:9878", "use the client listening on `ADDR`")
	tunnel := flags.String("tunnel", "127.0.0.1:19878", "with --remote, wait for the SSH forward at `ADDR`")
	if err := parseOptions(flags, runnerHeader, args); err != nil {
		return err
	}
	args = flags.Args()
	if len(args) == 0 {
		return errors.New("missing COMMAND; see vibemaxxer run --help")
	}
	if err := loopback("--proxy", *proxy); err != nil {
		return err
	}
	if err := loopback("--tunnel", *tunnel); err != nil {
		return err
	}

	if os.Getenv("VIBEMAXXER_RUN_SCOPE") == "" {
		target := "vibemaxxer.target"
		if *remote {
			target = "vibemaxxer-remote.target"
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		command := []string{"systemd-run", "--user", "--scope", "--quiet",
			"-p", "Wants=" + target, "-p", "After=" + target, "--",
			self, "run", "--proxy", *proxy, "--tunnel", *tunnel}
		if *remote {
			command = append(command, "--remote")
		}
		command = append(command, "--")
		command = append(command, args...)
		if err := os.Setenv("VIBEMAXXER_RUN_SCOPE", "1"); err != nil {
			return err
		}
		return execCommand(command, os.Environ())
	}
	for _, name := range []string{"VIBEMAXXER_RUN_SCOPE", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		if err := os.Unsetenv(name); err != nil {
			return err
		}
	}

	wait := ""
	if *remote {
		wait = *tunnel
	}
	if err := waitForProxy(*proxy, wait, 100, 200*time.Millisecond); err != nil {
		return err
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if err := os.Setenv(name, "http://"+*proxy); err != nil {
			return err
		}
	}
	return execCommand(args, os.Environ())
}

func waitForProxy(proxy, tunnel string, attempts int, delay time.Duration) error {
	ready := func(address string) bool {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}
	for range attempts {
		if ready(proxy) && (tunnel == "" || ready(tunnel)) {
			return nil
		}
		time.Sleep(delay)
	}
	if tunnel != "" {
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
