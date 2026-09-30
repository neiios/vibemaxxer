package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/neiios/vibemaxxer/internal/managed"
)

type commandExit struct{ code int }

func (e commandExit) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func runRun(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	bridgeAddress := flags.String("bridge", "127.0.0.1:8888", "address of the running bridge (external mode)")
	server := flags.String("server", "", "VPN server; enables on-demand managed mode")
	pin := flags.String("server-key", "", "pinned VPN server fingerprint")
	listen := flags.String("listen", "127.0.0.1:0", "managed loopback listener; 0 chooses a free port")
	block := flags.String("blocklist", "", "domain blocklist file")
	domains := flags.String("proxy-domains", "", "selective VPN domain file")
	ports := flags.String("direct-ports", "443", "allowed direct destination ports")
	key := keyFlag(flags)
	grace := flags.Duration("grace", 3*time.Second, "managed idle shutdown grace")
	timeout := flags.Duration("startup-timeout", 15*time.Second, "maximum managed startup wait")
	if err := flags.Parse(args); err != nil {
		return err
	}
	command := flags.Args()
	if len(command) == 0 {
		return errors.New("usage: vibemaxxer run [-bridge IP:PORT] -- COMMAND [ARGS...]")
	}
	explicitBridge, managedFlags := false, false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "bridge" {
			explicitBridge = true
		} else {
			managedFlags = true
		}
	})
	if *server != "" {
		if explicitBridge {
			return errors.New("-bridge cannot be combined with managed mode flags")
		}
		c, err := managed.Snapshot(*server, *pin, *listen, *key, *block, *domains, *ports, *grace)
		if err != nil {
			return err
		}
		lease, err := managed.Acquire(c, *timeout)
		if err != nil {
			return err
		}
		defer lease.Close()
		fmt.Fprintf(os.Stderr, "vibemaxxer: bridge %s; log: %s\n", lease.Address, lease.Log)
		return supervise(command, lease)
	}
	if managedFlags {
		return errors.New("managed flags require -server and -server-key")
	}
	conn, err := net.DialTimeout("tcp", *bridgeAddress, 2*time.Second)
	if err != nil {
		return fmt.Errorf("no bridge at %s; start 'vibemaxxer bridge' first", *bridgeAddress)
	}
	conn.Close()
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, command, proxyEnv(os.Environ(), *bridgeAddress))
}

var proxyVariables = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"}

func proxyEnv(environ []string, bridgeAddress string) []string {
	var noProxy []string
	env := make([]string, 0, len(environ)+6)
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if upper == "NO_PROXY" {
			for _, item := range strings.Split(value, ",") {
				if item = strings.TrimSpace(item); item != "" && !slices.Contains(noProxy, item) {
					noProxy = append(noProxy, item)
				}
			}
		}
		if !slices.Contains(proxyVariables, upper) {
			env = append(env, entry)
		}
	}
	for _, item := range []string{"localhost", "127.0.0.1", "::1"} {
		if !slices.Contains(noProxy, item) {
			noProxy = append(noProxy, item)
		}
	}
	url := "http://" + bridgeAddress
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY"} {
		env = append(env, name+"="+url, strings.ToLower(name)+"="+url)
	}
	joined := strings.Join(noProxy, ",")
	return append(env, "NO_PROXY="+joined, "no_proxy="+joined)
}

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
