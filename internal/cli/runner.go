package cli

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/neiios/vibemaxxer/internal/policy"
)

const runnerHeader = `Usage: vibemaxxer run --rules FILE [OPTION...] [--] COMMAND [ARG...]

Starts a proxy on a free loopback port, runs COMMAND through it, and
exits with COMMAND's status. The proxy lives exactly as long as COMMAND.
A run started from inside another run with the same rules and upstream
shares the outer proxy.`

const (
	runMarker    = "VIBEMAXXER_RUN"
	maxLogSize   = 10 << 20
	drainTimeout = 500 * time.Millisecond
)

type exitStatus int

func (e exitStatus) Error() string { return "exit status " + strconv.Itoa(int(e)) }

func runCommand(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	var opts options
	opts.flags(flags, policy.Client)
	logPath := flags.String("log", defaultLogPath(), "append the request log to `FILE`")
	if err := parseOptions(flags, runnerHeader, args); err != nil {
		return err
	}
	command := flags.Args()
	if len(command) == 0 {
		return errors.New("missing COMMAND; see vibemaxxer run --help")
	}
	if err := opts.validate(); err != nil {
		return err
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	digest, err := opts.digest()
	if err != nil {
		return err
	}
	for _, name := range []string{"ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		if err := os.Unsetenv(name); err != nil {
			return err
		}
	}
	if address, ok := outerProxy(os.Getenv(runMarker), digest); ok {
		if err := setProxy(address); err != nil {
			return err
		}
		return syscall.Exec(path, command, os.Environ())
	}

	logger, err := openLog(*logPath, command[0])
	if err != nil {
		return err
	}
	p, _, err := opts.proxy("client", policy.Client, logger)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	identity := "/" + hex.EncodeToString(nonce) + "/" + digest
	var requests sync.WaitGroup
	server := p.Server()
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Host == "" && r.URL.Path == identity {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		requests.Add(1)
		defer requests.Done()
		p.ServeHTTP(w, r)
	})
	go server.Serve(listener)

	address := listener.Addr().String()
	if err := setProxy(address); err != nil {
		return err
	}
	if err := os.Setenv(runMarker, address+"/"+hex.EncodeToString(nonce)); err != nil {
		return err
	}
	logger.Info("listening", "mode", "run", "address", address, "rules", opts.rules, "upstream", cmp.Or(opts.lan.server, opts.upstream), "transport", opts.transport())
	status, err := supervise(path, command, os.Environ())
	if err != nil {
		return err
	}
	listener.Close()
	finished := make(chan struct{})
	go func() { requests.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(drainTimeout):
	}
	if status.Signaled() {
		logger.Info("exited", "signal", status.Signal())
		return dieFrom(status.Signal())
	}
	logger.Info("exited", "status", status.ExitStatus())
	return exitStatus(status.ExitStatus())
}

func (o *options) digest() (string, error) {
	rules, err := os.ReadFile(o.rules)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	for _, part := range [][]byte{rules, []byte(o.upstream), []byte(o.lan.server), []byte(o.lan.serverKey), []byte(o.lan.key)} {
		fmt.Fprintf(hash, "%d:", len(part))
		hash.Write(part)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func outerProxy(marker, digest string) (string, bool) {
	address, nonce, ok := strings.Cut(marker, "/")
	if !ok || loopback(runMarker, address) != nil {
		return "", false
	}
	client := http.Client{Timeout: time.Second, Transport: &http.Transport{}}
	resp, err := client.Get((&url.URL{Scheme: "http", Host: address, Path: "/" + nonce + "/" + digest}).String())
	if err != nil {
		return "", false
	}
	resp.Body.Close()
	return address, resp.StatusCode == http.StatusNoContent
}

func setProxy(address string) error {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if err := os.Setenv(name, "http://"+address); err != nil {
			return err
		}
	}
	return nil
}

func defaultLogPath() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(dir) {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "vibemaxxer", "run.log")
}

func openLog(path, command string) (*slog.Logger, error) {
	var out io.Writer = io.Discard
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Size() > maxLogSize {
			if err := os.Rename(path, path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		out = file
	}
	return slog.New(slog.NewTextHandler(out, nil)).With("pid", os.Getpid(), "command", filepath.Base(command)), nil
}

func supervise(path string, args, env []string) (syscall.WaitStatus, error) {
	runtime.LockOSThread()
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2,
		syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
	pid, err := syscall.ForkExec(path, args, &syscall.ProcAttr{
		Env:   env,
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM},
	})
	if err != nil {
		return 0, err
	}
	go func() {
		for sig := range signals {
			switch sig := sig.(syscall.Signal); sig {
			case syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU:
			case syscall.SIGINT, syscall.SIGQUIT:
				if !inForeground() {
					_ = syscall.Kill(pid, sig)
				}
			default:
				_ = syscall.Kill(pid, sig)
			}
		}
	}()
	for {
		var status syscall.WaitStatus
		_, err := syscall.Wait4(pid, &status, syscall.WUNTRACED, nil)
		switch {
		case errors.Is(err, syscall.EINTR):
		case err != nil:
			return 0, err
		case status.Stopped():
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
			_ = syscall.Kill(pid, syscall.SIGCONT)
		default:
			return status, nil
		}
	}
}

func inForeground() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		return false
	}
	defer tty.Close()
	var foreground int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TIOCGPGRP, uintptr(unsafe.Pointer(&foreground)))
	return errno == 0 && int(foreground) == syscall.Getpgrp()
}

func dieFrom(sig syscall.Signal) error {
	switch sig {
	case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL:
		signal.Reset(sig)
		_ = syscall.Kill(syscall.Getpid(), sig)
		time.Sleep(time.Second)
	}
	return exitStatus(128 + int(sig))
}
