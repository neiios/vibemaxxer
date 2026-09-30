package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/neiios/vibemaxxer/internal/identity"
)

type managedConfig struct {
	Server, ServerKey, Listen     string
	Key                           []byte
	Block, Domains                domainRules
	BlockContents, DomainContents []byte
	Ports                         map[int]bool
	Grace                         time.Duration
	Executable                    string
}

func (c managedConfig) digest() string {
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:20])
}

func managedSnapshot(server, pin, listen, keyPath, blockPath, domainPath, ports string, grace time.Duration) (managedConfig, error) {
	c := managedConfig{Server: server, Listen: listen, Grace: grace}
	if err := validEndpoint(server); err != nil {
		return c, fmt.Errorf("-server %w", err)
	}
	var err error
	if c.ServerKey, err = identity.ParseFingerprint(pin); err != nil {
		return c, fmt.Errorf("-server-key: %w", err)
	}
	bind, err := netip.ParseAddrPort(listen)
	if err != nil || !bind.Addr().IsLoopback() {
		return c, errors.New("-listen must be a loopback IP:PORT (port 0 selects a free port)")
	}
	if grace < 100*time.Millisecond || grace > time.Minute {
		return c, errors.New("-grace must be between 100ms and 1m")
	}
	if c.Ports, err = parsePorts(ports); err != nil {
		return c, fmt.Errorf("-direct-ports: %w", err)
	}
	if c.Block, c.BlockContents, err = snapshotRules(blockPath); err != nil {
		return c, fmt.Errorf("-blocklist: %w", err)
	}
	if c.Domains, c.DomainContents, err = snapshotRules(domainPath); err != nil {
		return c, fmt.Errorf("-proxy-domains: %w", err)
	}
	id, err := identity.Load(keyPath)
	if err != nil {
		return c, err
	}
	c.Key = id.Key()
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return c, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return c, err
	}
	c.Executable = hex.EncodeToString(h.Sum(nil))
	return c, nil
}

func snapshotRules(path string) (domainRules, []byte, error) {
	if path == "" {
		return nil, nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	rules, err := parseDomainRules(path, string(data))
	return rules, data, err
}

func privateRuntime(path string) (string, error) {
	if path == "" {
		path = filepath.Join("/tmp", "vibemaxxer-"+strconv.Itoa(os.Getuid()))
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			path = filepath.Join(dir, "vibemaxxer")
		}
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("-runtime-dir must be absolute")
	}
	path = filepath.Clean(path)
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || (stat.Uid != 0 && stat.Uid != uint32(os.Getuid())) || (st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0) {
			return "", fmt.Errorf("unsafe runtime ancestor %s", p)
		}
		if p == "/" {
			break
		}
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return "", fmt.Errorf("runtime directory %s must be owned by this user and mode 0700 (no symlinks)", path)
	}
	if len(filepath.Join(path, "0123456789012345678901234567890123456789.sock")) >= 108 {
		return "", errors.New("runtime directory path too long for Unix socket")
	}
	return path, nil
}

func privateFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("unsafe private file %s", path)
	}
	return f, nil
}

func lockUntil(f *os.File, deadline time.Time) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("managed bridge startup timed out waiting for lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

type bridgeLease struct {
	net.Conn
	Address, Log string
}

func connectLease(socket, logPath string, deadline time.Time) (*bridgeLease, error) {
	st, err := os.Lstat(socket)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("unsafe control socket %s", socket)
	}
	conn, err := net.DialTimeout("unix", socket, time.Until(deadline))
	if err != nil {
		return nil, err
	}
	raw, err := conn.(*net.UnixConn).SyscallConn()
	var cred *syscall.Ucred
	if err == nil {
		err = raw.Control(func(fd uintptr) { cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
	}
	if err != nil || cred == nil || cred.Uid != uint32(os.Getuid()) {
		conn.Close()
		return nil, errors.New("control peer is not owned by this user")
	}
	_ = conn.SetDeadline(deadline)
	var address string
	if err := json.NewDecoder(io.LimitReader(conn, 1024)).Decode(&address); err != nil {
		conn.Close()
		return nil, err
	}
	bind, err := netip.ParseAddrPort(address)
	if err != nil || !bind.Addr().IsLoopback() || bind.Port() == 0 {
		conn.Close()
		return nil, errors.New("invalid managed bridge address")
	}
	_ = conn.SetDeadline(time.Time{})
	return &bridgeLease{Conn: conn, Address: address, Log: logPath}, nil
}

func acquireBridge(c managedConfig, runtime string, timeout time.Duration) (*bridgeLease, error) {
	if timeout < 100*time.Millisecond || timeout > time.Minute {
		return nil, errors.New("-startup-timeout must be between 100ms and 1m")
	}
	root, err := privateRuntime(runtime)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(root, c.digest())
	deadline := time.Now().Add(timeout)
	gate, err := privateFile(base + ".lock")
	if err != nil {
		return nil, err
	}
	defer gate.Close()
	if err := lockUntil(gate, deadline); err != nil {
		return nil, err
	}
	defer unlock(gate)
	launched := false
	for time.Now().Before(deadline) {
		if lease, err := connectLease(base+".sock", base+".log", deadline); err == nil {
			return lease, nil
		} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		owner, err := privateFile(base + ".owner")
		if err != nil {
			return nil, err
		}
		err = syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if launched {
				owner.Close()
				return nil, fmt.Errorf("managed bridge exited during startup; see %s.log", base)
			}
			launched = true
			err = launchManaged(c, base, owner)
			owner.Close()
			if err != nil {
				return nil, err
			}
		} else {
			owner.Close()
			if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
				return nil, err
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, fmt.Errorf("managed bridge startup timed out; see %s.log", base)
}

func launchManaged(c managedConfig, base string, owner *os.File) error {
	logFile, err := privateFile(base + ".log")
	if err != nil {
		return err
	}
	defer logFile.Close()
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, logFile.Fd(), syscall.F_SETFL, syscall.O_APPEND); errno != 0 {
		return errno
	}
	snapshot, err := os.CreateTemp(filepath.Dir(base), ".snapshot-")
	if err != nil {
		return err
	}
	defer snapshot.Close()
	if err = os.Remove(snapshot.Name()); err != nil {
		return err
	}
	if err = json.NewEncoder(snapshot).Encode(c); err != nil {
		return err
	}
	if _, err = snapshot.Seek(0, 0); err != nil {
		return err
	}
	cmd := exec.Command("/proc/self/exe", "_managed", base)
	cmd.ExtraFiles = []*os.File{owner, snapshot}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func runManaged(base string) error {
	owner := os.NewFile(3, "owner")
	snapshot := os.NewFile(4, "snapshot")
	defer owner.Close()
	defer snapshot.Close()
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	var c managedConfig
	if err := json.NewDecoder(snapshot).Decode(&c); err != nil {
		return err
	}
	snapshot.Close()
	root, err := privateRuntime(filepath.Dir(base))
	if err != nil {
		return err
	}
	if base != filepath.Join(root, c.digest()) {
		return errors.New("managed snapshot mismatch")
	}
	owned, err := owner.Stat()
	if err != nil {
		return err
	}
	stored, err := os.Lstat(base + ".owner")
	if err != nil || !os.SameFile(owned, stored) {
		return errors.New("invalid managed owner descriptor")
	}
	if err := syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	id, err := identity.FromKey(c.Key)
	if err != nil {
		return err
	}
	direct := newProxy(c.Ports, logger)
	if err := direct.refuseLocalPrefixes(); err != nil {
		return err
	}
	tcp, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	defer tcp.Close()
	if st, err := os.Lstat(base + ".sock"); err == nil {
		if st.Mode()&os.ModeSocket == 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
			return errors.New("unsafe stale control socket")
		}
		if err := os.Remove(base + ".sock"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syscall.Umask(0177)
	control, err := net.ListenUnix("unix", &net.UnixAddr{Name: base + ".sock", Net: "unix"})
	if err != nil {
		return err
	}
	defer control.Close()
	if err := os.Chmod(base+".sock", 0600); err != nil {
		return err
	}
	b := &bridge{server: c.Server, tlsConfig: id.ClientTLS(c.ServerKey), blocklist: c.Block, proxyDomains: c.Domains, direct: direct, logger: logger}
	logger.Info("managed bridge listening", "address", tcp.Addr(), "log", base+".log", "local_prefixes", direct.local)
	go b.probe()
	return serveManaged(control, tcp, b, base+".lock", c.Grace)
}

func serveManaged(control *net.UnixListener, tcp net.Listener, b *bridge, gatePath string, grace time.Duration) error {
	var mu sync.Mutex
	count := 0
	idle := time.Now()
	stopping := false
	failures := make(chan error, 2)
	go func() { failures <- b.serve(tcp) }()
	go func() {
		for {
			conn, err := control.AcceptUnix()
			if err != nil {
				failures <- err
				return
			}
			mu.Lock()
			if stopping {
				mu.Unlock()
				conn.Close()
				continue
			}
			count++
			mu.Unlock()
			go func() {
				defer conn.Close()
				defer func() {
					mu.Lock()
					count--
					if count == 0 {
						idle = time.Now()
					}
					mu.Unlock()
				}()
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if err := json.NewEncoder(conn).Encode(tcp.Addr().String()); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	gate, err := privateFile(gatePath)
	if err != nil {
		return err
	}
	defer gate.Close()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-failures:
			return err
		case <-tick.C:
			if err := syscall.Flock(int(gate.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				continue
			}
			mu.Lock()
			done := count == 0 && time.Since(idle) >= grace
			if done {
				stopping = true
				control.Close()
				tcp.Close()
			}
			mu.Unlock()
			unlock(gate)
			if done {
				b.logger.Info("last lease released; shutting down")
				return nil
			}
		}
	}
}
