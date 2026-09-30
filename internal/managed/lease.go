package managed

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Lease struct {
	net.Conn
	Address, Log string
}

func connectLease(socket, logPath string, deadline time.Time) (*Lease, error) {
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
	return &Lease{Conn: conn, Address: address, Log: logPath}, nil
}

func Acquire(c Config, runtime string, timeout time.Duration) (*Lease, error) {
	if timeout < 100*time.Millisecond || timeout > time.Minute {
		return nil, errors.New("-startup-timeout must be between 100ms and 1m")
	}
	root, err := RuntimeDir(runtime)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(root, c.Digest())
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
			err = launch(c, base, owner)
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
