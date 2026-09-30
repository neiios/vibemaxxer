package managed

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/proxy"
)

func Run(base string) error {
	owner := os.NewFile(3, "owner")
	snapshot := os.NewFile(4, "snapshot")
	defer owner.Close()
	defer snapshot.Close()
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	var c Config
	if err := json.NewDecoder(snapshot).Decode(&c); err != nil {
		return err
	}
	snapshot.Close()
	root, err := RuntimeDir(filepath.Dir(base))
	if err != nil {
		return err
	}
	if base != filepath.Join(root, c.Digest()) {
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
	direct := proxy.NewServer(c.Ports, logger)
	if err := direct.RefuseLocalPrefixes(); err != nil {
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
	b := &proxy.Bridge{Upstream: c.Server, TLSConfig: id.ClientTLS(c.ServerKey), Blocklist: c.Block, ProxyDomains: c.Domains, Direct: direct, Logger: logger}
	logger.Info("managed bridge listening", "address", tcp.Addr(), "log", base+".log", "local_prefixes", direct.LocalPrefixes())
	go b.Probe()
	return serve(control, tcp, b, base+".lock", c.Grace)
}

func serve(control *net.UnixListener, tcp net.Listener, b *proxy.Bridge, gatePath string, grace time.Duration) error {
	var mu sync.Mutex
	count := 0
	idle := time.Now()
	stopping := false
	failures := make(chan error, 2)
	go func() { failures <- b.Serve(tcp) }()
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
				b.Logger.Info("last lease released; shutting down")
				return nil
			}
		}
	}
}
