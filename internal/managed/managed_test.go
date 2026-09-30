package managed

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/neiios/vibemaxxer/internal/proxytest"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "_managed" {
		if err := Run(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "exiting:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func managedFixture(t *testing.T) (Config, string) {
	t.Helper()
	root, err := os.MkdirTemp("", "vmx-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if os.Getenv("VIBEMAXXER_TEST_NIX_SANDBOX") == "1" {
		if _, err := RuntimeDir(root); err != nil {
			t.Skipf("Nix sandbox cannot provide a trusted runtime ancestry: %v", err)
		}
	}
	key := filepath.Join(root, "identity.pem")
	server, _ := proxytest.ClosedPort(t)
	c, err := Snapshot(server, strings.Repeat("ab", 32), "127.0.0.1:0", key, "", "", "443", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return c, root
}
func mustLease(t *testing.T, c Config, root string) *Lease {
	t.Helper()
	lease, err := Acquire(c, root, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Close() })
	return lease
}
func waitStopped(t *testing.T, c Config, root string) {
	t.Helper()
	base := filepath.Join(root, c.Digest())
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_, err := os.Lstat(base + ".sock")
		if os.IsNotExist(err) {
			f, e := privateFile(base + ".owner")
			if e == nil {
				e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
				f.Close()
				if e == nil {
					return
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	logs, _ := os.ReadFile(base + ".log")
	t.Fatalf("bridge did not stop: %s", logs)
}
func leasePID(t *testing.T, l *Lease) int {
	t.Helper()
	raw, err := l.Conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cred *syscall.Ucred
	raw.Control(func(fd uintptr) {
		cred, err = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		t.Fatal(err)
	}
	return int(cred.Pid)
}

func TestManagedConcurrentLifecycle(t *testing.T) {
	c, root := managedFixture(t)
	const n = 24
	leases := make([]*Lease, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := range leases {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			leases[i], err = Acquire(c, root, 4*time.Second)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, l := range leases {
			l.Close()
		}
	}()
	for _, l := range leases {
		if l.Address != leases[0].Address || leasePID(t, l) != leasePID(t, leases[0]) {
			t.Fatal("concurrent launchers did not share daemon")
		}
	}
	for _, l := range leases[1:] {
		l.Close()
	}
	time.Sleep(2 * c.Grace)
	again := mustLease(t, c, root)
	if again.Address != leases[0].Address {
		t.Fatal("bridge stopped with a live lease")
	}
	again.Close()
	leases[0].Close()
	time.Sleep(c.Grace / 3)
	rejoin := mustLease(t, c, root)
	if rejoin.Address != leases[0].Address {
		t.Fatal("bridge not reused during grace")
	}
	time.Sleep(2 * c.Grace)
	rejoin.Close()
	waitStopped(t, c, root)
	restarted := mustLease(t, c, root)
	restarted.Close()
	waitStopped(t, c, root)
	logData, err := os.ReadFile(restarted.Log)
	if err != nil || !strings.Contains(string(logData), "last lease released") {
		t.Fatalf("missing persistent lifecycle log: %s %v", logData, err)
	}
}

func TestManagedShutdownRegistrationRace(t *testing.T) {
	c, root := managedFixture(t)
	c.Grace = 100 * time.Millisecond
	for i := 0; i < 12; i++ {
		l := mustLease(t, c, root)
		l.Close()
		time.Sleep(c.Grace + time.Duration(i%3-1)*5*time.Millisecond)
		l = mustLease(t, c, root)
		time.Sleep(2 * c.Grace)
		conn, err := net.DialTimeout("tcp", l.Address, time.Second)
		if err != nil {
			t.Fatalf("registered lease lost to shutdown: %v", err)
		}
		conn.Close()
		l.Close()
	}
	waitStopped(t, c, root)
}

func TestManagedCrashRecovery(t *testing.T) {
	c, root := managedFixture(t)
	l := mustLease(t, c, root)
	pid := leasePID(t, l)
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err != nil || cwd != "/" {
		t.Fatalf("daemon cwd %q %v", cwd, err)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	l.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := l.Read(make([]byte, 1)); err == nil {
		t.Fatal("lease survived daemon crash")
	}
	l.Close()
	next := mustLease(t, c, root)
	if leasePID(t, next) == pid {
		t.Fatal("did not replace crashed daemon")
	}
	next.Close()
	waitStopped(t, c, root)
}

func TestManagedConfigSnapshots(t *testing.T) {
	c, root := managedFixture(t)
	block, domains := filepath.Join(root, "block"), filepath.Join(root, "domains")
	os.WriteFile(block, []byte("blocked.example\n"), 0600)
	os.WriteFile(domains, []byte("vpn.example\n"), 0600)
	snapshot := func() Config {
		x, err := Snapshot(c.Server, c.ServerKey, c.Listen, filepath.Join(root, "identity.pem"), block, domains, "443", c.Grace)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	first := snapshot()
	if first.Digest() != snapshot().Digest() {
		t.Fatal("unstable digest")
	}
	a := mustLease(t, first, root)
	os.WriteFile(block, []byte("other.example\n"), 0600)
	second := snapshot()
	if first.Digest() == second.Digest() {
		t.Fatal("rule contents missing from key")
	}
	b := mustLease(t, second, root)
	if a.Address == b.Address {
		t.Fatal("different configs shared listener")
	}
	_, _, status := proxytest.Connect(t, a.Address, nil, proxytest.ConnectRequest("blocked.example:443"), "")
	if status != 403 {
		t.Fatalf("snapshot blocklist changed: %d", status)
	}
	conn, _, status := proxytest.Connect(t, a.Address, nil, proxytest.ConnectRequest("vpn.example:443"), "")
	conn.Close()
	if status != 502 {
		t.Fatalf("VPN route did not fail closed: %d", status)
	}
	data, _ := os.ReadFile(a.Log)
	if !strings.Contains(string(data), "destination blocked") || !strings.Contains(string(data), "no direct fallback") {
		t.Fatalf("missing diagnostics: %s", data)
	}
	for name, modify := range map[string]func(*Config){
		"server":          func(x *Config) { x.Server = "other:443" },
		"pin":             func(x *Config) { x.ServerKey = strings.Repeat("cd", 32) },
		"listen":          func(x *Config) { x.Listen = "127.0.0.1:8889" },
		"identity":        func(x *Config) { x.Key = []byte("other") },
		"ports":           func(x *Config) { x.Ports = map[int]bool{8443: true} },
		"binary":          func(x *Config) { x.Executable = "new version" },
		"grace":           func(x *Config) { x.Grace = time.Second },
		"domain contents": func(x *Config) { x.DomainContents = []byte("# comment\nvpn.example\n") },
		"empty vs absent": func(x *Config) { x.Domains = nil },
	} {
		t.Run(name, func(t *testing.T) {
			copy := first
			modify(&copy)
			if copy.Digest() == first.Digest() {
				t.Fatal("configuration collision")
			}
		})
	}
	a.Close()
	b.Close()
	waitStopped(t, first, root)
	waitStopped(t, second, root)
}

func TestManagedPrivateState(t *testing.T) {
	_, root := managedFixture(t)
	for _, mode := range []os.FileMode{0755, 0777, 0710} {
		os.Chmod(root, mode)
		if _, err := RuntimeDir(root); err == nil {
			t.Fatalf("accepted mode %o", mode)
		}
	}
	os.Chmod(root, 0700)
	link := root + "-link"
	os.Symlink(root, link)
	defer os.Remove(link)
	if _, err := RuntimeDir(link); err == nil {
		t.Fatal("accepted runtime symlink")
	}
	if _, err := RuntimeDir("relative"); err == nil {
		t.Fatal("accepted relative runtime")
	}
	if _, err := RuntimeDir(filepath.Join(link, "nested")); err == nil {
		t.Fatal("accepted symlink ancestor")
	}
	target := filepath.Join(root, "target")
	os.WriteFile(target, []byte("do not touch"), 0600)
	sym := filepath.Join(root, "sym")
	os.Symlink(target, sym)
	if f, err := privateFile(sym); err == nil {
		f.Close()
		t.Fatal("accepted symlink file")
	}
	hard := filepath.Join(root, "hard")
	os.Link(target, hard)
	if f, err := privateFile(hard); err == nil {
		f.Close()
		t.Fatal("accepted hardlinked file")
	}
	os.Remove(hard)
	os.Chmod(target, 0644)
	if f, err := privateFile(target); err == nil {
		f.Close()
		t.Fatal("accepted public file")
	}
	fifo := filepath.Join(root, "fifo")
	syscall.Mkfifo(fifo, 0600)
	if f, err := privateFile(fifo); err == nil {
		f.Close()
		t.Fatal("accepted FIFO")
	}
	if os.Getuid() == 0 {
		os.Chown(root, 12345, 12345)
		if _, err := RuntimeDir(root); err == nil {
			t.Fatal("accepted foreign owner")
		}
		os.Chown(root, 0, 0)
	}
}

func TestManagedStartupBounded(t *testing.T) {
	c, root := managedFixture(t)
	gate, err := privateFile(filepath.Join(root, c.Digest()) + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	syscall.Flock(int(gate.Fd()), syscall.LOCK_EX)
	start := time.Now()
	if _, err := Acquire(c, root, 150*time.Millisecond); err == nil {
		t.Fatal("accepted held startup lock")
	}
	if time.Since(start) > time.Second {
		t.Fatal("startup lock wait not bounded")
	}
	unlock(gate)
	owner, err := privateFile(filepath.Join(root, c.Digest()) + ".owner")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	syscall.Flock(int(owner.Fd()), syscall.LOCK_EX)
	start = time.Now()
	if _, err := Acquire(c, root, 150*time.Millisecond); err == nil {
		t.Fatal("accepted unready owner")
	}
	if time.Since(start) > time.Second {
		t.Fatal("startup readiness wait not bounded")
	}
	unlock(owner)
	l := mustLease(t, c, root)
	l.Close()
	waitStopped(t, c, root)
}

func TestManagedRejectUnsafeSocketAndStaleRecovery(t *testing.T) {
	c, root := managedFixture(t)
	socket := filepath.Join(root, c.Digest()) + ".sock"
	os.WriteFile(socket, []byte("not a socket"), 0600)
	if _, err := Acquire(c, root, time.Second); err == nil {
		t.Fatal("accepted non-socket control file")
	}
	data, _ := os.ReadFile(socket)
	if string(data) != "not a socket" {
		t.Fatal("overwrote unsafe control file")
	}
	os.Remove(socket)
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	os.Chmod(socket, 0600)
	l := mustLease(t, c, root)
	l.Close()
	waitStopped(t, c, root)
}

func TestManagedLeaseDisconnect(t *testing.T) {
	c, root := managedFixture(t)
	l := mustLease(t, c, root)
	raw, err := net.Dial("unix", filepath.Join(root, c.Digest())+".sock")
	if err != nil {
		t.Fatal(err)
	}
	var addr string
	if err = json.NewDecoder(bufio.NewReader(raw)).Decode(&addr); err != nil {
		t.Fatal(err)
	}
	l.Close()
	time.Sleep(2 * c.Grace)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")
	conn.Close()
	raw.Close()
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
	if _, err := Acquire(c, root, 200*time.Millisecond); err == nil {
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
	data, _ := os.ReadFile(filepath.Join(root, c.Digest()) + ".log")
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
	if empty.Digest() == c.Digest() {
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
