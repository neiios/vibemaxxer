package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neiios/vibemaxxer/internal/identity"
)

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func testLogger() (*slog.Logger, *logBuffer) {
	buf := &logBuffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Load(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func startServer(t *testing.T, id *identity.Identity, clients map[string]bool, ports map[int]bool, allowPrivate bool, logger *slog.Logger) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newProxy(ports, logger)
	p.allowPrivate = allowPrivate
	server := &http.Server{Handler: p, ReadHeaderTimeout: headerTimeout,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn)}
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)
	go server.Serve(tls.NewListener(listener, id.ServerTLS(clients)))
	t.Cleanup(func() { server.Close() })
	return listener.Addr().String()
}

func echoServer(t *testing.T) (address string, port int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
}

func startBridge(t *testing.T, b *bridge) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.serve(listener)
	t.Cleanup(func() { listener.Close() })
	return listener.Addr().String()
}

func connect(t *testing.T, address string, config *tls.Config, request, early string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	var conn net.Conn
	var err error
	if config != nil {
		conn, err = tls.Dial("tcp", address, config)
	} else {
		conn, err = net.Dial("tcp", address)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := io.WriteString(conn, request+early); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, response.Body)
	}
	response.Body.Close()
	return conn, reader, response.StatusCode
}

func connectRequest(target string) string {
	return "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
}

func assertEcho(t *testing.T, conn net.Conn, reader *bufio.Reader, alreadySent, payload string) {
	t.Helper()
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != alreadySent+payload {
		t.Fatalf("echo = %q, want %q", got, alreadySent+payload)
	}
}

func closedPort(t *testing.T) (address string, port int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	return listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
}

func waitForLog(t *testing.T, logs *logBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("want %q in log:\n%s", want, logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
