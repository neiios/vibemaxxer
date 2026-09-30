package proxytest

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

type LogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *LogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *LogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func Logger() (*slog.Logger, *LogBuffer) {
	buf := &LogBuffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

func Identity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Load(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func EchoServer(t *testing.T) (address string, port int) {
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

func Connect(t *testing.T, address string, config *tls.Config, request, early string) (net.Conn, *bufio.Reader, int) {
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

func ConnectRequest(target string) string {
	return "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
}

func AssertEcho(t *testing.T, conn net.Conn, reader *bufio.Reader, alreadySent, payload string) {
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

func ClosedPort(t *testing.T) (address string, port int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	return listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
}

func WaitForLog(t *testing.T, logs *LogBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("want %q in log:\n%s", want, logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
