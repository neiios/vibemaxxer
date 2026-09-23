package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFingerprint(t *testing.T) {
	id := testIdentity(t)
	fp := id.fingerprint()
	if len(fp) != 64 {
		t.Fatalf("fingerprint length %d", len(fp))
	}
	got, err := parseFingerprint("  " + strings.ToUpper(fp) + "\n")
	if err != nil || got != fp {
		t.Fatalf("uppercase fingerprint: %q, %v", got, err)
	}
	for _, bad := range []string{"", "abc", fp[:63], fp + "0", strings.Repeat("zz", 32)} {
		if _, err := parseFingerprint(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "identity.pem")
	first, err := loadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.fingerprint() != second.fingerprint() {
		t.Fatal("identity changed between loads")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode %o", info.Mode().Perm())
	}
	if err := os.WriteFile(path, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(path); err == nil {
		t.Fatal("corrupt key accepted")
	}
	if _, err := loadIdentity(""); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestMutualPinning(t *testing.T) {
	server, client, stranger := testIdentity(t), testIdentity(t), testIdentity(t)
	logger, logs := testLogger()
	address := startServer(t, server, map[string]bool{client.fingerprint(): true}, map[int]bool{443: true}, false, logger)

	_, _, status := connect(t, address, client.clientTLS(server.fingerprint()), "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "")
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("authenticated GET status %d", status)
	}

	_, err := tls.Dial("tcp", address, client.clientTLS(stranger.fingerprint()))
	if err == nil || !strings.Contains(err.Error(), server.fingerprint()) {
		t.Fatalf("wrong server pin: %v", err)
	}

	conn, err := tls.Dial("tcp", address, stranger.clientTLS(server.fingerprint()))
	if err == nil {
		io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
	}
	if err == nil {
		t.Fatal("unknown client accepted")
	}
	waitForLog(t, logs, "-client-key "+stranger.fingerprint())

	response, err := http.Get("http://" + address)
	if err == nil {
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext status %d", response.StatusCode)
		}
	}
}
