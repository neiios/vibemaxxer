package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMutualPinning(t *testing.T) {
	server, client, stranger := testIdentity(t), testIdentity(t), testIdentity(t)
	logger, logs := testLogger()
	address := startServer(t, server, map[string]bool{client.Fingerprint(): true}, map[int]bool{443: true}, false, logger)

	_, _, status := connect(t, address, client.ClientTLS(server.Fingerprint()), "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "")
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("authenticated GET status %d", status)
	}

	_, err := tls.Dial("tcp", address, client.ClientTLS(stranger.Fingerprint()))
	if err == nil || !strings.Contains(err.Error(), server.Fingerprint()) {
		t.Fatalf("wrong server pin: %v", err)
	}

	conn, err := tls.Dial("tcp", address, stranger.ClientTLS(server.Fingerprint()))
	if err == nil {
		io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
	}
	if err == nil {
		t.Fatal("unknown client accepted")
	}
	waitForLog(t, logs, "-client-key "+stranger.Fingerprint())

	response, err := http.Get("http://" + address)
	if err == nil {
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext status %d", response.StatusCode)
		}
	}
}
