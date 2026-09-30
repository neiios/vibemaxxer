package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/neiios/vibemaxxer/internal/identity"
)

func testBridge(t *testing.T, serverAddress string, serverKey string, list domainBlocklist) (address string, logs *logBuffer) {
	t.Helper()
	client := testIdentity(t)
	logger, logs := testLogger()
	b := &bridge{server: serverAddress, tlsConfig: client.ClientTLS(serverKey), blocklist: list, logger: logger}
	return startBridge(t, b), logs
}

func testPair(t *testing.T, list domainBlocklist, ports ...int) (bridgeAddress string, logs *logBuffer) {
	t.Helper()
	server, client := testIdentity(t), testIdentity(t)
	allowed := map[int]bool{443: true}
	for _, port := range ports {
		allowed[port] = true
	}
	serverLogger, _ := testLogger()
	serverAddress := startServer(t, server, map[string]bool{client.Fingerprint(): true}, allowed, true, serverLogger)
	logger, logs := testLogger()
	b := &bridge{server: serverAddress, tlsConfig: client.ClientTLS(server.Fingerprint()), blocklist: list, logger: logger}
	return startBridge(t, b), logs
}

func TestBridgeEndToEnd(t *testing.T) {
	target, port := echoServer(t)
	address, _ := testPair(t, nil, port)
	conn, reader, status := connect(t, address, nil, connectRequest(target), "early")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	assertEcho(t, conn, reader, "early", " and later")

	if _, _, status := connect(t, address, nil, connectRequest("127.0.0.1:22"), ""); status != http.StatusForbidden {
		t.Fatalf("disallowed port status %d", status)
	}
	if _, _, status := connect(t, address, nil, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", ""); status != http.StatusMethodNotAllowed {
		t.Fatalf("GET status %d", status)
	}
	if _, _, status := connect(t, address, nil, connectRequest("nonsense"), ""); status != http.StatusBadRequest {
		t.Fatalf("bad target status %d", status)
	}
}

func TestBridgeBlocklist(t *testing.T) {
	list := domainBlocklist{"blocked.example": true}
	closed, _ := closedPort(t)
	address, logs := testBridge(t, closed, strings.Repeat("0", 64), list)
	for _, target := range []string{"blocked.example:443", "api.BLOCKED.example.:443"} {
		if _, _, status := connect(t, address, nil, connectRequest(target), ""); status != http.StatusForbidden {
			t.Fatalf("%s: status %d", target, status)
		}
	}
	if !strings.Contains(logs.String(), "rule=blocked.example") {
		t.Fatalf("block not logged:\n%s", logs.String())
	}
	if _, _, status := connect(t, address, nil, connectRequest("notblocked.example:443"), ""); status != http.StatusBadGateway {
		t.Fatalf("unblocked status %d", status)
	}
}

func TestBridgeReportsUpstreamFailures(t *testing.T) {
	server, client := testIdentity(t), testIdentity(t)
	logger, _ := testLogger()
	serverAddress := startServer(t, server, map[string]bool{client.Fingerprint(): true}, map[int]bool{443: true}, true, logger)

	address, logs := testBridge(t, serverAddress, strings.Repeat("0", 64), nil)
	if _, _, status := connect(t, address, nil, connectRequest("example.com:443"), ""); status != http.StatusBadGateway {
		t.Fatalf("wrong pin status %d", status)
	}
	if !strings.Contains(logs.String(), server.Fingerprint()) {
		t.Fatalf("mismatch not logged with fingerprint:\n%s", logs.String())
	}

	address, _ = testBridge(t, serverAddress, server.Fingerprint(), nil)
	if _, _, status := connect(t, address, nil, connectRequest("example.com:443"), ""); status != http.StatusBadGateway {
		t.Fatalf("unpaired status %d", status)
	}
}

func TestProbeDistinguishesOutcomes(t *testing.T) {
	server, client, stranger := testIdentity(t), testIdentity(t), testIdentity(t)
	serverLogger, _ := testLogger()
	serverAddress := startServer(t, server, map[string]bool{client.Fingerprint(): true}, map[int]bool{443: true}, true, serverLogger)
	closed, _ := closedPort(t)
	for _, c := range []struct {
		name, server, pin string
		id                *identity.Identity
		want              string
	}{
		{"paired", serverAddress, server.Fingerprint(), client, "upstream verified"},
		{"unknown identity", serverAddress, server.Fingerprint(), stranger, "rejected this identity"},
		{"wrong pin", serverAddress, stranger.Fingerprint(), client, "upstream check failed"},
		{"unreachable", closed, server.Fingerprint(), client, "upstream check failed"},
	} {
		logger, logs := testLogger()
		b := &bridge{server: c.server, tlsConfig: c.id.ClientTLS(c.pin), logger: logger}
		b.probe()
		if !strings.Contains(logs.String(), c.want) {
			t.Errorf("%s: want %q in log:\n%s", c.name, c.want, logs.String())
		}
	}
}

func TestBridgeBoundsUpstreamReply(t *testing.T) {
	saved := upstreamReplyTimeout
	upstreamReplyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { upstreamReplyTimeout = saved })
	server, client := testIdentity(t), testIdentity(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	listener := tls.NewListener(raw, server.ServerTLS(map[string]bool{client.Fingerprint(): true}))
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			return
		}
		_, _ = conn.Read(make([]byte, 1024))
		<-done
	}()
	logger, logs := testLogger()
	address := startBridge(t, &bridge{server: raw.Addr().String(), tlsConfig: client.ClientTLS(server.Fingerprint()), logger: logger})
	started := time.Now()
	_, _, status := connect(t, address, nil, connectRequest("example.com:443"), "")
	if status != http.StatusGatewayTimeout {
		t.Fatalf("status %d", status)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("bridge waited %v for the upstream reply", elapsed)
	}
	if !strings.Contains(logs.String(), "did not answer") {
		t.Fatalf("timeout not logged:\n%s", logs.String())
	}
}
