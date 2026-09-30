package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/neiios/vibemaxxer/internal/domain"
	"github.com/neiios/vibemaxxer/internal/proxytest"
)

func testBridge(t *testing.T, serverAddress string, serverKey string, list domain.Rules) (address string, logs *proxytest.LogBuffer) {
	t.Helper()
	client := proxytest.Identity(t)
	logger, logs := proxytest.Logger()
	b := &Bridge{Upstream: serverAddress, TLSConfig: client.ClientTLS(serverKey), Blocklist: list, Logger: logger}
	return startBridge(t, b), logs
}

func testPair(t *testing.T, list domain.Rules, ports ...int) (bridgeAddress string, logs *proxytest.LogBuffer) {
	t.Helper()
	server, client := proxytest.Identity(t), proxytest.Identity(t)
	allowed := map[int]bool{443: true}
	for _, port := range ports {
		allowed[port] = true
	}
	serverLogger, _ := proxytest.Logger()
	serverAddress := startServer(t, server, map[string]bool{client.Fingerprint(): true}, allowed, true, serverLogger)
	logger, logs := proxytest.Logger()
	b := &Bridge{Upstream: serverAddress, TLSConfig: client.ClientTLS(server.Fingerprint()), Blocklist: list, Logger: logger}
	return startBridge(t, b), logs
}

func TestBridgeEndToEnd(t *testing.T) {
	target, port := proxytest.EchoServer(t)
	address, _ := testPair(t, nil, port)
	conn, reader, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest(target), "early")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	proxytest.AssertEcho(t, conn, reader, "early", " and later")

	if _, _, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest("127.0.0.1:22"), ""); status != http.StatusForbidden {
		t.Fatalf("disallowed port status %d", status)
	}
	if _, _, status := proxytest.Connect(t, address, nil, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", ""); status != http.StatusMethodNotAllowed {
		t.Fatalf("GET status %d", status)
	}
	if _, _, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest("nonsense"), ""); status != http.StatusBadRequest {
		t.Fatalf("bad target status %d", status)
	}
}

func TestBridgeBlocklist(t *testing.T) {
	list := domain.Rules{"blocked.example": true}
	closed, _ := proxytest.ClosedPort(t)
	address, logs := testBridge(t, closed, strings.Repeat("0", 64), list)
	for _, target := range []string{"blocked.example:443", "api.BLOCKED.example.:443"} {
		if _, _, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest(target), ""); status != http.StatusForbidden {
			t.Fatalf("%s: status %d", target, status)
		}
	}
	if !strings.Contains(logs.String(), "rule=blocked.example") {
		t.Fatalf("block not logged:\n%s", logs.String())
	}
	if _, _, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest("notblocked.example:443"), ""); status != http.StatusBadGateway {
		t.Fatalf("unblocked status %d", status)
	}
}

func TestBridgeReportsUpstreamFailures(t *testing.T) {
	server, client := proxytest.Identity(t), proxytest.Identity(t)
	logger, _ := proxytest.Logger()
	serverAddress := startServer(t, server, map[string]bool{client.Fingerprint(): true}, map[int]bool{443: true}, true, logger)

	address, logs := testBridge(t, serverAddress, strings.Repeat("0", 64), nil)
	if _, _, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest("example.com:443"), ""); status != http.StatusBadGateway {
		t.Fatalf("wrong pin status %d", status)
	}
	if !strings.Contains(logs.String(), server.Fingerprint()) {
		t.Fatalf("mismatch not logged with fingerprint:\n%s", logs.String())
	}

	address, _ = testBridge(t, serverAddress, server.Fingerprint(), nil)
	if _, _, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest("example.com:443"), ""); status != http.StatusBadGateway {
		t.Fatalf("unpaired status %d", status)
	}
}

func TestBridgeBoundsUpstreamReply(t *testing.T) {
	saved := upstreamReplyTimeout
	upstreamReplyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { upstreamReplyTimeout = saved })
	server, client := proxytest.Identity(t), proxytest.Identity(t)
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
	logger, logs := proxytest.Logger()
	address := startBridge(t, &Bridge{Upstream: raw.Addr().String(), TLSConfig: client.ClientTLS(server.Fingerprint()), Logger: logger})
	started := time.Now()
	_, _, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest("example.com:443"), "")
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
