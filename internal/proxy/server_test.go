package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neiios/vibemaxxer/internal/proxytest"
)

func testServer(t *testing.T, allowPrivate bool, ports ...int) (address string, config *tls.Config) {
	t.Helper()
	server, client := proxytest.Identity(t), proxytest.Identity(t)
	allowed := map[int]bool{443: true}
	for _, port := range ports {
		allowed[port] = true
	}
	logger, _ := proxytest.Logger()
	address = startServer(t, server, map[string]bool{client.Fingerprint(): true}, allowed, allowPrivate, logger)
	return address, client.ClientTLS(server.Fingerprint())
}

func TestConnectRejections(t *testing.T) {
	closed, port := proxytest.ClosedPort(t)
	address, config := testServer(t, true, port)
	cases := map[string]int{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n":        http.StatusMethodNotAllowed,
		proxytest.ConnectRequest("example.com:22"): http.StatusForbidden,
		proxytest.ConnectRequest("nonsense"):       http.StatusBadRequest,
		proxytest.ConnectRequest(":443"):           http.StatusBadRequest,
		proxytest.ConnectRequest("example.com:0"):  http.StatusBadRequest,
		proxytest.ConnectRequest(closed):           http.StatusBadGateway,
		"CONNECT " + closed + " HTTP/1.1\r\n\r\n":  http.StatusBadGateway,
	}
	for request, want := range cases {
		if _, _, got := proxytest.Connect(t, address, config, request, ""); got != want {
			t.Errorf("%q: status %d, want %d", request, got, want)
		}
	}
}

func TestTunnelEchoWithEarlyDataAndHalfClose(t *testing.T) {
	target, port := proxytest.EchoServer(t)
	address, config := testServer(t, true, port)
	conn, reader, status := proxytest.Connect(t, address, config, proxytest.ConnectRequest(target), "early")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	proxytest.AssertEcho(t, conn, reader, "early", " and later")
}

func TestPrivateDestinationsBlockedByDefault(t *testing.T) {
	target, port := proxytest.EchoServer(t)
	address, config := testServer(t, false, port)
	if _, _, status := proxytest.Connect(t, address, config, proxytest.ConnectRequest(target), ""); status != http.StatusForbidden {
		t.Fatalf("loopback destination status %d", status)
	}
	if _, _, status := proxytest.Connect(t, address, config, proxytest.ConnectRequest("localhost:"+strconv.Itoa(port)), ""); status != http.StatusForbidden {
		t.Fatalf("resolved loopback destination status %d", status)
	}
}

func TestTunnelUpstreamHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		first := make([]byte, 4)
		if _, err := io.ReadFull(conn, first); err != nil {
			received <- err.Error()
			return
		}
		if _, err := io.WriteString(conn, "pong"); err != nil {
			received <- err.Error()
			return
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			received <- err.Error()
			return
		}
		rest, _ := io.ReadAll(conn)
		received <- string(first) + string(rest)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	address, config := testServer(t, true, port)
	conn, reader, status := proxytest.Connect(t, address, config, proxytest.ConnectRequest(listener.Addr().String()), "")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(reader, pong); err != nil || string(pong) != "pong" {
		t.Fatalf("reply %q, %v", pong, err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := io.WriteString(conn, "late"); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*tls.Conn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(reader); err != nil || len(rest) != 0 {
		t.Fatalf("trailing data %q, %v", rest, err)
	}
	select {
	case got := <-received:
		if got != "pinglate" {
			t.Fatalf("target received %q, want %q", got, "pinglate")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never saw EOF")
	}
}

// Destination policy is the server's main safety property: a compromised or
// careless workstation must not reach the VPN host's LAN, loopback, or link-local
// networks through the tunnel.
func TestDestinationPolicy(t *testing.T) {
	s := &Server{local: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("203.0.113.0/24")}}
	for addr, want := range map[string]bool{
		"1.1.1.1": true, "2606:4700::1111": true, "2001:db8:2::10": true,
		"10.0.0.1": false, "192.168.1.1": false, "172.16.0.1": false, "127.0.0.1": false, "::1": false,
		"169.254.1.1": false, "fe80::1": false, "fd00::1": false, "100.64.0.1": false,
		"0.0.0.0": false, "224.0.0.1": false, "::ffff:192.168.1.1": false,
		"203.0.113.7": false, "2001:db8:1::10": false, "2001:db8:1::10%eth0": false, "fe80::1%eth0": false,
	} {
		if got := s.allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: allowed=%v", addr, got)
		}
	}
	prefixes, err := localPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	for _, prefix := range prefixes {
		if prefix.Contains(loopback) {
			return
		}
	}
	t.Fatalf("loopback missing from %v", prefixes)
}

func TestMutualPinning(t *testing.T) {
	server, client, stranger := proxytest.Identity(t), proxytest.Identity(t), proxytest.Identity(t)
	logger, logs := proxytest.Logger()
	address := startServer(t, server, map[string]bool{client.Fingerprint(): true}, map[int]bool{443: true}, false, logger)

	_, _, status := proxytest.Connect(t, address, client.ClientTLS(server.Fingerprint()), "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "")
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
	proxytest.WaitForLog(t, logs, "-client-key "+stranger.Fingerprint())

	response, err := http.Get("http://" + address)
	if err == nil {
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext status %d", response.StatusCode)
		}
	}
}
