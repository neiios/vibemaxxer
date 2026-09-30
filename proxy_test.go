package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func testServer(t *testing.T, allowPrivate bool, ports ...int) (address string, config *tls.Config) {
	t.Helper()
	server, client := testIdentity(t), testIdentity(t)
	allowed := map[int]bool{443: true}
	for _, port := range ports {
		allowed[port] = true
	}
	logger, _ := testLogger()
	address = startServer(t, server, map[string]bool{client.Fingerprint(): true}, allowed, allowPrivate, logger)
	return address, client.ClientTLS(server.Fingerprint())
}

func TestConnectRejections(t *testing.T) {
	closed, port := closedPort(t)
	address, config := testServer(t, true, port)
	cases := map[string]int{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n":       http.StatusMethodNotAllowed,
		connectRequest("example.com:22"):          http.StatusForbidden,
		connectRequest("nonsense"):                http.StatusBadRequest,
		connectRequest(":443"):                    http.StatusBadRequest,
		connectRequest("example.com:0"):           http.StatusBadRequest,
		connectRequest(closed):                    http.StatusBadGateway,
		"CONNECT " + closed + " HTTP/1.1\r\n\r\n": http.StatusBadGateway,
	}
	for request, want := range cases {
		if _, _, got := connect(t, address, config, request, ""); got != want {
			t.Errorf("%q: status %d, want %d", request, got, want)
		}
	}
}

func TestTunnelEchoWithEarlyDataAndHalfClose(t *testing.T) {
	target, port := echoServer(t)
	address, config := testServer(t, true, port)
	conn, reader, status := connect(t, address, config, connectRequest(target), "early")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	assertEcho(t, conn, reader, "early", " and later")
}

func TestPrivateDestinationsBlockedByDefault(t *testing.T) {
	target, port := echoServer(t)
	address, config := testServer(t, false, port)
	if _, _, status := connect(t, address, config, connectRequest(target), ""); status != http.StatusForbidden {
		t.Fatalf("loopback destination status %d", status)
	}
	if _, _, status := connect(t, address, config, connectRequest("localhost:"+strconv.Itoa(port)), ""); status != http.StatusForbidden {
		t.Fatalf("resolved loopback destination status %d", status)
	}
}

func TestPublicDestinationPolicy(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1": true, "2606:4700::1111": true,
		"10.0.0.1": false, "192.168.1.1": false, "172.16.0.1": false, "127.0.0.1": false,
		"169.254.1.1": false, "100.64.0.1": false, "::1": false, "fe80::1": false,
		"fd00::1": false, "0.0.0.0": false, "224.0.0.1": false, "::ffff:192.168.1.1": false,
	} {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := publicDestination(a); got != want {
			t.Errorf("%s: public=%v", addr, got)
		}
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := parsePorts("443, 8443")
	if err != nil || !ports[443] || !ports[8443] || len(ports) != 2 {
		t.Fatalf("ports %v, %v", ports, err)
	}
	for _, bad := range []string{"", "0", "65536", "https", "443,,8443"} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
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
	conn, reader, status := connect(t, address, config, connectRequest(listener.Addr().String()), "")
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

func TestLocalPrefixesRefused(t *testing.T) {
	p := &proxy{local: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("203.0.113.0/24")}}
	for addr, want := range map[string]bool{
		"2001:db8:1::10": false, "203.0.113.7": false,
		"2001:db8:2::10": true, "1.1.1.1": true,
		"10.0.0.1": false, "::1": false,
		"2001:db8:1::10%eth0": false, "fe80::1%eth0": false,
	} {
		if got := p.allowed(netip.MustParseAddr(addr)); got != want {
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
