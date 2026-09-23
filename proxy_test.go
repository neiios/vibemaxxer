package main

import (
	"crypto/tls"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
)

func testServer(t *testing.T, allowPrivate bool, ports ...int) (address string, config *tls.Config) {
	t.Helper()
	server, client := testIdentity(t), testIdentity(t)
	allowed := map[int]bool{443: true}
	for _, port := range ports {
		allowed[port] = true
	}
	logger, _ := testLogger()
	address = startServer(t, server, map[string]bool{client.fingerprint(): true}, allowed, allowPrivate, logger)
	return address, client.clientTLS(server.fingerprint())
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
