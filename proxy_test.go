package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testProxy(t *testing.T, mutate func(*proxyConfig)) *proxy {
	t.Helper()
	cfg := proxyConfig{
		allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
		ports:   map[int]bool{443: true}, dialTimeout: time.Second, maxTunnels: 8,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p := newProxy(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(p.Close)
	return p
}

func proxyServer(t *testing.T, p *proxy) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(p)
	t.Cleanup(func() { p.Close(); s.Close() })
	return s
}

func TestClientAllowlist(t *testing.T) {
	p := testProxy(t, func(c *proxyConfig) {
		c.allowed = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("::1/128")}
	})
	for _, tc := range []struct {
		remote string
		want   bool
	}{
		{"192.168.1.20:1234", true}, {"[::ffff:192.168.1.20]:1234", true},
		{"192.168.2.20:1234", false}, {"[::1]:1234", true},
		{"[2001:db8::1]:1234", false}, {"garbage", false},
	} {
		if got := p.clientAllowed(tc.remote); got != tc.want {
			t.Errorf("clientAllowed(%q) = %v, want %v", tc.remote, got, tc.want)
		}
	}
}

func TestRequestRejections(t *testing.T) {
	p := testProxy(t, nil)
	for _, tc := range []struct {
		name, method, target, remote string
		bodyLength                   int64
		status                       int
	}{
		{"unauthorized", "CONNECT", "example.com:443", "192.168.1.20:5000", 0, 403},
		{"plain HTTP", "GET", "example.com:443", "127.0.0.1:5000", 0, 405},
		{"port", "CONNECT", "example.com:22", "127.0.0.1:5000", 0, 403},
		{"missing port", "CONNECT", "example.com", "127.0.0.1:5000", 0, 400},
		{"invalid port", "CONNECT", "example.com:nope", "127.0.0.1:5000", 0, 400},
		{"out of range", "CONNECT", "example.com:65536", "127.0.0.1:5000", 0, 400},
		{"missing host", "CONNECT", ":443", "127.0.0.1:5000", 0, 400},
		{"userinfo", "CONNECT", "user@example.com:443", "127.0.0.1:5000", 0, 400},
		{"body", "CONNECT", "example.com:443", "127.0.0.1:5000", 1, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{
				Method: tc.method, RequestURI: tc.target, URL: &url.URL{Host: tc.target},
				RemoteAddr: tc.remote, ContentLength: tc.bodyLength,
				Header: http.Header{"X-Forwarded-For": {"127.0.0.1"}},
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}

func TestDestinationPolicy(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"1.1.1.1", true}, {"2606:4700:4700::1111", true},
		{"127.0.0.1", false}, {"::1", false}, {"::ffff:127.0.0.1", false},
		{"10.0.0.1", false}, {"172.16.0.1", false}, {"192.168.0.1", false},
		{"169.254.169.254", false}, {"fe80::1", false}, {"fc00::1", false},
		{"100.100.100.100", false}, {"0.0.0.0", false}, {"::", false},
		{"224.0.0.1", false}, {"ff02::1", false},
	} {
		if got := publicDestination(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("publicDestination(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	p := testProxy(t, nil)
	for _, target := range []string{"127.0.0.1:443", "[::1]:443", "localhost:443"} {
		conn, err := p.dial(context.Background(), target)
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, errPrivateDestination) {
			t.Errorf("dial(%q): want private destination rejection, got %v", target, err)
		}
	}
}

func TestHTTPSStreaming(t *testing.T) {
	finish := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			http.Error(w, "missing end-to-end header", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-finish:
			fmt.Fprint(w, "second\n")
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	addr := upstream.Listener.Addr().(*net.TCPAddr)
	p := testProxy(t, func(c *proxyConfig) {
		c.allowPrivate = true
		c.ports = map[int]bool{addr.Port: true}
	})
	s := proxyServer(t, p)
	proxyURL, _ := url.Parse(s.URL)
	// Trust only the test server certificate; never disable TLS verification.
	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("first streaming chunk = %q, %v", line, err)
	}
	close(finish)
	rest, err := io.ReadAll(reader)
	if err != nil || string(rest) != "second\n" {
		t.Fatalf("remaining stream = %q, %v", rest, err)
	}
}

// singleTCPServer serves one connection and always joins its goroutine at cleanup.
func singleTCPServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		accepted <- conn
		if err == nil {
			defer conn.Close()
			handler(conn)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		if conn := <-accepted; conn != nil {
			conn.Close()
		}
		<-done
	})
	return listener.Addr().String()
}

func rawConnect(t *testing.T, proxyAddress, target, earlyData string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", target, target, earlyData)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
	}
	return conn, reader, resp.StatusCode
}

func proxyForTarget(t *testing.T, target string, limit int) (*proxy, *httptest.Server) {
	t.Helper()
	endpoint := netip.MustParseAddrPort(target)
	p := testProxy(t, func(c *proxyConfig) {
		c.allowPrivate = true
		c.ports = map[int]bool{int(endpoint.Port()): true}
		c.maxTunnels = limit
	})
	return p, proxyServer(t, p)
}

func TestBufferedDataAndHalfClose(t *testing.T) {
	target := singleTCPServer(t, func(conn net.Conn) {
		data, _ := io.ReadAll(conn)
		fmt.Fprintf(conn, "reply:%s", data)
	})
	_, s := proxyForTarget(t, target, 8)
	conn, reader, status := rawConnect(t, s.Listener.Addr().String(), target, "early-tunnel-data")
	if status != 200 {
		t.Fatalf("CONNECT status = %d", status)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(reader)
	if err != nil || string(response) != "reply:early-tunnel-data" {
		t.Fatalf("response = %q, %v", response, err)
	}
}

func TestLimitAndShutdown(t *testing.T) {
	target := singleTCPServer(t, func(conn net.Conn) { io.Copy(conn, conn) })
	p, s := proxyForTarget(t, target, 1)
	_, reader, status := rawConnect(t, s.Listener.Addr().String(), target, "")
	if status != 200 {
		t.Fatalf("first CONNECT status = %d", status)
	}
	_, _, status = rawConnect(t, s.Listener.Addr().String(), target, "")
	if status != 503 {
		t.Fatalf("overloaded CONNECT status = %d", status)
	}
	p.Close()
	_, err := reader.ReadByte()
	if err == nil {
		t.Fatal("shutdown did not close the tunnel")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("timed out waiting for shutdown")
	}
	_, _, status = rawConnect(t, s.Listener.Addr().String(), target, "")
	if status != 503 {
		t.Fatalf("closed proxy CONNECT status = %d", status)
	}
}

func TestFailedDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := listener.Addr().String()
	listener.Close()
	_, s := proxyForTarget(t, target, 8)
	_, _, status := rawConnect(t, s.Listener.Addr().String(), target, "")
	if status != 502 {
		t.Fatalf("failed dial status = %d", status)
	}
}

func TestPrivateDestinationHTTPStatus(t *testing.T) {
	p := testProxy(t, nil)
	s := proxyServer(t, p)
	_, _, status := rawConnect(t, s.Listener.Addr().String(), "localhost:443", "")
	if status != 403 {
		t.Fatalf("private destination status = %d", status)
	}
}

func TestConfigurationParsing(t *testing.T) {
	for _, values := range [][]string{nil, {"192.168.1.20"}, {"192.168.1.0/24", "::1"}, {"::ffff:192.168.1.20"}} {
		if _, err := parseAllow(values); err != nil {
			t.Errorf("parseAllow(%v): %v", values, err)
		}
	}
	for _, value := range []string{"", "hostname", "192.168.1.0/99", "::ffff:192.168.1.0/120", "fe80::1%eth0"} {
		if _, err := parseAllow([]string{value}); err == nil {
			t.Errorf("parseAllow(%q): expected error", value)
		}
	}
	for _, value := range []string{"443", "443,8443", " 443 "} {
		if _, err := parsePorts(value); err != nil {
			t.Errorf("parsePorts(%q): %v", value, err)
		}
	}
	for _, value := range []string{"", "0", "65536", "443,", "https", "-1"} {
		if _, err := parsePorts(value); err == nil {
			t.Errorf("parsePorts(%q): expected error", value)
		}
	}
	allowed, _ := parseAllow([]string{"192.168.1.20"})
	if strings.Contains(fmt.Sprint(allowed), "127.0.0.1") {
		t.Fatal("explicit allowlist must replace the defaults")
	}
}
