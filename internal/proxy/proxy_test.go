package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neiios/vibemaxxer/internal/policy"
)

const clientRules = `
block .blocked.test
proxy .proxied.test
proxy internal.test
proxy denied.test
`

const serverRules = `
allow .proxied.test 80,443
allow internal.test
deny  secret.proxied.test
`

type resolver struct {
	mu     sync.Mutex
	names  map[string]string
	dialed []string
}

func (r *resolver) dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.dialed = append(r.dialed, address)
	real, ok := r.names[address]
	r.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: address, IsNotFound: true}}
	}
	return (&net.Dialer{}).DialContext(ctx, network, real)
}

func (r *resolver) log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.dialed...)
}

type chain struct {
	client, server string
	clientDNS      *resolver
	serverDNS      *resolver
	clientP        *Proxy
	clientPolicy   *policy.Policy
}

func echoServer(t *testing.T) string {
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
				conn.(*net.TCPConn).CloseWrite()
				conn.Close()
			}()
		}
	}()
	return listener.Addr().String()
}

func serve(t *testing.T, p *Proxy) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := p.Server()
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return listener.Addr().String()
}

func newChain(t *testing.T) *chain {
	t.Helper()
	echo := echoServer(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s auth=%q", r.Host, r.Header.Get("Proxy-Authorization"))
	}))
	t.Cleanup(origin.Close)
	originAddr := strings.TrimPrefix(origin.URL, "http://")
	logger := slog.New(slog.DiscardHandler)
	c := &chain{
		clientDNS: &resolver{names: map[string]string{
			"direct.test:443": echo, "direct.test:80": originAddr, "blocked.test:443": echo, "denied.test:443": echo,
		}},
		serverDNS: &resolver{names: map[string]string{
			"proxied.test:443": echo, "www.proxied.test:80": originAddr, "internal.test:443": echo,
			"secret.proxied.test:443": echo, "denied.test:443": echo, "proxied.test:8443": echo,
		}},
	}
	serverPolicy, err := policy.Parse("server.rules", serverRules, policy.Server)
	if err != nil {
		t.Fatal(err)
	}
	clientPolicy, err := policy.Parse("client.rules", clientRules, policy.Client)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New("vibemaxxer-server", serverPolicy, "", c.serverDNS.dial, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.server = serve(t, server)
	c.clientPolicy = clientPolicy
	c.clientP, c.client = c.newClient(t, c.server, idleTimeout)
	return c
}

func (c *chain) newClient(t *testing.T, upstream string, idle time.Duration) (*Proxy, string) {
	t.Helper()
	p, err := New("vibemaxxer-client", c.clientPolicy, upstream, c.clientDNS.dial, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p.idle = idle
	return p, serve(t, p)
}

func connect(t *testing.T, proxy, target, early string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", target, target, early); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, resp
}

func assertEcho(t *testing.T, conn net.Conn, reader *bufio.Reader, early, payload string) {
	t.Helper()
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != early+payload {
		t.Fatalf("echo = %q, want %q", got, early+payload)
	}
}

func TestStandaloneFiltering(t *testing.T) {
	t.Parallel()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct response")
	}))
	t.Cleanup(origin.Close)
	dns := &resolver{names: map[string]string{
		"direct.test:443": echoServer(t),
		"direct.test:80":  strings.TrimPrefix(origin.URL, "http://"),
	}}
	rules, err := policy.Parse("filter.rules", "block .blocked.test\n", policy.Client)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New("vibemaxxer-client", rules, "", dns.dial, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if p.proxied != nil {
		t.Fatal("standalone proxy initialized an upstream transport")
	}
	address := serve(t, p)
	for _, target := range []string{"direct.test:443", "blocked.test:443", "sub.blocked.test:443"} {
		conn, reader, resp := connect(t, address, target, "")
		if target == "direct.test:443" {
			if resp.StatusCode != http.StatusOK {
				t.Fatal(resp.Status)
			}
			assertEcho(t, conn, reader, "", "standalone tunnel")
		} else if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get("Proxy-Status"), "http_request_denied") {
			t.Fatalf("%s: %s %q", target, resp.Status, resp.Header.Get("Proxy-Status"))
		}
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	for _, tc := range []struct {
		host   string
		status int
		body   string
	}{
		{"direct.test", http.StatusOK, "direct response"},
		{"blocked.test", http.StatusForbidden, "http_request_denied"},
		{"sub.blocked.test", http.StatusForbidden, "http_request_denied"},
	} {
		fmt.Fprintf(conn, "GET http://%s/path HTTP/1.1\r\nHost: %s\r\n\r\n", tc.host, tc.host)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != tc.status || !strings.Contains(string(body), tc.body) {
			t.Fatalf("%s: %s %q, %v", tc.host, resp.Status, body, err)
		}
	}
	for _, address := range dns.log() {
		if address != "direct.test:443" && address != "direct.test:80" {
			t.Fatalf("blocked destination was dialed: %s", address)
		}
	}
}

func TestProxyRulesRequireUpstream(t *testing.T) {
	t.Parallel()
	rules, err := policy.Parse("client.rules", clientRules, policy.Client)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New("vibemaxxer-client", rules, "", nil, slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "proxy rules require -upstream") || p != nil {
		t.Fatalf("New without upstream = %v, %v", p, err)
	}
}

func TestConnectRouting(t *testing.T) {
	t.Parallel()
	c := newChain(t)
	for _, tc := range []struct {
		target      string
		status      int
		proxyStatus string
		clientDial  bool
		serverDial  bool
	}{
		{"direct.test:443", 200, "", true, false},
		{"Direct.Test.:443", 200, "", true, false},
		{"proxied.test:443", 200, "", false, true},
		{"internal.test:443", 200, "", false, true},
		{"blocked.test:443", 403, "vibemaxxer-client; error=http_request_denied", false, false},
		{"x.blocked.test:443", 403, "vibemaxxer-client; error=http_request_denied", false, false},
		{"denied.test:443", 403, "vibemaxxer-server; error=http_request_denied", false, false},
		{"secret.proxied.test:443", 403, "vibemaxxer-server; error=http_request_denied", false, false},
		{"proxied.test:8443", 403, "vibemaxxer-server; error=http_request_denied", false, false},
		{"127.0.0.1:443", 403, "vibemaxxer-client; error=destination_ip_prohibited", false, false},
		{"[::1]:443", 403, "vibemaxxer-client; error=destination_ip_prohibited", false, false},
		{"unknown.test:443", 502, "vibemaxxer-client; error=dns_error", true, false},
		{"direct.test", 400, "vibemaxxer-client; error=http_request_error", false, false},
		{"direct.test:0443", 400, "vibemaxxer-client; error=http_request_error", false, false},
	} {
		t.Run(tc.target, func(t *testing.T) {
			before := [2]int{len(c.clientDNS.log()), len(c.serverDNS.log())}
			conn, reader, resp := connect(t, c.client, tc.target, "early")
			if resp.StatusCode != tc.status || !strings.HasPrefix(resp.Header.Get("Proxy-Status"), tc.proxyStatus) {
				t.Fatalf("status %d %q; want %d %q", resp.StatusCode, resp.Header.Get("Proxy-Status"), tc.status, tc.proxyStatus)
			}
			if tc.status == 200 {
				assertEcho(t, conn, reader, "early", "payload")
			}
			after := [2]int{len(c.clientDNS.log()), len(c.serverDNS.log())}
			if dialed := after[0] > before[0]; dialed != tc.clientDial {
				t.Errorf("client dialed=%v, want %v", dialed, tc.clientDial)
			}
			if dialed := after[1] > before[1]; dialed != tc.serverDial {
				t.Errorf("server dialed=%v, want %v", dialed, tc.serverDial)
			}
		})
	}
}

func TestHTTPForwarding(t *testing.T) {
	t.Parallel()
	c := newChain(t)
	conn, err := net.Dial("tcp", c.client)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	for _, tc := range []struct{ url, status, body string }{
		{"http://direct.test/path?secret=1", "200 OK", `host=direct.test auth=""`},
		{"http://www.proxied.test/", "200 OK", `host=www.proxied.test auth=""`},
		{"http://blocked.test/", "403 Forbidden", "http_request_denied"},
		{"http://direct.test:8080/", "502 Bad Gateway", "dns_error"},
		{"http://proxied.test:81/", "403 Forbidden", "http_request_denied"},
		{"http://direct.test/again", "200 OK", `host=direct.test auth=""`},
	} {
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: ignored.test\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\n", tc.url)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.Status != tc.status || !strings.Contains(string(body), tc.body) {
			t.Fatalf("%s: %s %q; want %s %q", tc.url, resp.Status, body, tc.status, tc.body)
		}
	}
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: direct.test\r\n\r\n",
		"GET https://direct.test/ HTTP/1.1\r\nHost: direct.test\r\n\r\n",
		"GET http://127.0.0.1/ HTTP/1.1\r\nHost: x\r\n\r\n",
	} {
		fmt.Fprint(conn, request)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode/100 != 4 {
			t.Fatalf("%q: %s", request, resp.Status)
		}
	}
}

func TestUpstreamUnavailable(t *testing.T) {
	t.Parallel()
	c := newChain(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, client := c.newClient(t, listener.Addr().String(), idleTimeout)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, _, resp := connect(t, client, "proxied.test:443", "")
	if resp.StatusCode != 502 || !strings.Contains(resp.Header.Get("Proxy-Status"), "upstream proxy unavailable") {
		t.Fatalf("closing upstream: %d %q", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}
	listener.Close()
	_, _, resp = connect(t, client, "proxied.test:443", "")
	if resp.StatusCode != 502 {
		t.Fatalf("refused upstream: %d", resp.StatusCode)
	}
	httpConn, err := net.Dial("tcp", client)
	if err != nil {
		t.Fatal(err)
	}
	defer httpConn.Close()
	_ = httpConn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(httpConn, "GET http://proxied.test/ HTTP/1.1\r\nHost: proxied.test\r\n\r\n")
	httpResp, err := http.ReadResponse(bufio.NewReader(httpConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, httpResp.Body)
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("refused HTTP upstream: %s", httpResp.Status)
	}
	conn, reader, resp := connect(t, client, "direct.test:443", "")
	if resp.StatusCode != 200 {
		t.Fatalf("direct while upstream down: %d", resp.StatusCode)
	}
	assertEcho(t, conn, reader, "", "still direct")
	if dialed := c.clientDNS.log(); len(dialed) != 1 || dialed[0] != "direct.test:443" {
		t.Fatalf("client fell back to direct: %v", dialed)
	}
}

func TestIdleTunnelCloses(t *testing.T) {
	t.Parallel()
	c := newChain(t)
	_, client := c.newClient(t, c.server, 200*time.Millisecond)
	conn, reader, resp := connect(t, client, "direct.test:443", "")
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	for range 3 {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(conn, "x")
		if _, err := reader.ReadByte(); err != nil {
			t.Fatalf("active tunnel closed: %v", err)
		}
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("idle tunnel read: %v", err)
	}
}

func TestLimits(t *testing.T) {
	t.Parallel()
	c := newChain(t)
	conn, err := net.Dial("tcp", c.client)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT direct.test:443 HTTP/1.1\r\nHost: direct.test:443\r\nX: %s\r\n\r\n", strings.Repeat("a", 40<<10))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized header: %v %v", resp, err)
	}
	for range maxActive {
		c.clientP.slots <- struct{}{}
	}
	_, _, resp = connect(t, c.client, "direct.test:443", "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over limit: %d", resp.StatusCode)
	}
}

func TestGuard(t *testing.T) {
	t.Parallel()
	g := guard{local: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
	open := guard{allowPrivate: true}
	for addr, want := range map[string][2]bool{
		"203.0.113.7":      {true, true},
		"2606:4700::1":     {true, true},
		"10.1.2.3":         {false, true},
		"100.64.0.1":       {false, true},
		"fd12::1":          {false, true},
		"198.51.100.9":     {false, true},
		"127.0.0.1":        {false, false},
		"::ffff:127.0.0.1": {false, false},
		"169.254.169.254":  {false, false},
		"fd00:ec2::254":    {false, false},
		"0.1.2.3":          {false, false},
		"224.0.0.1":        {false, false},
		"::":               {false, false},
	} {
		a := netip.MustParseAddr(addr)
		if got := [2]bool{g.allowed(a), open.allowed(a)}; got != want {
			t.Errorf("%s: allowed=%v, want %v", addr, got, want)
		}
	}
	dial, err := Dialer(false)
	if err != nil {
		t.Fatal(err)
	}
	echo := echoServer(t)
	if _, err := dial(context.Background(), "tcp", echo); err == nil || !strings.Contains(err.Error(), errProhibited.Error()) {
		t.Fatalf("loopback dial: %v", err)
	}
}
