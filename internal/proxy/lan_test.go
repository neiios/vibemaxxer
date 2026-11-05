package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/policy"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Load(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func lanChain(t *testing.T) (*chain, *identity.Identity, *identity.Identity) {
	t.Helper()
	c := newChain(t)
	serverID, clientID := testIdentity(t), testIdentity(t)
	rules, err := policy.Parse("server.rules", serverRules, policy.Server)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New("vibemaxxer-server", rules, "", c.serverDNS.dial, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := p.Server()
	go server.Serve(tls.NewListener(listener, serverID.ServerTLS(map[string]bool{clientID.Fingerprint(): true})))
	t.Cleanup(func() { server.Close() })
	c.server = listener.Addr().String()
	c.clientP, c.client = c.tlsClient(t, clientID.ClientTLS(serverID.Fingerprint()))
	return c, serverID, clientID
}

func (c *chain) tlsClient(t *testing.T, config *tls.Config) (*Proxy, string) {
	t.Helper()
	p, err := NewTLS("vibemaxxer-client", c.clientPolicy, c.server, config, c.clientDNS.dial, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.proxied.CloseIdleConnections)
	return p, serve(t, p)
}

func TestLANRouting(t *testing.T) {
	t.Parallel()
	c, _, _ := lanChain(t)
	for _, tc := range []struct {
		target string
		status int
	}{
		{"proxied.test:443", 200},
		{"direct.test:443", 200},
		{"internal.test:443", 200},
		{"blocked.test:443", 403},
		{"secret.proxied.test:443", 403},
		{"denied.test:443", 403},
		{"proxied.test:8443", 403},
		{"127.0.0.1:443", 403},
	} {
		t.Run(tc.target, func(t *testing.T) {
			conn, reader, resp := connect(t, c.client, tc.target, "early")
			if resp.StatusCode != tc.status {
				t.Fatal(resp.Status)
			}
			if tc.status == 200 {
				assertEcho(t, conn, reader, "early", "TLS payload")
			}
		})
	}
	if got := c.clientDNS.log(); len(got) != 1 || got[0] != "direct.test:443" {
		t.Fatalf("proxied destination resolved locally: %v", got)
	}
	if got := c.serverDNS.log(); len(got) != 2 {
		t.Fatalf("blocked/denied destination dialed: %v", got)
	}
}

func httpVia(t *testing.T, proxy, target string) (int, string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: ignored.test\r\nProxy-Authorization: Basic secret\r\n\r\n", target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestLANHTTPForwarding(t *testing.T) {
	t.Parallel()
	c, _, _ := lanChain(t)
	for _, tc := range []struct {
		target string
		status int
		body   string
	}{
		{"http://www.proxied.test/path?secret=1", 200, `host=www.proxied.test auth=""`},
		{"http://direct.test/", 200, `host=direct.test auth=""`},
		{"http://blocked.test/", 403, "http_request_denied"},
		{"http://proxied.test:81/", 403, "http_request_denied"},
	} {
		status, body := httpVia(t, c.client, tc.target)
		if status != tc.status || !strings.Contains(body, tc.body) {
			t.Fatalf("%s: %d %q", tc.target, status, body)
		}
	}
}

func TestLANAuthenticationFailsClosed(t *testing.T) {
	t.Parallel()
	c, serverID, clientID := lanChain(t)
	stranger := testIdentity(t)
	for _, tc := range []struct {
		name   string
		config *tls.Config
	}{
		{"wrong-server", clientID.ClientTLS(stranger.Fingerprint())},
		{"unknown-client", stranger.ClientTLS(serverID.Fingerprint())},
		{"no-client", &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, address := c.tlsClient(t, tc.config)
			_, _, resp := connect(t, address, "proxied.test:443", "")
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("CONNECT authentication bypassed: %s", resp.Status)
			}
			status, _ := httpVia(t, address, "http://www.proxied.test/")
			if status != http.StatusBadGateway {
				t.Fatalf("HTTP authentication bypassed: %d", status)
			}
			conn, reader, resp := connect(t, address, "direct.test:443", "")
			if resp.StatusCode != 200 {
				t.Fatalf("direct path depends on LAN authentication: %s", resp.Status)
			}
			assertEcho(t, conn, reader, "", "still direct")
		})
	}
	for _, address := range c.clientDNS.log() {
		if address != "direct.test:443" {
			t.Fatalf("authentication failure fell back to direct: %s", address)
		}
	}
	plainConn, err := net.Dial("tcp", c.server)
	if err != nil {
		t.Fatal(err)
	}
	defer plainConn.Close()
	plainConn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(plainConn, "GET http://www.proxied.test/ HTTP/1.1\r\nHost: www.proxied.test\r\n\r\n")
	plainResp, err := http.ReadResponse(bufio.NewReader(plainConn), nil)
	if plainResp != nil {
		plainResp.Body.Close()
		if plainResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("TLS server accepted plaintext HTTP: %s", plainResp.Status)
		}
	} else if err == nil {
		t.Fatal("plaintext request was not rejected")
	}
	if got := c.serverDNS.log(); len(got) != 0 {
		t.Fatalf("unauthenticated request reached destination: %v", got)
	}
	plain := newChain(t)
	_, address := plain.tlsClient(t, clientID.ClientTLS(serverID.Fingerprint()))
	_, _, resp := connect(t, address, "proxied.test:443", "")
	if resp.StatusCode != http.StatusBadGateway || len(plain.serverDNS.log()) != 0 {
		t.Fatal("TLS client accepted a plaintext upstream")
	}
}

func TestLANUnavailable(t *testing.T) {
	t.Parallel()
	c, _, _ := lanChain(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	c.server = listener.Addr().String()
	_, address := c.tlsClient(t, testIdentity(t).ClientTLS(testIdentity(t).Fingerprint()))
	_, _, resp := connect(t, address, "proxied.test:443", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatal(resp.Status)
	}
	status, _ := httpVia(t, address, "http://www.proxied.test/")
	if status != http.StatusBadGateway || len(c.clientDNS.log()) != 0 {
		t.Fatal("unavailable TLS upstream fell back to direct")
	}
}
