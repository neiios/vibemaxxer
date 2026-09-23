package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStoreIdentity(t *testing.T) (*stateStore, *identity) {
	t.Helper()
	store, err := openStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := loadIdentity(store)
	if err != nil {
		t.Fatal(err)
	}
	return store, id
}

type wireCapture struct {
	sync.Mutex
	data []byte
}

func (w *wireCapture) record(data []byte) {
	w.Lock()
	defer w.Unlock()
	w.data = append(w.data, data...)
}

type recordingListener struct {
	net.Listener
	wire *wireCapture
}

type recordingConn struct {
	net.Conn
	wire *wireCapture
}

func (l *recordingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: conn, wire: l.wire}, nil
}

func (c *recordingConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	c.wire.record(data[:n])
	return n, err
}

func (c *recordingConn) Write(data []byte) (int, error) {
	c.wire.record(data)
	return c.Conn.Write(data)
}

type secureFixture struct {
	store   *stateStore
	id      *identity
	handler *secureHandler
	address string
	wire    *wireCapture
}

func secureServer(t *testing.T, mutate func(*proxyConfig)) *secureFixture {
	t.Helper()
	store, id := testStoreIdentity(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err := store.initServer(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	p := testProxy(t, mutate)
	handler := &secureHandler{store: store, proxy: p}
	wire := &wireCapture{}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	server := &http.Server{
		Handler: handler, TLSConfig: id.serverTLS(store), Protocols: protocols,
		ReadHeaderTimeout: time.Second, WriteTimeout: time.Second,
		ErrorLog: log.New(io.Discard, "", 0),
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(tls.NewListener(&recordingListener{Listener: listener, wire: wire}, server.TLSConfig))
	}()
	t.Cleanup(func() {
		p.Close()
		server.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("server: %v", err)
		}
	})
	return &secureFixture{store: store, id: id, handler: handler, address: listener.Addr().String(), wire: wire}
}

func testInvitation(t *testing.T, server *secureFixture) invitation {
	t.Helper()
	code, err := makeInvitation(server.store, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !validPairCode(code) {
		t.Fatalf("invalid generated code: %q", code)
	}
	return invitation{Address: server.address, ServerKey: server.id.fingerprint(), Token: code}
}

func pairedClient(t *testing.T, server *secureFixture) (*stateStore, *identity, bridgeState, invitation) {
	t.Helper()
	store, id := testStoreIdentity(t)
	invite := testInvitation(t, server)
	if err := pair(context.Background(), store, id, invite, "workstation", false); err != nil {
		t.Fatal(err)
	}
	config, err := store.readBridge()
	if err != nil {
		t.Fatal(err)
	}
	return store, id, config, invite
}

func tlsHTTPStatus(address string, config *tls.Config, request string) (int, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, config)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		return 0, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

const testGET = "GET / HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n"

func TestPairingAuthentication(t *testing.T) {
	server := secureServer(t, nil)
	store, client := testStoreIdentity(t)
	config := client.clientTLS(server.id.fingerprint())
	if status, err := tlsHTTPStatus(server.address, config, testGET); err == nil {
		t.Fatalf("unpaired client without enrollment window accepted: %d", status)
	}
	invite := testInvitation(t, server)
	if status, err := tlsHTTPStatus(server.address, config, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil || status != 403 {
		t.Fatalf("unpaired CONNECT during enrollment: %d %v", status, err)
	}
	noCert := config.Clone()
	noCert.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	if _, err := tlsHTTPStatus(server.address, noCert, testGET); err == nil {
		t.Fatal("missing client certificate accepted")
	}
	oldTLS := config.Clone()
	oldTLS.MinVersion, oldTLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if _, err := tlsHTTPStatus(server.address, oldTLS, testGET); err == nil {
		t.Fatal("TLS 1.2 accepted")
	}
	wrongPin := invite
	wrongPin.ServerKey = strings.Repeat("0", 64)
	if err := pair(context.Background(), store, client, wrongPin, "workstation", false); err == nil {
		t.Fatal("wrong server identity accepted")
	}
	badToken := invite
	badToken.Token = "incorrect"
	if err := pair(context.Background(), store, client, badToken, "workstation", false); err == nil {
		t.Fatal("bad token accepted")
	}
	if _, err := store.readBridge(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed pairing saved configuration: %v", err)
	}
	if err := pair(context.Background(), store, client, invite, "workstation", false); err != nil {
		t.Fatal(err)
	}
	if status, err := tlsHTTPStatus(server.address, config, testGET); err != nil || status != 405 {
		t.Fatalf("paired client not authorized: %d %v", status, err)
	}
	state, err := server.store.readServer()
	if err != nil || state.Pending != nil || state.Clients[client.fingerprint()].Name != "workstation" {
		t.Fatalf("incorrect saved enrollment: %+v %v", state, err)
	}
	if err := pair(context.Background(), store, client, invite, "workstation", true); err == nil {
		t.Fatal("single-use invitation was replayed")
	}
	if err := pair(context.Background(), store, client, invite, "workstation", false); err == nil || !strings.Contains(err.Error(), "already paired") {
		t.Fatalf("existing pairing overwritten without -replace: %v", err)
	}
	otherStore, otherID := testStoreIdentity(t)
	invite = testInvitation(t, server)
	if err := pair(context.Background(), otherStore, otherID, invite, "workstation", false); err == nil {
		t.Fatal("duplicate client name accepted")
	}
	if err := pair(context.Background(), otherStore, otherID, invite, "second-workstation", false); err != nil {
		t.Fatal(err)
	}
	// Reloading both identities must preserve all existing pins.
	reloaded, err := loadIdentity(store)
	if err != nil || reloaded.fingerprint() != client.fingerprint() {
		t.Fatalf("workstation identity did not persist: %v", err)
	}
	if status, err := tlsHTTPStatus(server.address, reloaded.clientTLS(server.id.fingerprint()), testGET); err != nil || status != 405 {
		t.Fatalf("reloaded client rejected: %d %v", status, err)
	}
}

func startTestBridge(t *testing.T, id *identity, config bridgeState, limit int, lists ...domainBlocklist) (string, context.CancelFunc) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	b := &bridge{identity: id, config: config, dialTimeout: time.Second, maxTunnels: limit,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if len(lists) > 0 {
		b.blocklist = lists[0]
	}
	go func() { done <- b.Serve(ctx, listener) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("bridge: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("bridge shutdown did not join handlers")
			}
		})
	}
	t.Cleanup(stop)
	return listener.Addr().String(), stop
}

func TestEncryptedBridgeHTTPSStreaming(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", http2), func(t *testing.T) {
			finish := make(chan struct{})
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer private-api-test-token" {
					http.Error(w, "missing end-to-end authorization", 401)
					return
				}
				fmt.Fprint(w, "private-first-streaming-chunk\n")
				w.(http.Flusher).Flush()
				select {
				case <-finish:
					fmt.Fprint(w, "private-last-streaming-chunk\n")
				case <-r.Context().Done():
				}
			}))
			upstream.EnableHTTP2 = http2
			upstream.StartTLS()
			defer upstream.Close()
			port := upstream.Listener.Addr().(*net.TCPAddr).Port
			server := secureServer(t, func(c *proxyConfig) {
				c.allowPrivate = true
				c.ports = map[int]bool{port: true}
			})
			_, id, config, invite := pairedClient(t, server)
			address, _ := startTestBridge(t, id, config, 8, domainBlocklist{"blocked.example": {}})
			proxyURL, _ := url.Parse("http://" + address)
			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyURL), ForceAttemptHTTP2: http2,
				TLSClientConfig: &tls.Config{RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs},
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
			req.Header.Set("Authorization", "Bearer private-api-test-token")
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			wantProto := 1
			if http2 {
				wantProto = 2
			}
			if response.StatusCode != 200 || response.ProtoMajor != wantProto {
				t.Fatalf("response = %s over %s", response.Status, response.Proto)
			}
			reader := bufio.NewReader(response.Body)
			if line, err := reader.ReadString('\n'); err != nil || line != "private-first-streaming-chunk\n" {
				t.Fatalf("first chunk: %q %v", line, err)
			}
			close(finish)
			if rest, err := io.ReadAll(reader); err != nil || string(rest) != "private-last-streaming-chunk\n" {
				t.Fatalf("last chunk: %q %v", rest, err)
			}
			server.wire.Lock()
			defer server.wire.Unlock()
			for _, secret := range []string{"CONNECT ", upstream.Listener.Addr().String(), invite.Token,
				"private-api-test-token", "private-first-streaming-chunk", "private-last-streaming-chunk"} {
				if bytes.Contains(server.wire.data, []byte(secret)) {
					t.Errorf("LAN TCP stream exposed %q", secret)
				}
			}
		})
	}
}

func TestEncryptedBufferedDataAndHalfClose(t *testing.T) {
	target := singleTCPServer(t, func(conn net.Conn) {
		data, _ := io.ReadAll(conn)
		fmt.Fprintf(conn, "reply:%s", data)
	})
	port := int(netip.MustParseAddrPort(target).Port())
	server := secureServer(t, func(c *proxyConfig) {
		c.allowPrivate = true
		c.ports = map[int]bool{port: true}
	})
	_, id, config, _ := pairedClient(t, server)
	address, _ := startTestBridge(t, id, config, 8)
	conn, reader, status := rawConnect(t, address, target, "early-tunnel-data")
	if status != 200 {
		t.Fatalf("CONNECT: %d", status)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "reply:early-tunnel-data" {
		t.Fatalf("half-close: %q %v", data, err)
	}
}

func requireClosed(t *testing.T, reader io.Reader) {
	t.Helper()
	var data [1]byte
	_, err := reader.Read(data[:])
	if err == nil {
		t.Fatal("connection was not closed")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("timed out waiting for connection closure")
	}
}

func TestRevocationClosesActiveTunnels(t *testing.T) {
	target := singleTCPServer(t, func(conn net.Conn) { io.Copy(conn, conn) })
	server := secureServer(t, func(c *proxyConfig) {
		c.allowPrivate = true
		c.ports = map[int]bool{int(netip.MustParseAddrPort(target).Port()): true}
	})
	_, id, config, _ := pairedClient(t, server)
	address, _ := startTestBridge(t, id, config, 8)
	_, reader, status := rawConnect(t, address, target, "")
	if status != 200 {
		t.Fatalf("CONNECT: %d", status)
	}
	var output bytes.Buffer
	if err := runClients([]string{"list", "-state-dir", server.store.dir}, &output); err != nil || !strings.Contains(output.String(), id.fingerprint()) {
		t.Fatalf("clients list: %q %v", output.String(), err)
	}
	// Exercise the same watch loop used by the actual server.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); server.handler.watchRevocations(ctx) }()
	defer func() { cancel(); <-done }()
	if err := runClients([]string{"revoke", "-state-dir", server.store.dir, "workstation"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	requireClosed(t, reader)
	if status, err := tlsHTTPStatus(server.address, id.clientTLS(config.ServerKey), testGET); err == nil {
		t.Fatalf("revoked client connected: %d", status)
	}
	// Even while a new invitation allows unpaired TLS handshakes, CONNECT is denied.
	testInvitation(t, server)
	if status, err := tlsHTTPStatus(server.address, id.clientTLS(config.ServerKey), testGET); err != nil || status != 403 {
		t.Fatalf("revoked client during enrollment: %d %v", status, err)
	}
}

func TestBridgeLimitAndShutdown(t *testing.T) {
	target := singleTCPServer(t, func(conn net.Conn) { io.Copy(conn, conn) })
	server := secureServer(t, func(c *proxyConfig) {
		c.allowPrivate = true
		c.ports = map[int]bool{int(netip.MustParseAddrPort(target).Port()): true}
	})
	_, id, config, _ := pairedClient(t, server)
	address, stop := startTestBridge(t, id, config, 1)
	_, reader, status := rawConnect(t, address, target, "")
	if status != 200 {
		t.Fatalf("CONNECT: %d", status)
	}
	second, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetDeadline(time.Now().Add(2 * time.Second))
	requireClosed(t, second)
	stop()
	requireClosed(t, reader)
}

func TestBridgeFailsClosed(t *testing.T) {
	server := secureServer(t, nil)
	_, id, config, _ := pairedClient(t, server)
	config.ServerKey = strings.Repeat("0", 64)
	address, _ := startTestBridge(t, id, config, 8)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	requireClosed(t, conn)
}

func TestBridgeShutdownDuringTLSHandshake(t *testing.T) {
	started := make(chan struct{})
	target := singleTCPServer(t, func(conn net.Conn) {
		data := make([]byte, 1024)
		conn.Read(data) // Read ClientHello but never send ServerHello.
		close(started)
		io.Copy(io.Discard, conn)
	})
	_, id := testStoreIdentity(t)
	config := bridgeState{Version: 1, Address: target, ServerKey: id.fingerprint()}
	address, stop := startTestBridge(t, id, config, 1)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("TLS handshake did not start")
	}
	stop()
	requireClosed(t, conn)
}

func TestPairCodeGuessLimit(t *testing.T) {
	server := secureServer(t, nil)
	invite := testInvitation(t, server)
	_, client := testStoreIdentity(t)
	wrong := "000000"
	if wrong == invite.Token {
		wrong = "999999"
	}
	for range 9 {
		if err := enroll(server.store, client.fingerprint(), pairRequest{Name: "test", Token: wrong}); !errors.Is(err, errEnrollmentDenied) {
			t.Fatalf("wrong code accepted: %v", err)
		}
	}
	state, err := server.store.readServer()
	if err != nil || state.Pending.Attempts != 9 {
		t.Fatalf("guess count was not persisted: %+v %v", state.Pending, err)
	}
	if err := enroll(server.store, client.fingerprint(), pairRequest{Name: "test", Token: invite.Token}); err != nil {
		t.Fatalf("valid code rejected before guess limit: %v", err)
	}
	invite = testInvitation(t, server)
	if wrong == invite.Token {
		wrong = "999999"
	}
	for range 10 {
		if err := enroll(server.store, client.fingerprint(), pairRequest{Name: "test", Token: wrong}); !errors.Is(err, errEnrollmentDenied) {
			t.Fatalf("wrong code accepted: %v", err)
		}
	}
	if err := enroll(server.store, client.fingerprint(), pairRequest{Name: "test", Token: invite.Token}); !errors.Is(err, errEnrollmentDenied) {
		t.Fatalf("code accepted after guess limit: %v", err)
	}
}

func TestInvitationLifecycleAndAtomicConsumption(t *testing.T) {
	server := secureServer(t, nil)
	first := testInvitation(t, server)
	second := testInvitation(t, server)
	_, client := testStoreIdentity(t)
	request := pairRequest{Name: "workstation", Token: first.Token}
	if err := enroll(server.store, client.fingerprint(), request); !errors.Is(err, errEnrollmentDenied) {
		t.Fatalf("superseded invitation accepted: %v", err)
	}
	request.Token = second.Token
	var wins atomic.Int32
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := enroll(server.store, client.fingerprint(), request); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, errEnrollmentDenied) {
				t.Errorf("enrollment: %v", err)
			}
		}()
	}
	workers.Wait()
	if wins.Load() != 1 {
		t.Fatalf("single-use invitation consumed %d times", wins.Load())
	}
	expired := testInvitation(t, server)
	if err := server.store.updateServer(func(state *serverState) error {
		state.Pending.ExpiresAt = time.Now().Add(-time.Second)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := enroll(server.store, client.fingerprint(), pairRequest{Name: "workstation", Token: expired.Token}); !errors.Is(err, errEnrollmentDenied) {
		t.Fatalf("expired invitation accepted: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(server.store.dir, "server.json"))
	if err != nil || bytes.Contains(data, []byte(expired.Token)) {
		t.Fatalf("state exposed invitation token: %v", err)
	}
}

func TestIdentityRenewalValidationAndPrivateState(t *testing.T) {
	store, id := testStoreIdentity(t)
	original, err := id.certificate()
	if err != nil {
		t.Fatal(err)
	}
	original.Leaf.NotAfter = time.Now().Add(time.Hour) // Enter renewal window.
	renewed, err := id.certificate()
	if err != nil || bytes.Equal(original.Certificate[0], renewed.Certificate[0]) || fingerprint(renewed.Leaf.RawSubjectPublicKeyInfo) != id.fingerprint() {
		t.Fatalf("certificate renewal did not preserve identity: %v", err)
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{renewed.Leaf}}
	if _, err := peerIdentity(state, x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*x509.Certificate){
		func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) },
		func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} },
		func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign },
		func(c *x509.Certificate) { c.Signature = make([]byte, len(c.Signature)) },
	} {
		cert := *renewed.Leaf
		change(&cert)
		state.PeerCertificates = []*x509.Certificate{&cert}
		if _, err := peerIdentity(state, x509.ExtKeyUsageClientAuth); err == nil {
			t.Fatal("invalid identity certificate accepted")
		}
	}
	if err := store.initServer("127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.pem", "server.json", ".lock"} {
		info, err := os.Stat(filepath.Join(store.dir, name))
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("non-private state %s: %v", name, err)
		}
	}
	if err := os.Remove(filepath.Join(store.dir, "identity.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(store); err == nil {
		t.Fatal("silently replaced lost identity")
	}
	if err := os.Chmod(store.dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(store.dir); err == nil {
		t.Fatal("accepted non-private state directory")
	}
}

func TestEncryptedCommandValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, args := range [][]string{
		{"-listen", "0.0.0.0:8888"}, {"-listen", "192.168.1.20:8888"},
		{"-listen", "localhost:8888"}, {"-listen", "127.0.0.1:0"},
		{"-dial-timeout", "0"}, {"-max-tunnels", "0"}, {"unexpected"},
	} {
		if err := runBridge(logger, args); err == nil {
			t.Errorf("bridge accepted invalid args %q", args)
		}
	}
	for _, endpoint := range []string{"0.0.0.0:8443", "[::]:8443", "[::ffff:0.0.0.0]:8443", "http://server:8443", "server", "server:0", "server:99999", "user@server:8443", "server/path:8443"} {
		if err := validEndpoint(endpoint); err == nil {
			t.Errorf("invalid endpoint accepted: %q", endpoint)
		}
	}
	if !validPairCode("000123") {
		t.Fatal("leading zeroes rejected")
	}
	for _, code := range []string{"", "12345", "1234567", "12a456", "-12345", "123456\n"} {
		if validPairCode(code) {
			t.Errorf("invalid code accepted: %q", code)
		}
	}
	for _, name := range []string{"", "with space", "new\nline", strings.Repeat("x", 65)} {
		if validClientName(name) {
			t.Errorf("invalid name accepted: %q", name)
		}
	}
}
