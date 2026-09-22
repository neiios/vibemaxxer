package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptedWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-WebSocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" {
			http.Error(w, "expected WebSocket upgrade", 400)
			return
		}
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		buffered.Flush()
		// One masked client text frame: FIN, length 1, mask, payload 'z'.
		frame := make([]byte, 7)
		if _, err := io.ReadFull(buffered, frame); err != nil || !bytes.Equal(frame, []byte{0x81, 0x81, 1, 2, 3, 4, 'z' ^ 1}) {
			t.Errorf("WebSocket client frame: %x %v", frame, err)
			return
		}
		conn.Write([]byte{0x81, 1, 'z'}) // Unmasked server text frame.
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()
	server := secureServer(t, func(c *proxyConfig) {
		c.allowPrivate = true
		c.ports = map[int]bool{int(netip.MustParseAddrPort(target).Port()): true}
	})
	_, id, config, _ := pairedClient(t, server)
	address, _ := startTestBridge(t, id, config, 8)
	conn, _, status := rawConnect(t, address, target, "")
	if status != 200 {
		t.Fatalf("CONNECT: %d", status)
	}
	innerTLS := tls.Client(conn, &tls.Config{
		ServerName: "127.0.0.1", RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
	})
	defer innerTLS.Close()
	if err := innerTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(innerTLS, "GET /socket HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", target)
	reader := bufio.NewReader(innerTLS)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 101 || response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("WebSocket upgrade: %+v", response)
	}
	innerTLS.Write([]byte{0x81, 0x81, 1, 2, 3, 4, 'z' ^ 1})
	frame := make([]byte, 3)
	if _, err := io.ReadFull(reader, frame); err != nil || !bytes.Equal(frame, []byte{0x81, 1, 'z'}) {
		t.Fatalf("WebSocket server frame: %x %v", frame, err)
	}
}

func TestTLSListenerRejectsPlaintext(t *testing.T) {
	server := secureServer(t, nil)
	conn, err := net.DialTimeout("tcp", server.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext request was not rejected: %d", response.StatusCode)
		}
	}
}

func TestPairingRespectsIPAllowlist(t *testing.T) {
	server := secureServer(t, func(c *proxyConfig) {
		c.allowed = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
	})
	invite := testInvitation(t, server)
	store, id := testStoreIdentity(t)
	if err := pair(context.Background(), store, id, invite, "workstation", false); err == nil {
		t.Fatal("pairing bypassed client IP allowlist")
	}
	state, err := server.store.readServer()
	if err != nil || len(state.Clients) != 0 || state.Pending == nil {
		t.Fatalf("denied client changed enrollment state: %v", err)
	}
}

func TestUnreadableAuthorizationFailsClosed(t *testing.T) {
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
	if err := server.store.locked(func() error { return server.store.writePrivate("server.json", []byte("invalid JSON")) }); err != nil {
		t.Fatal(err)
	}
	server.handler.closeRevoked()
	requireClosed(t, reader)
	if status, err := tlsHTTPStatus(server.address, id.clientTLS(config.ServerKey), testGET); err == nil {
		t.Fatalf("corrupt state permitted a connection: %d", status)
	}
}

func TestPairCommandAndInvitationValidation(t *testing.T) {
	server := secureServer(t, nil)
	var code bytes.Buffer
	if err := runPairCode([]string{"-state-dir", server.store.dir}, &code); err != nil {
		t.Fatal(err)
	}
	clientDir := filepath.Join(t.TempDir(), "client")
	var output bytes.Buffer
	if err := runPair([]string{"-state-dir", clientDir, "-name", "test-cli"}, &code, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Paired test-cli") || strings.Contains(output.String(), invitationPrefix) {
		t.Fatalf("unexpected command output: %q", output.String())
	}
	store, err := openStore(clientDir)
	if err != nil {
		t.Fatal(err)
	}
	config, err := store.readBridge()
	if err != nil || config.Address != server.address || config.ServerKey != server.id.fingerprint() {
		t.Fatalf("wrong saved bridge state: %+v %v", config, err)
	}
	invite := testInvitation(t, server)
	if err := pair(context.Background(), server.store, server.id, invite, "self", false); err == nil {
		t.Fatal("same-state self pairing accepted")
	}
	for _, change := range []func(*invitation){
		func(i *invitation) { i.ExpiresAt = time.Now().Add(-time.Second) },
		func(i *invitation) { i.Version = 2 },
		func(i *invitation) { i.Token = "short" },
		func(i *invitation) { i.ServerKey = "invalid" },
		func(i *invitation) { i.Address = "0.0.0.0:8443" },
	} {
		invalid := invite
		change(&invalid)
		data, _ := json.Marshal(invalid)
		if _, err := decodeInvitation(invitationPrefix + base64.RawURLEncoding.EncodeToString(data)); err == nil {
			t.Fatal("invalid invitation accepted")
		}
	}
	// Restarting the server retains clients but cancels outstanding invitations.
	if err := server.store.initServer(server.address); err != nil {
		t.Fatal(err)
	}
	state, err := server.store.readServer()
	if err != nil || state.Pending != nil || len(state.Clients) != 1 {
		t.Fatalf("server restart lost clients or kept invitation: %+v %v", state, err)
	}
}

func TestPrivateStateRejectsSymlinks(t *testing.T) {
	store, _ := testStoreIdentity(t)
	keyPath := filepath.Join(store.dir, "identity.pem")
	if err := os.Rename(keyPath, keyPath+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keyPath+".real", keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(store); err == nil {
		t.Fatal("identity symlink accepted")
	}
	if err := os.Symlink(store.dir, store.dir+"-link"); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(store.dir + "-link"); err == nil {
		t.Fatal("state directory symlink accepted")
	}
}

func TestCappedListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	capped := &cappedListener{Listener: listener, slots: make(chan struct{}, 1)}
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := capped.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := capped.Accept()
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	defer func() {
		listener.Close()
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener: %v", err)
		}
	}()
	second, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetDeadline(time.Now().Add(2 * time.Second))
	requireClosed(t, second)
	accepted.Close()
	accepted.Close() // Slot release must be idempotent.
	if len(capped.slots) != 0 {
		t.Fatal("closed connection did not release its slot")
	}
}
