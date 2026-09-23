package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBlocklistLoading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.txt")
	for _, tc := range []struct {
		text  string
		valid bool
	}{
		{"# comment\r\n Example.COM. \r\nexample.com\n", true}, {"", true},
		{"https://example.com", false}, {"example.com:443", false},
		{"*.example.com", false}, {"127.0.0.1", false}, {"::1", false},
		{"exämple.com", false}, {"a..com", false}, {"-a.com", false},
		{"a-.com", false}, {strings.Repeat("a", 64) + ".com", false},
		{"example.com # comment", false}, {"example.com..", false},
	} {
		if err := os.WriteFile(path, []byte(tc.text), 0600); err != nil {
			t.Fatal(err)
		}
		list, err := loadBlocklist(path)
		if (err == nil) != tc.valid {
			t.Fatalf("load %q: %v", tc.text, err)
		}
		if err != nil && !strings.Contains(err.Error(), path+":1:") {
			t.Fatal(err)
		}
		if tc.valid && list == nil {
			t.Fatal("empty file must still enable validation")
		}
	}
	if _, err := loadBlocklist(path + ".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	if list, err := loadBlocklist(""); list != nil || err != nil {
		t.Fatal("default not disabled")
	}
	if err := os.WriteFile(path, []byte("EXAMPLE.com.\nexample.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	list, err := loadBlocklist(path)
	if err != nil || len(list) != 1 {
		t.Fatalf("deduplication: %v %v", list, err)
	}
	for host, want := range map[string]bool{"example.com": true, "a.b.example.com": true, "notexample.com": false, "example.com.other.net": false} {
		if (list.match(host) != "") != want {
			t.Errorf("match %s", host)
		}
	}
}

func TestBridgeFilterRejectsBeforeUpstream(t *testing.T) {
	for _, tc := range []struct {
		request string
		status  int
	}{
		{"CONNECT ExAmPlE.COM.:443 HTTP/1.1\r\nHost: ExAmPlE.COM.:443\r\n\r\n", 403},
		{"CONNECT a.example.com:443 HTTP/1.1\r\nHost: a.example.com:443\r\n\r\n", 403},
		{"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 405},
		{"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n", 400},
		{"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 2\r\n\r\n", 400},
		{"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX: " + strings.Repeat("x", bridgeHeaderLimit) + "\r\n\r\n", 431},
	} {
		t.Run(fmt.Sprint(tc.status, len(tc.request)), func(t *testing.T) {
			local, client := net.Pipe()
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			// No identity/config: any attempt to establish TLS would panic.
			b := &bridge{blocklist: domainBlocklist{"example.com": {}}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			done := make(chan struct{})
			go func() { defer close(done); b.forward(context.Background(), local) }()
			written := make(chan struct{})
			go func() { defer close(written); io.WriteString(client, tc.request) }()
			resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "CONNECT"})
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Errorf("status %d, want %d", resp.StatusCode, tc.status)
			}
			client.Close()
			<-done
			<-written
		})
	}
}

func TestFilteredBridgeBufferedDataAndHalfClose(t *testing.T) {
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
	address, _ := startTestBridge(t, id, config, 8, domainBlocklist{"example.com": {}})
	for _, host := range []string{"example.com", "sub.example.com"} {
		_, _, status := rawConnect(t, address, host+":443", "")
		if status != 403 {
			t.Fatalf("blocked status: %d", status)
		}
	}
	// Use a hostname for the allowed path; destination DNS stays on the server.
	conn, reader, status := rawConnect(t, address, fmt.Sprintf("localhost:%d", port), "early-data")
	if status != 200 {
		t.Fatalf("allowed status: %d", status)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "reply:early-data" {
		t.Fatalf("relay: %q %v", data, err)
	}
}
