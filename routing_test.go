package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDomainRouting(t *testing.T) {
	for _, tc := range []struct {
		host   string
		direct bool
	}{
		{"example.com", false}, {"api.EXAMPLE.com.", false},
		{"notexample.com", true}, {"example.com.evil", true},
		{"127.0.0.1", true}, {"::1", true},
	} {
		b := &bridge{proxyDomains: domainRules{"example.com": true, "127.0.0.1": true}}
		if got := b.routeDirect(tc.host); got != tc.direct {
			t.Errorf("%s: direct=%v", tc.host, got)
		}
	}
	if (&bridge{}).routeDirect("example.com") {
		t.Fatal("default must proxy everything")
	}
	if !(&bridge{proxyDomains: domainRules{}}).routeDirect("example.com") {
		t.Fatal("empty list must route directly")
	}
}

func TestRoutingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains")
	if err := os.WriteFile(path, []byte("# comment\n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadDomainRules(path)
	if err != nil || rules == nil || len(rules) != 0 {
		t.Fatalf("empty file: %v, %v", rules, err)
	}
	if _, err := loadDomainRules(path + "-missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.WriteFile(path, []byte("https://example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDomainRules(path); err == nil {
		t.Fatal("invalid rule accepted")
	}
}

func TestDirectRoutingEndToEnd(t *testing.T) {
	target, port := echoServer(t)
	closed, _ := closedPort(t)
	logger, logs := testLogger()
	b := &bridge{server: closed, proxyDomains: domainRules{}, logger: logger,
		direct: &proxy{ports: map[int]bool{port: true}, allowPrivate: true}}
	address := startBridge(t, b)
	conn, reader, status := connect(t, address, nil, connectRequest(target), "early")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	assertEcho(t, conn, reader, "early", " and later")
	if !strings.Contains(logs.String(), "route=direct") {
		t.Fatal("route not logged")
	}
}

func TestRoutingRestrictions(t *testing.T) {
	closed, _ := closedPort(t)
	logger, _ := testLogger()
	b := &bridge{server: closed, proxyDomains: domainRules{"localhost": true},
		blocklist: domainRules{"blocked.example": true}, logger: logger}
	address := startBridge(t, b)
	for _, tc := range []struct {
		target string
		status int
	}{
		{"localhost:443", http.StatusBadGateway},
		{"blocked.example:443", http.StatusForbidden},
		{"127.0.0.1:443", http.StatusForbidden},
		{"127.0.0.1:22", http.StatusForbidden},
	} {
		if _, _, status := connect(t, address, nil, connectRequest(tc.target), ""); status != tc.status {
			t.Errorf("%s: status %d, want %d", tc.target, status, tc.status)
		}
	}
}

func TestMatchedDomainUsesServer(t *testing.T) {
	_, port := echoServer(t)
	server, client := testIdentity(t), testIdentity(t)
	logger, logs := testLogger()
	upstream := startServer(t, server, map[string]bool{client.Fingerprint(): true}, map[int]bool{port: true}, true, logger)
	b := &bridge{server: upstream, tlsConfig: client.ClientTLS(server.Fingerprint()), proxyDomains: domainRules{"localhost": true}, logger: logger}
	address := startBridge(t, b)
	target := "localhost:" + strconv.Itoa(port)
	conn, reader, status := connect(t, address, nil, connectRequest(target), "early")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	assertEcho(t, conn, reader, "early", " later")
	if !strings.Contains(logs.String(), "route=server") {
		t.Fatal("route not logged")
	}
}
