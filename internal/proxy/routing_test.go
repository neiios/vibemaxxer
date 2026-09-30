package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/neiios/vibemaxxer/internal/domain"
	"github.com/neiios/vibemaxxer/internal/proxytest"
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
		b := &Bridge{ProxyDomains: domain.Rules{"example.com": true, "127.0.0.1": true}}
		if got := b.routeDirect(tc.host); got != tc.direct {
			t.Errorf("%s: direct=%v", tc.host, got)
		}
	}
	if (&Bridge{}).routeDirect("example.com") {
		t.Fatal("default must proxy everything")
	}
	if !(&Bridge{ProxyDomains: domain.Rules{}}).routeDirect("example.com") {
		t.Fatal("empty list must route directly")
	}
}

func TestDirectRoutingEndToEnd(t *testing.T) {
	target, port := proxytest.EchoServer(t)
	closed, _ := proxytest.ClosedPort(t)
	logger, logs := proxytest.Logger()
	b := &Bridge{Upstream: closed, ProxyDomains: domain.Rules{}, Logger: logger,
		Direct: &Server{ports: map[int]bool{port: true}, allowPrivate: true}}
	address := startBridge(t, b)
	conn, reader, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest(target), "early")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	proxytest.AssertEcho(t, conn, reader, "early", " and later")
	if !strings.Contains(logs.String(), "route=direct") {
		t.Fatal("route not logged")
	}
}

func TestRoutingRestrictions(t *testing.T) {
	closed, _ := proxytest.ClosedPort(t)
	logger, _ := proxytest.Logger()
	b := &Bridge{Upstream: closed, ProxyDomains: domain.Rules{"localhost": true},
		Blocklist: domain.Rules{"blocked.example": true}, Direct: NewServer(map[int]bool{443: true}, logger), Logger: logger}
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
		if _, _, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest(tc.target), ""); status != tc.status {
			t.Errorf("%s: status %d, want %d", tc.target, status, tc.status)
		}
	}
}

func TestMatchedDomainUsesServer(t *testing.T) {
	_, port := proxytest.EchoServer(t)
	server, client := proxytest.Identity(t), proxytest.Identity(t)
	logger, logs := proxytest.Logger()
	upstream := startServer(t, server, map[string]bool{client.Fingerprint(): true}, map[int]bool{port: true}, true, logger)
	b := &Bridge{Upstream: upstream, TLSConfig: client.ClientTLS(server.Fingerprint()), ProxyDomains: domain.Rules{"localhost": true}, Logger: logger}
	address := startBridge(t, b)
	target := "localhost:" + strconv.Itoa(port)
	conn, reader, status := proxytest.Connect(t, address, nil, proxytest.ConnectRequest(target), "early")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	proxytest.AssertEcho(t, conn, reader, "early", " later")
	if !strings.Contains(logs.String(), "route=server") {
		t.Fatal("route not logged")
	}
}
