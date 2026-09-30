package proxy

import (
	"crypto/tls"
	"log/slog"
	"net"
	"testing"

	"github.com/neiios/vibemaxxer/internal/identity"
)

func startServer(t *testing.T, id *identity.Identity, clients map[string]bool, ports map[int]bool, allowPrivate bool, logger *slog.Logger) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(ports, logger)
	s.allowPrivate = allowPrivate
	server := s.HTTPServer()
	go server.Serve(tls.NewListener(listener, id.ServerTLS(clients)))
	t.Cleanup(func() { server.Close() })
	return listener.Addr().String()
}

func startBridge(t *testing.T, b *Bridge) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(listener)
	t.Cleanup(func() { listener.Close() })
	return listener.Addr().String()
}
