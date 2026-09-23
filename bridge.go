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
	"net/netip"
	"strconv"
	"time"
)

type bridge struct {
	server    string
	tlsConfig *tls.Config
	blocklist domainBlocklist
	logger    *slog.Logger
}

func (b *bridge) dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 30 * time.Second}, Config: b.tlsConfig}
	return dialer.DialContext(ctx, "tcp", b.server)
}

func (b *bridge) probe() {
	conn, err := b.dial()
	if err != nil {
		b.logger.Warn("upstream check failed; will retry per connection", "server", b.server, "error", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(headerTimeout))
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: probe\r\n\r\n")
	if err == nil {
		_, err = http.ReadResponse(bufio.NewReader(conn), nil)
	}
	if err != nil {
		b.logger.Warn("upstream rejected this identity; is it a -client-key on the server?", "server", b.server, "error", err)
		return
	}
	b.logger.Info("upstream verified", "server", b.server)
}

func (b *bridge) serve(listener net.Listener) error {
	slots := make(chan struct{}, maxTunnels)
	for {
		local, err := listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			local.Close()
			b.logger.Warn("connection limit reached")
			continue
		}
		go func() {
			defer func() { <-slots }()
			b.forward(local)
		}()
	}
}

func respond(conn net.Conn, status int, message string) {
	_ = conn.SetWriteDeadline(time.Now().Add(headerTimeout))
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n",
		status, http.StatusText(status), len(message)+1, message)
}

func (b *bridge) forward(local net.Conn) {
	defer local.Close()
	_ = local.SetReadDeadline(time.Now().Add(headerTimeout))
	reader := bufio.NewReader(local)
	r, err := http.ReadRequest(reader)
	if err != nil {
		respond(local, http.StatusBadRequest, "expected an HTTP CONNECT request")
		return
	}
	if r.Method != http.MethodConnect {
		respond(local, http.StatusMethodNotAllowed, "only CONNECT is supported")
		return
	}
	host, port, err := parseConnectTarget(r)
	if err != nil {
		respond(local, http.StatusBadRequest, err.Error())
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if _, err := netip.ParseAddr(host); err != nil {
		if rule := b.blocklist.match(host); rule != "" {
			b.logger.Info("destination blocked", "target", target, "rule", rule)
			respond(local, http.StatusForbidden, "destination domain blocked")
			return
		}
	}
	_ = local.SetReadDeadline(time.Time{})
	upstream, err := b.dial()
	if err != nil {
		b.logger.Warn("encrypted upstream unavailable; no direct fallback", "target", target, "error", err)
		respond(local, http.StatusBadGateway, "encrypted upstream unavailable")
		return
	}
	defer upstream.Close()
	if _, err := fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		respond(local, http.StatusBadGateway, "encrypted upstream unavailable")
		return
	}
	upstreamReader := bufio.NewReader(upstream)
	if _, err := upstreamReader.Peek(1); err != nil {
		b.logger.Warn("encrypted upstream rejected the connection; is this identity a -client-key on the server?", "target", target, "error", err)
		respond(local, http.StatusBadGateway, "encrypted upstream rejected the connection")
		return
	}
	pipe(local, reader, upstream, upstreamReader)
}
