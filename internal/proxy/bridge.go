package proxy

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

	"github.com/neiios/vibemaxxer/internal/domain"
)

var upstreamReplyTimeout = dialTimeout + headerTimeout

type Bridge struct {
	Upstream     string
	TLSConfig    *tls.Config
	Blocklist    domain.Rules
	ProxyDomains domain.Rules
	Direct       *Server
	Logger       *slog.Logger
}

func (b *Bridge) dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 30 * time.Second}, Config: b.TLSConfig}
	return dialer.DialContext(ctx, "tcp", b.Upstream)
}

func (b *Bridge) Probe() {
	conn, err := b.dial()
	if err != nil {
		b.Logger.Warn("upstream check failed; will retry per connection", "server", b.Upstream, "error", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(headerTimeout))
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: probe\r\n\r\n")
	if err == nil {
		_, err = http.ReadResponse(bufio.NewReader(conn), nil)
	}
	if err != nil {
		b.Logger.Warn("upstream rejected this identity; is it a -client-key on the server?", "server", b.Upstream, "error", err)
		return
	}
	b.Logger.Info("upstream verified", "server", b.Upstream)
}

func (b *Bridge) Serve(listener net.Listener) error {
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
			b.Logger.Warn("connection limit reached")
			continue
		}
		go func() {
			defer func() { <-slots }()
			b.forward(local)
		}()
	}
}

func (b *Bridge) routeDirect(host string) bool {
	if b.ProxyDomains == nil {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return b.ProxyDomains.Match(host) == ""
}

func (b *Bridge) forwardDirect(local net.Conn, reader *bufio.Reader, target string, port int) {
	b.Logger.Info("routing connection", "target", target, "route", "direct")
	if !b.Direct.ports[port] {
		respond(local, http.StatusForbidden, "direct destination port not allowed")
		return
	}
	upstream, err := b.Direct.dial(context.Background(), target)
	if err != nil {
		status := http.StatusBadGateway
		var netErr net.Error
		if errors.Is(err, errPrivateDestination) {
			status = http.StatusForbidden
		} else if errors.As(err, &netErr) && netErr.Timeout() {
			status = http.StatusGatewayTimeout
		}
		b.Logger.Warn("direct connection failed", "target", target, "route", "direct", "error", err)
		respond(local, status, http.StatusText(status))
		return
	}
	defer upstream.Close()
	_ = local.SetWriteDeadline(time.Now().Add(headerTimeout))
	if _, err := io.WriteString(local, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = local.SetWriteDeadline(time.Time{})
	pipe(local, reader, upstream, upstream)
}

func (b *Bridge) forward(local net.Conn) {
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
		if rule := b.Blocklist.Match(host); rule != "" {
			b.Logger.Info("destination blocked", "target", target, "rule", rule)
			respond(local, http.StatusForbidden, "destination domain blocked")
			return
		}
	}
	_ = local.SetReadDeadline(time.Time{})
	if b.routeDirect(host) {
		b.forwardDirect(local, reader, target, port)
		return
	}
	b.Logger.Info("routing connection", "target", target, "route", "server")
	upstream, err := b.dial()
	if err != nil {
		b.Logger.Warn("encrypted upstream unavailable; no direct fallback", "target", target, "error", err)
		respond(local, http.StatusBadGateway, "encrypted upstream unavailable")
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(upstreamReplyTimeout))
	if _, err := fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		respond(local, http.StatusBadGateway, "encrypted upstream unavailable")
		return
	}
	upstreamReader := bufio.NewReader(upstream)
	if _, err := upstreamReader.Peek(1); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			b.Logger.Warn("encrypted upstream did not answer", "target", target, "error", err)
			respond(local, http.StatusGatewayTimeout, "encrypted upstream timed out")
			return
		}
		b.Logger.Warn("encrypted upstream rejected the connection; is this identity a -client-key on the server?", "target", target, "error", err)
		respond(local, http.StatusBadGateway, "encrypted upstream rejected the connection")
		return
	}
	_ = upstream.SetDeadline(time.Time{})
	pipe(local, reader, upstream, upstreamReader)
}
