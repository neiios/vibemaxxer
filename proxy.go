package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	dialTimeout   = 10 * time.Second
	headerTimeout = 10 * time.Second
	maxTunnels    = 256
)

type proxy struct {
	ports        map[int]bool
	logger       *slog.Logger
	slots        chan struct{}
	allowPrivate bool
}

func newProxy(ports map[int]bool, logger *slog.Logger) *proxy {
	return &proxy{ports: ports, logger: logger, slots: make(chan struct{}, maxTunnels)}
}

func parseConnectTarget(r *http.Request) (host string, port int, err error) {
	host, portText, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		return "", 0, errors.New("expected CONNECT host:port")
	}
	port, err = strconv.Atoi(portText)
	if err != nil || host == "" || port < 1 || port > 65535 {
		return "", 0, errors.New("expected CONNECT host:port")
	}
	return host, port, nil
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func publicDestination(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !sharedAddressSpace.Contains(addr)
}

var errPrivateDestination = errors.New("private/local destination blocked")

func (p *proxy) dial(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if !p.allowPrivate {
		dialer.ControlContext = func(_ context.Context, _, address string, _ syscall.RawConn) error {
			endpoint, err := netip.ParseAddrPort(address)
			if err != nil || !publicDestination(endpoint.Addr()) {
				return errPrivateDestination
			}
			return nil
		}
	}
	return dialer.DialContext(ctx, "tcp", target)
}

func reject(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Connection", "close")
	http.Error(w, message, status)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", http.MethodConnect)
		reject(w, http.StatusMethodNotAllowed, "only CONNECT is supported")
		return
	}
	host, port, err := parseConnectTarget(r)
	if err != nil {
		reject(w, http.StatusBadRequest, err.Error())
		return
	}
	if !p.ports[port] {
		reject(w, http.StatusForbidden, "destination port not allowed")
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		reject(w, http.StatusServiceUnavailable, "tunnel limit reached")
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	upstream, err := p.dial(r.Context(), target)
	if err != nil {
		status := http.StatusBadGateway
		var netErr net.Error
		if errors.Is(err, errPrivateDestination) {
			status = http.StatusForbidden
		} else if errors.As(err, &netErr) && netErr.Timeout() {
			status = http.StatusGatewayTimeout
		}
		p.logger.Warn("connect failed", "client", r.RemoteAddr, "target", target, "error", err)
		reject(w, status, http.StatusText(status))
		return
	}
	defer upstream.Close()
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		p.logger.Warn("hijack failed", "error", err)
		return
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(headerTimeout))
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	started := time.Now()
	p.logger.Info("tunnel opened", "client", r.RemoteAddr, "target", target)
	pipe(client, buffered.Reader, upstream, upstream)
	p.logger.Info("tunnel closed", "client", r.RemoteAddr, "target", target, "duration", time.Since(started))
}

func pipe(a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(b, aReader); err != nil {
			a.Close()
			b.Close()
			return
		}
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	_, _ = io.Copy(a, bReader)
	a.Close()
	b.Close()
	<-done
}

func parsePorts(value string) (map[int]bool, error) {
	ports := make(map[int]bool)
	for _, part := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid destination port %q", part)
		}
		ports[port] = true
	}
	return ports, nil
}
