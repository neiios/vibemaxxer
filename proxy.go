package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type proxyConfig struct {
	allowed      []netip.Prefix
	ports        map[int]bool
	dialTimeout  time.Duration
	maxTunnels   int
	allowPrivate bool
}

type tunnel struct{ client, upstream net.Conn }

func (t *tunnel) close() {
	_ = t.client.Close()
	_ = t.upstream.Close()
}

type proxy struct {
	config  proxyConfig
	logger  *slog.Logger
	slots   chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	tunnels map[*tunnel]struct{}
}

func newProxy(config proxyConfig, logger *slog.Logger) *proxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &proxy{
		config: config, logger: logger, slots: make(chan struct{}, config.maxTunnels),
		ctx: ctx, cancel: cancel, tunnels: make(map[*tunnel]struct{}),
	}
}

func (p *proxy) clientAllowed(remote string) bool {
	peer, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	addr := peer.Addr().Unmap().WithZone("")
	for _, prefix := range p.config.allowed {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func publicDestination(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !sharedAddressSpace.Contains(addr)
}

var errPrivateDestination = errors.New("private/local destination blocked")

func (p *proxy) dial(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: p.config.dialTimeout, KeepAlive: 30 * time.Second}
	if !p.config.allowPrivate {
		// ControlContext receives the actual resolved IP before connect, not the
		// hostname. This blocks DNS rebinding without giving up Happy Eyeballs.
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
	// Trust only the TCP peer, never Forwarded or X-Forwarded-For headers.
	if !p.clientAllowed(r.RemoteAddr) {
		reject(w, http.StatusForbidden, "client not allowed")
		return
	}
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", http.MethodConnect)
		reject(w, http.StatusMethodNotAllowed, "only CONNECT is supported")
		return
	}
	host, portText, err := net.SplitHostPort(r.RequestURI)
	port, portErr := strconv.Atoi(portText)
	if err != nil || host == "" || strings.ContainsAny(host, "/?#@\\% \t\r\n") ||
		portErr != nil || port < 1 || port > 65535 || r.URL.Host != r.RequestURI ||
		r.URL.Scheme != "" || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		reject(w, http.StatusBadRequest, "expected CONNECT hostname:port without a request body")
		return
	}
	if !p.config.ports[port] {
		reject(w, http.StatusForbidden, "destination port not allowed")
		return
	}
	select {
	case <-p.ctx.Done():
		reject(w, http.StatusServiceUnavailable, "proxy shutting down")
		return
	default:
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		reject(w, http.StatusServiceUnavailable, "tunnel limit reached")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		reject(w, http.StatusInternalServerError, "HTTP/1.x connection required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.config.dialTimeout)
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	defer cancel()
	target := net.JoinHostPort(host, strconv.Itoa(port))
	upstream, err := p.dial(ctx, target)
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
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		p.logger.Warn("hijack failed", "error", err)
		return
	}
	t := &tunnel{client: client, upstream: upstream}
	defer t.close()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.tunnels[t] = struct{}{}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.tunnels, t)
		p.mu.Unlock()
	}()

	// Bound the CONNECT response write, but not the lifetime of a stream.
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	started := time.Now()
	p.logger.Info("tunnel opened", "client", r.RemoteAddr, "target", target)
	defer func() {
		p.logger.Info("tunnel closed", "client", r.RemoteAddr, "target", target, "duration", time.Since(started))
	}()

	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		// Hijack can return already-buffered tunnel bytes. Read those first.
		if _, err := io.Copy(upstream, buffered.Reader); err != nil {
			t.close()
			return
		}
		// A client may finish uploading and still expect a response.
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(client, upstream)
	t.close()
	<-uploadDone
}

func (p *proxy) Close() {
	p.cancel() // Interrupt pending DNS lookups and dials as well as active tunnels.
	p.mu.Lock()
	p.closed = true
	active := make([]*tunnel, 0, len(p.tunnels))
	for t := range p.tunnels {
		active = append(active, t)
	}
	p.mu.Unlock()
	for _, t := range active {
		t.close()
	}
}
