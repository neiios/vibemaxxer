package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/neiios/vibemaxxer/internal/policy"
)

const (
	headerTimeout   = 10 * time.Second
	dialTimeout     = 10 * time.Second
	upstreamTimeout = 30 * time.Second
	idleTimeout     = 15 * time.Minute
	maxActive       = 128
	maxHeaderBytes  = 32 << 10
)

type Proxy struct {
	name         string
	policy       *policy.Policy
	upstream     string
	upstreamDial DialFunc
	dial         DialFunc
	logger       *slog.Logger
	slots        chan struct{}
	direct       *http.Transport
	proxied      *http.Transport
	idle         time.Duration
}

func New(name string, rules *policy.Policy, upstream string, dial DialFunc, logger *slog.Logger) (*Proxy, error) {
	return newProxy(name, rules, upstream, nil, dial, logger)
}

func NewTLS(name string, rules *policy.Policy, upstream string, config *tls.Config, dial DialFunc, logger *slog.Logger) (*Proxy, error) {
	if config == nil || upstream == "" {
		return nil, errors.New("TLS upstream requires an address and TLS configuration")
	}
	return newProxy(name, rules, upstream, config.Clone(), dial, logger)
}

func newProxy(name string, rules *policy.Policy, upstream string, config *tls.Config, dial DialFunc, logger *slog.Logger) (*Proxy, error) {
	if upstream == "" && rules.RequiresUpstream() {
		return nil, errors.New("proxy rules require --upstream (SSH) or --server and --server-key (LAN TLS)")
	}
	p := &Proxy{name: name, policy: rules, upstream: upstream, dial: dial, logger: logger,
		slots: make(chan struct{}, maxActive), idle: idleTimeout,
		direct: &http.Transport{DialContext: dial, IdleConnTimeout: time.Minute}}
	if upstream != "" {
		netDialer := &net.Dialer{Timeout: upstreamTimeout}
		p.upstreamDial = netDialer.DialContext
		scheme := "http"
		if config != nil {
			scheme = "https"
			p.upstreamDial = (&tls.Dialer{NetDialer: netDialer, Config: config}).DialContext
		}
		p.proxied = &http.Transport{
			Proxy:               http.ProxyURL(&url.URL{Scheme: scheme, Host: upstream}),
			DialContext:         netDialer.DialContext,
			TLSClientConfig:     config,
			TLSHandshakeTimeout: headerTimeout,
			IdleConnTimeout:     time.Minute,
		}
	}
	return p, nil
}

func (p *Proxy) Server() *http.Server {
	return &http.Server{
		Handler:           p,
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(p.logger.Handler(), slog.LevelWarn),
	}
}

type failure struct {
	status int
	kind   string
	detail string
	header string
}

func fail(status int, kind, detail string) *failure {
	return &failure{status: status, kind: kind, detail: detail}
}

func (f *failure) Error() string { return f.kind + ": " + f.detail }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	attrs := []any{"method", r.Method}
	status, err := p.handle(w, r, &attrs)
	var f *failure
	if errors.As(err, &f) {
		status = f.status
		p.reject(w, r, f)
	}
	attrs = append(attrs, "status", status, "duration", time.Since(started).Round(time.Millisecond))
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	p.logger.Info("request", attrs...)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request, attrs *[]any) (int, error) {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		return 0, fail(http.StatusServiceUnavailable, "connection_limit_reached", "too many active requests")
	}
	host, port, address, err := destination(r)
	if err != nil {
		*attrs = append(*attrs, "target", r.URL.Host)
	}
	if errors.Is(err, policy.ErrIPLiteral) {
		return 0, fail(http.StatusForbidden, "destination_ip_prohibited", err.Error())
	}
	if err != nil {
		return 0, fail(http.StatusBadRequest, "http_request_error", err.Error())
	}
	action, rule := p.policy.Decide(host, port)
	*attrs = append(*attrs, "host", host, "port", port, "action", action.String(), "rule", rule)
	if action == policy.Block {
		return 0, fail(http.StatusForbidden, "http_request_denied", "denied by rule "+rule)
	}
	if r.Method != http.MethodConnect {
		switch {
		case host == policy.Loopback:
			address = r.URL.Host
		case port == 80:
			address = host
		}
		return p.forward(w, r, address, action)
	}
	var remote net.Conn
	var reader io.Reader
	if action == policy.Proxy {
		remote, reader, err = p.connectUpstream(r.Context(), address)
	} else {
		remote, err = p.dial(r.Context(), "tcp", address)
		reader = remote
	}
	if err != nil {
		if action == policy.Proxy {
			return 0, err
		}
		return 0, dialFailure(err)
	}
	return p.tunnel(w, remote, reader)
}

var hopByHop = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripHopByHop(h http.Header) {
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(name))
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, address string, action policy.Action) (int, error) {
	out := r.Clone(r.Context())
	out.URL.Host, out.Host, out.RequestURI, out.Close = address, "", "", false
	upgrade := upgradeType(r.Header)
	stripHopByHop(out.Header)
	if upgrade != "" {
		out.Header.Set("Connection", "Upgrade")
		out.Header.Set("Upgrade", upgrade)
	}
	transport, classify := p.direct, dialFailure
	if action == policy.Proxy {
		transport, classify = p.proxied, upstreamFailure
	}
	resp, err := transport.RoundTrip(out)
	if err != nil {
		return 0, classify(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return p.switchProtocols(w, resp, upgrade)
	}
	stripHopByHop(resp.Header)
	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(flusher{w, http.NewResponseController(w)}, resp.Body)
	return resp.StatusCode, err
}

func upgradeType(h http.Header) string {
	for _, value := range h.Values("Connection") {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return h.Get("Upgrade")
			}
		}
	}
	return ""
}

func (p *Proxy) switchProtocols(w http.ResponseWriter, resp *http.Response, upgrade string) (int, error) {
	backend, ok := resp.Body.(io.ReadWriteCloser)
	if !ok || upgrade == "" || !strings.EqualFold(upgradeType(resp.Header), upgrade) {
		return 0, fail(http.StatusBadGateway, "http_upgrade_failed", "destination switched to an unrequested protocol")
	}
	local, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return 0, fail(http.StatusInternalServerError, "proxy_internal_error", err.Error())
	}
	defer local.Close()
	stripHopByHop(resp.Header)
	resp.Header.Set("Connection", "Upgrade")
	resp.Header.Set("Upgrade", upgrade)
	buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	resp.Header.Write(buffered)
	buffered.WriteString("\r\n")
	if err := buffered.Flush(); err != nil {
		return 0, err
	}
	pipe(local, buffered.Reader, backend, backend, p.idle)
	return http.StatusSwitchingProtocols, nil
}

type flusher struct {
	io.Writer
	controller *http.ResponseController
}

func (f flusher) Write(p []byte) (int, error) {
	n, err := f.Writer.Write(p)
	if err == nil {
		err = f.controller.Flush()
	}
	return n, err
}

func destination(r *http.Request) (host string, port int, address string, err error) {
	authority := r.URL.Host
	if r.Method != http.MethodConnect {
		if r.URL.Scheme != "http" || authority == "" {
			return "", 0, "", errors.New("expected CONNECT or an absolute http:// URL")
		}
		if r.URL.Port() == "" {
			authority = net.JoinHostPort(r.URL.Hostname(), "80")
		}
	}
	name, portText, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, "", errors.New("expected HOST:PORT")
	}
	if port, err = policy.Port(portText); err != nil {
		return "", 0, "", err
	}
	if host, err = policy.Host(name); err != nil {
		return "", 0, "", err
	}
	if host != policy.Loopback {
		name = host
	}
	return host, port, net.JoinHostPort(name, portText), nil
}

func (p *Proxy) reject(w http.ResponseWriter, r *http.Request, f *failure) {
	header := f.header
	if header == "" {
		header = fmt.Sprintf("%s; error=%s; details=%s", p.name, f.kind, strconv.Quote(f.detail))
	}
	w.Header().Set("Proxy-Status", header)
	if r.Method == http.MethodConnect {
		w.Header().Set("Connection", "close")
	}
	http.Error(w, f.Error(), f.status)
}

func dialFailure(err error) *failure {
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.Is(err, errProhibited):
		return fail(http.StatusForbidden, "destination_ip_prohibited", "destination resolves to a prohibited address")
	case errors.As(err, &netErr) && netErr.Timeout():
		return fail(http.StatusGatewayTimeout, "connection_timeout", "destination did not answer in time")
	case errors.As(err, &dnsErr):
		return fail(http.StatusBadGateway, "dns_error", "destination name did not resolve")
	case errors.Is(err, syscall.ECONNREFUSED):
		return fail(http.StatusBadGateway, "connection_refused", "destination refused the connection")
	default:
		return fail(http.StatusBadGateway, "destination_unavailable", "destination unreachable")
	}
}

func upstreamFailure(err error) *failure {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fail(http.StatusGatewayTimeout, "connection_timeout", "upstream proxy did not answer in time")
	}
	return fail(http.StatusBadGateway, "destination_unavailable", "upstream proxy unavailable")
}

func (p *Proxy) connectUpstream(ctx context.Context, address string) (net.Conn, io.Reader, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	conn, err := p.upstreamDial(ctx, "tcp", p.upstream)
	if err != nil {
		return nil, nil, upstreamFailure(err)
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	reader := bufio.NewReader(conn)
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address)
	var resp *http.Response
	if err == nil {
		resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	}
	if err != nil {
		conn.Close()
		return nil, nil, upstreamFailure(err)
	}
	if resp.StatusCode/100 != 2 {
		conn.Close()
		return nil, nil, &failure{resp.StatusCode, "upstream", resp.Status, resp.Header.Get("Proxy-Status")}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, reader, nil
}

func (p *Proxy) tunnel(w http.ResponseWriter, remote net.Conn, remoteReader io.Reader) (int, error) {
	defer remote.Close()
	local, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return 0, fail(http.StatusInternalServerError, "proxy_internal_error", err.Error())
	}
	defer local.Close()
	if _, err := io.WriteString(local, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return 0, err
	}
	pipe(local, buffered.Reader, remote, remoteReader, p.idle)
	return http.StatusOK, nil
}
