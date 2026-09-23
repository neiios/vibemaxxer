package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

type bridge struct {
	config      bridgeState
	identity    *identity
	logger      *slog.Logger
	dialTimeout time.Duration
	maxTunnels  int
	blocklist   domainBlocklist
}

// Serve owns the listener and joins all connection handlers before returning.
// With filtering enabled, only the CONNECT header is inspected. The complete
// exchange is forwarded inside pinned, mutually authenticated TLS.
func (b *bridge) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer listener.Close()
	var workers sync.WaitGroup
	slots := make(chan struct{}, b.maxTunnels)
	var serveErr error
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				serveErr = err
			}
			break
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				b.forward(ctx, local)
			}()
		default:
			_ = local.Close()
			b.logger.Warn("bridge connection limit reached")
		}
	}
	cancel()
	workers.Wait()
	return serveErr
}

func (b *bridge) forward(ctx context.Context, local net.Conn) {
	defer local.Close()
	stopLocal := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer stopLocal()
	var upload io.Reader = local
	if b.blocklist != nil {
		var err error
		upload, err = b.filterCONNECT(local)
		if err != nil {
			return
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, b.dialTimeout)
	defer cancel()
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: b.dialTimeout, KeepAlive: 30 * time.Second},
		Config:    b.identity.clientTLS(b.config.ServerKey),
	}
	upstream, err := dialer.DialContext(dialCtx, "tcp", b.config.Address)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			b.logger.Warn("encrypted upstream connection failed; no direct fallback", "error", err)
		}
		return
	}
	cancel() // Only connection establishment has a timeout, not the tunnel.
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	t := &tunnel{client: local, upstream: upstream}
	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		if _, err := io.Copy(upstream, upload); err != nil {
			t.close()
			return
		}
		// TLS close_notify is the encrypted equivalent of TCP upload half-close.
		if conn, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = conn.CloseWrite()
		}
	}()
	_, _ = io.Copy(local, upstream)
	t.close()
	<-uploadDone
}

// Limit raw accepted connections as well as established CONNECT tunnels, so
// slow TLS handshakes and pairing requests cannot create unbounded handlers.
type cappedListener struct {
	net.Listener
	slots chan struct{}
}

type cappedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *cappedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (l *cappedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &cappedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}
