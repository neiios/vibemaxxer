// vibemaxxer is a small, access-controlled HTTP CONNECT proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type allowFlags []string

func (a *allowFlags) String() string { return strings.Join(*a, ",") }
func (a *allowFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func parseAllow(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		values = []string{"127.0.0.0/8", "::1/128"}
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if addr, err := netip.ParseAddr(value); err == nil && addr.Zone() == "" {
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid client IP/CIDR %q (use ordinary IPv4 CIDRs, not mapped IPv6 CIDRs)", value)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
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

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var clients allowFlags
	listen := flag.String("listen", "127.0.0.1:8888", "literal IP:port to listen on")
	flag.Var(&clients, "allow", "allowed client IP or CIDR; repeatable (default: loopback only)")
	portsFlag := flag.String("ports", "443", "comma-separated allowed destination ports")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "DNS and connection establishment timeout")
	maxTunnels := flag.Int("max-tunnels", 128, "maximum concurrent tunnels, including pending connections")
	allowPrivate := flag.Bool("allow-private-destinations", false, "permit connections to private/local destination addresses")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments; use -help")
	}
	bind, err := netip.ParseAddrPort(*listen)
	if err != nil || bind.Port() == 0 {
		return errors.New("-listen must be a literal IP and nonzero port, e.g. 192.168.1.50:8888")
	}
	if !bind.Addr().IsLoopback() && len(clients) == 0 {
		return errors.New("non-loopback listeners require an explicit -allow client IP/CIDR")
	}
	if *dialTimeout <= 0 || *maxTunnels < 1 {
		return errors.New("-dial-timeout and -max-tunnels must be positive")
	}
	allowed, err := parseAllow(clients)
	if err != nil {
		return err
	}
	ports, err := parsePorts(*portsFlag)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	proxy := newProxy(proxyConfig{
		allowed: allowed, ports: ports, dialTimeout: *dialTimeout,
		maxTunnels: *maxTunnels, allowPrivate: *allowPrivate,
	}, logger)
	defer proxy.Close()
	server := &http.Server{
		Handler: proxy, ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	listener, err := net.Listen("tcp", bind.String())
	if err != nil {
		return err
	}
	defer listener.Close()
	logger.Info("listening", "address", listener.Addr(), "allowed_clients", allowed, "ports", *portsFlag)
	logger.Info("outbound traffic follows host routing; configure your VPN and kill switch separately")
	if !bind.Addr().IsLoopback() {
		logger.Warn("plain HTTP proxy: use only on a trusted LAN; CONNECT destinations are not encrypted")
	}
	if *allowPrivate {
		logger.Warn("private/local destinations are enabled")
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		// Shutdown alone does not close hijacked CONNECT connections.
		proxy.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
