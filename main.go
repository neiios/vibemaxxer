// vibemaxxer is a paired TLS proxy with a loopback HTTP CONNECT bridge.
package main

import (
	"context"
	"crypto/tls"
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
		// Pairing is mandatory; an IP allowlist is an optional extra restriction.
		values = []string{"0.0.0.0/0", "::/0"}
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
	if err := run(logger, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func runServer(logger *slog.Logger, args []string) error {
	var clients allowFlags
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8443", "literal IP:port to listen on")
	flags.Var(&clients, "allow", "allowed client IP or CIDR; repeatable (default: any IP with pairing)")
	portsFlag := flags.String("ports", "443", "comma-separated allowed destination ports")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "DNS and connection establishment timeout")
	maxTunnels := flags.Int("max-tunnels", 128, "maximum concurrent tunnels, including pending connections")
	allowPrivate := flags.Bool("allow-private-destinations", false, "permit connections to private/local destination addresses")
	dir := flags.String("state-dir", defaultStateDir(), "private server configuration/identity directory")
	advertise := flags.String("advertise", "", "reachable hostname:port for invitations (default: listen address)")
	if err := parseCommandFlags(flags, args); err != nil {
		return err
	}
	bind, err := netip.ParseAddrPort(*listen)
	if err != nil || bind.Port() == 0 {
		return errors.New("-listen must be a literal IP and nonzero port, e.g. 192.168.1.50:8443")
	}
	if *dialTimeout <= 0 || *maxTunnels < 1 || *maxTunnels > 65536 {
		return errors.New("-dial-timeout must be positive and -max-tunnels must be 1–65536")
	}
	if *advertise == "" {
		*advertise = bind.String()
	}
	if err := validEndpoint(*advertise); err != nil {
		return err
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
	listener, err := net.Listen("tcp", bind.String())
	if err != nil {
		return err
	}
	defer listener.Close()
	store, err := openStore(*dir)
	if err != nil {
		return err
	}
	id, err := loadIdentity(store)
	if err != nil {
		return err
	}
	if err := store.initServer(*advertise); err != nil {
		return err
	}
	handler := &secureHandler{store: store, proxy: proxy}
	server := &http.Server{
		Handler: handler, TLSConfig: id.serverTLS(store),
		ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	// Hijacking requires outer HTTP/1.1. Inner HTTPS may still use HTTP/2.
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)
	listener = tls.NewListener(&cappedListener{Listener: listener, slots: make(chan struct{}, *maxTunnels+32)}, server.TLSConfig)
	watchCtx, cancelWatch := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); handler.watchRevocations(watchCtx) }()
	defer func() { cancelWatch(); <-watchDone }()
	logger.Info("TLS 1.3 with paired client identities enabled", "server_identity", id.fingerprint(), "advertise", *advertise)
	logger.Info("listening", "address", listener.Addr(), "allowed_clients", allowed, "ports", *portsFlag)
	logger.Info("outbound traffic follows host routing; configure your VPN and kill switch separately")
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
