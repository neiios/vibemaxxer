// vibemaxxer is a small, access-controlled HTTP CONNECT proxy.
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
	if err := run(logger); err != nil && !errors.Is(err, flag.ErrHelp) {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func runProxy(logger *slog.Logger, args []string, encrypted bool) error {
	var clients allowFlags
	mode, defaultListen := "plain", "127.0.0.1:8888"
	if encrypted {
		mode, defaultListen = "serve", "127.0.0.1:8443"
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.Usage = func() {
		printCommands(flags.Output())
		fmt.Fprintf(flags.Output(), "\n%s flags:\n", mode)
		flags.PrintDefaults()
	}
	listen := flags.String("listen", defaultListen, "literal IP:port to listen on")
	flags.Var(&clients, "allow", "allowed client IP or CIDR; repeatable (serve: optional additional restriction; plain: loopback default)")
	portsFlag := flags.String("ports", "443", "comma-separated allowed destination ports")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "DNS and connection establishment timeout")
	maxTunnels := flags.Int("max-tunnels", 128, "maximum concurrent tunnels, including pending connections")
	allowPrivate := flags.Bool("allow-private-destinations", false, "permit connections to private/local destination addresses")
	var dir, advertise string
	if encrypted {
		flags.StringVar(&dir, "state-dir", defaultStateDir(), "private server configuration/identity directory")
		flags.StringVar(&advertise, "advertise", "", "reachable hostname:port for invitations (default: listen address)")
	}
	if err := parseCommandFlags(flags, args); err != nil {
		return err
	}
	bind, err := netip.ParseAddrPort(*listen)
	if err != nil || bind.Port() == 0 {
		return errors.New("-listen must be a literal IP and nonzero port, e.g. 192.168.1.50:8888")
	}
	if !encrypted && !bind.Addr().IsLoopback() && len(clients) == 0 {
		return errors.New("non-loopback plain listeners require an explicit -allow client IP/CIDR")
	}
	if *dialTimeout <= 0 || *maxTunnels < 1 || *maxTunnels > 65536 {
		return errors.New("-dial-timeout must be positive and -max-tunnels must be 1–65536")
	}
	if encrypted && len(clients) == 0 {
		// Cryptographic pairing is mandatory; the IP allowlist is additional.
		clients = []string{"0.0.0.0/0", "::/0"}
	}
	if encrypted {
		if advertise == "" {
			advertise = bind.String()
		}
		if err := validEndpoint(advertise); err != nil {
			return err
		}
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
	if encrypted {
		store, err := openStore(dir)
		if err != nil {
			return err
		}
		id, err := loadIdentity(store)
		if err != nil {
			return err
		}
		if err := store.initServer(advertise); err != nil {
			return err
		}
		handler := &secureHandler{store: store, proxy: proxy}
		server.Handler = handler
		server.TLSConfig = id.serverTLS(store)
		server.WriteTimeout = 15 * time.Second
		// Hijacking requires outer HTTP/1.1. Inner HTTPS may still use HTTP/2.
		server.Protocols = new(http.Protocols)
		server.Protocols.SetHTTP1(true)
		listener = tls.NewListener(&cappedListener{Listener: listener, slots: make(chan struct{}, *maxTunnels+32)}, server.TLSConfig)
		watchCtx, cancelWatch := context.WithCancel(ctx)
		watchDone := make(chan struct{})
		go func() { defer close(watchDone); handler.watchRevocations(watchCtx) }()
		defer func() { cancelWatch(); <-watchDone }()
		logger.Info("TLS 1.3 with paired client identities enabled", "server_identity", id.fingerprint(), "advertise", advertise)
	}
	logger.Info("listening", "address", listener.Addr(), "allowed_clients", allowed, "ports", *portsFlag)
	logger.Info("outbound traffic follows host routing; configure your VPN and kill switch separately")
	if !encrypted && !bind.Addr().IsLoopback() {
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
