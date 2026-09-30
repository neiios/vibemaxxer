package cli

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/proxy"
)

func runServe(logger *slog.Logger, args []string) error {
	var clientKeys repeatable
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", "", "LAN IP:PORT to listen on (required; keep it off the VPN interface)")
	flags.Var(&clientKeys, "client-key", "fingerprint of an allowed workstation; repeatable")
	portsFlag := flags.String("ports", "443", "comma-separated allowed destination ports")
	keyPath := keyFlag(flags)
	if err := parseNoArgs(flags, args); err != nil {
		return err
	}
	if *listen == "" {
		return errors.New("-listen is required, e.g. -listen 192.168.1.50:8443")
	}
	bind, err := netip.ParseAddrPort(*listen)
	if err != nil || bind.Addr().IsUnspecified() {
		return errors.New("-listen must be a specific LAN IP:PORT such as 192.168.1.50:8443, never a wildcard")
	}
	if len(clientKeys) == 0 {
		return errors.New("at least one -client-key is required; run 'vibemaxxer key' on the workstation")
	}
	clients := make(map[string]bool)
	for _, value := range clientKeys {
		key, err := identity.ParseFingerprint(value)
		if err != nil {
			return fmt.Errorf("-client-key: %w", err)
		}
		clients[key] = true
	}
	ports, err := proxy.ParsePorts(*portsFlag)
	if err != nil {
		return err
	}
	id, err := identity.Load(*keyPath)
	if err != nil {
		return err
	}
	handler := proxy.NewServer(ports, logger)
	if err := handler.RefuseLocalPrefixes(); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", bind.String())
	if err != nil {
		return err
	}
	logger.Info("serving", "address", listener.Addr(), "identity", id.Fingerprint(), "ports", *portsFlag, "local_prefixes", handler.LocalPrefixes())
	for key := range clients {
		logger.Info("allowed client", "identity", key)
	}
	return handler.HTTPServer().Serve(tls.NewListener(listener, id.ServerTLS(clients)))
}
