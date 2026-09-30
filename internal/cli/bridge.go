package cli

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/neiios/vibemaxxer/internal/domain"
	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/proxy"
)

func runBridge(logger *slog.Logger, args []string) error {
	flags := flag.NewFlagSet("bridge", flag.ContinueOnError)
	server := flags.String("server", "", "VPN host HOST:PORT (required)")
	serverKey := flags.String("server-key", "", "fingerprint printed by 'vibemaxxer key' on the VPN host (required)")
	listen := flags.String("listen", "127.0.0.1:8888", "loopback IP:PORT for agents")
	blocklistPath := flags.String("blocklist", "", "file of domains to refuse, one per line, including subdomains")
	proxyDomainsPath := flags.String("proxy-domains", "", "file of domains to route through the server; all others connect directly")
	directPortsFlag := flags.String("direct-ports", "443", "comma-separated allowed destination ports for direct routes")
	keyPath := keyFlag(flags)
	if err := parseNoArgs(flags, args); err != nil {
		return err
	}
	if err := proxy.ValidEndpoint(*server); err != nil {
		return fmt.Errorf("-server %w", err)
	}
	key, err := identity.ParseFingerprint(*serverKey)
	if err != nil {
		return fmt.Errorf("-server-key: %w", err)
	}
	bind, err := netip.ParseAddrPort(*listen)
	if err != nil || !bind.Addr().IsLoopback() || bind.Port() == 0 {
		return errors.New("-listen must be a loopback IP:PORT such as 127.0.0.1:8888")
	}
	proxyDomains, err := domain.Load(*proxyDomainsPath)
	if err != nil {
		return fmt.Errorf("-proxy-domains: %w", err)
	}
	directPorts, err := proxy.ParsePorts(*directPortsFlag)
	if err != nil {
		return fmt.Errorf("-direct-ports: %w", err)
	}
	blocklist, err := domain.Load(*blocklistPath)
	if err != nil {
		return fmt.Errorf("-blocklist: %w", err)
	}
	id, err := identity.Load(*keyPath)
	if err != nil {
		return err
	}
	direct := proxy.NewServer(directPorts, logger)
	if err := direct.RefuseLocalPrefixes(); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", bind.String())
	if err != nil {
		return err
	}
	b := &proxy.Bridge{Upstream: *server, TLSConfig: id.ClientTLS(key), Blocklist: blocklist,
		ProxyDomains: proxyDomains, Direct: direct, Logger: logger}
	logger.Info("bridge listening", "address", listener.Addr(), "identity", id.Fingerprint(), "server", *server, "blocklist_rules", len(blocklist), "local_prefixes", direct.LocalPrefixes())
	go b.Probe()
	return b.Serve(listener)
}
