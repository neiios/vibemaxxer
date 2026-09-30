package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/neiios/vibemaxxer/internal/domain"
	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/managed"
	"github.com/neiios/vibemaxxer/internal/proxy"
)

type repeatable []string

func (r *repeatable) String() string { return strings.Join(*r, ",") }
func (r *repeatable) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func keyFlag(flags *flag.FlagSet) *string {
	return flags.String("key", identity.DefaultKeyPath(), "Ed25519 identity file, created on first use")
}

func runKey(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("key", flag.ContinueOnError)
	keyPath := keyFlag(flags)
	if err := parseNoArgs(flags, args); err != nil {
		return err
	}
	id, err := identity.Load(*keyPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n\nPass this on the other machine as -client-key (if this is the workstation)\nor -server-key (if this is the VPN host).\n", id.Fingerprint())
	return nil
}

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

var proxyVariables = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"}

func proxyEnv(environ []string, bridgeAddress string) []string {
	var noProxy []string
	env := make([]string, 0, len(environ)+6)
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if upper == "NO_PROXY" {
			for _, item := range strings.Split(value, ",") {
				if item = strings.TrimSpace(item); item != "" && !slices.Contains(noProxy, item) {
					noProxy = append(noProxy, item)
				}
			}
		}
		if !slices.Contains(proxyVariables, upper) {
			env = append(env, entry)
		}
	}
	for _, item := range []string{"localhost", "127.0.0.1", "::1"} {
		if !slices.Contains(noProxy, item) {
			noProxy = append(noProxy, item)
		}
	}
	url := "http://" + bridgeAddress
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY"} {
		env = append(env, name+"="+url, strings.ToLower(name)+"="+url)
	}
	joined := strings.Join(noProxy, ",")
	return append(env, "NO_PROXY="+joined, "no_proxy="+joined)
}

func runRun(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	bridgeAddress := flags.String("bridge", "127.0.0.1:8888", "address of the running bridge (external mode)")
	server := flags.String("server", "", "VPN server; enables on-demand managed mode")
	pin := flags.String("server-key", "", "pinned VPN server fingerprint")
	listen := flags.String("listen", "127.0.0.1:0", "managed loopback listener; 0 chooses a free port")
	block := flags.String("blocklist", "", "domain blocklist file")
	domains := flags.String("proxy-domains", "", "selective VPN domain file")
	ports := flags.String("direct-ports", "443", "allowed direct destination ports")
	key := keyFlag(flags)
	runtime := flags.String("runtime-dir", "", "private managed runtime directory (default $XDG_RUNTIME_DIR/vibemaxxer, or /tmp/vibemaxxer-UID when unset)")
	grace := flags.Duration("grace", 3*time.Second, "managed idle shutdown grace")
	timeout := flags.Duration("startup-timeout", 15*time.Second, "maximum managed startup wait")
	if err := flags.Parse(args); err != nil {
		return err
	}
	command := flags.Args()
	if len(command) == 0 {
		return errors.New("usage: vibemaxxer run [-bridge IP:PORT] -- COMMAND [ARGS...]")
	}
	explicitBridge, managedFlags := false, false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "bridge" {
			explicitBridge = true
		} else {
			managedFlags = true
		}
	})
	if *server != "" {
		if explicitBridge {
			return errors.New("-bridge cannot be combined with managed mode flags")
		}
		c, err := managed.Snapshot(*server, *pin, *listen, *key, *block, *domains, *ports, *grace)
		if err != nil {
			return err
		}
		lease, err := managed.Acquire(c, *runtime, *timeout)
		if err != nil {
			return err
		}
		defer lease.Close()
		fmt.Fprintf(os.Stderr, "vibemaxxer: bridge %s; log: %s\n", lease.Address, lease.Log)
		return supervise(command, lease)
	}
	if managedFlags {
		return errors.New("managed flags require -server and -server-key")
	}
	conn, err := net.DialTimeout("tcp", *bridgeAddress, 2*time.Second)
	if err != nil {
		return fmt.Errorf("no bridge at %s; start 'vibemaxxer bridge' first", *bridgeAddress)
	}
	conn.Close()
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, command, proxyEnv(os.Environ(), *bridgeAddress))
}

func parseNoArgs(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; see -help", flags.Arg(0))
	}
	return nil
}
