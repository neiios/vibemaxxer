package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type repeatable []string

func (r *repeatable) String() string { return strings.Join(*r, ",") }
func (r *repeatable) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func keyFlag(flags *flag.FlagSet) *string {
	return flags.String("key", defaultKeyPath(), "Ed25519 identity file, created on first use")
}

// validEndpoint accepts host:port with a nonzero port.
func validEndpoint(address string) error {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if err != nil || host == "" || portErr != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%q must be HOST:PORT", address)
	}
	return nil
}

func runKey(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("key", flag.ContinueOnError)
	keyPath := keyFlag(flags)
	if err := parseNoArgs(flags, args); err != nil {
		return err
	}
	id, err := loadIdentity(*keyPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n\nPass this on the other machine as -client-key (if this is the workstation)\nor -server-key (if this is the VPN host).\n", id.fingerprint())
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
	if len(clientKeys) == 0 {
		return errors.New("at least one -client-key is required; run 'vibemaxxer key' on the workstation")
	}
	clients := make(map[string]bool)
	for _, value := range clientKeys {
		key, err := parseFingerprint(value)
		if err != nil {
			return fmt.Errorf("-client-key: %w", err)
		}
		clients[key] = true
	}
	ports, err := parsePorts(*portsFlag)
	if err != nil {
		return err
	}
	id, err := loadIdentity(*keyPath)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           newProxy(ports, logger),
		ReadHeaderTimeout: headerTimeout,
		// Handshake failures are logged here, including unknown client fingerprints.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	// Hijacking needs HTTP/1.1 on the outer hop. Tunneled traffic may be anything.
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)
	logger.Info("serving", "address", listener.Addr(), "identity", id.fingerprint(), "ports", *portsFlag)
	for key := range clients {
		logger.Info("allowed client", "identity", key)
	}
	return server.Serve(tls.NewListener(listener, id.serverTLS(clients)))
}

func runBridge(logger *slog.Logger, args []string) error {
	flags := flag.NewFlagSet("bridge", flag.ContinueOnError)
	server := flags.String("server", "", "VPN host HOST:PORT (required)")
	serverKey := flags.String("server-key", "", "fingerprint printed by 'vibemaxxer key' on the VPN host (required)")
	listen := flags.String("listen", "127.0.0.1:8888", "loopback IP:PORT for agents")
	blocklistPath := flags.String("blocklist", "", "file of domains to refuse, one per line, including subdomains")
	keyPath := keyFlag(flags)
	if err := parseNoArgs(flags, args); err != nil {
		return err
	}
	if err := validEndpoint(*server); err != nil {
		return fmt.Errorf("-server %w", err)
	}
	key, err := parseFingerprint(*serverKey)
	if err != nil {
		return fmt.Errorf("-server-key: %w", err)
	}
	bind, err := netip.ParseAddrPort(*listen)
	if err != nil || !bind.Addr().IsLoopback() || bind.Port() == 0 {
		return errors.New("-listen must be a loopback IP:PORT such as 127.0.0.1:8888")
	}
	blocklist, err := loadBlocklist(*blocklistPath)
	if err != nil {
		return err
	}
	id, err := loadIdentity(*keyPath)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", bind.String())
	if err != nil {
		return err
	}
	b := &bridge{server: *server, tlsConfig: id.clientTLS(key), blocklist: blocklist, logger: logger}
	logger.Info("bridge listening", "address", listener.Addr(), "identity", id.fingerprint(), "server", *server, "blocklist_rules", len(blocklist))
	b.probe()
	return b.serve(listener)
}

var proxyVariables = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"}

// proxyEnv returns environ with proxy variables pointing at the bridge.
// Existing NO_PROXY entries are kept, deduplicated, and extended with loopback.
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
	bridgeAddress := flags.String("bridge", "127.0.0.1:8888", "address of the running bridge")
	if err := flags.Parse(args); err != nil {
		return err
	}
	command := flags.Args()
	if len(command) == 0 {
		return errors.New("usage: vibemaxxer run [-bridge IP:PORT] -- COMMAND [ARGS...]")
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
