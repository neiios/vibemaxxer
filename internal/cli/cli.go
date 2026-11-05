package cli

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"

	"github.com/neiios/vibemaxxer/internal/policy"
	"github.com/neiios/vibemaxxer/internal/proxy"
)

const usage = `Usage: vibemaxxer COMMAND [flags]

  client   Local HTTP proxy for applications; blocks domains and forwards other traffic directly
  server   Optional remote HTTP proxy; enforces its own allowlist and egresses
  run      Run a command with on-demand filtering (--remote for SSH, --lan for LAN TLS)
  key      Print/create this machine's Ed25519 LAN TLS identity fingerprint

Local filtering: vibemaxxer client -rules client.rules
SSH remote routing: client -upstream 127.0.0.1:18080 plus proxy rules.
LAN remote routing: client -server HOST:PORT -server-key PIN plus proxy rules;
                    server -tls -client-key PIN -listen LAN_IP:PORT.
Use COMMAND -help for flags.`

func Main(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	err := Run(logger, args)
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	logger.Error("exiting", "error", err)
	return 1
}

func Run(logger *slog.Logger, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stdout, usage)
		return nil
	}
	switch args[0] {
	case "run":
		return runCommand(args[1:])
	case "key":
		return keyCommand(args[1:])
	case "client":
		return run(logger, "client", policy.Client, "127.0.0.1:8080", args[1:])
	case "server":
		return run(logger, "server", policy.Server, "127.0.0.1:8081", args[1:])
	case "help", "-h", "-help", "--help":
		fmt.Fprintln(os.Stdout, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q; see 'vibemaxxer help'", args[0])
	}
}

func run(logger *slog.Logger, name string, mode policy.Mode, defaultListen string, args []string) error {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	listen := flags.String("listen", defaultListen, "IP:PORT to accept proxy requests on (loopback unless server -tls)")
	rules := flags.String("rules", "", "rules file (required)")
	allowPrivate := flags.Bool("allow-private", false, "permit private and local-network destination addresses")
	var lan lanOptions
	lan.flags(flags, mode)
	var upstream string
	if mode == policy.Client {
		flags.StringVar(&upstream, "upstream", "", "loopback IP:PORT of the SSH forward (alternative to -server for proxy rules)")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; see -help", flags.Arg(0))
	}
	keySet := false
	flags.Visit(func(f *flag.Flag) { keySet = keySet || f.Name == "key" })
	if err := lan.validate(mode, upstream, keySet); err != nil {
		return err
	}
	validateListen := func(value string) error { return loopback("-listen", value) }
	if lan.tls {
		validateListen = lanListen
	}
	if err := validateListen(*listen); err != nil {
		return err
	}
	if upstream != "" {
		if err := loopback("-upstream", upstream); err != nil {
			return err
		}
	}
	if *rules == "" {
		return errors.New("-rules is required")
	}
	pol, err := policy.Load(*rules, mode)
	if err != nil {
		return err
	}
	dial, err := proxy.Dialer(*allowPrivate)
	if err != nil {
		return err
	}
	tlsConfig, err := lan.config(mode)
	if err != nil {
		return err
	}
	var p *proxy.Proxy
	if lan.server != "" {
		upstream = lan.server
		p, err = proxy.NewTLS("vibemaxxer-"+name, pol, upstream, tlsConfig, dial, logger)
	} else {
		p, err = proxy.New("vibemaxxer-"+name, pol, upstream, dial, logger)
	}
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if lan.tls {
		listener = tls.NewListener(listener, tlsConfig)
	}
	transport := "none"
	if lan.server != "" || lan.tls {
		transport = "tls"
	} else if upstream != "" {
		transport = "ssh-forward"
	}
	logger.Info("listening", "mode", name, "address", listener.Addr(), "rules", *rules, "upstream", upstream, "transport", transport, "allow_private", *allowPrivate)
	return p.Server().Serve(listener)
}

func loopback(flagName, value string) error {
	addr, err := netip.ParseAddrPort(value)
	if err != nil || !addr.Addr().IsLoopback() || addr.Port() == 0 {
		return fmt.Errorf("%s must be a loopback IP:PORT such as 127.0.0.1:8080", flagName)
	}
	return nil
}
