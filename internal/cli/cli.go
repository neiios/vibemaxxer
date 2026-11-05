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

const usage = `vibemaxxer blocks, passes or reroutes HTTP traffic by hostname.

Usage: vibemaxxer COMMAND [OPTION...]

Commands:
  client   run the proxy that programs connect to
  server   run the proxy on the machine traffic should leave from
  run      run a command through the proxy
  key      print this machine's key fingerprint

Run 'vibemaxxer COMMAND --help' to see its options.
Docs: https://github.com/neiios/vibemaxxer`

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
	listen := flags.String("listen", defaultListen, "address to listen on")
	rules := flags.String("rules", "", "rules file (required)")
	allowPrivate := flags.Bool("allow-private", false, "also allow private, CGNAT and local network destinations")
	var lan lanOptions
	lan.flags(flags, mode)
	var upstream string
	if mode == policy.Client {
		flags.StringVar(&upstream, "upstream", "", "send proxied traffic to this SSH forward")
	}
	if err := parseOptions(flags, "Usage: vibemaxxer "+name+" --rules FILE [OPTION...]", args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; see vibemaxxer %s --help", flags.Arg(0), name)
	}
	keySet := false
	flags.Visit(func(f *flag.Flag) { keySet = keySet || f.Name == "key" })
	if err := lan.validate(mode, upstream, keySet); err != nil {
		return err
	}
	validateListen := func(value string) error { return loopback("--listen", value) }
	if lan.tls {
		validateListen = lanListen
	}
	if err := validateListen(*listen); err != nil {
		return err
	}
	if upstream != "" {
		if err := loopback("--upstream", upstream); err != nil {
			return err
		}
	}
	if *rules == "" {
		return errors.New("--rules is required")
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
