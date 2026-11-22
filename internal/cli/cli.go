package cli

import (
	"cmp"
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
  run      run a command through its own proxy
  key      print this machine's key fingerprint

Run 'vibemaxxer COMMAND --help' to see its options.
Docs: https://github.com/neiios/vibemaxxer`

func Main(args []string) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	err := Run(logger, args)
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var status exitStatus
	if errors.As(err, &status) {
		return int(status)
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
		return run(logger, "client", policy.Client, "127.0.0.1:9878", args[1:])
	case "server":
		return run(logger, "server", policy.Server, "127.0.0.1:8081", args[1:])
	case "help", "-h", "-help", "--help":
		fmt.Fprintln(os.Stdout, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q; see 'vibemaxxer help'", args[0])
	}
}

type options struct {
	rules    string
	upstream string
	lan      lanOptions
}

func (o *options) flags(flags *flag.FlagSet, mode policy.Mode) {
	flags.StringVar(&o.rules, "rules", "", "read rules from `FILE` (required)")
	o.lan.flags(flags, mode)
	if mode == policy.Client {
		flags.StringVar(&o.upstream, "upstream", "", "send proxied traffic to the SSH forward at `ADDR`")
	}
}

func (o *options) validate() error {
	if err := o.lan.validate(o.upstream); err != nil {
		return err
	}
	if o.upstream != "" {
		if err := loopback("--upstream", o.upstream); err != nil {
			return err
		}
	}
	if o.rules == "" {
		return errors.New("--rules is required")
	}
	return nil
}

func (o *options) transport() string {
	switch {
	case o.lan.server != "" || len(o.lan.clients) > 0:
		return "tls"
	case o.upstream != "":
		return "ssh-forward"
	}
	return "none"
}

func (o *options) proxy(name string, mode policy.Mode, logger *slog.Logger) (*proxy.Proxy, *tls.Config, error) {
	pol, err := policy.Load(o.rules, mode)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, err := o.lan.config()
	if err != nil {
		return nil, nil, err
	}
	upstream, upstreamTLS := o.upstream, (*tls.Config)(nil)
	if o.lan.server != "" {
		upstream, upstreamTLS = o.lan.server, tlsConfig
	}
	p, err := proxy.New("vibemaxxer-"+name, pol, upstream, upstreamTLS, proxy.Dialer(mode == policy.Client), logger)
	return p, tlsConfig, err
}

func run(logger *slog.Logger, name string, mode policy.Mode, defaultListen string, args []string) error {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	listen := flags.String("listen", defaultListen, "listen on `ADDR`")
	var opts options
	opts.flags(flags, mode)
	if err := parseOptions(flags, "Usage: vibemaxxer "+name+" --rules FILE [OPTION...]", args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; see vibemaxxer %s --help", flags.Arg(0), name)
	}
	if len(opts.lan.clients) == 0 {
		if err := loopback("--listen", *listen); err != nil {
			return err
		}
	}
	if err := opts.validate(); err != nil {
		return err
	}
	p, tlsConfig, err := opts.proxy(name, mode, logger)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if len(opts.lan.clients) > 0 {
		listener = tls.NewListener(listener, tlsConfig)
	}
	logger.Info("listening", "mode", name, "address", listener.Addr(), "rules", opts.rules, "upstream", cmp.Or(opts.lan.server, opts.upstream), "transport", opts.transport())
	return p.Server().Serve(listener)
}

func loopback(flagName, value string) error {
	addr, err := netip.ParseAddrPort(value)
	if err != nil || !addr.Addr().IsLoopback() || addr.Port() == 0 {
		return fmt.Errorf("%s must be a loopback IP:PORT such as 127.0.0.1:9878", flagName)
	}
	return nil
}
