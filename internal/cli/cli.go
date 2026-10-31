package cli

import (
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

  client   HTTP proxy for applications; routes each domain direct, via the server, or blocks it
  server   HTTP proxy behind the SSH forward; enforces its own allowlist and egresses

Typical chain: app → client 127.0.0.1:8080 → ssh -L 18080 → server 127.0.0.1:8081 → internet.
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
	listen := flags.String("listen", defaultListen, "loopback IP:PORT to accept proxy requests on")
	rules := flags.String("rules", "", "rules file (required)")
	allowPrivate := flags.Bool("allow-private", false, "permit private and local-network destination addresses")
	var upstream string
	if mode == policy.Client {
		flags.StringVar(&upstream, "upstream", "127.0.0.1:18080", "loopback IP:PORT of the SSH forward to the server")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; see -help", flags.Arg(0))
	}
	if err := loopback("-listen", *listen); err != nil {
		return err
	}
	if mode == policy.Client {
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
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	logger.Info("listening", "mode", name, "address", listener.Addr(), "rules", *rules, "upstream", upstream, "allow_private", *allowPrivate)
	return proxy.New("vibemaxxer-"+name, pol, upstream, dial, logger).Server().Serve(listener)
}

func loopback(flagName, value string) error {
	addr, err := netip.ParseAddrPort(value)
	if err != nil || !addr.Addr().IsLoopback() || addr.Port() == 0 {
		return fmt.Errorf("%s must be a loopback IP:PORT such as 127.0.0.1:8080", flagName)
	}
	return nil
}
