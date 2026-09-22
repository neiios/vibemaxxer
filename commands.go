package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"text/tabwriter"
	"time"
)

func run(logger *slog.Logger, args []string) error {
	if len(args) == 0 {
		printCommands(os.Stdout)
		return nil
	}
	switch args[0] {
	case "serve":
		return runServer(logger, args[1:])
	case "bridge":
		return runBridge(logger, args[1:])
	case "pair-code":
		return runPairCode(args[1:], os.Stdout)
	case "pair":
		return runPair(args[1:], os.Stdin, os.Stderr)
	case "clients":
		return runClients(args[1:], os.Stdout)
	case "help", "-h", "-help", "--help":
		printCommands(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q; use 'vibemaxxer help'", args[0])
	}
}

func printCommands(out io.Writer) {
	fmt.Fprintln(out, `Usage: vibemaxxer COMMAND [flags]

  serve       Encrypted TLS 1.3 CONNECT server (VPN host)
  pair-code   Create a single-use, 10-minute pairing invitation (VPN host)
  pair        Read an invitation from stdin and pair this workstation
  bridge      Loopback HTTP proxy forwarding through paired TLS
  clients     List or revoke paired workstations (VPN host)

Use COMMAND -help for flags. Running without a command prints this help.
Commands use ~/.config/vibemaxxer (or $XDG_CONFIG_HOME/vibemaxxer).
Override this with -state-dir, consistently for commands on the same machine.`)
}

func parseCommandFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments; use -help")
	}
	return nil
}

func runPairCode(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("pair-code", flag.ContinueOnError)
	dir := flags.String("state-dir", defaultStateDir(), "private configuration/identity directory")
	ttl := flags.Duration("ttl", 10*time.Minute, "invitation lifetime (1m to 1h); replaces any previous invitation")
	if err := parseCommandFlags(flags, args); err != nil {
		return err
	}
	store, err := openStore(*dir)
	if err != nil {
		return err
	}
	// Do not generate an identity for a server that has never been initialized.
	if _, err := store.readServer(); err != nil {
		return fmt.Errorf("start 'serve' with this state directory first: %w", err)
	}
	id, err := loadIdentity(store)
	if err != nil {
		return err
	}
	code, err := makeInvitation(store, id, *ttl)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, code)
	return err
}

func runPair(args []string, input io.Reader, out io.Writer) error {
	flags := flag.NewFlagSet("pair", flag.ContinueOnError)
	dir := flags.String("state-dir", defaultStateDir(), "private configuration/identity directory")
	hostname, _ := os.Hostname()
	name := flags.String("name", hostname, "workstation name (letters, digits, dots, underscores, hyphens)")
	replace := flags.Bool("replace", false, "explicitly replace this workstation's saved server")
	if err := parseCommandFlags(flags, args); err != nil {
		return err
	}
	fmt.Fprintln(out, "Paste the pairing invitation from your VPN host (sensitive; do not share it):")
	line, err := bufio.NewReader(io.LimitReader(input, maxInvitationSize+2)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	invite, err := decodeInvitation(line)
	if err != nil {
		return err
	}
	store, err := openStore(*dir)
	if err != nil {
		return err
	}
	id, err := loadIdentity(store)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := pair(ctx, store, id, invite, *name, *replace); err != nil {
		return err
	}
	fmt.Fprintf(out, "Paired %s with %s. Run 'vibemaxxer bridge' with the same -state-dir.\n", *name, invite.Address)
	return nil
}

func runClients(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-help" || args[0] == "--help" {
		fmt.Fprintln(out, "Usage: vibemaxxer clients list [-state-dir DIR]\n       vibemaxxer clients revoke [-state-dir DIR] NAME_OR_FULL_ID")
		return nil
	}
	action := args[0]
	flags := flag.NewFlagSet("clients "+action, flag.ContinueOnError)
	dir := flags.String("state-dir", defaultStateDir(), "private server configuration/identity directory")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if action != "list" && action != "revoke" || action == "list" && flags.NArg() != 0 || action == "revoke" && flags.NArg() != 1 {
		return errors.New("use 'clients list' or 'clients revoke [-state-dir DIR] NAME_OR_FULL_ID'")
	}
	store, err := openStore(*dir)
	if err != nil {
		return err
	}
	if action == "list" {
		state, err := store.readServer()
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(state.Clients))
		for id := range state.Clients {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "IDENTITY (SHA-256)\tNAME\tPAIRED AT")
		for _, id := range ids {
			client := state.Clients[id]
			fmt.Fprintf(writer, "%s\t%s\t%s\n", id, client.Name, client.AddedAt.Format(time.RFC3339))
		}
		return writer.Flush()
	}
	name := flags.Arg(0)
	err = store.updateServer(func(state *serverState) error {
		// Exact IDs take precedence over names. No ambiguous prefix matching.
		if _, ok := state.Clients[name]; ok {
			delete(state.Clients, name)
			return nil
		}
		for id, client := range state.Clients {
			if client.Name == name {
				delete(state.Clients, id)
				return nil
			}
		}
		return errors.New("no such paired client")
	})
	if err == nil {
		fmt.Fprintln(out, "Client revoked. New CONNECT requests are denied; active tunnels close within about one second.")
	}
	return err
}

func runBridge(logger *slog.Logger, args []string) error {
	flags := flag.NewFlagSet("bridge", flag.ContinueOnError)
	dir := flags.String("state-dir", defaultStateDir(), "private workstation configuration/identity directory")
	listen := flags.String("listen", "127.0.0.1:8888", "loopback IP:port for agents (never a LAN address)")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "upstream TCP and TLS handshake timeout")
	maxTunnels := flags.Int("max-tunnels", 128, "maximum local connections, including pending handshakes")
	if err := parseCommandFlags(flags, args); err != nil {
		return err
	}
	bind, err := netip.ParseAddrPort(*listen)
	if err != nil || !bind.Addr().IsLoopback() || bind.Addr().Zone() != "" || bind.Port() == 0 {
		return errors.New("bridge -listen must be a literal loopback IP and nonzero port")
	}
	if *dialTimeout <= 0 || *maxTunnels < 1 || *maxTunnels > 65536 {
		return errors.New("-dial-timeout must be positive and -max-tunnels must be 1–65536")
	}
	store, err := openStore(*dir)
	if err != nil {
		return err
	}
	config, err := store.readBridge()
	if err != nil {
		return fmt.Errorf("load bridge configuration (run 'pair' first): %w", err)
	}
	id, err := loadIdentity(store)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", bind.String())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("bridge listening", "address", listener.Addr(), "encrypted_upstream", config.Address)
	b := &bridge{config: config, identity: id, logger: logger, dialTimeout: *dialTimeout, maxTunnels: *maxTunnels}
	return b.Serve(ctx, listener)
}
