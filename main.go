package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, args []string) error {
	if len(args) == 0 {
		printCommands(os.Stdout)
		return nil
	}
	switch args[0] {
	case "key":
		return runKey(args[1:], os.Stdout)
	case "serve":
		return runServe(logger, args[1:])
	case "bridge":
		return runBridge(logger, args[1:])
	case "run":
		return runRun(args[1:])
	case "help", "-h", "-help", "--help":
		printCommands(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q; see 'vibemaxxer help'", args[0])
	}
}

func printCommands(out io.Writer) {
	fmt.Fprintln(out, `Usage: vibemaxxer COMMAND [flags]

  key      Print this machine's identity fingerprint (creates the key if missing)
  serve    CONNECT server on the VPN host; admits listed workstation fingerprints
  bridge   Loopback proxy on the workstation; forwards to the pinned VPN host
  run      Run a command with proxy variables pointing at the bridge

Setup: run 'key' on both machines and swap fingerprints, then
  VPN host:     vibemaxxer serve -listen LAN_IP:8443 -client-key WORKSTATION_FP
  workstation:  vibemaxxer bridge -server LAN_IP:8443 -server-key HOST_FP
                vibemaxxer run -- claude

Use COMMAND -help for flags.`)
}
