package cli

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/policy"
)

type fingerprints []string

func (f *fingerprints) String() string { return strings.Join(*f, ",") }
func (f *fingerprints) Set(value string) error {
	pin, err := identity.ParseFingerprint(value)
	if err == nil {
		*f = append(*f, pin)
	}
	return err
}

type lanOptions struct {
	key       string
	server    string
	serverKey string
	clients   fingerprints
}

func (o *lanOptions) flags(flags *flag.FlagSet, mode policy.Mode) {
	flags.StringVar(&o.key, "key", identity.DefaultKeyPath(), "identity file for LAN TLS")
	if mode == policy.Client {
		flags.StringVar(&o.server, "server", "", "send proxied traffic to this LAN server")
		flags.StringVar(&o.serverKey, "server-key", "", "fingerprint of the LAN server")
	} else {
		flags.Var(&o.clients, "client-key", "accept LAN clients over TLS with this fingerprint (repeatable)")
	}
}

func (o *lanOptions) validate(upstream string) error {
	switch {
	case o.server == "" && o.serverKey != "":
		return errors.New("--server-key requires --server")
	case o.server == "":
		return nil
	case upstream != "":
		return errors.New("--server (LAN TLS) and --upstream (SSH) are mutually exclusive")
	}
	host, port, err := net.SplitHostPort(o.server)
	if err != nil || host == "" {
		return errors.New("--server must be HOST:PORT")
	}
	if _, err := policy.Port(port); err != nil {
		return fmt.Errorf("--server: %w", err)
	}
	pin, err := identity.ParseFingerprint(o.serverKey)
	if err != nil {
		return fmt.Errorf("--server-key is required with --server: %w", err)
	}
	o.serverKey = pin
	return nil
}

func (o *lanOptions) config() (*tls.Config, error) {
	if o.server == "" && len(o.clients) == 0 {
		return nil, nil
	}
	id, err := identity.Load(o.key)
	if err != nil {
		return nil, err
	}
	if o.server != "" {
		return id.ClientTLS(o.serverKey), nil
	}
	clients := make(map[string]bool, len(o.clients))
	for _, pin := range o.clients {
		clients[pin] = true
	}
	return id.ServerTLS(clients), nil
}

func keyCommand(args []string) error {
	flags := flag.NewFlagSet("key", flag.ContinueOnError)
	path := flags.String("key", identity.DefaultKeyPath(), "identity file")
	if err := parseOptions(flags, "Usage: vibemaxxer key [--key FILE]\n\nPrints this machine's key fingerprint. Creates the key first if it\ndoesn't exist.", args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected argument; see vibemaxxer key --help")
	}
	id, err := identity.Load(*path)
	if err != nil {
		return err
	}
	fmt.Println(id.Fingerprint())
	return nil
}
