package cli

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
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
	tls       bool
	clients   fingerprints
}

func (o *lanOptions) flags(flags *flag.FlagSet, mode policy.Mode) {
	flags.StringVar(&o.key, "key", identity.DefaultKeyPath(), "Ed25519 identity file for LAN TLS (created if absent)")
	if mode == policy.Client {
		flags.StringVar(&o.server, "server", "", "LAN TLS server HOST:PORT (alternative to -upstream)")
		flags.StringVar(&o.serverKey, "server-key", "", "pinned LAN server fingerprint (required with -server)")
	} else {
		flags.BoolVar(&o.tls, "tls", false, "serve mutually authenticated TLS for LAN clients")
		flags.Var(&o.clients, "client-key", "allowed LAN client fingerprint (repeatable; requires -tls)")
	}
}

func (o *lanOptions) validate(mode policy.Mode, upstream string, keySet bool) error {
	if mode == policy.Client {
		if o.server != "" {
			if upstream != "" {
				return errors.New("-server (LAN TLS) and -upstream (SSH) are mutually exclusive")
			}
			host, port, err := net.SplitHostPort(o.server)
			if err != nil || host == "" {
				return errors.New("-server must be HOST:PORT")
			}
			if _, err := policy.Port(port); err != nil {
				return fmt.Errorf("-server: %w", err)
			}
			if addr, err := netip.ParseAddr(host); err == nil && (addr.Unmap().IsUnspecified() || addr.Unmap().IsMulticast()) {
				return errors.New("-server must name a concrete unicast destination")
			}
			pin, err := identity.ParseFingerprint(o.serverKey)
			if err != nil {
				return fmt.Errorf("-server-key is required with -server: %w", err)
			}
			o.serverKey = pin
		} else if o.serverKey != "" || keySet {
			return errors.New("-server-key and -key require -server")
		}
	} else if !o.tls && (len(o.clients) != 0 || keySet) {
		return errors.New("-client-key and -key require -tls")
	} else if o.tls && len(o.clients) == 0 {
		return errors.New("-tls requires at least one -client-key")
	}
	return nil
}

func (o *lanOptions) config(mode policy.Mode) (*tls.Config, error) {
	if o.server == "" && !o.tls {
		return nil, nil
	}
	id, err := identity.Load(o.key)
	if err != nil {
		return nil, err
	}
	if mode == policy.Client {
		return id.ClientTLS(o.serverKey), nil
	}
	clients := make(map[string]bool, len(o.clients))
	for _, pin := range o.clients {
		clients[pin] = true
	}
	return id.ServerTLS(clients), nil
}

func lanListen(value string) error {
	addr, err := netip.ParseAddrPort(value)
	if err != nil || addr.Port() == 0 || !(addr.Addr().Unmap().IsGlobalUnicast() || addr.Addr().Unmap().IsLoopback()) {
		return errors.New("-listen must be a concrete unicast IP:PORT for LAN TLS (wildcards are refused)")
	}
	return nil
}

func keyCommand(args []string) error {
	flags := flag.NewFlagSet("key", flag.ContinueOnError)
	path := flags.String("key", identity.DefaultKeyPath(), "Ed25519 identity file (created if absent)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected argument; use key -help")
	}
	id, err := identity.Load(*path)
	if err != nil {
		return err
	}
	fmt.Println(id.Fingerprint())
	return nil
}
