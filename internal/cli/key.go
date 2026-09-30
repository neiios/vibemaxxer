package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/neiios/vibemaxxer/internal/identity"
)

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
