package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/neiios/vibemaxxer/internal/identity"
)

type repeatable []string

func (r *repeatable) String() string { return strings.Join(*r, ",") }
func (r *repeatable) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func keyFlag(flags *flag.FlagSet) *string {
	return flags.String("key", identity.DefaultKeyPath(), "Ed25519 identity file, created on first use")
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
