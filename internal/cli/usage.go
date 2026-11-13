package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
)

var flagName = regexp.MustCompile(`(^|\s)-([a-z][a-z-]+)`)

var flagErrors = strings.NewReplacer(
	"flag provided but not defined:", "unknown option",
	"flag needs an argument:", "missing value for",
	"for flag ", "for ",
)

func parseOptions(flags *flag.FlagSet, header string, args []string) error {
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		printHelp(os.Stdout, flags, header)
		return err
	}
	if err != nil {
		return fmt.Errorf("%s; see %s --help", flagErrors.Replace(flagName.ReplaceAllString(err.Error(), "$1--$2")), "vibemaxxer "+flags.Name())
	}
	return nil
}

func printHelp(out io.Writer, flags *flag.FlagSet, header string) {
	fmt.Fprintf(out, "%s\n\nOptions:\n", header)
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	flags.VisitAll(func(f *flag.Flag) {
		metavar, usage := flag.UnquoteUsage(f)
		name := "--" + f.Name
		if metavar != "" {
			name += " " + metavar
		}
		if f.DefValue != "" && f.DefValue != "false" {
			usage += " (default " + f.DefValue + ")"
		}
		fmt.Fprintf(w, "  %s\t%s\n", name, usage)
	})
	fmt.Fprintf(w, "  -h, --help\tshow this help\n")
	w.Flush()
}
