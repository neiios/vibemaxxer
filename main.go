package main

import (
	"os"

	"github.com/neiios/vibemaxxer/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
