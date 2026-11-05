package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/armansheikhhosseini/certlapse/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := cli.NewRootCommand(version).ExecuteContext(ctx)
	var exit cli.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		os.Exit(exit.Code)
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
