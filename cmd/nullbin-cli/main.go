package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Nulliance/nullbin-cli/internal/cli"
)

// version is overridden at release build time via -ldflags="-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := cli.NewApp(version)
	os.Exit(app.Run(ctx, os.Args[1:]))
}
