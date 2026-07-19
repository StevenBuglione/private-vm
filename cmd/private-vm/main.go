package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/StevenBuglione/private-vm/internal/cli"
	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/systeminstall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	installer := systeminstall.NewDefault()
	daemon := cli.NewProductionInvoker(config.DefaultRuntimePath+"/control.sock", os.Stdin, stderr)
	return cli.New(cli.Dependencies{
		Stdout:  stdout,
		Stderr:  stderr,
		Invoker: cli.NewSystemInstallInvokerWithFallback(installer, daemon),
	}).Execute(ctx, args)
}
