package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/localmachine"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	backend, err := platformcommand.NewBackend(localmachine.NewEffects())
	if err != nil {
		stop()
		_, _ = os.Stderr.WriteString("Matrix CLI initialization failed\n")
		os.Exit(cli.ExitInternal)
	}
	exitCode := cli.Run(ctx, os.Args[1:], cli.Streams{
		In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr,
	}, backend)
	stop()
	os.Exit(exitCode)
}
