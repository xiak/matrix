package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiak/matrix/app/ui/platform/internal/web"
)

const listenAddressEnvironment = "MATRIX_UI_LISTEN_ADDRESS"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix UI process failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, lookup func(string) string) error {
	if ctx == nil || lookup == nil {
		return errors.New("Matrix UI process configuration is unavailable")
	}
	address := lookup(listenAddressEnvironment)
	if address == "" {
		return errors.New("Matrix UI process configuration is incomplete")
	}
	return web.Serve(ctx, address, web.NewHandler())
}
