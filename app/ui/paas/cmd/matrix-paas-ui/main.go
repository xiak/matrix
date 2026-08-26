package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiak/matrix/app/ui/paas/internal/web"
)

const listenAddressEnvironment = "MATRIX_PAAS_UI_LISTEN_ADDRESS"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix PaaS UI process failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	address := os.Getenv(listenAddressEnvironment)
	if address == "" {
		return errors.New("PaaS UI process configuration is incomplete")
	}
	return web.Serve(ctx, address, web.NewHandler())
}
