// matrix-product-endpoint serves one release-owned, fixed product destination.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var err error
	switch {
	case os.Args[1] == "--check":
		err = localcontainer.CheckEndpoint(ctx)
	default:
		err = localcontainer.ServeEndpoint(ctx, os.Args[1])
	}
	if err != nil {
		_, _ = os.Stderr.WriteString("Managed-service endpoint unavailable\n")
		os.Exit(1)
	}
}
