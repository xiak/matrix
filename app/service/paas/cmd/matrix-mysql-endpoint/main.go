package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var err error
	switch {
	case len(os.Args) == 1:
		err = localcontainer.ServeEndpoint(ctx, "mysql:3306")
	case len(os.Args) == 2 && os.Args[1] == "--check":
		err = localcontainer.CheckEndpoint(ctx)
	default:
		os.Exit(2)
	}
	if err != nil {
		// Endpoint failures never include native errors, addresses or payloads.
		_, _ = os.Stderr.WriteString("MySQL endpoint unavailable\n")
		os.Exit(1)
	}
}
