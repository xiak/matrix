package main

import (
	"context"
	"errors"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	nodedeployment "github.com/xiak/matrix/app/adapter/node/deployment"
	"github.com/xiak/matrix/app/service/nodeagent/internal/service/nethttp"
)

type terminalAdapter struct {
	deployment *nodedeployment.Service
}

func (adapter terminalAdapter) OpenTerminal(
	ctx context.Context,
	request nodev1.TerminalOpenRequest,
) (nethttp.TerminalSession, error) {
	terminal, err := adapter.deployment.OpenTerminal(ctx, request)
	if err != nil {
		return nil, mapTerminalError(err)
	}
	return terminalSessionAdapter{delegate: terminal}, nil
}

type terminalSessionAdapter struct {
	delegate composeadapter.Terminal
}

func (adapter terminalSessionAdapter) Read(value []byte) (int, error) {
	return adapter.delegate.Read(value)
}
func (adapter terminalSessionAdapter) Write(value []byte) (int, error) {
	return adapter.delegate.Write(value)
}
func (adapter terminalSessionAdapter) Close() error { return adapter.delegate.Close() }
func (adapter terminalSessionAdapter) Resize(ctx context.Context, size paasv1.TerminalSize) error {
	return mapTerminalError(adapter.delegate.Resize(ctx, size))
}
func (adapter terminalSessionAdapter) ExitCode(ctx context.Context) (int32, error) {
	code, err := adapter.delegate.ExitCode(ctx)
	return code, mapTerminalError(err)
}

func mapTerminalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, composeadapter.ErrTerminalUnsupported):
		return nethttp.ErrTerminalUnsupported
	case errors.Is(err, composeadapter.ErrTerminalUnavailable):
		return nethttp.ErrTerminalUnavailable
	default:
		return err
	}
}
