package port

import (
	"context"
	"errors"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var (
	ErrTerminalUnsupported = errors.New("terminal connector does not support the workload")
	ErrTerminalUnavailable = errors.New("terminal connector is unavailable")
	ErrTerminalRejected    = errors.New("terminal connector rejected the proof")
)

// TerminalConnection is the provider-neutral PaaS-to-node session. It exposes
// neither node endpoints nor Docker identities to the northbound transport.
type TerminalConnection interface {
	Receive(context.Context) ([]byte, *nodev1.TerminalServerControl, error)
	SendInput(context.Context, []byte) error
	Resize(context.Context, paasv1.TerminalSize) error
	CloseInput(context.Context) error
	Close()
}

type TerminalConnector interface {
	OpenTerminal(
		context.Context,
		string,
		nodev1.TerminalOpenRequest,
	) (TerminalConnection, error)
}
