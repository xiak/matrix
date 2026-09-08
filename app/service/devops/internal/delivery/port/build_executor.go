package port

import (
	"context"
	"errors"
	"io"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
)

var (
	// ErrBuildUnavailable means the adapter definitively did not retain an
	// accepted or terminal execution for this command.
	ErrBuildUnavailable = errors.New("build executor is unavailable")
	// ErrBuildOutcomeUnknown means an effect may exist. The caller must retain
	// the same command and let a later fence observe it rather than execute it.
	ErrBuildOutcomeUnknown = errors.New("build execution outcome is unknown")
	// ErrBuildConflict means the executor associated the deterministic command
	// identity with different immutable input.
	ErrBuildConflict = errors.New("build execution identity conflicts")
)

// BuildExecutor is the only delivery boundary allowed to execute untrusted
// verification code. A first fence may Execute; takeover fences may only
// Observe or Cancel the same deterministic command.
type BuildExecutor interface {
	Execute(context.Context, devopsbuildv1.Request, io.Reader) (devopsbuildv1.Receipt, error)
	Observe(context.Context, devopsbuildv1.Request) (devopsbuildv1.Receipt, bool, error)
	Cancel(context.Context, devopsbuildv1.Request) (devopsbuildv1.Receipt, bool, error)
}
