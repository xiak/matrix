//go:build !linux

package localmachine

import (
	"context"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
)

type localNodeSupervisor struct{}

func (localNodeSupervisor) Preflight(context.Context, uint64) error {
	return nodecommand.ErrPrecondition
}
func (localNodeSupervisor) Inspect(context.Context, nativeService) (nativeState, error) {
	return "", nodecommand.ErrPrecondition
}
func (localNodeSupervisor) Start(context.Context, nativeService) error {
	return nodecommand.ErrPrecondition
}
func (localNodeSupervisor) Stop(context.Context, nativeService) error {
	return nodecommand.ErrPrecondition
}
