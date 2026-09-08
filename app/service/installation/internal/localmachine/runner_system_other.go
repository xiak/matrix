//go:build !linux

package localmachine

import (
	"context"

	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
)

type unsupportedRunnerNodeSystem struct{}

func newRunnerNodeSystem() runnerNodeSystem { return unsupportedRunnerNodeSystem{} }

func (unsupportedRunnerNodeSystem) Preflight(
	context.Context,
	runnerSystemPlan,
) error {
	return runnernodecommand.ErrEffectUnavailable
}

func (unsupportedRunnerNodeSystem) Converge(
	context.Context,
	runnerSystemPlan,
) error {
	return runnernodecommand.ErrEffectUnavailable
}
