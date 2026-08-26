package localmachine

import (
	"context"
	"crypto/rand"
	"errors"
	"io"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

// Effects is the concrete Phase 1 Linux local-machine provider behind mx.
// It owns no lifecycle policy; every method delegates one journaled phase to
// its existing idempotent effect boundary.
type Effects struct {
	runtime  dockerRuntime
	entropy  io.Reader
	verifier installationVerifier
}

func NewEffects() *Effects {
	return &Effects{
		runtime: localDockerRuntime{}, entropy: rand.Reader,
		verifier: newHTTPInstallationVerifier(nil),
	}
}

func (effects *Effects) ApplyInstallPhase(
	ctx context.Context,
	plan platformcommand.InstallPlan,
	phase lifecycle.Phase,
) error {
	if effects == nil || effects.runtime == nil || effects.entropy == nil ||
		effects.verifier == nil || ctx == nil {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("local-machine effects are unavailable"),
		)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switch phase {
	case lifecycle.PhasePreflight:
		return preflightInstall(ctx, effects.runtime, plan)
	case lifecycle.PhaseStaging:
		return stageInstallation(plan, effects.entropy)
	case lifecycle.PhaseLoadingImages:
		return loadInstallImages(ctx, effects.runtime, plan)
	case lifecycle.PhaseConfiguring:
		return configureInstallation(ctx, effects.runtime, plan)
	case lifecycle.PhaseMigrating:
		return migrateInstallation(ctx, effects.runtime, plan)
	case lifecycle.PhaseStarting:
		return startInstallation(ctx, effects.runtime, plan)
	case lifecycle.PhaseVerifying:
		return effects.verifier.Verify(ctx, plan)
	default:
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("local-machine install phase is invalid"),
		)
	}
}

func (effects *Effects) RollbackInstall(
	ctx context.Context,
	plan platformcommand.InstallPlan,
) error {
	if effects == nil || effects.runtime == nil || ctx == nil {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("local-machine rollback is unavailable"),
		)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return rollbackInstallation(ctx, effects.runtime, plan)
}

var _ platformcommand.Effects = (*Effects)(nil)
