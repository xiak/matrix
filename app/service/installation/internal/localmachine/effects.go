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

// ObserveInstallation reads only authenticated installation-owned files and
// Docker provider state. It never invokes Compose convergence or migrations.
func (effects *Effects) ObserveInstallation(
	ctx context.Context,
	installed platformcommand.InstalledPlan,
) (bool, error) {
	if effects == nil || effects.runtime == nil || ctx == nil {
		return false, errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("local-machine observation is unavailable"),
		)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	plan, err := authenticateInstalledPlan(installed)
	if err != nil {
		return false, errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(plan.TrustBytes)
	return observeInstalledPlatform(ctx, effects.runtime, plan)
}

// VerifyInstallation reauthenticates the current release, checks the exact
// healthy Compose topology, verifies schema compatibility without applying
// migrations, and then executes the fixed PaaS/Audit application probe.
func (effects *Effects) VerifyInstallation(
	ctx context.Context,
	installed platformcommand.InstalledPlan,
) error {
	if effects == nil || effects.runtime == nil || effects.verifier == nil || ctx == nil {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("local-machine verification is unavailable"),
		)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	plan, err := authenticateInstalledPlan(installed)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(plan.TrustBytes)
	installation, _, _, err := inspectReadyInstalledPlatform(ctx, effects.runtime, plan)
	if err != nil {
		return err
	}
	if err := verifyInstallationMigrations(
		ctx, effects.runtime, plan, installation,
	); err != nil {
		return err
	}
	return effects.verifier.Verify(ctx, plan)
}

var _ platformcommand.Effects = (*Effects)(nil)
