// Package platformcommand owns the workflow behind the user-facing
// mx platform command tree. Durable lifecycle policy stays here while local
// Docker, Compose, PostgreSQL, and filesystem effects remain behind Effects.
package platformcommand

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/release"
	"github.com/xiak/matrix/app/service/installation/internal/topology"
)

const (
	defaultListener = "0.0.0.0"
	defaultPort     = uint16(8080)
)

var (
	ErrEffectPrecondition = errors.New("platform effect precondition failed")
	ErrEffectConflict     = errors.New("platform effect ownership conflict")
	ErrEffectVerification = errors.New("platform effect verification failed")
	ErrEffectUnavailable  = errors.New("platform effect dependency is unavailable")
	// ErrEffectOutcomeUnknown means a provider command started but completion
	// was not established. The journal phase stays active so the next replay
	// observes the owned effect before retrying it.
	ErrEffectOutcomeUnknown = errors.New("platform effect outcome is unknown")
)

// InstallPlan is authenticated input plus the installation-owned identity.
// TrustBytes contains a public key document, never credential material.
type InstallPlan struct {
	Root           string
	InstallationID string
	Listener       string
	Port           uint16
	Bundle         release.VerifiedBundle
	Trust          release.TrustRoot
	TrustBytes     []byte
}

// Effects is the closed local-machine boundary for install. Each phase must
// be idempotent. If a command may have taken effect without a known result,
// it returns ErrEffectOutcomeUnknown and observes ownership on replay.
type Effects interface {
	ApplyInstallPhase(context.Context, InstallPlan, lifecycle.Phase) error
	RollbackInstall(context.Context, InstallPlan) error
}

type Backend struct {
	effects Effects
	entropy io.Reader
	now     func() time.Time
}

func NewBackend(effects Effects) (*Backend, error) {
	if effects == nil {
		return nil, errors.New("platform lifecycle effects are required")
	}
	return &Backend{effects: effects, entropy: rand.Reader, now: time.Now}, nil
}

func (backend *Backend) Run(ctx context.Context, request cli.Request) (cli.Result, error) {
	if backend == nil || backend.effects == nil || backend.entropy == nil || backend.now == nil {
		return cli.Result{}, fault(cli.FaultInternal, "BACKEND_UNAVAILABLE")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	if request.Action != lifecycle.ActionInstall {
		return cli.Result{}, fault(cli.FaultPrecondition, "LIFECYCLE_ACTION_NOT_READY")
	}
	return backend.install(ctx, request)
}

func (backend *Backend) install(
	ctx context.Context,
	request cli.Request,
) (result cli.Result, returnErr error) {
	trustBytes, trust, err := release.ReadTrustRootFile(request.TrustKey)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "TRUST_ROOT_INVALID")
	}
	verified, err := release.VerifyDirectory(request.Bundle, trustBytes)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "RELEASE_BUNDLE_INVALID")
	}
	if verified.Manifest.TopologyDigest != topology.ContractDigest() {
		return cli.Result{}, fault(cli.FaultVerification, "TOPOLOGY_CONTRACT_UNSUPPORTED")
	}
	if verified.Manifest.Release.PreviousID != "" ||
		verified.Manifest.Release.PreviousVersion != "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "INSTALL_RELEASE_HAS_PREDECESSOR")
	}

	session, err := journal.Acquire(ctx, request.Root)
	if err != nil {
		return cli.Result{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.Result{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()

	initialized, err := session.Initialized()
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	var state lifecycle.Journal
	if initialized {
		state, err = session.Read()
		if err != nil {
			return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
		}
		if state.ReleaseTrust.KeyID != trust.KeyID ||
			state.ReleaseTrust.Fingerprint != trust.PublicKeyFingerprint {
			return cli.Result{}, fault(cli.FaultConflict, "RELEASE_TRUST_CONFLICT")
		}
	} else {
		installationID, identityErr := randomIdentity(backend.entropy, "mxi")
		if identityErr != nil {
			return cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_ID_GENERATION_FAILED")
		}
		state, err = lifecycle.New(installationID, lifecycle.ReleaseTrust{
			KeyID: trust.KeyID, Fingerprint: trust.PublicKeyFingerprint,
		})
		if err != nil {
			return cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_STATE_CREATION_FAILED")
		}
	}
	if state.Active == nil && state.CurrentReleaseID == verified.Manifest.Release.ID {
		if state.CurrentReleaseDigest != verified.ManifestSHA256 {
			return cli.Result{}, fault(cli.FaultConflict, "RELEASE_CONTENT_CONFLICT")
		}
		correlationID := ""
		if state.Last != nil {
			correlationID = state.Last.Command.ID
		}
		return cli.Result{
			State: "READY", ReleaseID: state.CurrentReleaseID,
			PreviousID: state.PreviousRelease, Changed: false,
			CorrelationID: correlationID,
		}, nil
	}

	commandID := ""
	if state.Active != nil {
		commandID = state.Active.Command.ID
	} else {
		commandID, err = randomIdentity(backend.entropy, "cmd")
		if err != nil {
			return cli.Result{}, fault(cli.FaultInternal, "COMMAND_ID_GENERATION_FAILED")
		}
	}

	command := lifecycle.Command{
		ID:              commandID,
		Action:          lifecycle.ActionInstall,
		InputDigest:     verified.ManifestSHA256,
		TargetReleaseID: verified.Manifest.Release.ID,
		RequestedAt:     canonicalNow(backend.now()),
	}
	started, err := lifecycle.Start(state, command)
	if err != nil {
		return cli.Result{}, lifecycleFault(err)
	}
	switch {
	case !initialized:
		if err := session.Initialize(started.Journal); err != nil {
			return cli.Result{}, stateWriteFault(err)
		}
	case started.Replay == lifecycle.ReplayNone:
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, stateWriteFault(err)
		}
	}

	plan := InstallPlan{
		Root: session.Root(), InstallationID: started.Journal.InstallationID,
		Listener: defaultListener, Port: defaultPort, Bundle: verified,
		Trust: trust, TrustBytes: append([]byte(nil), trustBytes...),
	}
	if started.Replay == lifecycle.ReplayCompleted {
		return completedResult(started.Journal, started.Execution, false)
	}
	return backend.driveInstall(ctx, session, plan)
}

func (backend *Backend) driveInstall(
	ctx context.Context,
	session *journal.Session,
	plan InstallPlan,
) (cli.Result, error) {
	for {
		state, err := session.Read()
		if err != nil {
			return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
		}
		if state.Active == nil {
			if state.Last == nil {
				return cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_EXECUTION_MISSING")
			}
			return completedResult(state, *state.Last, true)
		}
		execution := *state.Active
		if execution.Command.Action != lifecycle.ActionInstall {
			return cli.Result{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
		}

		if execution.Phase == lifecycle.PhaseRollingBack {
			if err := backend.effects.RollbackInstall(ctx, plan); err != nil {
				return cli.Result{}, backend.handleRollbackFailure(ctx, session, state, execution, err)
			}
			ready, err := lifecycle.Advance(
				state, execution.Command.ID, lifecycle.PhaseReady,
				nextJournalTime(backend.now(), execution.UpdatedAt),
			)
			if err != nil || session.Write(ready) != nil {
				return cli.Result{}, fault(cli.FaultInternal, "ROLLBACK_STATE_COMMIT_FAILED")
			}
			return cli.Result{}, storedFailure(ready.Last)
		}

		var effectErr error
		if execution.Phase != lifecycle.PhaseCommitting {
			effectErr = backend.effects.ApplyInstallPhase(ctx, plan, execution.Phase)
		}
		if effectErr != nil {
			if ctx.Err() != nil {
				return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
			}
			if errors.Is(effectErr, ErrEffectOutcomeUnknown) {
				return cli.Result{}, fault(cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
			}
			original := effectFault(execution.Phase, effectErr)
			failed, failErr := lifecycle.Fail(
				state, execution.Command.ID, original.Code,
				nextJournalTime(backend.now(), execution.UpdatedAt),
			)
			if failErr != nil || session.Write(failed) != nil {
				return cli.Result{}, fault(cli.FaultInternal, "FAILURE_INTENT_COMMIT_FAILED")
			}
			continue
		}

		next, ok := nextInstallPhase(execution.Phase)
		if !ok {
			return cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_PHASE_INVALID")
		}
		advanced, err := lifecycle.Advance(
			state, execution.Command.ID, next,
			nextJournalTime(backend.now(), execution.UpdatedAt),
		)
		if err != nil || session.Write(advanced) != nil {
			return cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_STATE_COMMIT_FAILED")
		}
		if advanced.Active == nil {
			return completedResult(advanced, *advanced.Last, true)
		}
	}
}

func (backend *Backend) handleRollbackFailure(
	ctx context.Context,
	session *journal.Session,
	state lifecycle.Journal,
	execution lifecycle.Execution,
	effectErr error,
) error {
	if ctx.Err() != nil {
		return fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	if errors.Is(effectErr, ErrEffectOutcomeUnknown) {
		return fault(cli.FaultUnavailable, "ROLLBACK_OUTCOME_UNKNOWN")
	}
	manual, err := lifecycle.Fail(
		state, execution.Command.ID, "ROLLBACK_FAILED",
		nextJournalTime(backend.now(), execution.UpdatedAt),
	)
	if err != nil || session.Write(manual) != nil {
		return fault(cli.FaultInternal, "ROLLBACK_FAILURE_COMMIT_FAILED")
	}
	return fault(cli.FaultInternal, "ROLLBACK_FAILED")
}

func nextInstallPhase(phase lifecycle.Phase) (lifecycle.Phase, bool) {
	switch phase {
	case lifecycle.PhasePreflight:
		return lifecycle.PhaseStaging, true
	case lifecycle.PhaseStaging:
		return lifecycle.PhaseLoadingImages, true
	case lifecycle.PhaseLoadingImages:
		return lifecycle.PhaseConfiguring, true
	case lifecycle.PhaseConfiguring:
		return lifecycle.PhaseMigrating, true
	case lifecycle.PhaseMigrating:
		return lifecycle.PhaseStarting, true
	case lifecycle.PhaseStarting:
		return lifecycle.PhaseVerifying, true
	case lifecycle.PhaseVerifying:
		return lifecycle.PhaseCommitting, true
	case lifecycle.PhaseCommitting:
		return lifecycle.PhaseReady, true
	default:
		return "", false
	}
}

func completedResult(
	state lifecycle.Journal,
	execution lifecycle.Execution,
	changed bool,
) (cli.Result, error) {
	if execution.Outcome != lifecycle.OutcomeSucceeded {
		return cli.Result{}, storedFailure(&execution)
	}
	return cli.Result{
		State: "READY", ReleaseID: state.CurrentReleaseID,
		PreviousID: state.PreviousRelease, Changed: changed,
		CorrelationID: execution.Command.ID,
	}, nil
}

func storedFailure(execution *lifecycle.Execution) error {
	if execution == nil || execution.FailureCode == "" {
		return fault(cli.FaultInternal, "INSTALLATION_RESULT_INVALID")
	}
	class := cli.FaultInternal
	switch {
	case execution.FailureCode == "PREFLIGHT_FAILED":
		class = cli.FaultPrecondition
	case execution.FailureCode == "OWNERSHIP_CONFLICT":
		class = cli.FaultConflict
	case strings.HasSuffix(execution.FailureCode, "_VERIFICATION_FAILED"):
		class = cli.FaultVerification
	case execution.FailureCode == "DEPENDENCY_UNAVAILABLE":
		class = cli.FaultUnavailable
	}
	return fault(class, execution.FailureCode)
}

func effectFault(phase lifecycle.Phase, err error) *cli.Fault {
	class := cli.FaultInternal
	code := phaseFailureCode(phase, "FAILED")
	switch {
	case errors.Is(err, ErrEffectPrecondition):
		class = cli.FaultPrecondition
		code = "PREFLIGHT_FAILED"
	case errors.Is(err, ErrEffectConflict):
		class = cli.FaultConflict
		code = "OWNERSHIP_CONFLICT"
	case errors.Is(err, ErrEffectVerification):
		class = cli.FaultVerification
		code = phaseFailureCode(phase, "VERIFICATION_FAILED")
	case errors.Is(err, ErrEffectUnavailable):
		class = cli.FaultUnavailable
		code = "DEPENDENCY_UNAVAILABLE"
	}
	return fault(class, code)
}

func phaseFailureCode(phase lifecycle.Phase, suffix string) string {
	switch phase {
	case lifecycle.PhasePreflight:
		return "PREFLIGHT_" + suffix
	case lifecycle.PhaseStaging:
		return "STAGING_" + suffix
	case lifecycle.PhaseLoadingImages:
		return "IMAGE_" + suffix
	case lifecycle.PhaseConfiguring:
		return "CONFIGURATION_" + suffix
	case lifecycle.PhaseMigrating:
		return "MIGRATION_" + suffix
	case lifecycle.PhaseStarting:
		return "START_" + suffix
	case lifecycle.PhaseVerifying:
		return "PLATFORM_" + suffix
	default:
		return "INSTALLATION_" + suffix
	}
}

func lifecycleFault(err error) error {
	switch {
	case errors.Is(err, lifecycle.ErrPrecondition):
		return fault(cli.FaultPrecondition, "INSTALLATION_PRECONDITION_FAILED")
	case errors.Is(err, lifecycle.ErrCommandConflict),
		errors.Is(err, lifecycle.ErrCommandInProgress):
		return fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
	default:
		return fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
}

func acquireFault(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	case errors.Is(err, journal.ErrOwnershipConflict):
		return fault(cli.FaultConflict, "INSTALLATION_ROOT_CONFLICT")
	case errors.Is(err, journal.ErrIntegrity):
		return fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	default:
		return fault(cli.FaultPrecondition, "INSTALLATION_ROOT_INVALID")
	}
}

func stateWriteFault(err error) error {
	if errors.Is(err, journal.ErrOwnershipConflict) || errors.Is(err, journal.ErrAlreadyInitialized) {
		return fault(cli.FaultConflict, "INSTALLATION_STATE_CONFLICT")
	}
	return fault(cli.FaultInternal, "INSTALLATION_STATE_WRITE_FAILED")
}

func fault(class cli.FaultClass, code string) *cli.Fault {
	value, err := cli.NewFault(class, code)
	if err != nil {
		panic("static platform lifecycle fault is invalid")
	}
	return value
}

func randomIdentity(entropy io.Reader, prefix string) (string, error) {
	var random [16]byte
	if _, err := io.ReadFull(entropy, random[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(random[:]), nil
}

func canonicalNow(value time.Time) time.Time {
	value = value.UTC().Truncate(time.Microsecond)
	if value.IsZero() {
		return time.Unix(0, 1000).UTC()
	}
	return value
}

func nextJournalTime(now time.Time, previous time.Time) time.Time {
	next := canonicalNow(now)
	if !next.After(previous) {
		next = previous.Add(time.Microsecond)
	}
	return next
}

var _ cli.Backend = (*Backend)(nil)
