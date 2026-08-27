// Package nodecommand owns the node-specific enrollment and startup workflow.
// It reuses the installation journal and release authority, but has no platform
// database, image-loading, backup, or tenant authority.
package nodecommand

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

var (
	ErrPrecondition   = errors.New("node effect precondition failed")
	ErrConflict       = errors.New("node effect ownership conflict")
	ErrVerification   = errors.New("node effect verification failed")
	ErrUnavailable    = errors.New("node dependency is unavailable")
	ErrOutcomeUnknown = errors.New("node effect outcome is unknown")
)

type Plan struct {
	Root          string
	Bundle        release.VerifiedBundle
	Trust         release.TrustRoot
	TrustBytes    []byte
	Configuration nodeconfig.Configuration
	Credentials   Credentials
	Binding       lifecycle.NodeBinding
}

// Effects separates supervision/filesystem effects from the durable workflow.
// ValidateEnrollment is side-effect free and precedes even root acquisition.
// Observe never starts a process or renews a source observation timestamp.
type Effects interface {
	ValidateEnrollment(Plan) error
	ReadInstallation(string) (nodeconfig.Configuration, Credentials, error)
	ApplyPhase(context.Context, Plan, lifecycle.Phase) error
	Rollback(context.Context, Plan) error
	Observe(context.Context, Plan) (bool, error)
}

type Backend struct {
	effects Effects
	now     func() time.Time
	entropy io.Reader
}

func NewBackend(effects Effects) (*Backend, error) {
	if effects == nil {
		return nil, errors.New("node lifecycle effects are required")
	}
	return &Backend{effects: effects, now: time.Now, entropy: rand.Reader}, nil
}

func (backend *Backend) Run(ctx context.Context, request cli.Request) (cli.Result, error) {
	if backend == nil || backend.effects == nil || backend.now == nil || backend.entropy == nil {
		return cli.Result{}, fault(cli.FaultInternal, "NODE_BACKEND_UNAVAILABLE")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	switch request.Action {
	case lifecycle.ActionInstall:
		return backend.install(ctx, request)
	case lifecycle.ActionStart, lifecycle.ActionStatus, lifecycle.ActionVerify:
		return backend.installed(ctx, request)
	default:
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_ACTION_UNSUPPORTED")
	}
}

func (backend *Backend) install(ctx context.Context, request cli.Request) (result cli.Result, resultErr error) {
	trustBytes, trust, err := release.ReadTrustRootFile(request.TrustKey)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "TRUST_ROOT_INVALID")
	}
	bundle, err := release.VerifyDirectory(request.Bundle, trustBytes)
	if err != nil || ValidateRelease(bundle) != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_RELEASE_INVALID")
	}
	if bundle.Manifest.Release.PreviousID != "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "INSTALL_RELEASE_HAS_PREDECESSOR")
	}
	config, material, err := enrollment(request.Root, request.Configuration)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_INVALID")
	}
	defer material.Clear()
	binding, err := Binding(config, material)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_INVALID")
	}
	plan := Plan{Root: request.Root, Bundle: bundle, Trust: trust, TrustBytes: trustBytes,
		Configuration: config, Credentials: material, Binding: binding}
	if ValidatePlan(plan) != nil || backend.effects.ValidateEnrollment(plan) != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_INVALID")
	}
	session, err := journal.Acquire(ctx, request.Root)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	defer closeSession(session, &result, &resultErr)
	initialized, err := session.Initialized()
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	var state lifecycle.Journal
	if initialized {
		state, err = readNodeJournal(session)
		if err != nil {
			return cli.Result{}, err
		}
		if state.InstallationID != config.Identity.InstallationID || *state.Node != binding ||
			state.ReleaseTrust != (lifecycle.ReleaseTrust{KeyID: trust.KeyID, Fingerprint: trust.PublicKeyFingerprint}) {
			return cli.Result{}, fault(cli.FaultConflict, "NODE_ENROLLMENT_CONFLICT")
		}
	} else {
		state, err = lifecycle.NewNode(config.Identity.InstallationID,
			lifecycle.ReleaseTrust{KeyID: trust.KeyID, Fingerprint: trust.PublicKeyFingerprint}, binding)
		if err != nil {
			return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_INVALID")
		}
	}
	if state.Active == nil && state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_MANUAL_INTERVENTION_REQUIRED")
	}
	if state.Active == nil && state.CurrentReleaseID == bundle.Manifest.Release.ID {
		if state.CurrentReleaseDigest != bundle.ManifestSHA256 {
			return cli.Result{}, fault(cli.FaultConflict, "RELEASE_CONTENT_CONFLICT")
		}
		return backend.observe(ctx, state, plan)
	}
	command, err := backend.command(state, lifecycle.ActionInstall)
	if err != nil {
		return cli.Result{}, err
	}
	command.InputDigest, command.TargetReleaseID = bundle.ManifestSHA256, bundle.Manifest.Release.ID
	started, err := lifecycle.Start(state, command)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	if !initialized {
		err = session.Initialize(started.Journal)
	} else if started.Replay == lifecycle.ReplayNone {
		err = session.Write(started.Journal)
	}
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	return backend.drive(ctx, session, plan)
}

func (backend *Backend) installed(ctx context.Context, request cli.Request) (result cli.Result, resultErr error) {
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	defer closeSession(session, &result, &resultErr)
	state, err := readNodeJournal(session)
	if err != nil {
		return cli.Result{}, err
	}
	if request.Action == lifecycle.ActionStatus && state.Active != nil {
		return resultFor(state, false), nil
	}
	if state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention {
		if request.Action == lifecycle.ActionStatus {
			return resultFor(state, false), nil
		}
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_MANUAL_INTERVENTION_REQUIRED")
	}
	if state.CurrentReleaseID == "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_NOT_INSTALLED")
	}
	plan, err := backend.installedPlan(session.Root(), state)
	if err != nil {
		return cli.Result{}, err
	}
	defer plan.Credentials.Clear()
	if request.Action == lifecycle.ActionStatus {
		return backend.observe(ctx, state, plan)
	}
	command, err := backend.command(state, request.Action)
	if err != nil {
		return cli.Result{}, err
	}
	started, err := lifecycle.Start(state, command)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	if started.Replay == lifecycle.ReplayNone {
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, journalFault(err)
		}
	}
	return backend.drive(ctx, session, plan)
}

func (backend *Backend) installedPlan(root string, state lifecycle.Journal) (Plan, error) {
	trustBytes, trust, err := release.ReadTrustRootFile(filepath.Join(root, filepath.FromSlash(layout.ReleaseTrust)))
	if err != nil || trust.KeyID != state.ReleaseTrust.KeyID || trust.PublicKeyFingerprint != state.ReleaseTrust.Fingerprint {
		return Plan{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	bundle, err := release.VerifyDirectory(filepath.Join(root, filepath.FromSlash(layout.ReleaseDirectory(state.CurrentReleaseID))), trustBytes)
	if err != nil || ValidateRelease(bundle) != nil || bundle.Manifest.Release.ID != state.CurrentReleaseID ||
		bundle.ManifestSHA256 != state.CurrentReleaseDigest {
		return Plan{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	config, material, err := backend.effects.ReadInstallation(root)
	if err != nil {
		return Plan{}, fault(cli.FaultVerification, "NODE_CONFIGURATION_INVALID")
	}
	plan := Plan{Root: root, Bundle: bundle, Trust: trust, TrustBytes: trustBytes,
		Configuration: config, Credentials: material, Binding: *state.Node}
	if config.Identity.InstallationID != state.InstallationID || ValidatePlan(plan) != nil || backend.effects.ValidateEnrollment(plan) != nil {
		material.Clear()
		return Plan{}, fault(cli.FaultVerification, "NODE_CONFIGURATION_INVALID")
	}
	return plan, nil
}

func (backend *Backend) command(state lifecycle.Journal, action lifecycle.Action) (lifecycle.Command, error) {
	if state.Active != nil {
		if state.Active.Command.Action != action {
			return lifecycle.Command{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
		}
		return state.Active.Command, nil
	}
	var entropy [16]byte
	if _, err := io.ReadFull(backend.entropy, entropy[:]); err != nil {
		return lifecycle.Command{}, fault(cli.FaultInternal, "COMMAND_ID_GENERATION_FAILED")
	}
	return lifecycle.Command{ID: "cmd-" + hex.EncodeToString(entropy[:]), Action: action,
		RequestedAt: backend.now().UTC().Truncate(time.Microsecond)}, nil
}

func (backend *Backend) drive(ctx context.Context, session *journal.Session, plan Plan) (cli.Result, error) {
	for {
		state, err := readNodeJournal(session)
		if err != nil {
			return cli.Result{}, err
		}
		if state.Active == nil {
			if state.Last == nil || state.Last.Outcome != lifecycle.OutcomeSucceeded {
				return cli.Result{}, fault(cli.FaultVerification, "NODE_COMMAND_FAILED")
			}
			return resultFor(state, state.Last.Command.Action != lifecycle.ActionVerify), nil
		}
		execution := *state.Active
		if execution.Phase == lifecycle.PhaseRollingBack {
			err = backend.effects.Rollback(ctx, plan)
		} else {
			err = backend.effects.ApplyPhase(ctx, plan, execution.Phase)
		}
		if err != nil {
			if ctx.Err() != nil {
				return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
			}
			if errors.Is(err, ErrOutcomeUnknown) {
				return cli.Result{}, fault(cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
			}
			normalized := effectFault(err)
			failed, failErr := lifecycle.Fail(state, execution.Command.ID, normalized.Code, backend.nextTime(execution.UpdatedAt))
			if failErr != nil || session.Write(failed) != nil {
				return cli.Result{}, fault(cli.FaultInternal, "FAILURE_STATE_COMMIT_FAILED")
			}
			if failed.Active == nil {
				return cli.Result{}, normalized
			}
			continue
		}
		next, ok := lifecycle.NextPhase(state)
		if execution.Phase == lifecycle.PhaseRollingBack {
			next, ok = lifecycle.PhaseReady, true
		}
		if !ok {
			return cli.Result{}, fault(cli.FaultInternal, "NODE_TRANSITION_INVALID")
		}
		advanced, err := lifecycle.Advance(state, execution.Command.ID, next, backend.nextTime(execution.UpdatedAt))
		if err != nil || session.Write(advanced) != nil {
			return cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_STATE_COMMIT_FAILED")
		}
		if execution.Phase == lifecycle.PhaseRollingBack {
			class := cli.FaultVerification
			switch execution.FailureCode {
			case "NODE_PREFLIGHT_FAILED":
				class = cli.FaultPrecondition
			case "NODE_OWNERSHIP_CONFLICT":
				class = cli.FaultConflict
			case "NODE_DEPENDENCY_UNAVAILABLE":
				class = cli.FaultUnavailable
			}
			return cli.Result{}, fault(class, execution.FailureCode)
		}
	}
}

func (backend *Backend) observe(ctx context.Context, state lifecycle.Journal, plan Plan) (cli.Result, error) {
	ready, err := backend.effects.Observe(ctx, plan)
	if err != nil {
		if ctx.Err() != nil {
			return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		return cli.Result{}, effectFault(err)
	}
	result := resultFor(state, false)
	result.State = "NOT_READY"
	if ready {
		result.State = "READY"
	}
	return result, nil
}

func (backend *Backend) nextTime(previous time.Time) time.Time {
	now := backend.now().UTC().Truncate(time.Microsecond)
	if !now.After(previous) {
		return previous.Add(time.Microsecond)
	}
	return now
}

func readNodeJournal(session *journal.Session) (lifecycle.Journal, error) {
	state, err := session.Read()
	if err != nil || state.Node == nil {
		return lifecycle.Journal{}, fault(cli.FaultVerification, "NODE_INSTALLATION_STATE_INVALID")
	}
	return state, nil
}

func closeSession(session *journal.Session, result *cli.Result, resultErr *error) {
	if err := session.Close(); err != nil && *resultErr == nil {
		*result, *resultErr = cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
	}
}

func resultFor(state lifecycle.Journal, changed bool) cli.Result {
	result := cli.Result{State: "NOT_READY", ReleaseID: state.CurrentReleaseID, Changed: changed,
		ExecutionTargetID: state.Node.ExecutionTargetID}
	if state.Active != nil {
		result.State, result.CorrelationID = string(state.Active.Phase), state.Active.Command.ID
	} else if state.Last != nil {
		result.State, result.CorrelationID = string(state.Last.Phase), state.Last.Command.ID
	}
	return result
}

func fault(class cli.FaultClass, code string) *cli.Fault {
	value, err := cli.NewFault(class, code)
	if err != nil {
		panic("invalid static node fault")
	}
	return value
}

func effectFault(err error) *cli.Fault {
	switch {
	case errors.Is(err, ErrConflict):
		return fault(cli.FaultConflict, "NODE_OWNERSHIP_CONFLICT")
	case errors.Is(err, ErrPrecondition):
		return fault(cli.FaultPrecondition, "NODE_PREFLIGHT_FAILED")
	case errors.Is(err, ErrUnavailable):
		return fault(cli.FaultUnavailable, "NODE_DEPENDENCY_UNAVAILABLE")
	default:
		return fault(cli.FaultVerification, "NODE_VERIFICATION_FAILED")
	}
}

func journalFault(err error) *cli.Fault {
	switch {
	case errors.Is(err, lifecycle.ErrCommandConflict), errors.Is(err, lifecycle.ErrCommandInProgress), errors.Is(err, journal.ErrOwnershipConflict):
		return fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
	case errors.Is(err, lifecycle.ErrPrecondition), errors.Is(err, journal.ErrNotInitialized):
		return fault(cli.FaultPrecondition, "NODE_NOT_INSTALLED")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	default:
		return fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
}
