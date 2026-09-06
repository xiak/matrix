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
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
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
	Root                      string
	Bundle                    release.VerifiedBundle
	Trust                     release.TrustRoot
	TrustBytes                []byte
	Configuration             nodeconfig.Configuration
	Credentials               Credentials
	Binding                   lifecycle.NodeBinding
	Previous                  *Plan
	ReleaseSource             *Plan
	RevokePreviousCredentials bool
}

// SupportPlan binds a diagnostic file to an authenticated journal snapshot.
// Producing it is not a lifecycle action and must not advance that journal.
type SupportPlan struct {
	Installation Plan
	Journal      lifecycle.Journal
	Output       string
	GeneratedAt  time.Time
}

func (plan Plan) Clear() {
	plan.Credentials.Clear()
	if plan.Previous != nil {
		plan.Previous.Credentials.Clear()
	}
	if plan.ReleaseSource != nil {
		plan.ReleaseSource.Credentials.Clear()
	}
}

// Effects separates supervision/filesystem effects from the durable workflow.
// ValidateEnrollment is side-effect free and precedes even root acquisition.
// Observe never starts a process or renews a source observation timestamp.
type Effects interface {
	ValidateEnrollment(Plan) error
	ReadInstallation(string) (nodeconfig.Configuration, Credentials, error)
	ReadRotation(string, string) (nodeconfig.Configuration, Credentials, error)
	FinalizeRotation(context.Context, Plan, lifecycle.Command) error
	StageRelease(context.Context, Plan) error
	ApplyPhase(context.Context, Plan, lifecycle.Phase) error
	Rollback(context.Context, Plan) error
	Observe(context.Context, Plan) (bool, error)
	WriteSupportEvidence(context.Context, SupportPlan) (created bool, err error)
}

type Backend struct {
	effects    Effects
	store      EnrollmentStore
	host       EnrollmentHost
	enrollment EnrollmentClient
	now        func() time.Time
	entropy    io.Reader
}

func NewBackend(effects Effects, store EnrollmentStore, host EnrollmentHost, enrollment EnrollmentClient) (*Backend, error) {
	if effects == nil || store == nil || host == nil || enrollment == nil {
		return nil, errors.New("node lifecycle and enrollment dependencies are required")
	}
	return &Backend{
		effects: effects, store: store, host: host, enrollment: enrollment,
		now: time.Now, entropy: rand.Reader,
	}, nil
}

func (backend *Backend) Run(ctx context.Context, request cli.Request) (cli.Result, error) {
	if backend == nil || backend.effects == nil || backend.store == nil || backend.host == nil ||
		backend.enrollment == nil || backend.now == nil || backend.entropy == nil {
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
	case lifecycle.ActionRotateCredentials:
		return backend.rotateCredentials(ctx, request)
	case lifecycle.ActionUpgrade, lifecycle.ActionRollback:
		return backend.changeRelease(ctx, request)
	case lifecycle.ActionStart, lifecycle.ActionStatus, lifecycle.ActionVerify:
		return backend.installed(ctx, request)
	case lifecycle.ActionSupport:
		return backend.support(ctx, request)
	default:
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_ACTION_UNSUPPORTED")
	}
}

func (backend *Backend) support(ctx context.Context, request cli.Request) (result cli.Result, resultErr error) {
	if request.Join != "" || request.Bundle != "" || request.TrustKey != "" || request.Configuration != "" ||
		request.BackupID != "" || request.ExpectedConfigurationDigest != "" || request.RevokePreviousCredentials ||
		request.RecoveryInput != "" || request.Resume || strings.TrimSpace(request.SupportOutput) == "" || len(request.SupportOutput) > 4096 ||
		!filepath.IsAbs(request.SupportOutput) || filepath.Clean(request.SupportOutput) != request.SupportOutput ||
		filepath.Dir(request.SupportOutput) != filepath.Join(request.Root, filepath.FromSlash(layout.SupportDirectory)) {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "SUPPORT_OUTPUT_INVALID")
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	defer closeSession(session, &result, &resultErr)
	state, err := readNodeJournal(session)
	if err != nil {
		return cli.Result{}, err
	}
	if state.Active != nil {
		return cli.Result{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
	}
	if state.CurrentReleaseID == "" || state.Last == nil {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_NOT_INSTALLED")
	}
	plan, err := backend.installedPlan(session.Root(), state)
	if err != nil {
		return cli.Result{}, err
	}
	defer plan.Clear()
	created, err := backend.effects.WriteSupportEvidence(ctx, SupportPlan{
		Installation: plan, Journal: state, Output: request.SupportOutput,
		GeneratedAt: backend.nextTime(state.Last.UpdatedAt),
	})
	if err != nil {
		if ctx.Err() != nil {
			return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		if errors.Is(err, ErrOutcomeUnknown) {
			return cli.Result{}, fault(cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
		}
		return cli.Result{}, effectFault(err)
	}
	result = resultFor(state, created)
	result.State = "SUPPORT_REPLAYED"
	if created {
		result.State = "SUPPORT_WRITTEN"
	}
	return result, nil
}

func (backend *Backend) install(ctx context.Context, request cli.Request) (result cli.Result, resultErr error) {
	if request.Configuration != "" || request.BackupID != "" || request.SupportOutput != "" ||
		request.ExpectedConfigurationDigest != "" || request.RevokePreviousCredentials ||
		request.RecoveryInput != "" || request.Resume || strings.TrimSpace(request.Join) == "" {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "NODE_INSTALL_INPUT_INVALID")
	}
	bundlePath, err := absoluteInstallInput(request.Bundle)
	if err != nil {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "NODE_INSTALL_INPUT_INVALID")
	}
	trustPath, err := absoluteInstallInput(request.TrustKey)
	if err != nil {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "NODE_INSTALL_INPUT_INVALID")
	}
	joinPath, err := absoluteInstallInput(request.Join)
	if err != nil {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "NODE_INSTALL_INPUT_INVALID")
	}
	joinFile, err := readNodeEnrollmentJoin(joinPath)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_JOIN_INVALID")
	}
	defer joinFile.Clear()
	trustBytes, trust, err := release.ReadTrustRootFile(trustPath)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "TRUST_ROOT_INVALID")
	}
	bundle, err := release.VerifyDirectory(bundlePath, trustBytes)
	if err != nil || ValidateRelease(bundle) != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_RELEASE_INVALID")
	}
	if bundle.Manifest.Release.PreviousID != "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "INSTALL_RELEASE_HAS_PREDECESSOR")
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
	if _, err := backend.store.ResumeEnrollmentCleanup(session.Root()); err != nil {
		return cli.Result{}, enrollmentCleanupFault(ctx, err)
	}
	var state lifecycle.Journal
	if initialized {
		state, err = readNodeJournal(session)
		if err != nil {
			return cli.Result{}, err
		}
		intent, exists, readErr := backend.store.ReadEnrollmentIntent(session.Root())
		if readErr != nil {
			return cli.Result{}, enrollmentStateFault(readErr)
		}
		matchesRequest := state.Node != nil && state.InstallationID == joinFile.Join.InstallationID &&
			state.Node.ExecutionTargetID == string(joinFile.Join.ExecutionTargetID) &&
			state.ReleaseTrust == (lifecycle.ReleaseTrust{KeyID: trust.KeyID, Fingerprint: trust.PublicKeyFingerprint})
		if rejectedEnrollmentCleanupPending(state) {
			if !matchesRequest || state.Last.Command.TargetReleaseID != bundle.Manifest.Release.ID ||
				state.Last.Command.InputDigest != bundle.ManifestSHA256 ||
				(exists && !sameEnrollmentJoin(intent.Join, joinFile.Join)) {
				intent.Clear()
				return cli.Result{}, fault(cli.FaultConflict, "NODE_ENROLLMENT_CONFLICT")
			}
			intent.Clear()
			if exists {
				if err := backend.cleanupRejectedEnrollment(ctx, session.Root(), state); err != nil {
					return cli.Result{}, enrollmentCleanupFault(ctx, err)
				}
			}
			return cli.Result{}, fault(cli.FaultVerification, lifecycle.NodeEnrollmentRejectedFailureCode)
		}
		if state.Active == nil && state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention {
			intent.Clear()
			return cli.Result{}, fault(cli.FaultPrecondition, "NODE_MANUAL_INTERVENTION_REQUIRED")
		}
		if state.Active == nil && state.CurrentReleaseID != "" {
			if !matchesRequest || state.CurrentReleaseID != bundle.Manifest.Release.ID ||
				state.CurrentReleaseDigest != bundle.ManifestSHA256 ||
				(exists && !sameEnrollmentJoin(intent.Join, joinFile.Join)) {
				intent.Clear()
				return cli.Result{}, fault(cli.FaultConflict, "NODE_ENROLLMENT_CONFLICT")
			}
			intent.Clear()
			if exists {
				if err := backend.finalizeCompletedEnrollment(session.Root(), state); err != nil {
					return cli.Result{}, enrollmentCleanupFault(ctx, err)
				}
			}
			plan, planErr := backend.installedPlan(session.Root(), state)
			if planErr != nil {
				return cli.Result{}, planErr
			}
			defer plan.Clear()
			return backend.observe(ctx, state, plan)
		}
		if !exists {
			return cli.Result{}, fault(cli.FaultConflict, "NODE_ENROLLMENT_CONFLICT")
		}
		intent.Clear()
	}
	ceremony, err := backend.prepareEnrollment(ctx, session.Root(), joinFile)
	if err != nil {
		return cli.Result{}, enrollmentStateFaultWithContext(ctx, err)
	}
	defer ceremony.Clear()
	plan, err := planFromEnrollment(request.Root, bundle, trust, trustBytes, ceremony.intent, ceremony.response)
	if err != nil || backend.effects.ValidateEnrollment(plan) != nil {
		plan.Clear()
		return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_INVALID")
	}
	defer plan.Clear()
	if initialized {
		if state.InstallationID != plan.Configuration.Identity.InstallationID || *state.Node != plan.Binding ||
			state.ReleaseTrust != (lifecycle.ReleaseTrust{KeyID: trust.KeyID, Fingerprint: trust.PublicKeyFingerprint}) {
			return cli.Result{}, fault(cli.FaultConflict, "NODE_ENROLLMENT_CONFLICT")
		}
	} else {
		state, err = lifecycle.NewNode(plan.Configuration.Identity.InstallationID,
			lifecycle.ReleaseTrust{KeyID: trust.KeyID, Fingerprint: trust.PublicKeyFingerprint}, plan.Binding)
		if err != nil {
			return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_INVALID")
		}
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
		err = session.InitializeNode(started.Journal)
	} else if started.Replay == lifecycle.ReplayNone {
		err = session.Write(started.Journal)
	}
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	return backend.drive(ctx, session, plan, &ceremony)
}

func (backend *Backend) installed(ctx context.Context, request cli.Request) (result cli.Result, resultErr error) {
	if request.Join != "" || request.Bundle != "" || request.TrustKey != "" || request.Configuration != "" ||
		request.BackupID != "" || request.SupportOutput != "" || request.ExpectedConfigurationDigest != "" ||
		request.RevokePreviousCredentials || request.RecoveryInput != "" || request.Resume {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "NODE_OPERATION_INPUT_INVALID")
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	defer closeSession(session, &result, &resultErr)
	if request.Action != lifecycle.ActionStatus {
		if _, err := backend.store.ResumeEnrollmentCleanup(session.Root()); err != nil {
			return cli.Result{}, enrollmentCleanupFault(ctx, err)
		}
	}
	state, err := readNodeJournal(session)
	if err != nil {
		return cli.Result{}, err
	}
	if request.Action == lifecycle.ActionStatus && state.Active != nil {
		return resultFor(state, false), nil
	}
	if state.Active != nil && state.Active.Command.Action == lifecycle.ActionRotateCredentials {
		if request.Action != lifecycle.ActionStart {
			return cli.Result{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
		}
		plan, err := backend.rotationPlan(session.Root(), state)
		if err != nil {
			return cli.Result{}, err
		}
		defer plan.Clear()
		return backend.drive(ctx, session, plan, nil)
	}
	if state.Active != nil && (state.Active.Command.Action == lifecycle.ActionUpgrade || state.Active.Command.Action == lifecycle.ActionRollback) {
		if request.Action != lifecycle.ActionStart {
			return cli.Result{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
		}
		plan, err := backend.activeReleasePlan(session.Root(), state)
		if err != nil {
			return cli.Result{}, err
		}
		defer plan.Clear()
		return backend.drive(ctx, session, plan, nil)
	}
	if state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention {
		if request.Action == lifecycle.ActionStatus {
			return resultFor(state, false), nil
		}
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_MANUAL_INTERVENTION_REQUIRED")
	}
	if request.Action == lifecycle.ActionStart && rejectedEnrollmentCleanupPending(state) {
		if err := backend.cleanupRejectedEnrollment(ctx, session.Root(), state); err != nil {
			return cli.Result{}, enrollmentCleanupFault(ctx, err)
		}
		return cli.Result{}, fault(cli.FaultVerification, lifecycle.NodeEnrollmentRejectedFailureCode)
	}
	resumeInstall := request.Action == lifecycle.ActionStart && state.CurrentReleaseID == "" &&
		state.Active != nil && state.Active.Command.Action == lifecycle.ActionInstall &&
		(state.Active.Phase == lifecycle.PhaseStarting || state.Active.Phase == lifecycle.PhaseVerifying ||
			state.Active.Phase == lifecycle.PhaseCommitting || state.Active.Phase == lifecycle.PhaseRollingBack)
	if state.CurrentReleaseID == "" && !resumeInstall {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_NOT_INSTALLED")
	}
	if resumeInstall {
		// Boot may finish an already configured installation, but cannot enroll
		// a node or allocate another command. The staged release and protected
		// material must still authenticate against the original sealed intent.
		plan, ceremony, err := backend.storedEnrollmentPlan(session.Root(), state)
		if err != nil {
			return cli.Result{}, enrollmentStateFault(err)
		}
		defer plan.Clear()
		defer ceremony.Clear()
		return backend.drive(ctx, session, plan, &ceremony)
	}
	plan, err := backend.installedPlan(session.Root(), state)
	if err != nil {
		return cli.Result{}, err
	}
	defer plan.Credentials.Clear()
	if request.Action == lifecycle.ActionStart && state.Active == nil {
		if err := backend.finalizeCompletedEnrollment(session.Root(), state); err != nil {
			return cli.Result{}, enrollmentCleanupFault(ctx, err)
		}
	}
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
	return backend.drive(ctx, session, plan, nil)
}

func (backend *Backend) releasePlan(root string, state lifecycle.Journal) (Plan, error) {
	releaseID, releaseDigest := state.CurrentReleaseID, state.CurrentReleaseDigest
	if releaseID == "" && state.Active != nil {
		releaseID, releaseDigest = state.Active.Command.TargetReleaseID, state.Active.Command.InputDigest
	}
	return backend.releasePlanAt(root, state, releaseID, releaseDigest)
}

func (backend *Backend) releasePlanAt(root string, state lifecycle.Journal, releaseID, releaseDigest string) (Plan, error) {
	trustBytes, trust, err := release.ReadTrustRootFile(filepath.Join(root, filepath.FromSlash(layout.ReleaseTrust)))
	if err != nil || trust.KeyID != state.ReleaseTrust.KeyID || trust.PublicKeyFingerprint != state.ReleaseTrust.Fingerprint {
		return Plan{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	bundle, err := release.VerifyDirectory(filepath.Join(root, filepath.FromSlash(layout.ReleaseDirectory(releaseID))), trustBytes)
	if err != nil || ValidateInstalledRelease(bundle) != nil || bundle.Manifest.Release.ID != releaseID ||
		bundle.ManifestSHA256 != releaseDigest {
		return Plan{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	return Plan{Root: root, Bundle: bundle, Trust: trust, TrustBytes: trustBytes, Binding: *state.Node}, nil
}

func (backend *Backend) installedPlan(root string, state lifecycle.Journal) (Plan, error) {
	plan, err := backend.releasePlan(root, state)
	if err != nil {
		return Plan{}, err
	}
	config, material, err := backend.effects.ReadInstallation(root)
	if err != nil {
		return Plan{}, fault(cli.FaultVerification, "NODE_CONFIGURATION_INVALID")
	}
	plan.Configuration, plan.Credentials = config, material
	if config.Identity.InstallationID != state.InstallationID || ValidatePlan(plan) != nil || backend.effects.ValidateEnrollment(plan) != nil {
		material.Clear()
		return Plan{}, fault(cli.FaultVerification, "NODE_CONFIGURATION_INVALID")
	}
	return plan, nil
}

func (backend *Backend) changeRelease(ctx context.Context, request cli.Request) (result cli.Result, resultErr error) {
	if request.Configuration != "" || request.Join != "" || request.TrustKey != "" || request.BackupID != "" ||
		request.SupportOutput != "" || request.ExpectedConfigurationDigest != "" || request.RevokePreviousCredentials ||
		request.RecoveryInput != "" ||
		(request.Action == lifecycle.ActionUpgrade && request.Resume == (request.Bundle != "")) ||
		(request.Action == lifecycle.ActionRollback && (request.Resume || request.Bundle != "")) {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "NODE_RELEASE_INPUT_INVALID")
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	defer closeSession(session, &result, &resultErr)
	if _, err := backend.store.ResumeEnrollmentCleanup(session.Root()); err != nil {
		return cli.Result{}, enrollmentCleanupFault(ctx, err)
	}
	state, err := readNodeJournal(session)
	if err != nil {
		return cli.Result{}, err
	}
	if state.CurrentReleaseID == "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_NOT_INSTALLED")
	}
	if state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_MANUAL_INTERVENTION_REQUIRED")
	}
	if state.Active != nil {
		if state.Active.Command.Action != request.Action {
			return cli.Result{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
		}
		plan, err := backend.activeReleasePlan(session.Root(), state)
		if err != nil {
			return cli.Result{}, err
		}
		defer plan.Clear()
		if request.Bundle != "" {
			candidate, err := release.VerifyDirectory(request.Bundle, plan.TrustBytes)
			if err != nil || ValidateRelease(candidate) != nil {
				return cli.Result{}, fault(cli.FaultVerification, "NODE_RELEASE_INVALID")
			}
			if candidate.Manifest.Release.ID != plan.Bundle.Manifest.Release.ID || candidate.ManifestSHA256 != plan.Bundle.ManifestSHA256 {
				return cli.Result{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
			}
		}
		return backend.drive(ctx, session, plan, nil)
	}
	source, err := backend.installedPlan(session.Root(), state)
	if err != nil {
		return cli.Result{}, err
	}
	defer source.Clear()
	if request.Resume || (request.Action == lifecycle.ActionRollback && state.PreviousRelease == "") {
		return backend.replayReleaseChange(ctx, state, source, request.Action)
	}
	var candidate release.VerifiedBundle
	if request.Action == lifecycle.ActionUpgrade {
		candidate, err = release.VerifyDirectory(request.Bundle, source.TrustBytes)
		if err != nil || ValidateRelease(candidate) != nil {
			return cli.Result{}, fault(cli.FaultVerification, "NODE_RELEASE_INVALID")
		}
		if candidate.Manifest.Release.ID == state.CurrentReleaseID {
			if candidate.ManifestSHA256 != state.CurrentReleaseDigest {
				return cli.Result{}, fault(cli.FaultConflict, "RELEASE_CONTENT_CONFLICT")
			}
			return backend.replayReleaseChange(ctx, state, source, request.Action)
		}
		if !nodeReleaseSuccessor(candidate, source.Bundle) {
			return cli.Result{}, fault(cli.FaultPrecondition, "NODE_RELEASE_TRANSITION_UNSUPPORTED")
		}
	} else {
		previous, err := backend.releasePlanAt(session.Root(), state, state.PreviousRelease, state.PreviousReleaseDigest)
		if err != nil {
			return cli.Result{}, err
		}
		candidate = previous.Bundle
		if !nodeReleaseSuccessor(source.Bundle, candidate) {
			return cli.Result{}, fault(cli.FaultPrecondition, "NODE_RELEASE_TRANSITION_UNSUPPORTED")
		}
	}
	plan := source
	plan.Bundle, plan.ReleaseSource = candidate, &source
	if ValidatePlan(plan) != nil || backend.effects.ValidateEnrollment(plan) != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_RELEASE_INVALID")
	}
	if state.NodeCredentialRotation != nil {
		if err := backend.effects.FinalizeRotation(ctx, source, *state.NodeCredentialRotation); err != nil {
			return cli.Result{}, fault(cli.FaultUnavailable, "NODE_CREDENTIAL_CLEANUP_PENDING")
		}
	}
	// Only authenticated immutable release bytes are staged before accepting an
	// activation intent. No process, boot entry or credential may change here.
	// Thus every accepted command can resume without the operator's media.
	if err := backend.effects.StageRelease(ctx, plan); err != nil {
		if ctx.Err() != nil {
			return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		return cli.Result{}, effectFault(err)
	}
	staged, err := backend.releasePlanAt(session.Root(), state, candidate.Manifest.Release.ID, candidate.ManifestSHA256)
	if err != nil {
		return cli.Result{}, err
	}
	plan.Bundle = staged.Bundle
	command, err := backend.command(state, request.Action)
	if err != nil {
		return cli.Result{}, err
	}
	if request.Action == lifecycle.ActionUpgrade {
		command.InputDigest, command.TargetReleaseID = candidate.ManifestSHA256, candidate.Manifest.Release.ID
	}
	started, err := lifecycle.Start(state, command)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	if err := session.Write(started.Journal); err != nil {
		return cli.Result{}, journalFault(err)
	}
	return backend.drive(ctx, session, plan, nil)
}

func (backend *Backend) replayReleaseChange(ctx context.Context, state lifecycle.Journal, plan Plan, action lifecycle.Action) (cli.Result, error) {
	receipt := state.NodeReleaseChange
	if receipt == nil || receipt.Command.Action != action {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_RELEASE_CHANGE_NOT_FOUND")
	}
	result, err := backend.observe(ctx, state, plan)
	result.CorrelationID = receipt.Command.ID
	return result, err
}

func (backend *Backend) activeReleasePlan(root string, state lifecycle.Journal) (Plan, error) {
	source, err := backend.installedPlan(root, state)
	if err != nil {
		return Plan{}, err
	}
	execution := state.Active
	if execution == nil || (execution.Command.Action != lifecycle.ActionUpgrade && execution.Command.Action != lifecycle.ActionRollback) {
		source.Clear()
		return Plan{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
	}
	plan, err := backend.releasePlanAt(root, state, execution.Destination, execution.DestinationDigest)
	if err != nil {
		source.Clear()
		return Plan{}, err
	}
	plan.Configuration, plan.Credentials, plan.ReleaseSource = source.Configuration, source.Credentials, &source
	if ValidatePlan(plan) != nil || backend.effects.ValidateEnrollment(plan) != nil ||
		(execution.Command.Action == lifecycle.ActionUpgrade && !nodeReleaseSuccessor(plan.Bundle, source.Bundle)) ||
		(execution.Command.Action == lifecycle.ActionRollback && !nodeReleaseSuccessor(source.Bundle, plan.Bundle)) {
		plan.Clear()
		return Plan{}, fault(cli.FaultVerification, "NODE_RELEASE_INVALID")
	}
	return plan, nil
}

func (backend *Backend) rotateCredentials(ctx context.Context, request cli.Request) (result cli.Result, resultErr error) {
	if request.Join != "" || request.Bundle != "" || request.TrustKey != "" || request.BackupID != "" ||
		request.SupportOutput != "" || request.RecoveryInput != "" || request.Resume ||
		paasv1.ValidateDigest("expectedConfigurationDigest", request.ExpectedConfigurationDigest) != nil {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "NODE_ROTATION_INPUT_INVALID")
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
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	defer closeSession(session, &result, &resultErr)
	if _, err := backend.store.ResumeEnrollmentCleanup(session.Root()); err != nil {
		return cli.Result{}, enrollmentCleanupFault(ctx, err)
	}
	state, err := readNodeJournal(session)
	if err != nil {
		return cli.Result{}, err
	}
	if state.CurrentReleaseID == "" || (state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention) {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_NOT_INSTALLED")
	}
	plan, err := backend.releasePlan(session.Root(), state)
	if err != nil {
		return cli.Result{}, err
	}
	plan.Configuration, plan.Credentials, plan.Binding = config, material, binding
	if binding.ExecutionTargetID != state.Node.ExecutionTargetID || config.Identity.InstallationID != state.InstallationID {
		return cli.Result{}, fault(cli.FaultConflict, "NODE_ENROLLMENT_CONFLICT")
	}
	if state.Active == nil && binding == *state.Node {
		receipt := state.NodeCredentialRotation
		if receipt == nil || receipt.InputDigest != binding.ConfigurationDigest ||
			receipt.ExpectedConfigurationDigest != request.ExpectedConfigurationDigest ||
			receipt.RevokePreviousCredentials != request.RevokePreviousCredentials {
			return cli.Result{}, fault(cli.FaultConflict, "NODE_CONFIGURATION_CONFLICT")
		}
		if ValidatePlan(plan) != nil || backend.effects.ValidateEnrollment(plan) != nil {
			return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_INVALID")
		}
		if err := backend.effects.FinalizeRotation(ctx, plan, *receipt); err != nil {
			return cli.Result{}, fault(cli.FaultUnavailable, "NODE_CREDENTIAL_CLEANUP_PENDING")
		}
		result, err := backend.observe(ctx, state, plan)
		result.CorrelationID = receipt.ID
		return result, err
	}
	if request.ExpectedConfigurationDigest != state.Node.ConfigurationDigest || binding == *state.Node {
		return cli.Result{}, fault(cli.FaultConflict, "NODE_CONFIGURATION_CONFLICT")
	}
	if state.Active != nil {
		command := state.Active.Command
		if command.Action != lifecycle.ActionRotateCredentials || command.InputDigest != binding.ConfigurationDigest ||
			command.ExpectedConfigurationDigest != request.ExpectedConfigurationDigest ||
			command.RevokePreviousCredentials != request.RevokePreviousCredentials {
			return cli.Result{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
		}
	}
	var previousConfiguration nodeconfig.Configuration
	var previousCredentials Credentials
	if state.Active != nil {
		previousConfiguration, previousCredentials, err = backend.effects.ReadRotation(session.Root(), state.Node.ConfigurationDigest)
	}
	if state.Active == nil || (err != nil && (state.Active.Phase == lifecycle.PhasePreflight || state.Active.Phase == lifecycle.PhaseStaging)) {
		previousConfiguration, previousCredentials, err = backend.effects.ReadInstallation(session.Root())
	}
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_ROTATION_INPUT_UNAVAILABLE")
	}
	defer previousCredentials.Clear()
	previous := plan
	previous.Configuration, previous.Credentials, previous.Binding = previousConfiguration, previousCredentials, *state.Node
	plan.Previous, plan.RevokePreviousCredentials = &previous, request.RevokePreviousCredentials
	// The old bytes must match their sealed commitment, but their certificates
	// may have expired. Only the candidate must be currently usable.
	if ValidatePlan(plan) != nil || backend.effects.ValidateEnrollment(plan) != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_INVALID")
	}
	if state.Active == nil && state.NodeCredentialRotation != nil {
		if err := backend.effects.FinalizeRotation(ctx, previous, *state.NodeCredentialRotation); err != nil {
			return cli.Result{}, fault(cli.FaultUnavailable, "NODE_CREDENTIAL_CLEANUP_PENDING")
		}
	}
	command, err := backend.command(state, lifecycle.ActionRotateCredentials)
	if err != nil {
		return cli.Result{}, err
	}
	command.InputDigest, command.ExpectedConfigurationDigest = binding.ConfigurationDigest, request.ExpectedConfigurationDigest
	command.RevokePreviousCredentials = request.RevokePreviousCredentials
	started, err := lifecycle.Start(state, command)
	if err != nil {
		return cli.Result{}, journalFault(err)
	}
	if started.Replay == lifecycle.ReplayNone {
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, journalFault(err)
		}
	}
	return backend.drive(ctx, session, plan, nil)
}

func (backend *Backend) rotationPlan(root string, state lifecycle.Journal) (Plan, error) {
	plan, err := backend.releasePlan(root, state)
	if err != nil {
		return Plan{}, err
	}
	command := state.Active.Command
	previous := plan
	previous.Configuration, previous.Credentials, err = backend.effects.ReadRotation(root, command.ExpectedConfigurationDigest)
	if err != nil {
		return Plan{}, fault(cli.FaultVerification, "NODE_ROTATION_INPUT_UNAVAILABLE")
	}
	plan.Configuration, plan.Credentials, err = backend.effects.ReadRotation(root, command.InputDigest)
	plan.Binding.ConfigurationDigest = command.InputDigest
	plan.Previous, plan.RevokePreviousCredentials = &previous, command.RevokePreviousCredentials
	if err != nil || ValidatePlan(plan) != nil || plan.Configuration.Identity.InstallationID != state.InstallationID ||
		backend.effects.ValidateEnrollment(plan) != nil {
		plan.Clear()
		return Plan{}, fault(cli.FaultVerification, "NODE_ROTATION_INPUT_UNAVAILABLE")
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

func (backend *Backend) drive(
	ctx context.Context,
	session *journal.Session,
	plan Plan,
	ceremony *enrollmentCeremony,
) (cli.Result, error) {
	resuming := true
	for {
		state, err := readNodeJournal(session)
		if err != nil {
			return cli.Result{}, err
		}
		if state.Active == nil {
			if state.Last == nil || state.Last.Outcome != lifecycle.OutcomeSucceeded {
				return cli.Result{}, fault(cli.FaultVerification, "NODE_COMMAND_FAILED")
			}
			if ceremony != nil && state.Last.Command.Action == lifecycle.ActionInstall {
				if err := backend.store.FinalizeEnrollment(session.Root(), ceremony.intent, ceremony.response); err != nil {
					return cli.Result{}, enrollmentCleanupFault(ctx, err)
				}
			}
			if state.NodeCredentialRotation != nil &&
				(state.Last.Command.Action == lifecycle.ActionRotateCredentials || state.Last.Command.Action == lifecycle.ActionStart) {
				if err := backend.effects.FinalizeRotation(ctx, plan, *state.NodeCredentialRotation); err != nil {
					return cli.Result{}, fault(cli.FaultUnavailable, "NODE_CREDENTIAL_CLEANUP_PENDING")
				}
			}
			return resultFor(state, state.Last.Command.Action != lifecycle.ActionVerify), nil
		}
		execution := *state.Active
		resumed := resuming
		enrollmentCommit := ceremony != nil && execution.Command.Action == lifecycle.ActionInstall &&
			execution.Phase == lifecycle.PhaseCommitting
		if resumed && !enrollmentCommit &&
			(execution.Phase == lifecycle.PhaseVerifying || execution.Phase == lifecycle.PhaseCommitting) &&
			(execution.Command.Action == lifecycle.ActionInstall || execution.Command.Action == lifecycle.ActionStart ||
				execution.Command.Action == lifecycle.ActionRotateCredentials || execution.Command.Action == lifecycle.ActionUpgrade ||
				execution.Command.Action == lifecycle.ActionRollback) {
			// An interrupted late phase may resume after a kernel boot, which
			// discards transient units. Reconcile the same sealed services before
			// verifying them; do not rewind the journal or issue another command.
			err = backend.effects.ApplyPhase(ctx, plan, lifecycle.PhaseStarting)
		}
		resuming = false
		recoverSource := execution.Phase == lifecycle.PhaseRollingBack && execution.FailureCode != ""
		if err == nil {
			if recoverSource {
				err = backend.effects.Rollback(ctx, plan)
			} else if enrollmentCommit {
				// COMMITTING is the durable proof that local verification
				// succeeded before the remote target can be published. On a
				// later process invocation, reconcile and reverify before the
				// idempotent completion replay, but never run a post-publication
				// provider effect.
				if resumed {
					err = backend.effects.ApplyPhase(ctx, plan, lifecycle.PhaseStarting)
					if err == nil {
						err = backend.effects.ApplyPhase(ctx, plan, lifecycle.PhaseVerifying)
					}
				}
			} else {
				err = backend.effects.ApplyPhase(ctx, plan, execution.Phase)
			}
		}
		if err != nil && enrollmentCommit && resumed {
			if ctx.Err() != nil {
				return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
			}
			if errors.Is(err, ErrOutcomeUnknown) {
				return cli.Result{}, fault(cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
			}
			return cli.Result{}, effectFault(err)
		}
		completionRejected := false
		if err == nil && ceremony != nil && execution.Command.Action == lifecycle.ActionInstall &&
			execution.Phase == lifecycle.PhaseCommitting {
			err = backend.completeEnrollment(ctx, *ceremony)
			if errors.Is(err, ErrEnrollmentUnavailable) {
				if ctx.Err() != nil {
					return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
				}
				return cli.Result{}, fault(cli.FaultUnavailable, "NODE_ENROLLMENT_COMPLETION_PENDING")
			}
			completionRejected = errors.Is(err, ErrEnrollmentRejected)
		}
		if err != nil {
			if ctx.Err() != nil {
				return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
			}
			if errors.Is(err, ErrOutcomeUnknown) {
				return cli.Result{}, fault(cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
			}
			if recoverSource && execution.FailureCode == lifecycle.NodeEnrollmentRejectedFailureCode && errors.Is(err, ErrUnavailable) {
				return cli.Result{}, fault(cli.FaultUnavailable, "NODE_DEPENDENCY_UNAVAILABLE")
			}
			normalized := effectFault(err)
			if completionRejected {
				normalized = fault(cli.FaultVerification, lifecycle.NodeEnrollmentRejectedFailureCode)
			}
			failed, failErr := lifecycle.Fail(state, execution.Command.ID, normalized.Code, backend.nextTime(execution.UpdatedAt))
			if failErr != nil || session.Write(failed) != nil {
				return cli.Result{}, fault(cli.FaultInternal, "FAILURE_STATE_COMMIT_FAILED")
			}
			if failed.Active == nil || execution.Command.Action == lifecycle.ActionRotateCredentials {
				return cli.Result{}, normalized
			}
			continue
		}
		next, ok := lifecycle.NextPhase(state)
		if recoverSource {
			next, ok = lifecycle.PhaseReady, true
		}
		if !ok {
			return cli.Result{}, fault(cli.FaultInternal, "NODE_TRANSITION_INVALID")
		}
		advanced, err := lifecycle.Advance(state, execution.Command.ID, next, backend.nextTime(execution.UpdatedAt))
		if err != nil || session.Write(advanced) != nil {
			return cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_STATE_COMMIT_FAILED")
		}
		if recoverSource {
			if execution.FailureCode == lifecycle.NodeEnrollmentRejectedFailureCode {
				if ceremony == nil {
					return cli.Result{}, fault(cli.FaultVerification, "NODE_ENROLLMENT_STATE_INVALID")
				}
				if err := backend.store.CleanupRejectedEnrollment(ctx, plan, ceremony.intent, ceremony.response); err != nil {
					return cli.Result{}, enrollmentCleanupFault(ctx, err)
				}
			}
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
	result := cli.Result{State: "NOT_READY", ReleaseID: state.CurrentReleaseID, PreviousID: state.PreviousRelease, Changed: changed,
		ExecutionTargetID: state.Node.ExecutionTargetID, ConfigurationDigest: state.Node.ConfigurationDigest}
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

func enrollmentStateFaultWithContext(ctx context.Context, err error) *cli.Fault {
	if ctx != nil && ctx.Err() != nil {
		return fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	return enrollmentStateFault(err)
}

func enrollmentStateFault(err error) *cli.Fault {
	switch {
	case errors.Is(err, ErrEnrollmentUnavailable), errors.Is(err, ErrUnavailable), errors.Is(err, ErrOutcomeUnknown):
		return fault(cli.FaultUnavailable, "NODE_ENROLLMENT_UNAVAILABLE")
	case errors.Is(err, ErrEnrollmentRejected):
		return fault(cli.FaultVerification, lifecycle.NodeEnrollmentRejectedFailureCode)
	case errors.Is(err, ErrConflict):
		return fault(cli.FaultConflict, "NODE_ENROLLMENT_CONFLICT")
	default:
		return fault(cli.FaultVerification, "NODE_ENROLLMENT_STATE_INVALID")
	}
}

func enrollmentCleanupFault(ctx context.Context, err error) *cli.Fault {
	if ctx != nil && ctx.Err() != nil {
		return fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	switch {
	case errors.Is(err, ErrUnavailable), errors.Is(err, ErrOutcomeUnknown):
		return fault(cli.FaultUnavailable, "NODE_ENROLLMENT_CLEANUP_PENDING")
	case errors.Is(err, ErrConflict):
		return fault(cli.FaultConflict, "NODE_ENROLLMENT_CLEANUP_CONFLICT")
	default:
		return fault(cli.FaultVerification, "NODE_ENROLLMENT_CLEANUP_INVALID")
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
