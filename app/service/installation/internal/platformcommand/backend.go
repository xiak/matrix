// Package platformcommand owns the workflow behind the user-facing
// mx platform command tree. Durable lifecycle policy stays here while local
// Docker, Compose, PostgreSQL, and filesystem effects remain behind Effects.
package platformcommand

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const (
	defaultListener                     = "0.0.0.0"
	defaultPort                         = uint16(8080)
	MaximumCredentialRecoveryInputBytes = 16 * 1024
)

var (
	ErrEffectPrecondition = errors.New("platform effect precondition failed")
	ErrEffectConflict     = errors.New("platform effect ownership conflict")
	ErrEffectVerification = errors.New("platform effect verification failed")
	ErrEffectUnavailable  = errors.New("platform effect dependency is unavailable")
	// ErrEffectRecoveryRequired means rollback has safely removed the failed
	// candidate, but restoring the source runtime would cross an authenticated
	// database contract boundary. Only recovery from the upgrade backup can
	// restore that source profile.
	ErrEffectRecoveryRequired = errors.New("platform effect requires authenticated recovery")
	// ErrEffectOutcomeUnknown means a provider command started but completion
	// was not established. The journal phase stays active so the next replay
	// observes the owned effect before retrying it.
	ErrEffectOutcomeUnknown = errors.New("platform effect outcome is unknown")
	// Only a verified one-shot IAM result can establish these no-mutation
	// rejections. Filesystem/provider failures cannot close an unknown recovery.
	ErrCredentialRecoveryInvalid   = errors.New("local credential recovery input rejected")
	ErrCredentialRecoveryForbidden = errors.New("local credential recovery is forbidden")
	ErrCredentialRecoveryConflict  = errors.New("local credential recovery intent conflicts")
)

// InstallPlan is authenticated input plus the installation-owned identity.
// TrustBytes contains a public key document, never credential material.
type InstallPlan struct {
	Root           string
	InstallationID string
	CorrelationID  string
	Listener       string
	Port           uint16
	PreviousID     string
	PreviousDigest string
	Bundle         release.VerifiedBundle
	Trust          release.TrustRoot
	TrustBytes     []byte
}

// InstalledPlan is the sealed identity of the currently committed release.
// Local-machine effects must reauthenticate installation-owned files against
// these values before trusting provider state.
type InstalledPlan struct {
	Root             string
	InstallationID   string
	CorrelationID    string
	Listener         string
	Port             uint16
	ReleaseID        string
	ReleaseDigest    string
	PreviousID       string
	PreviousDigest   string
	TrustKeyID       string
	TrustFingerprint string
}

type BackupPlan struct {
	InstalledPlan
	BackupID  string
	CreatedAt time.Time
}

type SupportPlan struct {
	InstalledPlan
	Output        string
	CorrelationID string
	GeneratedAt   time.Time
}

// UpgradePlan binds the authenticated committed source, signed immediate
// successor, and the backup identity persisted before any upgrade effect.
type UpgradePlan struct {
	Source    InstalledPlan
	Target    InstallPlan
	BackupID  string
	CreatedAt time.Time
}

// RollbackPlan binds the authenticated current release and its exact signed
// predecessor. Current remains an InstallPlan because automatic upgrade
// rollback may need the verified candidate before it has been staged.
type RollbackPlan struct {
	Current  InstallPlan
	Previous InstalledPlan
}

// RecoverySource is the authenticated, installation-bound identity committed
// by a selected protected backup. BackupDigest binds the sealed manifest and
// its exact artifact commitments into the durable recovery command.
type RecoverySource struct {
	InstallationID string
	BackupID       string
	BackupDigest   string
	ReleaseID      string
	ReleaseDigest  string
	Database       release.DatabaseProfile
}

// RecoveryPlan binds the current committed release, the authenticated release
// named by the selected backup, and the exact protected backup identity.
type RecoveryPlan struct {
	Current      InstallPlan
	Target       InstallPlan
	BackupID     string
	BackupDigest string
}

// CredentialRecoveryInput is the operator's private intent, not an IAM
// authorization. Installation derives all authority and expected-state fields
// from its sealed provenance and the restricted IAM inspection result.
type CredentialRecoveryInput struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	CommandID  string       `json:"commandId"`
	Password   iamv1.Secret `json:"password"`
}

// The request is private transient material; only CommandID/InputCommitment
// enter the ordinary journal. A receipt-only resume needs no password.
type CredentialRecoveryPlan struct {
	InstalledPlan
	CommandID       string
	InputCommitment string
	Request         *iamv1.LocalCredentialRecoveryRequest
}

// This entrypoint is supported only by the exact composition that implements
// the dedicated IAM transaction and closed offline Audit fact. A contract-only
// consumer must not invoke it against the earlier running authority profile.
func ValidateCredentialRecoveryProfile(profile release.DatabaseProfile) error {
	current := release.CurrentDatabaseProfile()
	if release.ValidateDatabaseUpgradePath(profile, current) != nil ||
		(profile != current && profile != release.SupportedDatabasePredecessorProfile()) {
		return ErrEffectPrecondition
	}
	return nil
}

func (CredentialRecoveryInput) String() string {
	return "platform credential recovery input <redacted>"
}
func (CredentialRecoveryInput) GoString() string {
	return "platform credential recovery input <redacted>"
}

func DecodeCredentialRecoveryInput(source []byte) (CredentialRecoveryInput, error) {
	var input CredentialRecoveryInput
	if contractjson.DecodeObjectBytes(source, MaximumCredentialRecoveryInputBytes, &input) != nil ||
		input.APIVersion != lifecycle.APIVersion || input.Kind != "PlatformCredentialRecoveryInput" ||
		lifecycle.ValidateCommandID(input.CommandID) != nil || !input.Password.Present() {
		return CredentialRecoveryInput{}, errors.New("credential recovery input is invalid")
	}
	return input, nil
}

// Effects is the closed local-machine lifecycle boundary. Mutating phases are
// idempotent; status remains observational. If a command may have taken effect
// without a known result, it returns ErrEffectOutcomeUnknown and observes
// ownership on replay.
type Effects interface {
	ApplyInstallPhase(context.Context, InstallPlan, lifecycle.Phase) error
	RollbackInstall(context.Context, InstallPlan) error
	ApplyUpgradePhase(context.Context, UpgradePlan, lifecycle.Phase) error
	RollbackUpgrade(context.Context, UpgradePlan) error
	ApplyRollbackPhase(context.Context, RollbackPlan, lifecycle.Phase) error
	InspectBackup(context.Context, InstalledPlan, string) (RecoverySource, error)
	ApplyRecoveryPhase(context.Context, RecoveryPlan, lifecycle.Phase) error
	PrepareCredentialRecovery(context.Context, InstalledPlan, string, *lifecycle.Execution) (CredentialRecoveryPlan, error)
	ApplyCredentialRecoveryPhase(context.Context, CredentialRecoveryPlan, lifecycle.Phase) error
	NodeConnectionsDigest(context.Context, InstalledPlan) (string, error)
	PrepareNodeConnections(context.Context, InstalledPlan, string, string, *lifecycle.Execution) (NodeConnectionsPlan, error)
	ApplyNodeConnectionsPhase(context.Context, NodeConnectionsPlan, lifecycle.Phase) error
	VerifyInstallation(context.Context, InstalledPlan) error
	ObserveInstallation(context.Context, InstalledPlan) (bool, error)
	CreateBackup(context.Context, BackupPlan) error
	WriteSupportEvidence(context.Context, SupportPlan) error
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
	switch request.Action {
	case lifecycle.ActionInstall:
		return backend.install(ctx, request)
	case lifecycle.ActionUpgrade:
		return backend.upgrade(ctx, request)
	case lifecycle.ActionRollback:
		return backend.rollback(ctx, request)
	case lifecycle.ActionRecover:
		return backend.recover(ctx, request)
	case lifecycle.ActionRecoverCredentials:
		return backend.recoverCredentials(ctx, request)
	case lifecycle.ActionConfigureNodes:
		return backend.configureNodes(ctx, request)
	case lifecycle.ActionStatus:
		return backend.status(ctx, request)
	case lifecycle.ActionVerify, lifecycle.ActionBackup, lifecycle.ActionSupport:
		return backend.operation(ctx, request)
	default:
		return cli.Result{}, fault(cli.FaultPrecondition, "LIFECYCLE_ACTION_NOT_READY")
	}
}

func (backend *Backend) status(
	ctx context.Context,
	request cli.Request,
) (result cli.Result, returnErr error) {
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.Result{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := readPlatformJournal(session)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	result = statusResult(state)
	if state.Active != nil {
		return result, nil
	}
	if state.CurrentReleaseID == "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	}
	if state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention {
		return result, nil
	}
	ready, err := backend.effects.ObserveInstallation(ctx, installedPlan(session.Root(), state))
	if err != nil {
		if ctx.Err() != nil {
			return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		return cli.Result{}, effectFault(lifecycle.PhaseVerifying, err)
	}
	if ready {
		result.State = "READY"
	} else {
		result.State = "NOT_READY"
	}
	result.ConfigurationDigest, err = backend.effects.NodeConnectionsDigest(ctx, installedPlan(session.Root(), state))
	if err != nil {
		return cli.Result{}, effectFault(lifecycle.PhaseVerifying, err)
	}
	return result, nil
}

func (backend *Backend) operation(
	ctx context.Context,
	request cli.Request,
) (result cli.Result, returnErr error) {
	supportOutput := ""
	supportDigest := ""
	if request.Action == lifecycle.ActionSupport {
		var err error
		supportOutput, supportDigest, err = supportOutputBinding(
			request.Root, request.SupportOutput,
		)
		if err != nil {
			return cli.Result{}, fault(cli.FaultInvalidArgument, "SUPPORT_OUTPUT_INVALID")
		}
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.Result{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := readPlatformJournal(session)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.Active != nil && state.Active.Command.Action != request.Action {
		return cli.Result{}, lifecycleFault(lifecycle.ErrCommandInProgress)
	}
	command, err := backend.operationCommand(state, request.Action, supportDigest)
	if err != nil {
		return cli.Result{}, err
	}
	started, err := lifecycle.Start(state, command)
	if err != nil {
		return cli.Result{}, lifecycleFault(err)
	}
	if started.Replay == lifecycle.ReplayCompleted {
		return operationResult(started.Journal, started.Execution, false)
	}
	if started.Replay == lifecycle.ReplayNone {
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, stateWriteFault(err)
		}
	}
	installed := installedPlan(session.Root(), started.Journal)
	installed.CorrelationID = command.ID
	var effectErr error
	switch request.Action {
	case lifecycle.ActionVerify:
		effectErr = backend.effects.VerifyInstallation(ctx, installed)
	case lifecycle.ActionBackup:
		effectErr = backend.effects.CreateBackup(ctx, BackupPlan{
			InstalledPlan: installed, BackupID: command.BackupID,
			CreatedAt: started.Execution.StartedAt,
		})
	case lifecycle.ActionSupport:
		effectErr = backend.effects.WriteSupportEvidence(ctx, SupportPlan{
			InstalledPlan: installed, Output: supportOutput,
			CorrelationID: command.ID, GeneratedAt: started.Execution.StartedAt,
		})
	}
	if effectErr != nil {
		if ctx.Err() != nil {
			return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		if errors.Is(effectErr, ErrEffectOutcomeUnknown) {
			return cli.Result{}, fault(cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
		}
		normalized := effectFault(started.Execution.Phase, effectErr)
		failed, failErr := lifecycle.Fail(
			started.Journal, command.ID, normalized.Code,
			nextJournalTime(backend.now(), started.Execution.UpdatedAt),
		)
		if failErr != nil || session.Write(failed) != nil {
			return cli.Result{}, fault(cli.FaultInternal, "FAILURE_STATE_COMMIT_FAILED")
		}
		return cli.Result{}, normalized
	}
	ready, err := lifecycle.Advance(
		started.Journal, command.ID, lifecycle.PhaseReady,
		nextJournalTime(backend.now(), started.Execution.UpdatedAt),
	)
	if err != nil || session.Write(ready) != nil {
		return cli.Result{}, fault(cli.FaultInternal, "OPERATION_STATE_COMMIT_FAILED")
	}
	return operationResult(ready, *ready.Last, true)
}

func (backend *Backend) operationCommand(
	state lifecycle.Journal,
	action lifecycle.Action,
	supportDigest string,
) (lifecycle.Command, error) {
	if state.Active != nil {
		command := state.Active.Command
		if action == lifecycle.ActionSupport {
			command.InputDigest = supportDigest
		}
		return command, nil
	}
	commandID, err := randomIdentity(backend.entropy, "cmd")
	if err != nil {
		return lifecycle.Command{}, fault(cli.FaultInternal, "COMMAND_ID_GENERATION_FAILED")
	}
	command := lifecycle.Command{
		ID: commandID, Action: action, RequestedAt: canonicalNow(backend.now()),
	}
	switch action {
	case lifecycle.ActionBackup:
		command.BackupID, err = randomIdentity(backend.entropy, "backup")
		if err != nil {
			return lifecycle.Command{}, fault(cli.FaultInternal, "BACKUP_ID_GENERATION_FAILED")
		}
	case lifecycle.ActionSupport:
		command.InputDigest = supportDigest
	}
	return command, nil
}

func operationResult(
	state lifecycle.Journal,
	execution lifecycle.Execution,
	changed bool,
) (cli.Result, error) {
	if execution.Outcome != lifecycle.OutcomeSucceeded {
		return cli.Result{}, storedFailure(&execution)
	}
	result := cli.Result{
		State: "READY", ReleaseID: state.CurrentReleaseID,
		PreviousID: state.PreviousRelease, CorrelationID: execution.Command.ID,
		Changed: changed && execution.Command.Action != lifecycle.ActionVerify,
	}
	if execution.Command.Action == lifecycle.ActionBackup {
		result.BackupID = execution.Command.BackupID
	}
	return result, nil
}

func supportOutputBinding(root, output string) (string, string, error) {
	if root == "" || output == "" || len(output) > 4096 ||
		!filepath.IsAbs(output) || filepath.Clean(output) != output {
		return "", "", errors.New("support output path is invalid")
	}
	supportRoot := filepath.Join(root, filepath.FromSlash(layout.SupportDirectory))
	name := filepath.Base(output)
	if filepath.Dir(output) != supportRoot || name == "." || name == ".." ||
		len(name) > 128 || strings.HasPrefix(name, ".") ||
		!strings.EqualFold(filepath.Ext(name), ".json") {
		return "", "", errors.New("support output is outside its owned directory")
	}
	digest := sha256.Sum256([]byte(output))
	return output, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func installedPlan(root string, state lifecycle.Journal) InstalledPlan {
	return InstalledPlan{
		Root: root, InstallationID: state.InstallationID,
		Listener: defaultListener, Port: defaultPort,
		ReleaseID: state.CurrentReleaseID, ReleaseDigest: state.CurrentReleaseDigest,
		PreviousID: state.PreviousRelease, PreviousDigest: state.PreviousReleaseDigest,
		TrustKeyID:       state.ReleaseTrust.KeyID,
		TrustFingerprint: state.ReleaseTrust.Fingerprint,
	}
}

func previousInstalledPlan(root string, state lifecycle.Journal) InstalledPlan {
	return InstalledPlan{
		Root: root, InstallationID: state.InstallationID,
		Listener: defaultListener, Port: defaultPort,
		ReleaseID: state.PreviousRelease, ReleaseDigest: state.PreviousReleaseDigest,
		TrustKeyID:       state.ReleaseTrust.KeyID,
		TrustFingerprint: state.ReleaseTrust.Fingerprint,
	}
}

func statusResult(state lifecycle.Journal) cli.Result {
	result := cli.Result{
		ReleaseID: state.CurrentReleaseID, PreviousID: state.PreviousRelease,
	}
	switch {
	case state.Active != nil:
		result.State = string(state.Active.Phase)
		result.CorrelationID = state.Active.Command.ID
	case state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention:
		result.State = string(lifecycle.PhaseManualIntervention)
		result.CorrelationID = state.Last.Command.ID
	case state.Last != nil:
		result.State = string(state.Last.Phase)
		result.CorrelationID = state.Last.Command.ID
	default:
		result.State = "NOT_READY"
	}
	return result
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
	if verified.Manifest.Kind != release.ManifestKind {
		return cli.Result{}, fault(cli.FaultVerification, "RELEASE_PROFILE_UNSUPPORTED")
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
		state, err = readPlatformJournal(session)
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
		CorrelationID: commandID,
		Listener:      defaultListener, Port: defaultPort, Bundle: verified,
		Trust: trust, TrustBytes: append([]byte(nil), trustBytes...),
	}
	defer clear(plan.TrustBytes)
	if started.Replay == lifecycle.ReplayCompleted {
		return completedResult(started.Journal, started.Execution, false)
	}
	return backend.driveReleaseChange(
		ctx, session, lifecycle.ActionInstall,
		func(ctx context.Context, phase lifecycle.Phase) error {
			return backend.effects.ApplyInstallPhase(ctx, plan, phase)
		},
		func(ctx context.Context) error {
			return backend.effects.RollbackInstall(ctx, plan)
		},
	)
}

func (backend *Backend) upgrade(
	ctx context.Context,
	request cli.Request,
) (result cli.Result, returnErr error) {
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.Result{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := readPlatformJournal(session)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.Active != nil && state.Active.Command.Action != lifecycle.ActionUpgrade {
		return cli.Result{}, lifecycleFault(lifecycle.ErrCommandInProgress)
	}
	if state.CurrentReleaseID == "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	}

	trustPath := filepath.Join(session.Root(), filepath.FromSlash(layout.ReleaseTrust))
	trustBytes, trust, err := release.ReadTrustRootFile(trustPath)
	if err != nil || trust.KeyID != state.ReleaseTrust.KeyID ||
		trust.PublicKeyFingerprint != state.ReleaseTrust.Fingerprint {
		clear(trustBytes)
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	defer clear(trustBytes)
	sourceBundle, err := authenticateJournalRelease(
		session.Root(), state.CurrentReleaseID, state.CurrentReleaseDigest, trustBytes,
	)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	targetBundle, err := release.VerifyDirectory(request.Bundle, trustBytes)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "RELEASE_BUNDLE_INVALID")
	}
	if targetBundle.Manifest.Kind != release.ManifestKind {
		return cli.Result{}, fault(cli.FaultVerification, "RELEASE_PROFILE_UNSUPPORTED")
	}
	if targetBundle.Manifest.TopologyDigest != topology.ContractDigest() {
		return cli.Result{}, fault(cli.FaultVerification, "TOPOLOGY_CONTRACT_UNSUPPORTED")
	}
	if state.Active == nil && targetBundle.Manifest.Release.ID == state.CurrentReleaseID {
		if targetBundle.ManifestSHA256 != state.CurrentReleaseDigest {
			return cli.Result{}, fault(cli.FaultConflict, "RELEASE_CONTENT_CONFLICT")
		}
		correlationID := ""
		backupID := ""
		if state.Last != nil {
			correlationID = state.Last.Command.ID
			if state.Last.Command.Action == lifecycle.ActionUpgrade {
				backupID = state.Last.Command.BackupID
			}
		}
		return cli.Result{
			State: "READY", ReleaseID: state.CurrentReleaseID,
			PreviousID: state.PreviousRelease, BackupID: backupID,
			Changed: false, CorrelationID: correlationID,
		}, nil
	}
	if targetBundle.Manifest.Release.PreviousID != state.CurrentReleaseID ||
		targetBundle.Manifest.Release.PreviousVersion != sourceBundle.Manifest.Release.Version {
		return cli.Result{}, fault(cli.FaultPrecondition, "UPGRADE_PREDECESSOR_MISMATCH")
	}
	if release.ValidateDatabaseUpgradePath(
		sourceBundle.Manifest.Database, targetBundle.Manifest.Database,
	) != nil {
		return cli.Result{}, fault(cli.FaultPrecondition, "UPGRADE_SCHEMA_INCOMPATIBLE")
	}

	commandID := ""
	backupID := ""
	if state.Active != nil {
		commandID = state.Active.Command.ID
		backupID = state.Active.Command.BackupID
	} else {
		commandID, err = randomIdentity(backend.entropy, "cmd")
		if err != nil {
			return cli.Result{}, fault(cli.FaultInternal, "COMMAND_ID_GENERATION_FAILED")
		}
		backupID, err = randomIdentity(backend.entropy, "backup")
		if err != nil {
			return cli.Result{}, fault(cli.FaultInternal, "BACKUP_ID_GENERATION_FAILED")
		}
	}
	started, err := lifecycle.Start(state, lifecycle.Command{
		ID: commandID, Action: lifecycle.ActionUpgrade,
		InputDigest:     targetBundle.ManifestSHA256,
		TargetReleaseID: targetBundle.Manifest.Release.ID,
		BackupID:        backupID,
		RequestedAt:     canonicalNow(backend.now()),
	})
	if err != nil {
		return cli.Result{}, lifecycleFault(err)
	}
	if started.Replay == lifecycle.ReplayCompleted {
		return completedResult(started.Journal, started.Execution, false)
	}
	if started.Replay == lifecycle.ReplayNone {
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, stateWriteFault(err)
		}
	}
	sourcePlan := installedPlan(session.Root(), started.Journal)
	sourcePlan.CorrelationID = commandID
	targetPlan := InstallPlan{
		Root: session.Root(), InstallationID: started.Journal.InstallationID,
		CorrelationID: commandID,
		Listener:      defaultListener, Port: defaultPort,
		PreviousID: sourcePlan.ReleaseID, PreviousDigest: sourcePlan.ReleaseDigest,
		Bundle: targetBundle,
		Trust:  trust, TrustBytes: append([]byte(nil), trustBytes...),
	}
	defer clear(targetPlan.TrustBytes)
	plan := UpgradePlan{
		Source: sourcePlan, Target: targetPlan,
		BackupID: backupID, CreatedAt: started.Execution.StartedAt,
	}
	return backend.driveReleaseChange(
		ctx, session, lifecycle.ActionUpgrade,
		func(ctx context.Context, phase lifecycle.Phase) error {
			return backend.effects.ApplyUpgradePhase(ctx, plan, phase)
		},
		func(ctx context.Context) error {
			return backend.effects.RollbackUpgrade(ctx, plan)
		},
	)
}

func (backend *Backend) rollback(
	ctx context.Context,
	request cli.Request,
) (result cli.Result, returnErr error) {
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.Result{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := readPlatformJournal(session)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.Active != nil && state.Active.Command.Action != lifecycle.ActionRollback {
		return cli.Result{}, lifecycleFault(lifecycle.ErrCommandInProgress)
	}
	if state.CurrentReleaseID == "" || state.PreviousRelease == "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "ROLLBACK_PREDECESSOR_UNAVAILABLE")
	}

	trustPath := filepath.Join(session.Root(), filepath.FromSlash(layout.ReleaseTrust))
	trustBytes, trust, err := release.ReadTrustRootFile(trustPath)
	if err != nil || trust.KeyID != state.ReleaseTrust.KeyID ||
		trust.PublicKeyFingerprint != state.ReleaseTrust.Fingerprint {
		clear(trustBytes)
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	defer clear(trustBytes)
	currentBundle, err := authenticateJournalRelease(
		session.Root(), state.CurrentReleaseID, state.CurrentReleaseDigest, trustBytes,
	)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	previousBundle, err := authenticateJournalRelease(
		session.Root(), state.PreviousRelease, state.PreviousReleaseDigest, trustBytes,
	)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	if currentBundle.Manifest.Release.PreviousID != previousBundle.Manifest.Release.ID ||
		currentBundle.Manifest.Release.PreviousVersion != previousBundle.Manifest.Release.Version {
		return cli.Result{}, fault(cli.FaultPrecondition, "ROLLBACK_PREDECESSOR_MISMATCH")
	}
	if release.ValidateDatabaseUpgradePath(
		previousBundle.Manifest.Database, currentBundle.Manifest.Database,
	) != nil {
		return cli.Result{}, fault(cli.FaultPrecondition, "ROLLBACK_SCHEMA_INCOMPATIBLE")
	}
	if previousBundle.Manifest.Database != currentBundle.Manifest.Database {
		return cli.Result{}, fault(cli.FaultPrecondition, "ROLLBACK_REQUIRES_AUTHENTICATED_RECOVERY")
	}

	if state.Active == nil {
		ready, observeErr := backend.effects.ObserveInstallation(
			ctx, installedPlan(session.Root(), state),
		)
		if observeErr != nil {
			if ctx.Err() != nil {
				return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
			}
			return cli.Result{}, effectFault(lifecycle.PhaseVerifying, observeErr)
		}
		if !ready {
			return cli.Result{}, fault(cli.FaultPrecondition, "ROLLBACK_SOURCE_NOT_READY")
		}
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
	started, err := lifecycle.Start(state, lifecycle.Command{
		ID: commandID, Action: lifecycle.ActionRollback,
		RequestedAt: canonicalNow(backend.now()),
	})
	if err != nil {
		return cli.Result{}, lifecycleFault(err)
	}
	if started.Replay == lifecycle.ReplayCompleted {
		return completedResult(started.Journal, started.Execution, false)
	}
	if started.Replay == lifecycle.ReplayNone {
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, stateWriteFault(err)
		}
	}
	currentPlan := InstallPlan{
		Root: session.Root(), InstallationID: started.Journal.InstallationID,
		CorrelationID: commandID,
		Listener:      defaultListener, Port: defaultPort,
		PreviousID: started.Journal.PreviousRelease, PreviousDigest: started.Journal.PreviousReleaseDigest,
		Bundle: currentBundle,
		Trust:  trust, TrustBytes: append([]byte(nil), trustBytes...),
	}
	defer clear(currentPlan.TrustBytes)
	previousPlan := previousInstalledPlan(session.Root(), started.Journal)
	previousPlan.CorrelationID = commandID
	plan := RollbackPlan{
		Current: currentPlan, Previous: previousPlan,
	}
	return backend.driveReleaseChange(
		ctx, session, lifecycle.ActionRollback,
		func(ctx context.Context, phase lifecycle.Phase) error {
			return backend.effects.ApplyRollbackPhase(ctx, plan, phase)
		},
		nil,
	)
}

func (backend *Backend) recover(
	ctx context.Context,
	request cli.Request,
) (result cli.Result, returnErr error) {
	if lifecycle.ValidateBackupID(request.BackupID) != nil {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "BACKUP_ID_INVALID")
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.Result{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := readPlatformJournal(session)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.Active != nil && state.Active.Command.Action != lifecycle.ActionRecover {
		return cli.Result{}, lifecycleFault(lifecycle.ErrCommandInProgress)
	}
	if state.CurrentReleaseID == "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	}

	trustPath := filepath.Join(session.Root(), filepath.FromSlash(layout.ReleaseTrust))
	trustBytes, trust, err := release.ReadTrustRootFile(trustPath)
	if err != nil || trust.KeyID != state.ReleaseTrust.KeyID ||
		trust.PublicKeyFingerprint != state.ReleaseTrust.Fingerprint {
		clear(trustBytes)
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	defer clear(trustBytes)
	currentBundle, err := authenticateJournalRelease(
		session.Root(), state.CurrentReleaseID, state.CurrentReleaseDigest, trustBytes,
	)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	source, err := backend.effects.InspectBackup(
		ctx, installedPlan(session.Root(), state), request.BackupID,
	)
	if err != nil {
		if ctx.Err() != nil {
			return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		return cli.Result{}, effectFault(lifecycle.PhaseRecovering, err)
	}
	if source.InstallationID != state.InstallationID || source.BackupID != request.BackupID ||
		source.ReleaseID == "" || source.ReleaseDigest == "" || source.BackupDigest == "" ||
		release.ValidateDatabaseProfile(source.Database) != nil {
		return cli.Result{}, fault(cli.FaultVerification, "RECOVERY_SOURCE_INVALID")
	}
	targetBundle, err := authenticateJournalRelease(
		session.Root(), source.ReleaseID, source.ReleaseDigest, trustBytes,
	)
	if err != nil || targetBundle.Manifest.Database != source.Database {
		return cli.Result{}, fault(cli.FaultVerification, "RECOVERY_RELEASE_INVALID")
	}
	if currentBundle.Manifest.Database != targetBundle.Manifest.Database {
		return cli.Result{}, fault(cli.FaultPrecondition, "RECOVERY_SCHEMA_INCOMPATIBLE")
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
	started, err := lifecycle.Start(state, lifecycle.Command{
		ID: commandID, Action: lifecycle.ActionRecover,
		InputDigest: source.ReleaseDigest, BackupDigest: source.BackupDigest,
		TargetReleaseID: source.ReleaseID, BackupID: source.BackupID,
		RequestedAt: canonicalNow(backend.now()),
	})
	if err != nil {
		return cli.Result{}, lifecycleFault(err)
	}
	if started.Replay == lifecycle.ReplayCompleted {
		return completedResult(started.Journal, started.Execution, false)
	}
	if started.Replay == lifecycle.ReplayNone {
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, stateWriteFault(err)
		}
	}
	currentPlan := InstallPlan{
		Root: session.Root(), InstallationID: started.Journal.InstallationID,
		CorrelationID: commandID,
		Listener:      defaultListener, Port: defaultPort,
		PreviousID: started.Journal.PreviousRelease, PreviousDigest: started.Journal.PreviousReleaseDigest,
		Bundle: currentBundle,
		Trust:  trust, TrustBytes: append([]byte(nil), trustBytes...),
	}
	defer clear(currentPlan.TrustBytes)
	targetPreviousID, targetPreviousDigest := "", ""
	if targetBundle.Manifest.Release.ID == currentBundle.Manifest.Release.ID {
		targetPreviousID = started.Journal.PreviousRelease
		targetPreviousDigest = started.Journal.PreviousReleaseDigest
	}
	targetPlan := InstallPlan{
		Root: session.Root(), InstallationID: started.Journal.InstallationID,
		CorrelationID: commandID,
		Listener:      defaultListener, Port: defaultPort,
		PreviousID: targetPreviousID, PreviousDigest: targetPreviousDigest,
		Bundle: targetBundle,
		Trust:  trust, TrustBytes: append([]byte(nil), trustBytes...),
	}
	defer clear(targetPlan.TrustBytes)
	plan := RecoveryPlan{
		Current: currentPlan, Target: targetPlan,
		BackupID: source.BackupID, BackupDigest: source.BackupDigest,
	}
	return backend.driveReleaseChange(
		ctx, session, lifecycle.ActionRecover,
		func(ctx context.Context, phase lifecycle.Phase) error {
			return backend.effects.ApplyRecoveryPhase(ctx, plan, phase)
		},
		nil,
	)
}

func (backend *Backend) recoverCredentials(ctx context.Context, request cli.Request) (result cli.Result, returnErr error) {
	if (request.RecoveryInput == "") == !request.Resume || strings.TrimSpace(request.RecoveryInput) != request.RecoveryInput {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "CREDENTIAL_RECOVERY_INPUT_INVALID")
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result, returnErr = cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := readPlatformJournal(session)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.Active != nil && state.Active.Command.Action != lifecycle.ActionRecoverCredentials {
		return cli.Result{}, lifecycleFault(lifecycle.ErrCommandInProgress)
	}
	if state.CurrentReleaseID == "" {
		return cli.Result{}, fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	}
	trustBytes, trust, err := release.ReadTrustRootFile(filepath.Join(session.Root(), filepath.FromSlash(layout.ReleaseTrust)))
	if err != nil || trust.KeyID != state.ReleaseTrust.KeyID || trust.PublicKeyFingerprint != state.ReleaseTrust.Fingerprint {
		clear(trustBytes)
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	defer clear(trustBytes)
	bundle, err := authenticateJournalRelease(session.Root(), state.CurrentReleaseID, state.CurrentReleaseDigest, trustBytes)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	if ValidateCredentialRecoveryProfile(bundle.Manifest.Database) != nil {
		return cli.Result{}, fault(cli.FaultPrecondition, "CREDENTIAL_RECOVERY_PROFILE_UNSUPPORTED")
	}
	previous := state.Active
	if previous == nil && state.Last != nil && state.Last.Command.Action == lifecycle.ActionRecoverCredentials {
		previous = state.Last
	}
	if request.Resume && previous == nil {
		return cli.Result{}, fault(cli.FaultPrecondition, "CREDENTIAL_RECOVERY_NOT_PENDING")
	}
	installed := installedPlan(session.Root(), state)
	plan, err := backend.effects.PrepareCredentialRecovery(ctx, installed, request.RecoveryInput, previous)
	if err != nil {
		return cli.Result{}, credentialRecoveryFault(ctx, lifecycle.PhaseStaging, err)
	}
	if plan.InstalledPlan != installed || lifecycle.ValidateCommandID(plan.CommandID) != nil ||
		iamv1.ValidateDigest("inputCommitment", plan.InputCommitment) != nil {
		return cli.Result{}, fault(cli.FaultVerification, "CREDENTIAL_RECOVERY_PLAN_INVALID")
	}
	started, err := lifecycle.Start(state, lifecycle.Command{
		ID: plan.CommandID, Action: lifecycle.ActionRecoverCredentials,
		InputDigest: plan.InputCommitment, RequestedAt: canonicalNow(backend.now()),
	})
	if err != nil {
		return cli.Result{}, lifecycleFault(err)
	}
	if started.Replay == lifecycle.ReplayCompleted {
		return operationResult(started.Journal, started.Execution, false)
	}
	if started.Replay == lifecycle.ReplayNone {
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, stateWriteFault(err)
		}
	}
	plan.CorrelationID = plan.CommandID
	return backend.driveCredentialRecovery(ctx, session, plan)
}

func (backend *Backend) driveCredentialRecovery(ctx context.Context, session *journal.Session, plan CredentialRecoveryPlan) (cli.Result, error) {
	for {
		state, err := readPlatformJournal(session)
		if err != nil || state.Active == nil || state.Active.Command.Action != lifecycle.ActionRecoverCredentials ||
			state.Active.Command.ID != plan.CommandID || state.Active.Command.InputDigest != plan.InputCommitment {
			return cli.Result{}, fault(cli.FaultVerification, "CREDENTIAL_RECOVERY_STATE_INVALID")
		}
		execution := *state.Active
		err = backend.effects.ApplyCredentialRecoveryPhase(ctx, plan, execution.Phase)
		if err != nil {
			normalized := credentialRecoveryFault(ctx, execution.Phase, err)
			// A committed outcome is one-way. Cleanup failure retains COMMITTING;
			// unknown/database/provider failures retain the exact pending intent.
			definitive := errors.Is(err, ErrCredentialRecoveryInvalid) || errors.Is(err, ErrCredentialRecoveryForbidden) || errors.Is(err, ErrCredentialRecoveryConflict)
			if ctx.Err() != nil || execution.Phase == lifecycle.PhaseCommitting || !definitive {
				return cli.Result{}, normalized
			}
			failed, failErr := lifecycle.Fail(state, plan.CommandID, normalized.Code, nextJournalTime(backend.now(), execution.UpdatedAt))
			if failErr != nil || session.Write(failed) != nil {
				return cli.Result{}, fault(cli.FaultInternal, "CREDENTIAL_RECOVERY_STATE_COMMIT_FAILED")
			}
			continue
		}
		next, ok := lifecycle.NextPhase(state)
		if !ok {
			return cli.Result{}, fault(cli.FaultInternal, "CREDENTIAL_RECOVERY_PHASE_INVALID")
		}
		advanced, err := lifecycle.Advance(state, plan.CommandID, next, nextJournalTime(backend.now(), execution.UpdatedAt))
		if err != nil || session.Write(advanced) != nil {
			return cli.Result{}, fault(cli.FaultInternal, "CREDENTIAL_RECOVERY_STATE_COMMIT_FAILED")
		}
		if advanced.Active == nil {
			return operationResult(advanced, *advanced.Last, true)
		}
	}
}

func credentialRecoveryFault(ctx context.Context, phase lifecycle.Phase, err error) *cli.Fault {
	switch {
	case ctx.Err() != nil:
		return fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	case errors.Is(err, ErrCredentialRecoveryInvalid):
		return fault(cli.FaultInvalidArgument, "CREDENTIAL_RECOVERY_INVALID")
	case errors.Is(err, ErrCredentialRecoveryForbidden):
		return fault(cli.FaultPrecondition, "CREDENTIAL_RECOVERY_FORBIDDEN")
	case errors.Is(err, ErrCredentialRecoveryConflict):
		return fault(cli.FaultConflict, "CREDENTIAL_RECOVERY_CONFLICT")
	case errors.Is(err, ErrEffectOutcomeUnknown):
		return fault(cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
	default:
		return effectFault(phase, err)
	}
}

func readPlatformJournal(session *journal.Session) (lifecycle.Journal, error) {
	state, err := session.Read()
	if err != nil || state.Node != nil {
		return lifecycle.Journal{}, errors.New("installation root is not a sealed platform")
	}
	return state, nil
}

func authenticateJournalRelease(
	root string,
	releaseID string,
	digest string,
	trustBytes []byte,
) (release.VerifiedBundle, error) {
	releaseRoot := filepath.Join(
		root, filepath.FromSlash(layout.ReleaseDirectory(releaseID)),
	)
	bundle, err := release.VerifyDirectory(releaseRoot, trustBytes)
	if err != nil || bundle.Manifest.Kind != release.ManifestKind || bundle.Manifest.Release.ID != releaseID ||
		bundle.ManifestSHA256 != digest ||
		topology.ValidateInstalledContract(bundle.Manifest) != nil {
		return release.VerifiedBundle{}, errors.New("committed release authentication failed")
	}
	return bundle, nil
}

func (backend *Backend) driveReleaseChange(
	ctx context.Context,
	session *journal.Session,
	action lifecycle.Action,
	apply func(context.Context, lifecycle.Phase) error,
	rollback func(context.Context) error,
) (cli.Result, error) {
	if (action != lifecycle.ActionInstall && action != lifecycle.ActionUpgrade &&
		action != lifecycle.ActionRollback && action != lifecycle.ActionRecover) || apply == nil ||
		(action != lifecycle.ActionRollback && action != lifecycle.ActionRecover && rollback == nil) {
		return cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_DRIVER_INVALID")
	}
	for {
		state, err := readPlatformJournal(session)
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
		if execution.Command.Action != action {
			return cli.Result{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
		}

		if execution.Phase == lifecycle.PhaseRollingBack && execution.FailureCode != "" {
			if err := rollback(ctx); err != nil {
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
			effectErr = apply(ctx, execution.Phase)
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

		next, ok := lifecycle.NextPhase(state)
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
	if errors.Is(effectErr, ErrEffectUnavailable) {
		return fault(cli.FaultUnavailable, "ROLLBACK_DEPENDENCY_UNAVAILABLE")
	}
	if errors.Is(effectErr, ErrEffectRecoveryRequired) {
		manual, err := lifecycle.Fail(
			state, execution.Command.ID, "AUTHENTICATED_RECOVERY_REQUIRED",
			nextJournalTime(backend.now(), execution.UpdatedAt),
		)
		if err != nil || session.Write(manual) != nil {
			return fault(cli.FaultInternal, "ROLLBACK_FAILURE_COMMIT_FAILED")
		}
		return fault(cli.FaultPrecondition, "AUTHENTICATED_RECOVERY_REQUIRED")
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

func completedResult(
	state lifecycle.Journal,
	execution lifecycle.Execution,
	changed bool,
) (cli.Result, error) {
	if execution.Outcome != lifecycle.OutcomeSucceeded {
		return cli.Result{}, storedFailure(&execution)
	}
	result := cli.Result{
		State: "READY", ReleaseID: state.CurrentReleaseID,
		PreviousID: state.PreviousRelease, Changed: changed,
		CorrelationID: execution.Command.ID,
	}
	if execution.Command.BackupID != "" {
		result.BackupID = execution.Command.BackupID
	}
	return result, nil
}

func storedFailure(execution *lifecycle.Execution) error {
	if execution == nil || execution.FailureCode == "" {
		return fault(cli.FaultInternal, "INSTALLATION_RESULT_INVALID")
	}
	class := cli.FaultInternal
	switch {
	case execution.FailureCode == "CREDENTIAL_RECOVERY_INVALID":
		class = cli.FaultInvalidArgument
	case execution.FailureCode == "CREDENTIAL_RECOVERY_FORBIDDEN":
		class = cli.FaultPrecondition
	case execution.FailureCode == "CREDENTIAL_RECOVERY_CONFLICT":
		class = cli.FaultConflict
	case execution.FailureCode == "PREFLIGHT_FAILED":
		class = cli.FaultPrecondition
	case execution.FailureCode == "AUTHENTICATED_RECOVERY_REQUIRED":
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
	case lifecycle.PhaseBackingUp:
		return "BACKUP_" + suffix
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
	case lifecycle.PhaseRecovering:
		return "RECOVERY_" + suffix
	case lifecycle.PhaseRecoveringCredentials:
		return "CREDENTIAL_RECOVERY_" + suffix
	default:
		return "INSTALLATION_" + suffix
	}
}

func lifecycleFault(err error) error {
	switch {
	case errors.Is(err, lifecycle.ErrManualIntervention):
		return fault(cli.FaultPrecondition, "PLATFORM_MANUAL_INTERVENTION_REQUIRED")
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
	case errors.Is(err, journal.ErrNotInitialized):
		return fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
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
