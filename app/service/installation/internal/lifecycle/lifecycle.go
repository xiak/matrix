// Package lifecycle owns the compact, provider-neutral installation journal
// state machine. Provider effects and persistence stay outside this package.
package lifecycle

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const APIVersion = "installation.matrix.xiak.com/v1"

var (
	ErrCommandConflict   = errors.New("installation command identity conflicts with stored input")
	ErrCommandInProgress = errors.New("another installation command is in progress")
	ErrInvalidTransition = errors.New("installation phase transition is invalid")
	ErrPrecondition      = errors.New("installation lifecycle precondition failed")
)

type Action string

const (
	ActionInstall            Action = "INSTALL"
	ActionVerify             Action = "VERIFY"
	ActionStatus             Action = "STATUS"
	ActionBackup             Action = "BACKUP"
	ActionUpgrade            Action = "UPGRADE"
	ActionRollback           Action = "ROLLBACK"
	ActionRecover            Action = "RECOVER"
	ActionSupport            Action = "SUPPORT"
	ActionStart              Action = "START"
	ActionRotateCredentials  Action = "ROTATE_CREDENTIALS"
	ActionRecoverCredentials Action = "RECOVER_CREDENTIALS"
	ActionConfigureNodes     Action = "CONFIGURE_NODES"
)

type Phase string

const (
	PhasePreflight             Phase = "PREFLIGHT"
	PhaseBackingUp             Phase = "BACKING_UP"
	PhaseStaging               Phase = "STAGING"
	PhaseLoadingImages         Phase = "LOADING_IMAGES"
	PhaseConfiguring           Phase = "CONFIGURING"
	PhaseMigrating             Phase = "MIGRATING"
	PhaseStarting              Phase = "STARTING"
	PhaseVerifying             Phase = "VERIFYING"
	PhaseCommitting            Phase = "COMMITTING"
	PhaseRollingBack           Phase = "ROLLING_BACK"
	PhaseRecovering            Phase = "RECOVERING"
	PhaseRecoveringCredentials Phase = "RECOVERING_CREDENTIALS"
	PhaseReady                 Phase = "READY"
	PhaseManualIntervention    Phase = "MANUAL_INTERVENTION"
)

type Outcome string

const (
	OutcomeSucceeded          Outcome = "SUCCEEDED"
	OutcomeFailed             Outcome = "FAILED"
	OutcomeRolledBack         Outcome = "ROLLED_BACK"
	OutcomeManualIntervention Outcome = "MANUAL_INTERVENTION"
)

type Replay string

const (
	ReplayNone      Replay = "NONE"
	ReplayActive    Replay = "ACTIVE"
	ReplayCompleted Replay = "COMPLETED"
)

type Command struct {
	ID                          string    `json:"id"`
	Action                      Action    `json:"action"`
	InputDigest                 string    `json:"inputDigest,omitempty"`
	BackupDigest                string    `json:"backupDigest,omitempty"`
	TargetReleaseID             string    `json:"targetReleaseId,omitempty"`
	BackupID                    string    `json:"backupId,omitempty"`
	ExpectedConfigurationDigest string    `json:"expectedConfigurationDigest,omitempty"`
	RevokePreviousCredentials   bool      `json:"revokePreviousCredentials,omitempty"`
	RequestedAt                 time.Time `json:"requestedAt"`
}

type Execution struct {
	Command           Command   `json:"command"`
	Phase             Phase     `json:"phase"`
	Outcome           Outcome   `json:"outcome,omitempty"`
	FailureCode       string    `json:"failureCode,omitempty"`
	StartedAt         time.Time `json:"startedAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
	CompletedAt       time.Time `json:"completedAt,omitempty"`
	SourceRelease     string    `json:"sourceRelease,omitempty"`
	SourceDigest      string    `json:"sourceDigest,omitempty"`
	Destination       string    `json:"destinationRelease,omitempty"`
	DestinationDigest string    `json:"destinationDigest,omitempty"`
}

type Journal struct {
	APIVersion             string       `json:"apiVersion"`
	Version                uint64       `json:"version"`
	InstallationID         string       `json:"installationId"`
	ReleaseTrust           ReleaseTrust `json:"releaseTrust"`
	Node                   *NodeBinding `json:"node,omitempty"`
	NodeCredentialRotation *Command     `json:"nodeCredentialRotation,omitempty"`
	CurrentReleaseID       string       `json:"currentReleaseId,omitempty"`
	CurrentReleaseDigest   string       `json:"currentReleaseDigest,omitempty"`
	PreviousRelease        string       `json:"previousReleaseId,omitempty"`
	PreviousReleaseDigest  string       `json:"previousReleaseDigest,omitempty"`
	Active                 *Execution   `json:"active,omitempty"`
	Last                   *Execution   `json:"last,omitempty"`
}

// NodeBinding seals the purpose of this installation root and the complete
// enrollment commitment. Platform journals omit it, preserving their bytes.
type NodeBinding struct {
	ExecutionTargetID   string `json:"executionTargetId"`
	ConfigurationDigest string `json:"configurationDigest"`
}

// ReleaseTrust pins the out-of-band public trust root for the complete
// installation lifetime. Upgrade cannot replace either identity.
type ReleaseTrust struct {
	KeyID       string `json:"keyId"`
	Fingerprint string `json:"fingerprint"`
}

type StartResult struct {
	Journal   Journal
	Execution Execution
	Replay    Replay
}

var (
	installationIDPattern   = regexp.MustCompile(`^mxi-[0-9a-f]{32}$`)
	commandIDPattern        = regexp.MustCompile(`^cmd-[0-9a-f]{32}$`)
	releaseIDPattern        = regexp.MustCompile(`^matrix-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?-[0-9a-f]{12}$`)
	backupIDPattern         = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)
	digestPattern           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	failureCodePattern      = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	trustKeyIDPattern       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._@+-]{0,126}[A-Za-z0-9])?$`)
	trustFingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func New(installationID string, trust ReleaseTrust) (Journal, error) {
	journal := Journal{
		APIVersion: APIVersion, Version: 1, InstallationID: installationID,
		ReleaseTrust: trust,
	}
	if err := ValidateJournal(journal); err != nil {
		return Journal{}, err
	}
	return journal, nil
}

func NewNode(installationID string, trust ReleaseTrust, binding NodeBinding) (Journal, error) {
	value, err := New(installationID, trust)
	if err != nil {
		return Journal{}, err
	}
	value.Node = &binding
	if err := ValidateJournal(value); err != nil {
		return Journal{}, err
	}
	return value, nil
}

func ValidateInstallationID(value string) error {
	if !installationIDPattern.MatchString(value) {
		return errors.New("installation identity is invalid")
	}
	return nil
}

func ValidateBackupID(value string) error {
	if !backupIDPattern.MatchString(value) {
		return errors.New("backup identity is invalid")
	}
	return nil
}

func ValidateCommandID(value string) error {
	if !commandIDPattern.MatchString(value) {
		return errors.New("installation command identity is invalid")
	}
	return nil
}

func Start(journal Journal, command Command) (StartResult, error) {
	if err := ValidateJournal(journal); err != nil {
		return StartResult{}, fmt.Errorf("stored installation journal is invalid: %w", err)
	}
	if err := validateCommand(command, journal.Node != nil); err != nil {
		return StartResult{}, err
	}
	if journal.Active != nil {
		if journal.Active.Command.ID != command.ID {
			return StartResult{}, ErrCommandInProgress
		}
		if !sameCommandInput(journal.Active.Command, command) {
			return StartResult{}, ErrCommandConflict
		}
		return StartResult{Journal: journal, Execution: *journal.Active, Replay: ReplayActive}, nil
	}
	if journal.Last != nil && journal.Last.Command.ID == command.ID {
		if !sameCommandInput(journal.Last.Command, command) {
			return StartResult{}, ErrCommandConflict
		}
		return StartResult{Journal: journal, Execution: *journal.Last, Replay: ReplayCompleted}, nil
	}
	if err := validateActionPrecondition(journal, command); err != nil {
		return StartResult{}, err
	}
	execution := Execution{
		Command:       command,
		Phase:         workflow(command.Action, journal.Node != nil)[0],
		StartedAt:     command.RequestedAt,
		UpdatedAt:     command.RequestedAt,
		SourceRelease: journal.CurrentReleaseID,
		SourceDigest:  journal.CurrentReleaseDigest,
		Destination:   command.TargetReleaseID,
	}
	if command.Action == ActionInstall || command.Action == ActionUpgrade ||
		command.Action == ActionRecover {
		execution.DestinationDigest = command.InputDigest
	}
	if command.Action == ActionRollback {
		execution.Destination = journal.PreviousRelease
		execution.DestinationDigest = journal.PreviousReleaseDigest
	}
	journal.Version++
	journal.Active = &execution
	return StartResult{Journal: journal, Execution: execution, Replay: ReplayNone}, nil
}

func Advance(journal Journal, commandID string, next Phase, at time.Time) (Journal, error) {
	if err := ValidateJournal(journal); err != nil {
		return Journal{}, fmt.Errorf("stored installation journal is invalid: %w", err)
	}
	if journal.Active == nil || journal.Active.Command.ID != commandID {
		return Journal{}, ErrCommandConflict
	}
	if !canonicalTime(at) || !at.After(journal.Active.UpdatedAt) {
		return Journal{}, ErrInvalidTransition
	}
	execution := *journal.Active
	if execution.FailureCode != "" && execution.Phase == PhaseRollingBack {
		if next != PhaseReady {
			return Journal{}, ErrInvalidTransition
		}
		execution.Phase = next
		execution.UpdatedAt = at
		execution.CompletedAt = at
		execution.Outcome = OutcomeRolledBack
		journal.Version++
		journal.Active = nil
		journal.Last = &execution
		return journal, nil
	}
	sequence := workflow(execution.Command.Action, journal.Node != nil)
	index := phaseIndex(sequence, execution.Phase)
	if index < 0 || index+1 >= len(sequence) || sequence[index+1] != next {
		return Journal{}, ErrInvalidTransition
	}
	execution.Phase = next
	execution.UpdatedAt = at
	if execution.Command.Action == ActionRotateCredentials || execution.Command.Action == ActionConfigureNodes {
		execution.FailureCode = ""
	}
	journal.Version++
	if next == PhaseReady {
		execution.Outcome = OutcomeSucceeded
		if execution.Command.Action == ActionRecoverCredentials && execution.FailureCode != "" {
			execution.Outcome = OutcomeFailed
		}
		execution.CompletedAt = at
		if execution.Outcome == OutcomeSucceeded {
			applySuccessfulPointerChange(&journal, execution)
		}
		journal.Active = nil
		journal.Last = &execution
		return journal, nil
	}
	journal.Active = &execution
	return journal, nil
}

// Fail records a normalized failure. Install and upgrade enter an explicit
// rollback intent before any cleanup effect. Read-only/backup failures finish
// without changing release pointers. A failed rollback or recovery requires
// an operator decision and is terminally recorded as manual intervention.
func Fail(journal Journal, commandID, failureCode string, at time.Time) (Journal, error) {
	if err := ValidateJournal(journal); err != nil {
		return Journal{}, fmt.Errorf("stored installation journal is invalid: %w", err)
	}
	if journal.Active == nil || journal.Active.Command.ID != commandID ||
		!failureCodePattern.MatchString(failureCode) || !canonicalTime(at) ||
		!at.After(journal.Active.UpdatedAt) {
		return Journal{}, ErrInvalidTransition
	}
	execution := *journal.Active
	execution.FailureCode = failureCode
	execution.UpdatedAt = at
	journal.Version++
	switch execution.Command.Action {
	case ActionRecoverCredentials:
		if execution.Phase != PhaseStaging && execution.Phase != PhaseRecoveringCredentials {
			return Journal{}, ErrInvalidTransition
		}
		// A definitive IAM rejection has no credential effect. Seal that
		// result before removing its private input; cleanup can then resume
		// without attempting the rejected recovery again.
		execution.Phase = PhaseCommitting
		journal.Active = &execution
		return journal, nil
	case ActionRotateCredentials, ActionConfigureNodes:
		// Credential retirement is one-way. A failed attempt keeps the exact
		// candidate intent for retry; it never restores the old trust set.
		journal.Active = &execution
		return journal, nil
	case ActionInstall, ActionUpgrade:
		if execution.Phase == PhaseCommitting || execution.Phase == PhaseRollingBack {
			return finishManual(journal, execution, at), nil
		}
		execution.Phase = PhaseRollingBack
		journal.Active = &execution
		return journal, nil
	case ActionRollback, ActionRecover:
		return finishManual(journal, execution, at), nil
	case ActionVerify, ActionStatus, ActionBackup, ActionSupport, ActionStart:
		execution.Outcome = OutcomeFailed
		execution.CompletedAt = at
		journal.Active = nil
		journal.Last = &execution
		return journal, nil
	default:
		return Journal{}, ErrInvalidTransition
	}
}

func ValidateJournal(journal Journal) error {
	var problems []error
	if journal.APIVersion != APIVersion || journal.Version == 0 || journal.Version > 9007199254740991 ||
		!installationIDPattern.MatchString(journal.InstallationID) {
		problems = append(problems, errors.New("installation journal identity is invalid"))
	}
	if !trustKeyIDPattern.MatchString(journal.ReleaseTrust.KeyID) ||
		!trustFingerprintPattern.MatchString(journal.ReleaseTrust.Fingerprint) {
		problems = append(problems, errors.New("installation release trust is invalid"))
	}
	if journal.Node != nil && (!trustKeyIDPattern.MatchString(journal.Node.ExecutionTargetID) ||
		!digestPattern.MatchString(journal.Node.ConfigurationDigest)) {
		problems = append(problems, errors.New("node installation binding is invalid"))
	}
	if rotation := journal.NodeCredentialRotation; rotation != nil {
		if journal.Node == nil || journal.CurrentReleaseID == "" || rotation.Action != ActionRotateCredentials ||
			validateCommand(*rotation, true) != nil || rotation.InputDigest != journal.Node.ConfigurationDigest {
			problems = append(problems, errors.New("committed node credential rotation is invalid"))
		}
	}
	if (journal.CurrentReleaseID == "") != (journal.CurrentReleaseDigest == "") ||
		(journal.CurrentReleaseID != "" && (!releaseIDPattern.MatchString(journal.CurrentReleaseID) ||
			!digestPattern.MatchString(journal.CurrentReleaseDigest))) {
		problems = append(problems, errors.New("current release identity is invalid"))
	}
	if (journal.PreviousRelease == "") != (journal.PreviousReleaseDigest == "") ||
		(journal.PreviousRelease != "" && (!releaseIDPattern.MatchString(journal.PreviousRelease) ||
			!digestPattern.MatchString(journal.PreviousReleaseDigest) ||
			journal.PreviousRelease == journal.CurrentReleaseID || journal.CurrentReleaseID == "")) {
		problems = append(problems, errors.New("previous release identity is invalid"))
	}
	if journal.Active != nil {
		problems = append(problems, validateExecution(*journal.Active, false, journal.Node != nil))
		if journal.CurrentReleaseID != journal.Active.SourceRelease ||
			journal.CurrentReleaseDigest != journal.Active.SourceDigest {
			problems = append(problems, errors.New("active command source does not match the current release"))
		}
		if journal.Active.Command.Action == ActionRotateCredentials &&
			(journal.Node == nil || journal.Active.Command.ExpectedConfigurationDigest != journal.Node.ConfigurationDigest) {
			problems = append(problems, errors.New("active rotation source does not match the node commitment"))
		}
	}
	if journal.Last != nil {
		problems = append(problems, validateExecution(*journal.Last, true, journal.Node != nil))
		problems = append(problems, validateCompletedPointers(journal, *journal.Last))
	}
	if journal.Active != nil && journal.Last != nil &&
		journal.Active.Command.ID == journal.Last.Command.ID {
		problems = append(problems, errors.New("active and completed command identities collide"))
	}
	return errors.Join(problems...)
}

// ValidateNodeTransition keeps the node's lifetime identity immutable while
// admitting only the final transition of its already sealed credential command.
// Persistence uses this boundary instead of treating any version increment as
// permission to replace a credential commitment or its replay receipt.
func ValidateNodeTransition(before, after Journal) error {
	invalid := errors.New("node commitment change lacks a verified rotation transition")
	if (before.Node == nil) != (after.Node == nil) {
		return invalid
	}
	if before.Node == nil {
		if after.NodeCredentialRotation != nil {
			return invalid
		}
		return nil
	}
	if before.Node.ExecutionTargetID != after.Node.ExecutionTargetID {
		return invalid
	}
	receiptEqual := before.NodeCredentialRotation == nil && after.NodeCredentialRotation == nil
	if before.NodeCredentialRotation != nil && after.NodeCredentialRotation != nil {
		receiptEqual = *before.NodeCredentialRotation == *after.NodeCredentialRotation
	}
	if before.Node.ConfigurationDigest == after.Node.ConfigurationDigest && receiptEqual {
		return nil
	}
	if before.Active == nil || before.Active.Command.Action != ActionRotateCredentials ||
		before.Active.Phase != PhaseCommitting || after.Active != nil || after.Last == nil {
		return invalid
	}
	expected, err := Advance(before, before.Active.Command.ID, PhaseReady, after.Last.CompletedAt)
	if err != nil || *expected.Node != *after.Node || expected.NodeCredentialRotation == nil ||
		after.NodeCredentialRotation == nil || *expected.NodeCredentialRotation != *after.NodeCredentialRotation ||
		*expected.Last != *after.Last || expected.CurrentReleaseID != after.CurrentReleaseID ||
		expected.CurrentReleaseDigest != after.CurrentReleaseDigest || expected.PreviousRelease != after.PreviousRelease ||
		expected.PreviousReleaseDigest != after.PreviousReleaseDigest {
		return invalid
	}
	return nil
}

func validateCommand(command Command, node bool) error {
	if !commandIDPattern.MatchString(command.ID) || !canonicalTime(command.RequestedAt) {
		return errors.New("installation command identity or time is invalid")
	}
	if len(workflow(command.Action, node)) == 0 {
		return errors.New("installation action is unsupported for this root")
	}
	if command.Action != ActionRotateCredentials && command.Action != ActionConfigureNodes &&
		(command.ExpectedConfigurationDigest != "" || command.RevokePreviousCredentials) {
		return errors.New("installation command contains unrelated credential input")
	}
	switch command.Action {
	case ActionConfigureNodes:
		if !digestPattern.MatchString(command.InputDigest) || !digestPattern.MatchString(command.ExpectedConfigurationDigest) ||
			command.InputDigest == command.ExpectedConfigurationDigest || command.RevokePreviousCredentials || command.TargetReleaseID != "" || command.BackupID != "" || command.BackupDigest != "" {
			return errors.New("node controller configuration input is invalid")
		}
	case ActionRecoverCredentials:
		if !digestPattern.MatchString(command.InputDigest) || command.TargetReleaseID != "" ||
			command.BackupID != "" || command.BackupDigest != "" {
			return errors.New("platform credential recovery input is invalid")
		}
	case ActionRotateCredentials:
		if !digestPattern.MatchString(command.InputDigest) || !digestPattern.MatchString(command.ExpectedConfigurationDigest) ||
			command.InputDigest == command.ExpectedConfigurationDigest || command.TargetReleaseID != "" ||
			command.BackupID != "" || command.BackupDigest != "" {
			return errors.New("node credential rotation input is invalid")
		}
	case ActionInstall:
		if !digestPattern.MatchString(command.InputDigest) ||
			!releaseIDPattern.MatchString(command.TargetReleaseID) || command.BackupID != "" ||
			command.BackupDigest != "" {
			return errors.New("release-changing command input is invalid")
		}
	case ActionUpgrade:
		if !digestPattern.MatchString(command.InputDigest) ||
			!releaseIDPattern.MatchString(command.TargetReleaseID) ||
			!backupIDPattern.MatchString(command.BackupID) || command.BackupDigest != "" {
			return errors.New("upgrade command input is invalid")
		}
	case ActionRecover:
		if !digestPattern.MatchString(command.InputDigest) ||
			!releaseIDPattern.MatchString(command.TargetReleaseID) ||
			!backupIDPattern.MatchString(command.BackupID) ||
			!digestPattern.MatchString(command.BackupDigest) {
			return errors.New("recovery command input is invalid")
		}
	case ActionBackup:
		if command.InputDigest != "" || command.TargetReleaseID != "" ||
			!backupIDPattern.MatchString(command.BackupID) || command.BackupDigest != "" {
			return errors.New("backup command input is invalid")
		}
	case ActionSupport:
		if !digestPattern.MatchString(command.InputDigest) ||
			command.TargetReleaseID != "" || command.BackupID != "" ||
			command.BackupDigest != "" {
			return errors.New("support command input is invalid")
		}
	case ActionVerify, ActionStatus, ActionRollback, ActionStart:
		if command.InputDigest != "" || command.TargetReleaseID != "" || command.BackupID != "" ||
			command.BackupDigest != "" {
			return errors.New("installation command contains unrelated input")
		}
	default:
		return errors.New("installation command action is unsupported")
	}
	return nil
}

func validateActionPrecondition(journal Journal, command Command) error {
	switch command.Action {
	case ActionRotateCredentials:
		if journal.Node == nil || journal.CurrentReleaseID == "" ||
			journal.Node.ConfigurationDigest != command.ExpectedConfigurationDigest {
			return ErrPrecondition
		}
	case ActionInstall:
		if journal.CurrentReleaseID != "" || journal.PreviousRelease != "" {
			return ErrPrecondition
		}
	case ActionUpgrade:
		if journal.CurrentReleaseID == "" || command.TargetReleaseID == journal.CurrentReleaseID {
			return ErrPrecondition
		}
	case ActionRollback:
		if journal.CurrentReleaseID == "" || journal.PreviousRelease == "" {
			return ErrPrecondition
		}
	case ActionVerify, ActionStatus, ActionBackup, ActionSupport, ActionStart, ActionRecoverCredentials, ActionConfigureNodes:
		if journal.CurrentReleaseID == "" {
			return ErrPrecondition
		}
	case ActionRecover:
		if journal.CurrentReleaseID == "" {
			return ErrPrecondition
		}
	}
	return nil
}

func validateExecution(execution Execution, completed bool, node bool) error {
	var problems []error
	problems = append(problems, validateCommand(execution.Command, node))
	if !canonicalTime(execution.StartedAt) || !canonicalTime(execution.UpdatedAt) ||
		execution.StartedAt != execution.Command.RequestedAt || execution.UpdatedAt.Before(execution.StartedAt) {
		problems = append(problems, errors.New("installation execution time is invalid"))
	}
	if (execution.SourceRelease == "") != (execution.SourceDigest == "") ||
		(execution.SourceRelease != "" && (!releaseIDPattern.MatchString(execution.SourceRelease) ||
			!digestPattern.MatchString(execution.SourceDigest))) {
		problems = append(problems, errors.New("installation source release is invalid"))
	}
	switch execution.Command.Action {
	case ActionInstall, ActionUpgrade:
		if execution.Destination != execution.Command.TargetReleaseID ||
			execution.DestinationDigest != execution.Command.InputDigest ||
			!releaseIDPattern.MatchString(execution.Destination) ||
			!digestPattern.MatchString(execution.DestinationDigest) {
			problems = append(problems, errors.New("installation destination release is invalid"))
		}
	case ActionRecover:
		if execution.Destination != execution.Command.TargetReleaseID ||
			execution.DestinationDigest != execution.Command.InputDigest ||
			!releaseIDPattern.MatchString(execution.Destination) ||
			!digestPattern.MatchString(execution.DestinationDigest) {
			problems = append(problems, errors.New("installation destination release is invalid"))
		}
	case ActionRollback:
		if !releaseIDPattern.MatchString(execution.Destination) ||
			!digestPattern.MatchString(execution.DestinationDigest) ||
			execution.Destination == execution.SourceRelease {
			problems = append(problems, errors.New("rollback destination release is invalid"))
		}
	default:
		if execution.Destination != "" || execution.DestinationDigest != "" {
			problems = append(problems, errors.New("non-release command has a destination release"))
		}
	}
	if execution.Command.Action == ActionInstall && execution.SourceRelease != "" {
		problems = append(problems, errors.New("install command has a source release"))
	}
	if execution.Command.Action != ActionInstall && execution.SourceRelease == "" {
		problems = append(problems, errors.New("installed command lacks a source release"))
	}
	if completed {
		if execution.Outcome != OutcomeSucceeded && execution.Outcome != OutcomeFailed &&
			execution.Outcome != OutcomeRolledBack && execution.Outcome != OutcomeManualIntervention {
			problems = append(problems, errors.New("completed installation outcome is invalid"))
		}
		switch execution.Outcome {
		case OutcomeSucceeded, OutcomeRolledBack:
			if execution.Phase != PhaseReady {
				problems = append(problems, errors.New("successful installation execution is not ready"))
			}
		case OutcomeFailed:
			credentialRecoveryCompleted := execution.Command.Action == ActionRecoverCredentials && execution.Phase == PhaseReady && execution.FailureCode != ""
			if !credentialRecoveryCompleted && (phaseIndex(workflow(execution.Command.Action, node), execution.Phase) < 0 || execution.Phase == PhaseReady) {
				problems = append(problems, errors.New("failed installation execution phase is invalid"))
			}
		case OutcomeManualIntervention:
			if execution.Phase != PhaseManualIntervention {
				problems = append(problems, errors.New("manual installation execution phase is invalid"))
			}
		}
		if !canonicalTime(execution.CompletedAt) || execution.CompletedAt != execution.UpdatedAt {
			problems = append(problems, errors.New("completed installation time is invalid"))
		}
	} else {
		if phaseIndex(workflow(execution.Command.Action, node), execution.Phase) < 0 &&
			execution.Phase != PhaseRollingBack {
			problems = append(problems, errors.New("active installation execution phase is invalid"))
		}
		if execution.Outcome != "" || !execution.CompletedAt.IsZero() {
			problems = append(problems, errors.New("active installation execution is terminal"))
		}
		if execution.Phase == PhaseRollingBack &&
			(execution.Command.Action == ActionInstall || execution.Command.Action == ActionUpgrade) &&
			execution.FailureCode == "" {
			problems = append(problems, errors.New("installation rollback intent lacks a failure"))
		}
		if execution.Phase == PhaseRollingBack && execution.Command.Action != ActionInstall &&
			execution.Command.Action != ActionUpgrade && execution.Command.Action != ActionRollback {
			problems = append(problems, errors.New("installation action cannot roll back"))
		}
	}
	if execution.FailureCode != "" && !failureCodePattern.MatchString(execution.FailureCode) {
		problems = append(problems, errors.New("installation failure code is invalid"))
	}
	if execution.Command.Action == ActionRecoverCredentials {
		if completed {
			if execution.Phase != PhaseReady || (execution.Outcome != OutcomeSucceeded && execution.Outcome != OutcomeFailed) ||
				(execution.Outcome == OutcomeSucceeded && execution.FailureCode != "") ||
				(execution.Outcome == OutcomeFailed && execution.FailureCode == "") {
				problems = append(problems, errors.New("credential recovery completion is invalid"))
			}
		} else if execution.FailureCode != "" && execution.Phase != PhaseCommitting {
			problems = append(problems, errors.New("rejected credential recovery is not finalizing"))
		}
	}
	return errors.Join(problems...)
}

func sameCommandInput(left, right Command) bool {
	return left.ID == right.ID && left.Action == right.Action &&
		left.InputDigest == right.InputDigest && left.TargetReleaseID == right.TargetReleaseID &&
		left.BackupID == right.BackupID && left.BackupDigest == right.BackupDigest &&
		left.ExpectedConfigurationDigest == right.ExpectedConfigurationDigest &&
		left.RevokePreviousCredentials == right.RevokePreviousCredentials
}

func workflow(action Action, node bool) []Phase {
	if node {
		switch action {
		case ActionInstall:
			return []Phase{PhasePreflight, PhaseStaging, PhaseConfiguring, PhaseStarting, PhaseVerifying, PhaseCommitting, PhaseReady}
		case ActionRotateCredentials:
			return []Phase{PhasePreflight, PhaseStaging, PhaseConfiguring, PhaseStarting, PhaseVerifying, PhaseCommitting, PhaseReady}
		case ActionStart:
			return []Phase{PhaseStarting, PhaseVerifying, PhaseReady}
		case ActionVerify, ActionStatus:
			return []Phase{PhaseVerifying, PhaseReady}
		default:
			return nil
		}
	}
	switch action {
	case ActionConfigureNodes:
		return []Phase{PhaseStaging, PhaseConfiguring, PhaseStarting, PhaseVerifying, PhaseCommitting, PhaseReady}
	case ActionRecoverCredentials:
		return []Phase{PhaseStaging, PhaseRecoveringCredentials, PhaseCommitting, PhaseReady}
	case ActionInstall:
		return []Phase{PhasePreflight, PhaseStaging, PhaseLoadingImages, PhaseConfiguring,
			PhaseMigrating, PhaseStarting, PhaseVerifying, PhaseCommitting, PhaseReady}
	case ActionUpgrade:
		return []Phase{PhasePreflight, PhaseBackingUp, PhaseStaging, PhaseLoadingImages,
			PhaseConfiguring, PhaseMigrating, PhaseStarting, PhaseVerifying, PhaseCommitting, PhaseReady}
	case ActionVerify, ActionStatus, ActionSupport:
		return []Phase{PhaseVerifying, PhaseReady}
	case ActionBackup:
		return []Phase{PhaseBackingUp, PhaseReady}
	case ActionRollback:
		return []Phase{PhaseRollingBack, PhaseStarting, PhaseVerifying, PhaseCommitting, PhaseReady}
	case ActionRecover:
		return []Phase{PhaseRecovering, PhaseStarting, PhaseVerifying, PhaseCommitting, PhaseReady}
	default:
		return nil
	}
}

// NextPhase exposes only the next admitted transition in the closed lifecycle
// workflow so orchestration does not duplicate the state machine sequence.
func NextPhase(journal Journal) (Phase, bool) {
	if journal.Active == nil {
		return "", false
	}
	sequence := workflow(journal.Active.Command.Action, journal.Node != nil)
	index := phaseIndex(sequence, journal.Active.Phase)
	if index < 0 || index+1 >= len(sequence) {
		return "", false
	}
	return sequence[index+1], true
}

func phaseIndex(phases []Phase, phase Phase) int {
	for index, candidate := range phases {
		if candidate == phase {
			return index
		}
	}
	return -1
}

func applySuccessfulPointerChange(journal *Journal, execution Execution) {
	switch execution.Command.Action {
	case ActionRotateCredentials:
		binding := *journal.Node
		binding.ConfigurationDigest = execution.Command.InputDigest
		journal.Node = &binding
		command := execution.Command
		journal.NodeCredentialRotation = &command
	case ActionInstall:
		journal.CurrentReleaseID = execution.Destination
		journal.CurrentReleaseDigest = execution.DestinationDigest
		journal.PreviousRelease = ""
		journal.PreviousReleaseDigest = ""
	case ActionUpgrade:
		journal.PreviousRelease = execution.SourceRelease
		journal.PreviousReleaseDigest = execution.SourceDigest
		journal.CurrentReleaseID = execution.Destination
		journal.CurrentReleaseDigest = execution.DestinationDigest
	case ActionRollback:
		journal.CurrentReleaseID = execution.Destination
		journal.CurrentReleaseDigest = execution.DestinationDigest
		journal.PreviousRelease = ""
		journal.PreviousReleaseDigest = ""
	case ActionRecover:
		journal.CurrentReleaseID = execution.Destination
		journal.CurrentReleaseDigest = execution.DestinationDigest
		journal.PreviousRelease = ""
		journal.PreviousReleaseDigest = ""
	}
}

func validateCompletedPointers(journal Journal, execution Execution) error {
	switch execution.Outcome {
	case OutcomeSucceeded:
		if execution.Command.Action == ActionRotateCredentials &&
			(journal.Node == nil || journal.Node.ConfigurationDigest != execution.Command.InputDigest ||
				journal.NodeCredentialRotation == nil || !sameCommandInput(*journal.NodeCredentialRotation, execution.Command)) {
			return errors.New("successful credential rotation is not current")
		}
		switch execution.Command.Action {
		case ActionInstall, ActionUpgrade, ActionRollback, ActionRecover:
			if journal.CurrentReleaseID != execution.Destination ||
				journal.CurrentReleaseDigest != execution.DestinationDigest {
				return errors.New("successful command destination is not current")
			}
		default:
			if journal.CurrentReleaseID != execution.SourceRelease ||
				journal.CurrentReleaseDigest != execution.SourceDigest {
				return errors.New("read-only command changed the current release")
			}
		}
		if execution.Command.Action == ActionUpgrade &&
			(journal.PreviousRelease != execution.SourceRelease ||
				journal.PreviousReleaseDigest != execution.SourceDigest) {
			return errors.New("successful upgrade did not retain its source release")
		}
		if (execution.Command.Action == ActionInstall || execution.Command.Action == ActionRollback ||
			execution.Command.Action == ActionRecover) && journal.PreviousRelease != "" {
			return errors.New("successful command retained an invalid previous release")
		}
	case OutcomeFailed, OutcomeRolledBack, OutcomeManualIntervention:
		if journal.CurrentReleaseID != execution.SourceRelease ||
			journal.CurrentReleaseDigest != execution.SourceDigest {
			return errors.New("failed command changed the current release")
		}
	}
	return nil
}

func finishManual(journal Journal, execution Execution, at time.Time) Journal {
	execution.Phase = PhaseManualIntervention
	execution.Outcome = OutcomeManualIntervention
	execution.CompletedAt = at
	journal.Active = nil
	journal.Last = &execution
	return journal
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Round(0) &&
		value.Nanosecond()%1000 == 0
}
