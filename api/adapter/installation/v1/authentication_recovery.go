// Package installationv1 owns versioned cross-process adapter contracts
// shared by Matrix installation and the processes it isolates during product
// recovery.
package installationv1

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const (
	AuthenticationRecoveryAPIVersion                   = "installation.matrix.xiak.com/v1"
	AuthenticationRecoveryClosureKind                  = "IAMAuthenticationRecoveryClosure"
	AuthenticationRecoveryCompletionKind               = "IAMAuthenticationRecoveryCompletion"
	AuthenticationRecoveryIntentKind                   = "IAMAuthenticationRecoveryIntent"
	AuthenticationRecoverySecuritySnapshotKind         = "IAMAuthenticationRecoverySecuritySnapshot"
	AuthenticationRecoveryClosureEnvelopeKind          = "IAMAuthenticationRecoveryClosureEnvelope"
	AuthenticationRecoveryPurpose                      = "IAM_AUTHENTICATION_BACKUP_RECOVERY"
	AuthenticationRecoveryStateClosed                  = "CLOSED"
	AuthenticationRecoveryStateReopened                = "REOPENED"
	MaximumAuthenticationRecoveryBytes                 = int64(4096)
	MaximumAuthenticationRecoverySecuritySnapshotBytes = int64(2 * 1024 * 1024)
	MaximumAuthenticationRecoveryEnvelopeBytes         = MaximumAuthenticationRecoverySecuritySnapshotBytes + 2*MaximumAuthenticationRecoveryBytes
	// This is a bounded recovery transport, not an account creation quota or
	// an accepted installation capacity. Both the item and byte limits apply.
	MaximumAuthenticationRecoverySnapshotItems = 3000
	maximumAuthenticationRecoveryEpoch         = uint64(math.MaxInt64)

	AuthenticationRecoveryCloseCommand     = "close"
	AuthenticationRecoveryReconcileCommand = "reconcile"
	AuthenticationRecoveryReopenCommand    = "reopen"

	AuthenticationRecoveryDatabaseDSNFileEnvironment      = "MATRIX_IAM_AUTHENTICATION_RECOVERY_DATABASE_DSN_FILE"
	AuthenticationRecoveryMigrationDSNFileEnvironment     = "MATRIX_MIGRATION_IAM_AUTHENTICATION_RECOVERY_DSN_FILE"
	AuthenticationRecoveryIntentFileEnvironment           = "MATRIX_IAM_AUTHENTICATION_RECOVERY_INTENT_FILE"
	AuthenticationRecoveryClosureFileEnvironment          = "MATRIX_IAM_AUTHENTICATION_RECOVERY_CLOSURE_FILE"
	AuthenticationRecoverySecuritySnapshotFileEnvironment = "MATRIX_IAM_AUTHENTICATION_RECOVERY_SECURITY_SNAPSHOT_FILE"

	AuthenticationRecoveryExitSuccess     = 0
	AuthenticationRecoveryExitInvalid     = 2
	AuthenticationRecoveryExitForbidden   = 3
	AuthenticationRecoveryExitConflict    = 4
	AuthenticationRecoveryExitUnavailable = 6

	AuthenticationRecoveryErrorInvalid     = "IAM_AUTHENTICATION_RECOVERY_INVALID"
	AuthenticationRecoveryErrorForbidden   = "IAM_AUTHENTICATION_RECOVERY_FORBIDDEN"
	AuthenticationRecoveryErrorConflict    = "IAM_AUTHENTICATION_RECOVERY_CONFLICT"
	AuthenticationRecoveryErrorUnavailable = "IAM_AUTHENTICATION_RECOVERY_UNAVAILABLE"
)

// The signed purpose-only IAM executable accepts exactly one command. close
// consumes the intent file and returns a closure; reconcile consumes that
// closure after database restore and returns the same closure; reopen consumes
// it again and returns a completion. Only exit zero carries a verified JSON
// result. Interruption, timeout, damaged output or any unlisted exit remains
// unknown and must be resolved by replaying the same sealed command, never by
// constructing another epoch or recovery intent.

var (
	ErrInvalidAuthenticationRecoveryClosure          = errors.New("IAM authentication recovery closure is invalid")
	ErrInvalidAuthenticationRecoveryCompletion       = errors.New("IAM authentication recovery completion is invalid")
	ErrInvalidAuthenticationRecoveryIntent           = errors.New("IAM authentication recovery intent is invalid")
	ErrInvalidAuthenticationRecoverySecuritySnapshot = errors.New("IAM authentication recovery security snapshot is invalid")
	ErrInvalidAuthenticationRecoveryClosureEnvelope  = errors.New("IAM authentication recovery closure envelope is invalid")
	installationIDPattern                            = regexp.MustCompile(`^mxi-[0-9a-f]{32}$`)
	commandIDPattern                                 = regexp.MustCompile(`^cmd-[0-9a-f]{32}$`)
	backupIDPattern                                  = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)
	digestPattern                                    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	releaseIDPattern                                 = regexp.MustCompile(`^matrix-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?-[0-9a-f]{12}$`)
)

// AuthenticationRecoveryIntent is the non-secret tuple authenticated by the
// installation owner before an isolation record can be constructed. The two
// release digests must come from the installation's successful signature and
// content verification of the complete release manifests; those manifests
// commit their complete database profiles. Shape validation and digesting this
// value do not authenticate a release, isolate a process, or admit recovery.
type AuthenticationRecoveryIntent struct {
	APIVersion          string `json:"apiVersion"`
	Kind                string `json:"kind"`
	Purpose             string `json:"purpose"`
	InstallationID      string `json:"installationId"`
	Epoch               uint64 `json:"epoch"`
	CommandID           string `json:"commandId"`
	BackupID            string `json:"backupId"`
	BackupDigest        string `json:"backupDigest"`
	SourceReleaseID     string `json:"sourceReleaseId"`
	SourceReleaseDigest string `json:"sourceReleaseDigest"`
	TargetReleaseID     string `json:"targetReleaseId"`
	TargetReleaseDigest string `json:"targetReleaseDigest"`
	TOTPCustodyDigest   string `json:"totpCustodyDigest"`
	// Omission preserves historical intent bytes only. New snapshot-aware
	// execution requires ValidateCurrentAuthenticationRecoveryIntent.
	AuthenticationStateDigest string `json:"authenticationStateDigest,omitempty"`
}

// AuthenticationRecoveryClosure is a non-secret, one-way isolation record.
// Its presence never authorizes reopening authentication. RecoveryIntentDigest
// is owned by installation and commits the exact source and target signed
// release identities, their complete database profiles, and this backup and
// custody tuple. IAM only compares the exact closure with its purpose-limited
// recovery receipt; it cannot select another installation, backup, or target.
//
// There is deliberately no caller-constructible OPEN state. ClosedAt is
// database time from the purpose-only close transaction and is repeated
// exactly after a lost response. The installation persists these bytes before
// the first destructive database effect.
type AuthenticationRecoveryClosure struct {
	APIVersion             string    `json:"apiVersion"`
	Kind                   string    `json:"kind"`
	Purpose                string    `json:"purpose"`
	InstallationID         string    `json:"installationId"`
	Epoch                  uint64    `json:"epoch"`
	State                  string    `json:"state"`
	CommandID              string    `json:"commandId"`
	BackupID               string    `json:"backupId"`
	BackupDigest           string    `json:"backupDigest"`
	RecoveryIntentDigest   string    `json:"recoveryIntentDigest"`
	TOTPCustodyDigest      string    `json:"totpCustodyDigest"`
	ClosedAt               time.Time `json:"closedAt"`
	SecuritySnapshotDigest string    `json:"securitySnapshotDigest,omitempty"`
}

// AuthenticationRecoveryCompletion is historical evidence that the restored
// authority reconciled this exact closure and performed its one-shot replay
// fencing before authentication reopened. It is not a Session, permission or
// reusable recovery capability. ClosureDigest binds every closure field,
// including its database close time.
type AuthenticationRecoveryCompletion struct {
	APIVersion             string    `json:"apiVersion"`
	Kind                   string    `json:"kind"`
	Purpose                string    `json:"purpose"`
	InstallationID         string    `json:"installationId"`
	Epoch                  uint64    `json:"epoch"`
	State                  string    `json:"state"`
	CommandID              string    `json:"commandId"`
	ClosureDigest          string    `json:"closureDigest"`
	CompletedAt            time.Time `json:"completedAt"`
	SecuritySnapshotDigest string    `json:"securitySnapshotDigest,omitempty"`
}

// AuthenticationRecoveryAttemptWindow preserves a source authority's bounded
// attempt debit. It is not a reservation, reusable proof, or new attempt
// allowance. Reopening must reconcile it with the restored budget before any
// authentication is accepted; the window is never restarted by recovery.
type AuthenticationRecoveryAttemptWindow struct {
	WindowStartedAt time.Time `json:"windowStartedAt"`
	UsedAttempts    uint8     `json:"usedAttempts"`
	Sequence        uint64    `json:"sequence"`
}

// AuthenticationRecoveryUserReplay is the non-secret replay floor for one
// actual USER. All current identity and authorization qualifications belong
// to AuthenticationStateDigest, not to this deliberately smaller projection.
// Empty FactorID with step -1 explicitly means no current ACTIVE factor.
// A null window means IAM proved that no attempt row existed, not that an
// omitted or unrecognized row may be treated as unused allowance.
type AuthenticationRecoveryUserReplay struct {
	UserID           string                               `json:"userId"`
	FactorID         string                               `json:"factorId"`
	LastConsumedStep int64                                `json:"lastConsumedStep"`
	PasswordAttempts *AuthenticationRecoveryAttemptWindow `json:"passwordAttempts"`
	TOTPAttempts     *AuthenticationRecoveryAttemptWindow `json:"totpAttempts"`
}

type AuthenticationRecoveryAccountReplay struct {
	AccountID string                             `json:"accountId"`
	Users     []AuthenticationRecoveryUserReplay `json:"users"`
}

// AuthenticationRecoverySecuritySnapshot is emitted only after the same
// close transaction committed the complete authority projection, replay
// floors and immutable receipt. AuthenticationStateDigest is calculated by
// IAM's one closed SQL projection, shared with the exported backup snapshot;
// this codec cannot establish its completeness, provenance or freshness.
// Installation seals these exact bytes outside the database restore scope.
// It must not construct subsets, infer absent users, or resample after restore.
type AuthenticationRecoverySecuritySnapshot struct {
	APIVersion                string                                `json:"apiVersion"`
	Kind                      string                                `json:"kind"`
	Purpose                   string                                `json:"purpose"`
	InstallationID            string                                `json:"installationId"`
	BootstrapDigest           string                                `json:"bootstrapDigest"`
	Epoch                     uint64                                `json:"epoch"`
	CommandID                 string                                `json:"commandId"`
	RecoveryIntentDigest      string                                `json:"recoveryIntentDigest"`
	ClosedAt                  time.Time                             `json:"closedAt"`
	AuthenticationStateDigest string                                `json:"authenticationStateDigest"`
	Accounts                  []AuthenticationRecoveryAccountReplay `json:"accounts"`
}

// AuthenticationRecoveryClosureEnvelope is a one-shot, bounded close result.
// It is not a streaming lease. Installation persists and verifies the snapshot
// before the closure, and both before destructive effects. The historical
// bare Closure encoding is never a fallback for this execution contract.
type AuthenticationRecoveryClosureEnvelope struct {
	APIVersion       string                                 `json:"apiVersion"`
	Kind             string                                 `json:"kind"`
	Purpose          string                                 `json:"purpose"`
	Closure          AuthenticationRecoveryClosure          `json:"closure"`
	SecuritySnapshot AuthenticationRecoverySecuritySnapshot `json:"securitySnapshot"`
}

func ValidateAuthenticationRecoveryIntent(value AuthenticationRecoveryIntent) error {
	if value.APIVersion != AuthenticationRecoveryAPIVersion ||
		value.Kind != AuthenticationRecoveryIntentKind ||
		value.Purpose != AuthenticationRecoveryPurpose ||
		!installationIDPattern.MatchString(value.InstallationID) ||
		value.Epoch == 0 || value.Epoch > maximumAuthenticationRecoveryEpoch ||
		!commandIDPattern.MatchString(value.CommandID) ||
		!backupIDPattern.MatchString(value.BackupID) ||
		!validDigest(value.BackupDigest) ||
		!releaseIDPattern.MatchString(value.SourceReleaseID) ||
		!validDigest(value.SourceReleaseDigest) ||
		!releaseIDPattern.MatchString(value.TargetReleaseID) ||
		!validDigest(value.TargetReleaseDigest) ||
		!validDigest(value.TOTPCustodyDigest) ||
		(value.AuthenticationStateDigest != "" && !validDigest(value.AuthenticationStateDigest)) {
		return ErrInvalidAuthenticationRecoveryIntent
	}
	return nil
}

func ValidateCurrentAuthenticationRecoveryIntent(value AuthenticationRecoveryIntent) error {
	if ValidateAuthenticationRecoveryIntent(value) != nil || !validDigest(value.AuthenticationStateDigest) {
		return ErrInvalidAuthenticationRecoveryIntent
	}
	return nil
}

func EncodeAuthenticationRecoveryIntent(value AuthenticationRecoveryIntent) ([]byte, error) {
	if ValidateAuthenticationRecoveryIntent(value) != nil {
		return nil, ErrInvalidAuthenticationRecoveryIntent
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumAuthenticationRecoveryBytes {
		return nil, ErrInvalidAuthenticationRecoveryIntent
	}
	return encoded, nil
}

// DecodeAuthenticationRecoveryIntent accepts only the exact canonical bytes
// emitted by EncodeAuthenticationRecoveryIntent. This is the sole protected
// FILE representation consumed by the purpose-only close command.
func DecodeAuthenticationRecoveryIntent(reader io.Reader) (AuthenticationRecoveryIntent, error) {
	if reader == nil {
		return AuthenticationRecoveryIntent{}, ErrInvalidAuthenticationRecoveryIntent
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumAuthenticationRecoveryBytes+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumAuthenticationRecoveryBytes {
		return AuthenticationRecoveryIntent{}, ErrInvalidAuthenticationRecoveryIntent
	}
	var value AuthenticationRecoveryIntent
	if contractjson.DecodeObjectBytes(encoded, MaximumAuthenticationRecoveryBytes, &value) != nil ||
		ValidateAuthenticationRecoveryIntent(value) != nil {
		return AuthenticationRecoveryIntent{}, ErrInvalidAuthenticationRecoveryIntent
	}
	canonical, err := EncodeAuthenticationRecoveryIntent(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return AuthenticationRecoveryIntent{}, ErrInvalidAuthenticationRecoveryIntent
	}
	return value, nil
}

// AuthenticationRecoveryIntentDigest is the only framing for the exact,
// already-authenticated installation recovery tuple. It is consistency
// evidence, not a signature, authorization, current recovery qualification,
// or permission to reopen authentication.
func AuthenticationRecoveryIntentDigest(value AuthenticationRecoveryIntent) (string, error) {
	encoded, err := EncodeAuthenticationRecoveryIntent(value)
	if err != nil {
		return "", ErrInvalidAuthenticationRecoveryIntent
	}
	framed := authenticationRecoveryBindingBytes(
		"matrix.installation.iam-authentication-recovery-intent.v1",
		encoded,
	)
	clear(encoded)
	digest := sha256.Sum256(framed)
	clear(framed)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// ValidateAuthenticationRecoveryClosureForIntent proves only that the closed
// document binds this exact authenticated tuple. Callers must separately prove
// that installation removed every old process and durably wrote the closure.
func ValidateAuthenticationRecoveryClosureForIntent(closure AuthenticationRecoveryClosure, intent AuthenticationRecoveryIntent) error {
	if ValidateAuthenticationRecoveryClosure(closure) != nil ||
		ValidateAuthenticationRecoveryIntent(intent) != nil ||
		closure.APIVersion != intent.APIVersion ||
		closure.Purpose != intent.Purpose ||
		closure.InstallationID != intent.InstallationID ||
		closure.Epoch != intent.Epoch ||
		closure.CommandID != intent.CommandID ||
		closure.BackupID != intent.BackupID ||
		closure.BackupDigest != intent.BackupDigest ||
		closure.TOTPCustodyDigest != intent.TOTPCustodyDigest {
		return ErrInvalidAuthenticationRecoveryClosure
	}
	digest, err := AuthenticationRecoveryIntentDigest(intent)
	if err != nil || subtle.ConstantTimeCompare([]byte(closure.RecoveryIntentDigest), []byte(digest)) != 1 {
		return ErrInvalidAuthenticationRecoveryClosure
	}
	return nil
}

func ValidateAuthenticationRecoveryClosure(value AuthenticationRecoveryClosure) error {
	if value.APIVersion != AuthenticationRecoveryAPIVersion ||
		value.Kind != AuthenticationRecoveryClosureKind ||
		value.Purpose != AuthenticationRecoveryPurpose ||
		!installationIDPattern.MatchString(value.InstallationID) ||
		value.Epoch == 0 || value.Epoch > maximumAuthenticationRecoveryEpoch ||
		value.State != AuthenticationRecoveryStateClosed ||
		!commandIDPattern.MatchString(value.CommandID) ||
		!backupIDPattern.MatchString(value.BackupID) ||
		!validDigest(value.BackupDigest) ||
		!validDigest(value.RecoveryIntentDigest) ||
		!validDigest(value.TOTPCustodyDigest) ||
		!validAuthenticationRecoveryTime(value.ClosedAt) ||
		(value.SecuritySnapshotDigest != "" && !validDigest(value.SecuritySnapshotDigest)) {
		return ErrInvalidAuthenticationRecoveryClosure
	}
	return nil
}

func ValidateCurrentAuthenticationRecoveryClosure(value AuthenticationRecoveryClosure) error {
	if ValidateAuthenticationRecoveryClosure(value) != nil || !validDigest(value.SecuritySnapshotDigest) {
		return ErrInvalidAuthenticationRecoveryClosure
	}
	return nil
}

// AuthenticationRecoveryClosureDigest is the sole commitment framing for a
// canonical CLOSED receipt. It is consistency evidence only; current recovery
// qualification remains owned by the purpose-limited IAM transaction.
func AuthenticationRecoveryClosureDigest(value AuthenticationRecoveryClosure) (string, error) {
	encoded, err := EncodeAuthenticationRecoveryClosure(value)
	if err != nil {
		return "", ErrInvalidAuthenticationRecoveryClosure
	}
	framed := authenticationRecoveryBindingBytes(
		"matrix.installation.iam-authentication-recovery-closure.v1", encoded,
	)
	clear(encoded)
	digest := sha256.Sum256(framed)
	clear(framed)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func EncodeAuthenticationRecoveryClosure(value AuthenticationRecoveryClosure) ([]byte, error) {
	if ValidateAuthenticationRecoveryClosure(value) != nil {
		return nil, ErrInvalidAuthenticationRecoveryClosure
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumAuthenticationRecoveryBytes {
		return nil, ErrInvalidAuthenticationRecoveryClosure
	}
	return encoded, nil
}

// DecodeAuthenticationRecoveryClosure accepts only the exact canonical bytes
// emitted by EncodeAuthenticationRecoveryClosure. Whitespace, reordered,
// duplicate, unknown, NULL, or trailing input is rejected so every consumer
// compares one unambiguous isolation record.
func DecodeAuthenticationRecoveryClosure(reader io.Reader) (AuthenticationRecoveryClosure, error) {
	if reader == nil {
		return AuthenticationRecoveryClosure{}, ErrInvalidAuthenticationRecoveryClosure
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumAuthenticationRecoveryBytes+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumAuthenticationRecoveryBytes {
		return AuthenticationRecoveryClosure{}, ErrInvalidAuthenticationRecoveryClosure
	}
	var value AuthenticationRecoveryClosure
	if contractjson.DecodeObjectBytes(encoded, MaximumAuthenticationRecoveryBytes, &value) != nil ||
		ValidateAuthenticationRecoveryClosure(value) != nil {
		return AuthenticationRecoveryClosure{}, ErrInvalidAuthenticationRecoveryClosure
	}
	canonical, err := EncodeAuthenticationRecoveryClosure(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return AuthenticationRecoveryClosure{}, ErrInvalidAuthenticationRecoveryClosure
	}
	return value, nil
}

func ValidateAuthenticationRecoveryCompletion(value AuthenticationRecoveryCompletion) error {
	if value.APIVersion != AuthenticationRecoveryAPIVersion ||
		value.Kind != AuthenticationRecoveryCompletionKind ||
		value.Purpose != AuthenticationRecoveryPurpose ||
		!installationIDPattern.MatchString(value.InstallationID) ||
		value.Epoch == 0 || value.Epoch > maximumAuthenticationRecoveryEpoch ||
		value.State != AuthenticationRecoveryStateReopened ||
		!commandIDPattern.MatchString(value.CommandID) ||
		!validDigest(value.ClosureDigest) ||
		!validAuthenticationRecoveryTime(value.CompletedAt) ||
		(value.SecuritySnapshotDigest != "" && !validDigest(value.SecuritySnapshotDigest)) {
		return ErrInvalidAuthenticationRecoveryCompletion
	}
	return nil
}

// ValidateAuthenticationRecoveryCompletionForClosure rejects a completion
// for another installation, epoch, command or closure. Reopen must occur
// strictly after the database-time close transaction.
func ValidateAuthenticationRecoveryCompletionForClosure(
	completion AuthenticationRecoveryCompletion,
	closure AuthenticationRecoveryClosure,
) error {
	if ValidateAuthenticationRecoveryCompletion(completion) != nil ||
		ValidateAuthenticationRecoveryClosure(closure) != nil ||
		completion.APIVersion != closure.APIVersion ||
		completion.Purpose != closure.Purpose ||
		completion.InstallationID != closure.InstallationID ||
		completion.Epoch != closure.Epoch ||
		completion.CommandID != closure.CommandID ||
		completion.SecuritySnapshotDigest != closure.SecuritySnapshotDigest ||
		!completion.CompletedAt.After(closure.ClosedAt) {
		return ErrInvalidAuthenticationRecoveryCompletion
	}
	digest, err := AuthenticationRecoveryClosureDigest(closure)
	if err != nil || subtle.ConstantTimeCompare([]byte(completion.ClosureDigest), []byte(digest)) != 1 {
		return ErrInvalidAuthenticationRecoveryCompletion
	}
	return nil
}

func EncodeAuthenticationRecoveryCompletion(value AuthenticationRecoveryCompletion) ([]byte, error) {
	if ValidateAuthenticationRecoveryCompletion(value) != nil {
		return nil, ErrInvalidAuthenticationRecoveryCompletion
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumAuthenticationRecoveryBytes {
		return nil, ErrInvalidAuthenticationRecoveryCompletion
	}
	return encoded, nil
}

// DecodeAuthenticationRecoveryCompletion accepts only the exact canonical
// bytes emitted by EncodeAuthenticationRecoveryCompletion.
func DecodeAuthenticationRecoveryCompletion(reader io.Reader) (AuthenticationRecoveryCompletion, error) {
	if reader == nil {
		return AuthenticationRecoveryCompletion{}, ErrInvalidAuthenticationRecoveryCompletion
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumAuthenticationRecoveryBytes+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumAuthenticationRecoveryBytes {
		return AuthenticationRecoveryCompletion{}, ErrInvalidAuthenticationRecoveryCompletion
	}
	var value AuthenticationRecoveryCompletion
	if contractjson.DecodeObjectBytes(encoded, MaximumAuthenticationRecoveryBytes, &value) != nil ||
		ValidateAuthenticationRecoveryCompletion(value) != nil {
		return AuthenticationRecoveryCompletion{}, ErrInvalidAuthenticationRecoveryCompletion
	}
	canonical, err := EncodeAuthenticationRecoveryCompletion(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return AuthenticationRecoveryCompletion{}, ErrInvalidAuthenticationRecoveryCompletion
	}
	return value, nil
}

func ValidateAuthenticationRecoverySecuritySnapshot(value AuthenticationRecoverySecuritySnapshot) error {
	if value.APIVersion != AuthenticationRecoveryAPIVersion || value.Kind != AuthenticationRecoverySecuritySnapshotKind ||
		value.Purpose != AuthenticationRecoveryPurpose || !installationIDPattern.MatchString(value.InstallationID) ||
		!validDigest(value.BootstrapDigest) || value.Epoch == 0 || value.Epoch > maximumAuthenticationRecoveryEpoch ||
		!commandIDPattern.MatchString(value.CommandID) || !validDigest(value.RecoveryIntentDigest) ||
		!validDigest(value.AuthenticationStateDigest) || !validAuthenticationRecoveryTime(value.ClosedAt) ||
		value.ClosedAt.Unix() < 0 || len(value.Accounts) == 0 || len(value.Accounts) >= MaximumAuthenticationRecoverySnapshotItems {
		return ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	items, previousAccount := len(value.Accounts), ""
	for _, account := range value.Accounts {
		if iamv1.ValidateID("accountId", account.AccountID) != nil || account.AccountID <= previousAccount || len(account.Users) == 0 {
			return ErrInvalidAuthenticationRecoverySecuritySnapshot
		}
		previousAccount = account.AccountID
		if len(account.Users) > MaximumAuthenticationRecoverySnapshotItems-items {
			return ErrInvalidAuthenticationRecoverySecuritySnapshot
		}
		items += len(account.Users)
		previousUser := ""
		factors := make(map[string]bool, len(account.Users))
		for _, user := range account.Users {
			if iamv1.ValidateID("userId", user.UserID) != nil || user.UserID <= previousUser ||
				!validAuthenticationRecoveryAttemptWindow(user.PasswordAttempts, value.ClosedAt, true) ||
				!validAuthenticationRecoveryAttemptWindow(user.TOTPAttempts, value.ClosedAt, false) {
				return ErrInvalidAuthenticationRecoverySecuritySnapshot
			}
			previousUser = user.UserID
			if user.FactorID == "" {
				if user.LastConsumedStep != -1 {
					return ErrInvalidAuthenticationRecoverySecuritySnapshot
				}
			} else {
				if iamv1.ValidateID("factorId", user.FactorID) != nil || factors[user.FactorID] ||
					user.LastConsumedStep < 0 || user.LastConsumedStep > value.ClosedAt.Unix()/30+1 {
					return ErrInvalidAuthenticationRecoverySecuritySnapshot
				}
				factors[user.FactorID] = true
			}
		}
	}
	return nil
}

func validAuthenticationRecoveryAttemptWindow(value *AuthenticationRecoveryAttemptWindow, closedAt time.Time, allowZero bool) bool {
	if value == nil {
		return true
	}
	return validAuthenticationRecoveryTime(value.WindowStartedAt) && !value.WindowStartedAt.After(closedAt) &&
		value.Sequence > 0 && value.Sequence <= maximumAuthenticationRecoveryEpoch &&
		value.UsedAttempts <= 5 && (allowZero || value.UsedAttempts > 0)
}

func EncodeAuthenticationRecoverySecuritySnapshot(value AuthenticationRecoverySecuritySnapshot) ([]byte, error) {
	if ValidateAuthenticationRecoverySecuritySnapshot(value) != nil {
		return nil, ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaximumAuthenticationRecoverySecuritySnapshotBytes {
		return nil, ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	return encoded, nil
}

// DecodeAuthenticationRecoverySecuritySnapshot rejects omitted/null sets,
// omitted optional-state fields, duplicate keys and noncanonical encodings.
// Successfully decoding an explicit complete-looking set is not proof that
// the trusted IAM producer actually enumerated the complete database.
func DecodeAuthenticationRecoverySecuritySnapshot(reader io.Reader) (AuthenticationRecoverySecuritySnapshot, error) {
	if reader == nil {
		return AuthenticationRecoverySecuritySnapshot{}, ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumAuthenticationRecoverySecuritySnapshotBytes+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumAuthenticationRecoverySecuritySnapshotBytes {
		return AuthenticationRecoverySecuritySnapshot{}, ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	var value AuthenticationRecoverySecuritySnapshot
	if contractjson.DecodeObjectBytes(encoded, MaximumAuthenticationRecoverySecuritySnapshotBytes, &value) != nil {
		return AuthenticationRecoverySecuritySnapshot{}, ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	canonical, err := EncodeAuthenticationRecoverySecuritySnapshot(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return AuthenticationRecoverySecuritySnapshot{}, ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	return value, nil
}

// AuthenticationRecoverySecuritySnapshotDigest is the only framing of this
// transport document. It is distinct from AuthenticationStateDigest (the
// closed SQL authority projection) and from the TOTP wrapping-key custody.
func AuthenticationRecoverySecuritySnapshotDigest(value AuthenticationRecoverySecuritySnapshot) (string, error) {
	encoded, err := EncodeAuthenticationRecoverySecuritySnapshot(value)
	if err != nil {
		return "", ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	framed := authenticationRecoveryBindingBytes("matrix.installation.iam-authentication-recovery-security-snapshot.v1", encoded)
	clear(encoded)
	digest := sha256.Sum256(framed)
	clear(framed)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateAuthenticationRecoverySecuritySnapshotForClosure(value AuthenticationRecoverySecuritySnapshot, closure AuthenticationRecoveryClosure) error {
	if ValidateAuthenticationRecoverySecuritySnapshot(value) != nil || ValidateCurrentAuthenticationRecoveryClosure(closure) != nil ||
		value.InstallationID != closure.InstallationID || value.Epoch != closure.Epoch || value.CommandID != closure.CommandID ||
		value.RecoveryIntentDigest != closure.RecoveryIntentDigest || !value.ClosedAt.Equal(closure.ClosedAt) {
		return ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	digest, err := AuthenticationRecoverySecuritySnapshotDigest(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(digest), []byte(closure.SecuritySnapshotDigest)) != 1 {
		return ErrInvalidAuthenticationRecoverySecuritySnapshot
	}
	return nil
}

func ValidateAuthenticationRecoveryClosureEnvelope(value AuthenticationRecoveryClosureEnvelope) error {
	if value.APIVersion != AuthenticationRecoveryAPIVersion || value.Kind != AuthenticationRecoveryClosureEnvelopeKind ||
		value.Purpose != AuthenticationRecoveryPurpose ||
		ValidateAuthenticationRecoverySecuritySnapshotForClosure(value.SecuritySnapshot, value.Closure) != nil {
		return ErrInvalidAuthenticationRecoveryClosureEnvelope
	}
	return nil
}

// The bootstrap digest must come from the caller's authenticated installation
// authority, not from the returned envelope or a restored database.
func ValidateAuthenticationRecoveryClosureEnvelopeForIntent(value AuthenticationRecoveryClosureEnvelope, intent AuthenticationRecoveryIntent, bootstrapDigest string) error {
	if ValidateAuthenticationRecoveryClosureEnvelope(value) != nil || ValidateCurrentAuthenticationRecoveryIntent(intent) != nil ||
		ValidateAuthenticationRecoveryClosureForIntent(value.Closure, intent) != nil ||
		value.SecuritySnapshot.AuthenticationStateDigest != intent.AuthenticationStateDigest ||
		!validDigest(bootstrapDigest) || subtle.ConstantTimeCompare([]byte(value.SecuritySnapshot.BootstrapDigest), []byte(bootstrapDigest)) != 1 {
		return ErrInvalidAuthenticationRecoveryClosureEnvelope
	}
	return nil
}

func EncodeAuthenticationRecoveryClosureEnvelope(value AuthenticationRecoveryClosureEnvelope) ([]byte, error) {
	if ValidateAuthenticationRecoveryClosureEnvelope(value) != nil {
		return nil, ErrInvalidAuthenticationRecoveryClosureEnvelope
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaximumAuthenticationRecoveryEnvelopeBytes {
		return nil, ErrInvalidAuthenticationRecoveryClosureEnvelope
	}
	return encoded, nil
}

func DecodeAuthenticationRecoveryClosureEnvelope(reader io.Reader) (AuthenticationRecoveryClosureEnvelope, error) {
	if reader == nil {
		return AuthenticationRecoveryClosureEnvelope{}, ErrInvalidAuthenticationRecoveryClosureEnvelope
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumAuthenticationRecoveryEnvelopeBytes+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumAuthenticationRecoveryEnvelopeBytes {
		return AuthenticationRecoveryClosureEnvelope{}, ErrInvalidAuthenticationRecoveryClosureEnvelope
	}
	var value AuthenticationRecoveryClosureEnvelope
	if contractjson.DecodeObjectBytes(encoded, MaximumAuthenticationRecoveryEnvelopeBytes, &value) != nil {
		return AuthenticationRecoveryClosureEnvelope{}, ErrInvalidAuthenticationRecoveryClosureEnvelope
	}
	canonical, err := EncodeAuthenticationRecoveryClosureEnvelope(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return AuthenticationRecoveryClosureEnvelope{}, ErrInvalidAuthenticationRecoveryClosureEnvelope
	}
	return value, nil
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func validAuthenticationRecoveryTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Equal(value.Truncate(time.Microsecond))
}

func authenticationRecoveryBindingBytes(domain string, fields ...[]byte) []byte {
	encoded := binary.BigEndian.AppendUint32(nil, uint32(len(domain)))
	encoded = append(encoded, domain...)
	for _, field := range fields {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
		encoded = append(encoded, field...)
	}
	return encoded
}
