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
)

const (
	AuthenticationRecoveryAPIVersion     = "installation.matrix.xiak.com/v1"
	AuthenticationRecoveryClosureKind    = "IAMAuthenticationRecoveryClosure"
	AuthenticationRecoveryCompletionKind = "IAMAuthenticationRecoveryCompletion"
	AuthenticationRecoveryIntentKind     = "IAMAuthenticationRecoveryIntent"
	AuthenticationRecoveryPurpose        = "IAM_AUTHENTICATION_BACKUP_RECOVERY"
	AuthenticationRecoveryStateClosed    = "CLOSED"
	AuthenticationRecoveryStateReopened  = "REOPENED"
	MaximumAuthenticationRecoveryBytes   = int64(4096)
	maximumAuthenticationRecoveryEpoch   = uint64(math.MaxInt64)

	AuthenticationRecoveryCloseCommand     = "close"
	AuthenticationRecoveryReconcileCommand = "reconcile"
	AuthenticationRecoveryReopenCommand    = "reopen"

	AuthenticationRecoveryDatabaseDSNFileEnvironment  = "MATRIX_IAM_AUTHENTICATION_RECOVERY_DATABASE_DSN_FILE"
	AuthenticationRecoveryMigrationDSNFileEnvironment = "MATRIX_MIGRATION_IAM_AUTHENTICATION_RECOVERY_DSN_FILE"
	AuthenticationRecoveryIntentFileEnvironment       = "MATRIX_IAM_AUTHENTICATION_RECOVERY_INTENT_FILE"
	AuthenticationRecoveryClosureFileEnvironment      = "MATRIX_IAM_AUTHENTICATION_RECOVERY_CLOSURE_FILE"

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
	ErrInvalidAuthenticationRecoveryClosure    = errors.New("IAM authentication recovery closure is invalid")
	ErrInvalidAuthenticationRecoveryCompletion = errors.New("IAM authentication recovery completion is invalid")
	ErrInvalidAuthenticationRecoveryIntent     = errors.New("IAM authentication recovery intent is invalid")
	installationIDPattern                      = regexp.MustCompile(`^mxi-[0-9a-f]{32}$`)
	commandIDPattern                           = regexp.MustCompile(`^cmd-[0-9a-f]{32}$`)
	backupIDPattern                            = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)
	digestPattern                              = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	releaseIDPattern                           = regexp.MustCompile(`^matrix-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?-[0-9a-f]{12}$`)
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
	APIVersion           string    `json:"apiVersion"`
	Kind                 string    `json:"kind"`
	Purpose              string    `json:"purpose"`
	InstallationID       string    `json:"installationId"`
	Epoch                uint64    `json:"epoch"`
	State                string    `json:"state"`
	CommandID            string    `json:"commandId"`
	BackupID             string    `json:"backupId"`
	BackupDigest         string    `json:"backupDigest"`
	RecoveryIntentDigest string    `json:"recoveryIntentDigest"`
	TOTPCustodyDigest    string    `json:"totpCustodyDigest"`
	ClosedAt             time.Time `json:"closedAt"`
}

// AuthenticationRecoveryCompletion is historical evidence that the restored
// authority reconciled this exact closure and performed its one-shot replay
// fencing before authentication reopened. It is not a Session, permission or
// reusable recovery capability. ClosureDigest binds every closure field,
// including its database close time.
type AuthenticationRecoveryCompletion struct {
	APIVersion     string    `json:"apiVersion"`
	Kind           string    `json:"kind"`
	Purpose        string    `json:"purpose"`
	InstallationID string    `json:"installationId"`
	Epoch          uint64    `json:"epoch"`
	State          string    `json:"state"`
	CommandID      string    `json:"commandId"`
	ClosureDigest  string    `json:"closureDigest"`
	CompletedAt    time.Time `json:"completedAt"`
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
		!validDigest(value.TOTPCustodyDigest) {
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
		!validAuthenticationRecoveryTime(value.ClosedAt) {
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
		!validAuthenticationRecoveryTime(value.CompletedAt) {
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
