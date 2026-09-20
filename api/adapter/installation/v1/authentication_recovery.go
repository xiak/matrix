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

	"github.com/xiak/matrix/api/contractjson"
)

const (
	AuthenticationRecoveryAPIVersion   = "installation.matrix.xiak.com/v1"
	AuthenticationRecoveryClosureKind  = "IAMAuthenticationRecoveryClosure"
	AuthenticationRecoveryIntentKind   = "IAMAuthenticationRecoveryIntent"
	AuthenticationRecoveryPurpose      = "IAM_AUTHENTICATION_BACKUP_RECOVERY"
	AuthenticationRecoveryStateClosed  = "CLOSED"
	MaximumAuthenticationRecoveryBytes = int64(4096)
	maximumAuthenticationRecoveryEpoch = uint64(math.MaxInt64)
)

var (
	ErrInvalidAuthenticationRecoveryClosure = errors.New("IAM authentication recovery closure is invalid")
	ErrInvalidAuthenticationRecoveryIntent  = errors.New("IAM authentication recovery intent is invalid")
	installationIDPattern                   = regexp.MustCompile(`^mxi-[0-9a-f]{32}$`)
	commandIDPattern                        = regexp.MustCompile(`^cmd-[0-9a-f]{32}$`)
	backupIDPattern                         = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)
	digestPattern                           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	releaseIDPattern                        = regexp.MustCompile(`^matrix-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?-[0-9a-f]{12}$`)
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
// This contract deliberately has no OPEN state or completion receipt. Those
// semantics remain unavailable until current recovery qualification and the
// complete post-restore invalidation boundary have independently been frozen.
type AuthenticationRecoveryClosure struct {
	APIVersion           string `json:"apiVersion"`
	Kind                 string `json:"kind"`
	Purpose              string `json:"purpose"`
	InstallationID       string `json:"installationId"`
	Epoch                uint64 `json:"epoch"`
	State                string `json:"state"`
	CommandID            string `json:"commandId"`
	BackupID             string `json:"backupId"`
	BackupDigest         string `json:"backupDigest"`
	RecoveryIntentDigest string `json:"recoveryIntentDigest"`
	TOTPCustodyDigest    string `json:"totpCustodyDigest"`
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

// AuthenticationRecoveryIntentDigest is the only framing for the exact,
// already-authenticated installation recovery tuple. It is consistency
// evidence, not a signature, authorization, current recovery qualification,
// or permission to reopen authentication.
func AuthenticationRecoveryIntentDigest(value AuthenticationRecoveryIntent) (string, error) {
	if ValidateAuthenticationRecoveryIntent(value) != nil {
		return "", ErrInvalidAuthenticationRecoveryIntent
	}
	epoch := make([]byte, 8)
	binary.BigEndian.PutUint64(epoch, value.Epoch)
	framed := authenticationRecoveryBindingBytes(
		"matrix.installation.iam-authentication-recovery-intent.v1",
		[]byte(value.APIVersion), []byte(value.Kind), []byte(value.Purpose),
		[]byte(value.InstallationID), epoch, []byte(value.CommandID),
		[]byte(value.BackupID), []byte(value.BackupDigest),
		[]byte(value.SourceReleaseID), []byte(value.SourceReleaseDigest),
		[]byte(value.TargetReleaseID), []byte(value.TargetReleaseDigest),
		[]byte(value.TOTPCustodyDigest),
	)
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
		!validDigest(value.TOTPCustodyDigest) {
		return ErrInvalidAuthenticationRecoveryClosure
	}
	return nil
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

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
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
