// Package installationv1 owns versioned cross-process adapter contracts
// shared by Matrix installation and the processes it isolates during product
// recovery.
package installationv1

import (
	"bytes"
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
	AuthenticationRecoveryPurpose      = "IAM_AUTHENTICATION_BACKUP_RECOVERY"
	AuthenticationRecoveryStateClosed  = "CLOSED"
	MaximumAuthenticationRecoveryBytes = int64(4096)
	maximumAuthenticationRecoveryEpoch = uint64(math.MaxInt64)
)

var (
	ErrInvalidAuthenticationRecoveryClosure = errors.New("IAM authentication recovery closure is invalid")
	installationIDPattern                   = regexp.MustCompile(`^mxi-[0-9a-f]{32}$`)
	commandIDPattern                        = regexp.MustCompile(`^cmd-[0-9a-f]{32}$`)
	backupIDPattern                         = regexp.MustCompile(`^backup-[0-9a-f]{32}$`)
	digestPattern                           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

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
