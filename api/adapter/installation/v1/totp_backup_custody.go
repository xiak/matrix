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
	"regexp"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

// The snapshot helper writes exactly one canonical lease line and then keeps
// its exporting transaction open. A consumer may request normal closure only
// by writing TOTPBackupCustodyReleaseFrame and immediately closing stdin; the
// helper accepts success only after it observes EOF with no other bytes. Exit
// zero means that exact rollback/close path completed, never that a backup was
// independently verified or published. All other, unknown, interrupted, or
// timed-out outcomes are failures and the ephemeral lease must not be reused.
const (
	TOTPBackupCustodyAPIVersion = "installation.matrix.xiak.com/v1"
	TOTPBackupCustodyKind       = "IAMTOTPBackupCustody"
	TOTPBackupSnapshotLeaseKind = "IAMTOTPBackupSnapshotLease"
	TOTPBackupCustodyPurpose    = "IAM_TOTP_BACKUP_CUSTODY"

	TOTPBackupCustodySnapshotCommand             = "snapshot"
	TOTPBackupCustodyDatabaseDSNFileEnvironment  = "MATRIX_IAM_BACKUP_CUSTODY_DATABASE_DSN_FILE"
	TOTPBackupCustodyMigrationDSNFileEnvironment = "MATRIX_MIGRATION_IAM_BACKUP_CUSTODY_DSN_FILE"
	TOTPBackupCustodyReleaseFrame                = "RELEASE\n"
	TOTPBackupSnapshotLeaseMaximumSeconds        = 600

	TOTPBackupCustodyExitSuccess     = 0
	TOTPBackupCustodyExitInvalid     = 2
	TOTPBackupCustodyExitForbidden   = 3
	TOTPBackupCustodyExitUnavailable = 6

	TOTPBackupCustodyErrorInvalid     = "IAM_BACKUP_CUSTODY_INVALID"
	TOTPBackupCustodyErrorForbidden   = "IAM_BACKUP_CUSTODY_FORBIDDEN"
	TOTPBackupCustodyErrorUnavailable = "IAM_BACKUP_CUSTODY_UNAVAILABLE"

	MaximumTOTPBackupCustodyBytes   = int64(8192)
	maximumPostgresSnapshotIDLength = 96
)

var (
	ErrInvalidTOTPBackupCustody       = errors.New("IAM TOTP backup custody is invalid")
	ErrInvalidTOTPBackupSnapshotLease = errors.New("IAM TOTP backup snapshot lease is invalid")
	postgresSnapshotIDPattern         = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{8}-[1-9][0-9]*$`)
)

// TOTPBackupRequiredKey is non-secret evidence for one immutable wrapping key
// required by the exact database snapshot. It contains no seed or key material.
type TOTPBackupRequiredKey struct {
	KeyID         string `json:"keyId"`
	FormatVersion uint8  `json:"formatVersion"`
	Commitment    string `json:"commitment"`
}

// TOTPBackupCustody is the bounded, persistable requirement set returned by
// IAM for an exact database snapshot. Only the purpose-limited IAM authority
// may decide that the sorted set is complete, including when it is empty.
// Shape validation and its digest confer no database access or recovery right.
type TOTPBackupCustody struct {
	APIVersion      string                  `json:"apiVersion"`
	Kind            string                  `json:"kind"`
	Purpose         string                  `json:"purpose"`
	InstallationID  string                  `json:"installationId"`
	BootstrapDigest string                  `json:"bootstrapDigest"`
	KeysetRevision  uint64                  `json:"keysetRevision"`
	RequiredKeys    []TOTPBackupRequiredKey `json:"requiredKeys"`
}

// TOTPBackupSnapshotLease is a private cross-process response. SnapshotID is
// intentionally outside TOTPBackupCustody: it is valid only while the trusted
// helper keeps its exporting transaction open and must never be persisted in a
// backup, Audit event, recovery command, or support artifact. This document by
// itself does not prove that the exporting transaction is still alive.
type TOTPBackupSnapshotLease struct {
	APIVersion    string            `json:"apiVersion"`
	Kind          string            `json:"kind"`
	Purpose       string            `json:"purpose"`
	SnapshotID    string            `json:"snapshotId"`
	Custody       TOTPBackupCustody `json:"custody"`
	CustodyDigest string            `json:"custodyDigest"`
}

func ValidateTOTPBackupCustody(value TOTPBackupCustody) error {
	if value.APIVersion != TOTPBackupCustodyAPIVersion ||
		value.Kind != TOTPBackupCustodyKind ||
		value.Purpose != TOTPBackupCustodyPurpose ||
		!installationIDPattern.MatchString(value.InstallationID) ||
		iamv1.ValidateDigest("bootstrapDigest", value.BootstrapDigest) != nil ||
		value.KeysetRevision == 0 || value.KeysetRevision > iamv1.MaxTOTPKeysetRevision ||
		value.RequiredKeys == nil ||
		len(value.RequiredKeys) > iamv1.MaxTOTPWrappingKeys {
		return ErrInvalidTOTPBackupCustody
	}
	previous := ""
	for _, required := range value.RequiredKeys {
		if iamv1.ValidateID("keyId", required.KeyID) != nil ||
			required.KeyID <= previous ||
			required.FormatVersion != 1 ||
			iamv1.ValidateDigest("commitment", required.Commitment) != nil {
			return ErrInvalidTOTPBackupCustody
		}
		previous = required.KeyID
	}
	return nil
}

// TOTPBackupCustodyDigest binds only the persistent scope and exact sorted
// requirement set. It deliberately excludes the ephemeral PostgreSQL snapshot
// identifier so restore and readiness can recompute the same custody evidence.
func TOTPBackupCustodyDigest(value TOTPBackupCustody) (string, error) {
	if ValidateTOTPBackupCustody(value) != nil {
		return "", ErrInvalidTOTPBackupCustody
	}
	fields := [][]byte{
		[]byte(value.APIVersion), []byte(value.Kind), []byte(value.Purpose),
		[]byte(value.InstallationID), []byte(value.BootstrapDigest),
		binary.BigEndian.AppendUint64(nil, value.KeysetRevision),
	}
	for _, required := range value.RequiredKeys {
		fields = append(fields, []byte(required.KeyID), []byte{required.FormatVersion}, []byte(required.Commitment))
	}
	framed := authenticationRecoveryBindingBytes(
		"matrix.installation.iam-totp-backup-custody.v1", fields...,
	)
	digest := sha256.Sum256(framed)
	clear(framed)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateTOTPBackupSnapshotLease(value TOTPBackupSnapshotLease) error {
	if value.APIVersion != TOTPBackupCustodyAPIVersion ||
		value.Kind != TOTPBackupSnapshotLeaseKind ||
		value.Purpose != TOTPBackupCustodyPurpose ||
		len(value.SnapshotID) == 0 || len(value.SnapshotID) > maximumPostgresSnapshotIDLength ||
		!postgresSnapshotIDPattern.MatchString(value.SnapshotID) ||
		ValidateTOTPBackupCustody(value.Custody) != nil ||
		iamv1.ValidateDigest("custodyDigest", value.CustodyDigest) != nil {
		return ErrInvalidTOTPBackupSnapshotLease
	}
	digest, err := TOTPBackupCustodyDigest(value.Custody)
	if err != nil || subtle.ConstantTimeCompare([]byte(value.CustodyDigest), []byte(digest)) != 1 {
		return ErrInvalidTOTPBackupSnapshotLease
	}
	return nil
}

func EncodeTOTPBackupSnapshotLease(value TOTPBackupSnapshotLease) ([]byte, error) {
	if ValidateTOTPBackupSnapshotLease(value) != nil {
		return nil, ErrInvalidTOTPBackupSnapshotLease
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumTOTPBackupCustodyBytes {
		return nil, ErrInvalidTOTPBackupSnapshotLease
	}
	return encoded, nil
}

// DecodeTOTPBackupSnapshotLease accepts only the exact canonical bytes emitted
// by EncodeTOTPBackupSnapshotLease. The caller must separately authenticate the
// helper, its dedicated database identity, and its still-open transaction.
func DecodeTOTPBackupSnapshotLease(reader io.Reader) (TOTPBackupSnapshotLease, error) {
	if reader == nil {
		return TOTPBackupSnapshotLease{}, ErrInvalidTOTPBackupSnapshotLease
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumTOTPBackupCustodyBytes+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumTOTPBackupCustodyBytes {
		return TOTPBackupSnapshotLease{}, ErrInvalidTOTPBackupSnapshotLease
	}
	var value TOTPBackupSnapshotLease
	if contractjson.DecodeObjectBytes(encoded, MaximumTOTPBackupCustodyBytes, &value) != nil ||
		ValidateTOTPBackupSnapshotLease(value) != nil {
		return TOTPBackupSnapshotLease{}, ErrInvalidTOTPBackupSnapshotLease
	}
	canonical, err := EncodeTOTPBackupSnapshotLease(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return TOTPBackupSnapshotLease{}, ErrInvalidTOTPBackupSnapshotLease
	}
	return value, nil
}
