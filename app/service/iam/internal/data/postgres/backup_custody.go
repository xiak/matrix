package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	"github.com/xiak/matrix/api/contractjson"
)

var (
	ErrBackupCustodyForbidden   = errors.New("IAM backup custody context is forbidden")
	ErrBackupCustodyUnavailable = errors.New("IAM backup custody is unavailable")
)

// TOTPBackupSnapshot owns one dedicated, read-only PostgreSQL transaction.
// It has no credential material and never commits, including normal release.
// The composition root bounds its lifetime and owns the private pipe protocol.
type TOTPBackupSnapshot struct {
	connection *pgx.Conn
	tx         pgx.Tx
	lease      installationv1.TOTPBackupSnapshotLease
}

func OpenTOTPBackupSnapshot(ctx context.Context, config *pgx.ConnConfig) (*TOTPBackupSnapshot, error) {
	if ctx == nil || config == nil {
		return nil, ErrBackupCustodyUnavailable
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > time.Duration(installationv1.TOTPBackupSnapshotLeaseMaximumSeconds)*time.Second {
		return nil, ErrBackupCustodyUnavailable
	}
	config = config.Copy()
	if config.RuntimeParams == nil {
		config.RuntimeParams = map[string]string{}
	}
	config.RuntimeParams["application_name"] = "matrix-iam-backup-custody"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, ErrBackupCustodyUnavailable
	}
	value := &TOTPBackupSnapshot{connection: connection}
	fail := func(err error) (*TOTPBackupSnapshot, error) {
		_ = value.Close()
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "42501" {
			return nil, ErrBackupCustodyForbidden
		}
		return nil, ErrBackupCustodyUnavailable
	}
	// Do not let an administrative DSN or a login inheriting other authority
	// masquerade as this purpose-only capability, even under SET ROLE.
	var allowed bool
	if err := connection.QueryRow(ctx, `SELECT session_user='matrix_iam_backup_custody_login'
	 AND current_user=session_user AND pg_has_role(session_user,'matrix_iam_backup_custody','USAGE')
	 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=session_user AND
	   (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls))
	 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname NOT IN (session_user,'matrix_iam_backup_custody')
	   AND pg_has_role(session_user,r.oid,'MEMBER'))`).Scan(&allowed); err != nil {
		return fail(err)
	}
	if !allowed {
		_ = value.Close()
		return nil, ErrBackupCustodyForbidden
	}
	value.tx, err = connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fail(err)
	}
	remaining := strconv.FormatInt(max(1, time.Until(deadline).Milliseconds()), 10)
	if _, err := value.tx.Exec(ctx, `SELECT set_config('statement_timeout',$1,true),
	 set_config('idle_in_transaction_session_timeout',$1,true)`, remaining); err != nil {
		return fail(err)
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_totp_backup_custody()").Scan(&encoded); err != nil {
		return fail(err)
	}
	var custody installationv1.TOTPBackupCustody
	if contractjson.DecodeObjectBytes(encoded, installationv1.MaximumTOTPBackupCustodyBytes, &custody) != nil ||
		installationv1.ValidateTOTPBackupCustody(custody) != nil {
		return fail(nil)
	}
	digest, err := installationv1.TOTPBackupCustodyDigest(custody)
	if err != nil {
		return fail(err)
	}
	var snapshotID string
	if err := value.tx.QueryRow(ctx, "SELECT pg_catalog.pg_export_snapshot()").Scan(&snapshotID); err != nil {
		return fail(err)
	}
	value.lease = installationv1.TOTPBackupSnapshotLease{APIVersion: installationv1.TOTPBackupCustodyAPIVersion,
		Kind: installationv1.TOTPBackupSnapshotLeaseKind, Purpose: installationv1.TOTPBackupCustodyPurpose,
		SnapshotID: snapshotID, Custody: custody, CustodyDigest: digest}
	if installationv1.ValidateTOTPBackupSnapshotLease(value.lease) != nil {
		return fail(nil)
	}
	// Fence an orphaned exporter at the database too. The helper's cancellation
	// is not the only mechanism bounding vacuum/snapshot retention.
	remaining = strconv.FormatInt(max(1, time.Until(deadline).Milliseconds()), 10)
	if _, err := value.tx.Exec(ctx, "SELECT set_config('idle_in_transaction_session_timeout',$1,true)", remaining); err != nil {
		return fail(err)
	}
	return value, nil
}

func (value *TOTPBackupSnapshot) Lease() installationv1.TOTPBackupSnapshotLease {
	result := value.lease
	result.Custody.RequiredKeys = append([]installationv1.TOTPBackupRequiredKey{}, result.Custody.RequiredKeys...)
	return result
}

func (value *TOTPBackupSnapshot) Close() error {
	if value == nil || value.connection == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var rollbackError error
	if value.tx != nil {
		rollbackError = value.tx.Rollback(ctx)
		value.tx = nil
	}
	closeError := value.connection.Close(ctx)
	value.connection = nil
	if rollbackError != nil || closeError != nil {
		return ErrBackupCustodyUnavailable
	}
	return nil
}
