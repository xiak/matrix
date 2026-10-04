package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	"github.com/xiak/matrix/api/contractjson"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/authenticationrecovery"
)

var (
	_ authenticationrecovery.Repository  = (*Repository)(nil)
	_ authenticationrecovery.Transaction = (*transaction)(nil)
)

func (repository *Repository) WithinAuthenticationRecoveryTransaction(
	ctx context.Context,
	callback func(context.Context, authenticationrecovery.Transaction) error,
) error {
	if repository == nil || repository.pool == nil {
		return authenticationrecovery.ErrUnavailable
	}
	if ctx == nil || callback == nil {
		return authenticationrecovery.ErrInvalidArgument
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
	if err != nil {
		return mapAuthenticationRecoveryDatabaseError("begin IAM authentication recovery", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return mapAuthenticationRecoveryDatabaseError("set IAM authentication recovery timezone", err)
	}
	if err := callback(ctx, &transaction{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapAuthenticationRecoveryDatabaseError("commit IAM authentication recovery", err)
	}
	return nil
}

func (value *transaction) PrepareAuthenticationClose(ctx context.Context, intent installationv1.AuthenticationRecoveryIntent, digest string) (installationv1.AuthenticationRecoverySecuritySnapshot, error) {
	encodedIntent, err := installationv1.EncodeAuthenticationRecoveryIntent(intent)
	if err != nil {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, authenticationrecovery.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.prepare_authentication_recovery_close($1::jsonb,$2)", encodedIntent, digest).Scan(&encoded); err != nil {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, mapAuthenticationRecoveryDatabaseError("prepare IAM authentication close", err)
	}
	var snapshot installationv1.AuthenticationRecoverySecuritySnapshot
	if contractjson.DecodeObjectBytes(encoded, installationv1.MaximumAuthenticationRecoverySecuritySnapshotBytes, &snapshot) != nil ||
		installationv1.ValidateAuthenticationRecoverySecuritySnapshot(snapshot) != nil {
		return installationv1.AuthenticationRecoverySecuritySnapshot{}, authenticationrecovery.ErrUnavailable
	}
	return snapshot, nil
}

func (value *transaction) InspectNewAuthentication(ctx context.Context, intent installationv1.AuthenticationRecoveryIntent, digest string) (installationv1.AuthenticationRecoveryInspection, error) {
	encodedIntent, err := installationv1.EncodeAuthenticationRecoveryIntent(intent)
	if err != nil {
		return installationv1.AuthenticationRecoveryInspection{}, authenticationrecovery.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.inspect_new_authentication_recovery($1::jsonb,$2)", encodedIntent, digest).Scan(&encoded); err != nil {
		return installationv1.AuthenticationRecoveryInspection{}, mapAuthenticationRecoveryDatabaseError("inspect new IAM authentication recovery", err)
	}
	var inspection installationv1.AuthenticationRecoveryInspection
	if contractjson.DecodeObjectBytes(encoded, installationv1.MaximumAuthenticationRecoveryBytes, &inspection) != nil ||
		installationv1.ValidateAuthenticationRecoveryInspection(inspection) != nil {
		return installationv1.AuthenticationRecoveryInspection{}, authenticationrecovery.ErrUnavailable
	}
	return inspection, nil
}

func (value *transaction) CloseAuthentication(ctx context.Context, mutation authenticationrecovery.CloseMutation) (installationv1.AuthenticationRecoveryClosure, error) {
	intent, err := json.Marshal(mutation.Intent)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.ClosedEvent)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrUnavailable
	}
	snapshot, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(mutation.SecuritySnapshot)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrUnavailable
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.close_authentication_recovery($1::jsonb,$2,$3::jsonb,$4::jsonb,$5)",
		intent, mutation.IntentDigest, event, snapshot, mutation.SecuritySnapshotDigest).Scan(&encoded); err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, mapAuthenticationRecoveryDatabaseError("close IAM authentication", err)
	}
	return decodeAuthenticationRecoveryClosure(encoded)
}

func (value *transaction) ReconcileAuthentication(ctx context.Context, mutation authenticationrecovery.ReconcileMutation) (installationv1.AuthenticationRecoveryClosure, error) {
	closure, err := json.Marshal(mutation.Closure)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrInvalidArgument
	}
	closedEvent, err := json.Marshal(mutation.ClosedEvent)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrUnavailable
	}
	reconciledEvent, err := json.Marshal(mutation.ReconciledEvent)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrUnavailable
	}
	snapshot, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(mutation.SecuritySnapshot)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrUnavailable
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.reconcile_authentication_recovery($1::jsonb,$2,$3::jsonb,$4::jsonb,$5::jsonb)",
		closure, mutation.ClosureDigest, closedEvent, reconciledEvent, snapshot).Scan(&encoded); err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, mapAuthenticationRecoveryDatabaseError("reconcile IAM authentication", err)
	}
	return decodeAuthenticationRecoveryClosure(encoded)
}

func (value *transaction) ReopenAuthentication(ctx context.Context, mutation authenticationrecovery.ReopenMutation) (installationv1.AuthenticationRecoveryCompletion, error) {
	closure, err := json.Marshal(mutation.Closure)
	if err != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, authenticationrecovery.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.ReopenedEvent)
	if err != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, authenticationrecovery.ErrUnavailable
	}
	snapshot, err := installationv1.EncodeAuthenticationRecoverySecuritySnapshot(mutation.SecuritySnapshot)
	if err != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, authenticationrecovery.ErrUnavailable
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.reopen_authentication_recovery($1::jsonb,$2,$3::jsonb,$4::jsonb)",
		closure, mutation.ClosureDigest, event, snapshot).Scan(&encoded); err != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, mapAuthenticationRecoveryDatabaseError("reopen IAM authentication", err)
	}
	var result installationv1.AuthenticationRecoveryCompletion
	if json.Unmarshal(encoded, &result) != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, authenticationrecovery.ErrUnavailable
	}
	result.CompletedAt = result.CompletedAt.UTC()
	if installationv1.ValidateAuthenticationRecoveryCompletion(result) != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, authenticationrecovery.ErrUnavailable
	}
	return result, nil
}

func decodeAuthenticationRecoveryClosure(encoded []byte) (installationv1.AuthenticationRecoveryClosure, error) {
	var result installationv1.AuthenticationRecoveryClosure
	if json.Unmarshal(encoded, &result) != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrUnavailable
	}
	result.ClosedAt = result.ClosedAt.UTC()
	if installationv1.ValidateAuthenticationRecoveryClosure(result) != nil {
		return installationv1.AuthenticationRecoveryClosure{}, authenticationrecovery.ErrUnavailable
	}
	return result, nil
}

func mapAuthenticationRecoveryDatabaseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "22023":
			return fmt.Errorf("%s: %w", operation, authenticationrecovery.ErrInvalidArgument)
		case "42501":
			return fmt.Errorf("%s: %w", operation, authenticationrecovery.ErrForbidden)
		case "23505", "P0002":
			return fmt.Errorf("%s: %w", operation, authenticationrecovery.ErrConflict)
		case "40001", "40P01":
			return fmt.Errorf("%s: %w", operation, authenticationrecovery.ErrRetryableTransaction)
		}
	}
	return fmt.Errorf("%s: %w", operation, authenticationrecovery.ErrUnavailable)
}
