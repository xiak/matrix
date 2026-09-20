package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/notificationdispatch"
)

type NotificationRepository struct{ pool *pgxpool.Pool }
type notificationTransaction struct{ tx pgx.Tx }

func NewNotificationRepository(pool *pgxpool.Pool) (*NotificationRepository, error) {
	if pool == nil {
		return nil, notificationdispatch.ErrUnavailable
	}
	return &NotificationRepository{pool: pool}, nil
}

func (repository *NotificationRepository) WithinTransaction(ctx context.Context, callback func(context.Context, notificationdispatch.Transaction) error) error {
	if repository == nil || repository.pool == nil || ctx == nil || callback == nil {
		return notificationdispatch.ErrUnavailable
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return mapNotificationDeliveryError(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return mapNotificationDeliveryError(err)
	}
	if err = callback(ctx, &notificationTransaction{tx: tx}); err != nil {
		return err
	}
	return mapNotificationDeliveryError(tx.Commit(ctx))
}

func (value *notificationTransaction) ReadKeyset(ctx context.Context) (*authority.EmailVerificationKeyset, error) {
	// Same narrow decoder as the API; the dedicated SQL grants do not include
	// that API transaction's other methods or any table access.
	return (&transaction{tx: value.tx}).ReadEmailVerificationKeyset(ctx)
}

func (value *notificationTransaction) Claim(ctx context.Context, worker string) (notificationdispatch.Claim, bool, error) {
	var claim notificationdispatch.Claim
	var keyID *string
	err := value.tx.QueryRow(ctx, `SELECT tenant_id,notification_id,user_id,installation_id,kind,email,created_at,fence,lease_expires_at,
		verification_id,bootstrap_digest,credential_generation,contact_revision,issued_at,expires_at,key_id,nonce,ciphertext
		FROM iam.claim_security_notification($1)`, worker).Scan(&claim.AccountID, &claim.NotificationID, &claim.UserID, &claim.InstallationID, &claim.Kind, &claim.Recipient,
		&claim.CreatedAt, &claim.Fence, &claim.LeaseExpiresAt, &claim.Binding.VerificationID, &claim.Binding.BootstrapDigest, &claim.Binding.CredentialGeneration,
		&claim.Binding.ContactRevision, &claim.Binding.IssuedAt, &claim.Binding.ExpiresAt, &keyID, &claim.Sealed.Nonce, &claim.Sealed.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return claim, false, nil
	}
	if err != nil {
		return notificationdispatch.Claim{}, false, mapNotificationDeliveryError(err)
	}
	claim.Binding.AccountID, claim.Binding.UserID, claim.Binding.InstallationID, claim.Binding.Recipient = claim.AccountID, claim.UserID, claim.InstallationID, claim.Recipient
	claim.CreatedAt, claim.LeaseExpiresAt = claim.CreatedAt.UTC(), claim.LeaseExpiresAt.UTC()
	claim.Binding.IssuedAt, claim.Binding.ExpiresAt = claim.Binding.IssuedAt.UTC(), claim.Binding.ExpiresAt.UTC()
	if keyID != nil {
		claim.Sealed.KeyID = *keyID
		claim.Sealed.FormatVersion = 1
	}
	return claim, true, nil
}

func (value *notificationTransaction) Complete(ctx context.Context, claim notificationdispatch.Claim, worker string, result authority.MailSubmission) error {
	if result.Validate() != nil {
		return notificationdispatch.ErrUnavailable
	}
	var code any
	if result.SMTPCode != 0 {
		code = result.SMTPCode
	}
	_, err := value.tx.Exec(ctx, "SELECT iam.complete_security_notification($1,$2,$3,$4,$5,$6)", claim.AccountID, claim.NotificationID, worker, claim.Fence, result.State, code)
	return mapNotificationDeliveryError(err)
}

func mapNotificationDeliveryError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var failure *pgconn.PgError
	if errors.As(err, &failure) {
		if failure.Code == "40001" || failure.Code == "40P01" {
			return notificationdispatch.ErrRetryableTransaction
		}
		if failure.Code == "P0002" {
			return notificationdispatch.ErrStaleLease
		}
	}
	return fmt.Errorf("IAM notification database: %w", notificationdispatch.ErrUnavailable)
}
