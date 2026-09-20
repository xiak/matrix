package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) RegisterEmailVerificationKeyset(ctx context.Context, registration authority.EmailVerificationKeyset) error {
	encoded, err := json.Marshal(registration)
	if err != nil {
		return identityaccess.ErrUnavailable
	}
	_, err = value.tx.Exec(ctx, "SELECT iam.register_email_verification_keyset($1::jsonb)", string(encoded))
	return mapDatabaseError("register IAM email verification custody", err)
}

func (value *transaction) ReadEmailVerificationKeyset(ctx context.Context) (*authority.EmailVerificationKeyset, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_email_verification_keyset()").Scan(&encoded); err != nil {
		return nil, mapDatabaseError("read IAM email verification custody", err)
	}
	if encoded == nil {
		return nil, nil
	}
	var stored authority.EmailVerificationKeyset
	if contractjson.DecodeObjectBytes(encoded, iamv1.MaxEmailVerificationKeyringBytes, &stored) != nil || len(stored.Keys) == 0 || len(stored.Keys) > 8 {
		return nil, identityaccess.ErrUnavailable
	}
	return &stored, nil
}

func (value *transaction) ReadNotificationContact(ctx context.Context, subject identityaccess.NotificationContactSubject) (iamv1.NotificationContact, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_notification_contact($1,$2,$3)", subject.AccountID, subject.UserID, subject.SessionID).Scan(&encoded); err != nil {
		return iamv1.NotificationContact{}, mapNotificationDatabaseError("read IAM notification contact", err)
	}
	var result iamv1.NotificationContact
	if contractjson.DecodeObjectBytes(encoded, 4096, &result) != nil {
		return iamv1.NotificationContact{}, identityaccess.ErrUnavailable
	}
	if result.VerifiedAt != nil {
		normalized := result.VerifiedAt.UTC()
		result.VerifiedAt = &normalized
	}
	if iamv1.ValidateNotificationContact(result) != nil || result.AccountID != subject.AccountID || result.UserID != subject.UserID {
		return iamv1.NotificationContact{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadNotificationVerification(ctx context.Context, subject identityaccess.NotificationContactSubject, id string) (iamv1.NotificationContactVerification, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_notification_verification($1,$2,$3,$4)", subject.AccountID, subject.UserID, subject.SessionID, id).Scan(&encoded); err != nil {
		return iamv1.NotificationContactVerification{}, mapNotificationDatabaseError("read IAM notification verification", err)
	}
	result, err := decodeNotificationVerification(encoded, subject)
	if err != nil || result.ID != id {
		return iamv1.NotificationContactVerification{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) StartNotificationVerification(ctx context.Context, change identityaccess.NotificationVerificationStart) (iamv1.NotificationContactVerification, error) {
	encoded, err := json.Marshal(change.AuditEvent)
	if err != nil {
		return iamv1.NotificationContactVerification{}, identityaccess.ErrUnavailable
	}
	b := change.Binding
	var result []byte
	err = value.tx.QueryRow(ctx, `SELECT iam.start_notification_verification($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb)`,
		change.Subject.AccountID, change.Subject.UserID, change.Subject.SessionID, change.PasswordAttempt.ID, change.PasswordAttempt.Sequence,
		change.RequestID, change.PasswordAttempt.IntentDigest, b.VerificationID, change.NotificationID, b.InstallationID, b.BootstrapDigest,
		b.CredentialGeneration, b.Recipient, change.Sealed.KeyID, change.Sealed.Nonce, change.Sealed.Ciphertext, b.IssuedAt, b.ExpiresAt, string(encoded)).Scan(&result)
	if err != nil {
		return iamv1.NotificationContactVerification{}, mapNotificationDatabaseError("start IAM notification verification", err)
	}
	return decodeNotificationVerification(result, change.Subject)
}

func (value *transaction) ReserveNotificationConfirmation(ctx context.Context, subject identityaccess.NotificationContactSubject, id, attemptID string) (identityaccess.NotificationConfirmationAttempt, bool, error) {
	result := identityaccess.NotificationConfirmationAttempt{Subject: subject, ID: attemptID}
	result.Binding.AccountID, result.Binding.UserID, result.Binding.VerificationID = subject.AccountID, subject.UserID, id
	result.Sealed.FormatVersion = 1
	b := &result.Binding
	err := value.tx.QueryRow(ctx, `SELECT installation_id,bootstrap_digest,credential_generation,contact_revision,email,issued_at,expires_at,key_id,nonce,ciphertext,attempt_sequence
		FROM iam.reserve_notification_confirmation($1,$2,$3,$4,$5)`, subject.AccountID, subject.UserID, subject.SessionID, id, attemptID).Scan(
		&b.InstallationID, &b.BootstrapDigest, &b.CredentialGeneration, &b.ContactRevision, &b.Recipient, &b.IssuedAt, &b.ExpiresAt,
		&result.Sealed.KeyID, &result.Sealed.Nonce, &result.Sealed.Ciphertext, &result.Sequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.NotificationConfirmationAttempt{}, false, nil
	}
	if err != nil {
		return identityaccess.NotificationConfirmationAttempt{}, false, mapNotificationDatabaseError("reserve IAM email confirmation", err)
	}
	b.IssuedAt, b.ExpiresAt = b.IssuedAt.UTC(), b.ExpiresAt.UTC()
	info, aad, err := iamv1.EmailVerificationCipherContext(*b, result.Sealed.KeyID)
	clear(info)
	clear(aad)
	if err != nil || result.Sequence == 0 || len(result.Sealed.Nonce) != 12 || len(result.Sealed.Ciphertext) != 24 {
		return identityaccess.NotificationConfirmationAttempt{}, false, identityaccess.ErrUnavailable
	}
	return result, true, nil
}

func (value *transaction) RejectNotificationConfirmation(ctx context.Context, attempt identityaccess.NotificationConfirmationAttempt) error {
	_, err := value.tx.Exec(ctx, "SELECT iam.reject_notification_confirmation($1,$2,$3,$4)", attempt.Subject.AccountID, attempt.Subject.UserID, attempt.ID, attempt.Sequence)
	return mapDatabaseError("reject IAM email confirmation", err)
}

func (value *transaction) ConfirmNotificationContact(ctx context.Context, change identityaccess.NotificationConfirmation) (iamv1.NotificationContactVerification, error) {
	encoded, err := json.Marshal(change.AuditEvent)
	if err != nil {
		return iamv1.NotificationContactVerification{}, identityaccess.ErrUnavailable
	}
	a := change.Attempt
	var result []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.confirm_notification_contact($1,$2,$3,$4,$5,$6,$7,$8::jsonb)",
		a.Subject.AccountID, a.Subject.UserID, a.Subject.SessionID, a.Binding.VerificationID, a.ID, a.Sequence, change.NotificationID, string(encoded)).Scan(&result)
	if err != nil {
		return iamv1.NotificationContactVerification{}, mapNotificationDatabaseError("confirm IAM notification contact", err)
	}
	return decodeNotificationVerification(result, a.Subject)
}

func decodeNotificationVerification(encoded []byte, subject identityaccess.NotificationContactSubject) (iamv1.NotificationContactVerification, error) {
	var result iamv1.NotificationContactVerification
	if contractjson.DecodeObjectBytes(encoded, 4096, &result) != nil {
		return result, identityaccess.ErrUnavailable
	}
	result.IssuedAt, result.ExpiresAt, result.Delivery.UpdatedAt = result.IssuedAt.UTC(), result.ExpiresAt.UTC(), result.Delivery.UpdatedAt.UTC()
	if result.CompletedAt != nil {
		normalized := result.CompletedAt.UTC()
		result.CompletedAt = &normalized
	}
	if iamv1.ValidateNotificationContactVerification(result) != nil || result.AccountID != subject.AccountID || result.UserID != subject.UserID {
		return iamv1.NotificationContactVerification{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func mapNotificationDatabaseError(operation string, err error) error {
	var failure *pgconn.PgError
	if errors.As(err, &failure) {
		if failure.Code == "42501" {
			return fmt.Errorf("%s: %w", operation, identityaccess.ErrForbidden)
		}
		if failure.Code == "P0003" {
			return fmt.Errorf("%s: %w", operation, identityaccess.ErrOverloaded)
		}
	}
	return mapDatabaseError(operation, err)
}
