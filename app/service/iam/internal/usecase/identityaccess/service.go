package identityaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

const (
	defaultSessionLifetime        = 8 * time.Hour
	defaultMaxTransactionAttempts = 5
)

func NewAuthority(repository Repository, config Config) (*Authority, error) {
	if repository == nil {
		return nil, errors.New("IAM repository is required")
	}
	if config.SessionLifetime == 0 {
		config.SessionLifetime = defaultSessionLifetime
	}
	if config.SessionLifetime < time.Minute || config.SessionLifetime > 24*time.Hour ||
		config.SessionLifetime%time.Second != 0 {
		return nil, errors.New("IAM session lifetime must be whole seconds between one minute and 24 hours")
	}
	if config.MaxTransactionAttempts == 0 {
		config.MaxTransactionAttempts = defaultMaxTransactionAttempts
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("IAM transaction attempts must be between one and ten")
	}
	if config.NewID == nil {
		config.NewID = newID
	}
	return &Authority{
		repository:  repository,
		config:      config,
		passwords:   authority.NewPasswordHasher(nil),
		credentials: authority.NewCredentialIssuer(nil),
	}, nil
}

func (service *Authority) withinTransaction(
	ctx context.Context,
	callback func(context.Context, Transaction) error,
) error {
	if service == nil || service.repository == nil {
		return ErrUnavailable
	}
	if ctx == nil || callback == nil {
		return ErrInvalidArgument
	}
	var transactionErr error
	for attempt := 0; attempt < service.config.MaxTransactionAttempts; attempt++ {
		transactionErr = service.repository.WithinTransaction(ctx, callback)
		if transactionErr == nil || !errors.Is(transactionErr, ErrRetryableTransaction) {
			return transactionErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return fmt.Errorf("IAM transaction attempts exhausted: %w", transactionErr)
}

func newID(prefix string) (string, error) {
	if err := iamv1.ValidateID("idPrefix", prefix); err != nil {
		return "", err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		clear(random)
		return "", ErrUnavailable
	}
	result := prefix + "-" + hex.EncodeToString(random)
	clear(random)
	if err := iamv1.ValidateID("generatedId", result); err != nil {
		return "", ErrUnavailable
	}
	return result, nil
}

func digestSanitized(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", ErrUnavailable
	}
	digest := sha256.New()
	digest.Write([]byte("matrix.iam.request.v1\x00"))
	digest.Write([]byte(domain))
	digest.Write([]byte{0})
	digest.Write(encoded)
	clear(encoded)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func newAuditEvent(
	eventID string,
	tenantID iamv1.OrganizationID,
	actor auditv1.ActorReference,
	action auditv1.Action,
	target auditv1.TargetReference,
	result auditv1.Result,
	decisionID iamv1.DecisionID,
	requestDigest string,
	requestID string,
	correlationID string,
	occurredAt time.Time,
) (auditv1.Event, error) {
	event := auditv1.Event{
		APIVersion:    auditv1.APIVersion,
		Kind:          "AuditEvent",
		EventID:       auditv1.EventID(eventID),
		TenantID:      auditv1.TenantID(tenantID),
		Actor:         actor,
		IAMDecisionID: auditv1.DecisionID(decisionID),
		Action:        action,
		Target:        target,
		Result:        result,
		RequestDigest: requestDigest,
		RequestID:     requestID,
		CorrelationID: correlationID,
		OccurredAt:    occurredAt,
	}
	if err := auditv1.ValidateEventForSource(auditv1.SourceIAM, event); err != nil {
		return auditv1.Event{}, fmt.Errorf("%w: construct IAM Audit event", ErrUnavailable)
	}
	return event, nil
}

func transactionTime(ctx context.Context, transaction Transaction) (time.Time, error) {
	if transaction == nil {
		return time.Time{}, ErrUnavailable
	}
	value, err := transaction.TransactionTime(ctx)
	if err != nil || value.IsZero() || value.Location() != time.UTC ||
		value != value.Round(0) || value.Nanosecond()%1_000 != 0 {
		return time.Time{}, ErrUnavailable
	}
	return value, nil
}
