package auditlog

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
	"github.com/xiak/matrix/app/service/audit/internal/authority"
)

const (
	defaultMaxTransactionAttempts = 5
	maximumSequence               = uint64(9007199254740991)
)

func NewService(repository Repository, iam IAM, config Config) (*Service, error) {
	if repository == nil || iam == nil {
		return nil, errors.New("Audit repository and IAM client are required")
	}
	codec, err := authority.NewCursorCodec(config.CursorKey)
	if err != nil {
		return nil, errors.New("Audit cursor key is invalid")
	}
	if config.MaxTransactionAttempts == 0 {
		config.MaxTransactionAttempts = defaultMaxTransactionAttempts
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("Audit transaction attempts must be between one and ten")
	}
	if config.NewID == nil {
		config.NewID = newID
	}
	return &Service{repository: repository, iam: iam, config: config, cursors: codec}, nil
}

func (service *Service) withinTransaction(
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
	return fmt.Errorf("Audit transaction attempts exhausted: %w", transactionErr)
}

func newID(prefix string) (string, error) {
	if auditv1.ValidateID("idPrefix", prefix) != nil {
		return "", ErrUnavailable
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		clear(random)
		return "", ErrUnavailable
	}
	result := prefix + "-" + hex.EncodeToString(random)
	clear(random)
	if auditv1.ValidateID("generatedId", result) != nil {
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
	digest.Write([]byte("matrix.audit.request.v1\x00"))
	digest.Write([]byte(domain))
	digest.Write([]byte{0})
	digest.Write(encoded)
	clear(encoded)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func transactionTime(ctx context.Context, transaction Transaction) (time.Time, error) {
	if transaction == nil {
		return time.Time{}, ErrUnavailable
	}
	now, err := transaction.TransactionTime(ctx)
	if err != nil || now.IsZero() || now.Location() != time.UTC ||
		now != now.Round(0) || now.Nanosecond()%1_000 != 0 {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func sourceForIdentity(identity iamv1.ServiceIdentity) (auditv1.Source, error) {
	if iamv1.ValidateServiceIdentity(identity) != nil {
		return "", ErrUnavailable
	}
	switch identity.Purpose {
	case iamv1.ServiceIAM:
		return auditv1.SourceIAM, nil
	case iamv1.ServicePaaS:
		return auditv1.SourcePaaS, nil
	case iamv1.ServiceAudit:
		return auditv1.SourceAudit, nil
	default:
		return "", ErrUnauthenticated
	}
}

func actorForDecision(decision iamv1.AuthorizationDecision) (auditv1.ActorReference, error) {
	if iamv1.ValidateAuthorizationDecision(decision) != nil || !decision.Allowed || decision.Subject == nil ||
		decision.Subject.Type != iamv1.PrincipalUser {
		return auditv1.ActorReference{}, ErrUnavailable
	}
	actor := auditv1.ActorReference{
		Type: auditv1.ActorUser,
		ID:   auditv1.ActorID(decision.Subject.ID),
	}
	if auditv1.ValidateActor(actor) != nil {
		return auditv1.ActorReference{}, ErrUnavailable
	}
	return actor, nil
}
