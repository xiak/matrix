package auditdispatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func NewUsecase(
	repository Repository,
	ingestor AuditIngestor,
	config Config,
) (*Usecase, error) {
	if repository == nil || ingestor == nil {
		return nil, errors.New("IAM Audit repository and ingestor are required")
	}
	if strings.TrimSpace(config.WorkerID) != config.WorkerID ||
		auditv1.ValidateID("workerId", config.WorkerID) != nil {
		return nil, errors.New("IAM Audit worker ID is invalid")
	}
	if config.LeaseDuration < time.Second || config.LeaseDuration > 5*time.Minute ||
		config.LeaseDuration%time.Second != 0 {
		return nil, errors.New("IAM Audit lease duration must be whole seconds between one second and five minutes")
	}
	if config.DeliveryTimeout <= 0 || config.DeliveryTimeout >= config.LeaseDuration {
		return nil, errors.New("IAM Audit delivery timeout must be positive and shorter than its lease")
	}
	if config.InitialBackoff < time.Second || config.InitialBackoff > 24*time.Hour ||
		config.InitialBackoff%time.Second != 0 {
		return nil, errors.New("IAM Audit initial backoff is invalid")
	}
	if config.MaxBackoff < config.InitialBackoff || config.MaxBackoff > 24*time.Hour ||
		config.MaxBackoff%time.Second != 0 {
		return nil, errors.New("IAM Audit maximum backoff is invalid")
	}
	if config.MaxAttempts < 1 || config.MaxAttempts > 100 {
		return nil, errors.New("IAM Audit maximum attempts must be between 1 and 100")
	}
	return &Usecase{repository: repository, ingestor: ingestor, config: config}, nil
}

func (usecase *Usecase) DispatchOnce(ctx context.Context) (Result, error) {
	if usecase == nil || usecase.repository == nil || usecase.ingestor == nil {
		return Result{}, errors.New("IAM Audit dispatch use case is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("IAM Audit dispatch context is nil")
	}
	claim, found, err := usecase.repository.Claim(
		ctx,
		usecase.config.WorkerID,
		usecase.config.LeaseDuration,
	)
	if err != nil {
		return Result{}, fmt.Errorf("claim IAM Audit event: %w", err)
	}
	if !found {
		return Result{}, nil
	}
	if err := ValidateClaim(claim); err != nil {
		return Result{}, fmt.Errorf("validate claimed IAM Audit event: %w", err)
	}
	result := Result{Claimed: true}
	deliveryContext, cancel := context.WithTimeout(ctx, usecase.config.DeliveryTimeout)
	deliveryErr := usecase.ingestor.Ingest(deliveryContext, claim.Event)
	cancel()
	completion := Completion{
		EventID: claim.EventID, WorkerID: usecase.config.WorkerID,
		FencingToken: claim.FencingToken,
	}
	switch {
	case deliveryErr == nil:
		completion.Outcome = OutcomeDelivered
		result.Delivered = true
	case terminalDeliveryError(deliveryErr):
		completion.Outcome = OutcomeDeadLetter
		completion.ErrorCode = "audit.delivery.rejected"
		result.DeadLetter = true
	case claim.Attempts >= usecase.config.MaxAttempts:
		completion.Outcome = OutcomeDeadLetter
		completion.ErrorCode = "audit.delivery.exhausted"
		result.DeadLetter = true
	default:
		completion.Outcome = OutcomeRetry
		completion.RetryDelay = backoff(usecase.config, claim.Attempts)
		result.Retried = true
	}
	if err := usecase.repository.Complete(ctx, completion); err != nil {
		return Result{}, fmt.Errorf("complete IAM Audit event: %w", err)
	}
	return result, nil
}

func (usecase *Usecase) Snapshot(ctx context.Context) (Snapshot, error) {
	if usecase == nil || usecase.repository == nil {
		return Snapshot{}, errors.New("IAM Audit dispatch use case is nil")
	}
	if ctx == nil {
		return Snapshot{}, errors.New("IAM Audit snapshot context is nil")
	}
	return usecase.repository.Snapshot(ctx)
}

// ValidateClaim binds the event chain to its independently stored IAM owner.
func ValidateClaim(claim Claim) error {
	var problems []error
	problems = append(problems,
		auditv1.ValidateEventForSource(auditv1.SourceIAM, claim.Event),
		auditv1.ValidateID("organizationId", string(claim.OrganizationID)),
	)
	if claim.InstallationID != "" {
		problems = append(problems, auditv1.ValidateID("installationId", claim.InstallationID))
	}
	if claim.EventID != claim.Event.EventID {
		problems = append(problems, errors.New("IAM Audit claim and event identity differ"))
	}
	if claim.Event.InstallationID != "" {
		if claim.InstallationID != claim.Event.InstallationID {
			problems = append(problems, errors.New("IAM Audit event differs from its owner's sealed installation"))
		}
	} else if string(claim.OrganizationID) != string(claim.Event.TenantID) {
		problems = append(problems, errors.New("IAM Audit event differs from its owning tenant"))
	}
	if claim.Attempts < 1 || claim.Attempts > 100 {
		problems = append(problems, errors.New("IAM Audit claim attempt is invalid"))
	}
	if claim.FencingToken < 1 || claim.FencingToken > 9007199254740991 {
		problems = append(problems, errors.New("IAM Audit claim fencing token is invalid"))
	}
	if claim.LeaseExpiresAt.IsZero() || claim.LeaseExpiresAt.Location() != time.UTC ||
		claim.LeaseExpiresAt != claim.LeaseExpiresAt.Round(0) ||
		claim.LeaseExpiresAt.Nanosecond()%1_000 != 0 {
		problems = append(problems, errors.New("IAM Audit claim lease expiry is invalid"))
	}
	return errors.Join(problems...)
}

func terminalDeliveryError(err error) bool {
	return errors.Is(err, ErrIngestInvalid) ||
		errors.Is(err, ErrIngestUnauthenticated) ||
		errors.Is(err, ErrIngestConflict)
}

func backoff(config Config, attempts int) time.Duration {
	delay := config.InitialBackoff
	for attempt := 1; attempt < attempts && delay < config.MaxBackoff; attempt++ {
		if delay > config.MaxBackoff/2 {
			return config.MaxBackoff
		}
		delay *= 2
	}
	if delay > config.MaxBackoff {
		return config.MaxBackoff
	}
	return delay
}
