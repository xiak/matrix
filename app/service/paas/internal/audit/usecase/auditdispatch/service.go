package auditdispatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

func NewUsecase(
	repository Repository,
	ingestor audit.Ingestor,
	config Config,
) (*Usecase, error) {
	if repository == nil || ingestor == nil {
		return nil, errors.New("Audit repository and ingestor are required")
	}
	if strings.TrimSpace(config.WorkerID) != config.WorkerID || config.WorkerID == "" ||
		len([]byte(config.WorkerID)) > 128 {
		return nil, errors.New("Audit worker ID is invalid")
	}
	if config.LeaseDuration < time.Second || config.LeaseDuration > 5*time.Minute ||
		config.LeaseDuration%time.Second != 0 {
		return nil, errors.New("Audit lease duration must be between one second and five minutes")
	}
	if config.DeliveryTimeout <= 0 || config.DeliveryTimeout >= config.LeaseDuration {
		return nil, errors.New("Audit delivery timeout must be positive and shorter than its lease")
	}
	if config.InitialBackoff <= 0 || config.InitialBackoff > 24*time.Hour {
		return nil, errors.New("Audit initial backoff is invalid")
	}
	if config.MaxBackoff < config.InitialBackoff || config.MaxBackoff > 24*time.Hour {
		return nil, errors.New("Audit maximum backoff is invalid")
	}
	if config.MaxAttempts < 1 || config.MaxAttempts > 100 {
		return nil, errors.New("Audit maximum attempts must be between 1 and 100")
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Usecase{repository: repository, ingestor: ingestor, config: config}, nil
}

func (usecase *Usecase) DispatchOnce(ctx context.Context) (Result, error) {
	if usecase == nil || usecase.repository == nil || usecase.ingestor == nil {
		return Result{}, errors.New("Audit dispatch use case is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("Audit dispatch context is nil")
	}
	claim, found, err := usecase.repository.Claim(
		ctx,
		usecase.config.WorkerID,
		usecase.config.LeaseDuration,
	)
	if err != nil {
		return Result{}, fmt.Errorf("claim Audit event: %w", err)
	}
	if !found {
		return Result{}, nil
	}
	if err := validateClaim(claim); err != nil {
		return Result{}, fmt.Errorf("validate claimed Audit event: %w", err)
	}
	result := Result{Claimed: true}
	deliveryContext, cancel := context.WithTimeout(ctx, usecase.config.DeliveryTimeout)
	deliveryErr := usecase.ingestor.Ingest(deliveryContext, claim.Event)
	cancel()
	completion := Completion{
		TenantID: claim.TenantID, EventID: claim.EventID,
		Stream: claim.Stream, WorkerID: usecase.config.WorkerID,
		FencingToken: claim.FencingToken,
	}
	if deliveryErr == nil {
		completion.Outcome = OutcomeDelivered
		result.Delivered = true
	} else if terminalDeliveryError(deliveryErr) {
		completion.Outcome = OutcomeDeadLetter
		completion.ErrorCode = "AUDIT_DELIVERY_REJECTED"
		result.DeadLetter = true
	} else if claim.Attempts >= usecase.config.MaxAttempts {
		completion.Outcome = OutcomeDeadLetter
		completion.ErrorCode = "AUDIT_DELIVERY_EXHAUSTED"
		result.DeadLetter = true
	} else {
		now := usecase.config.Now().UTC()
		if err := validateClock(now); err != nil {
			return Result{}, err
		}
		completion.Outcome = OutcomeRetry
		completion.RetryAt = now.Add(backoff(usecase.config, claim.Attempts))
		result.Retried = true
	}
	if err := usecase.repository.Complete(ctx, completion); err != nil {
		return Result{}, fmt.Errorf("complete Audit event: %w", err)
	}
	return result, nil
}

func (usecase *Usecase) Snapshot(ctx context.Context) (Snapshot, error) {
	if usecase == nil || usecase.repository == nil {
		return Snapshot{}, errors.New("Audit dispatch use case is nil")
	}
	if ctx == nil {
		return Snapshot{}, errors.New("Audit snapshot context is nil")
	}
	return usecase.repository.Snapshot(ctx)
}

func validateClaim(claim Claim) error {
	var problems []error
	problems = append(problems, audit.ValidateEvent(claim.Event))
	if claim.Stream != StreamAppHosting && claim.Stream != StreamManagedService {
		problems = append(problems, errors.New("Audit claim stream is invalid"))
	}
	if claim.TenantID != claim.Event.TenantID || claim.EventID != claim.Event.EventID {
		problems = append(problems, errors.New("Audit claim and event identity differ"))
	}
	if claim.Attempts < 1 || claim.Attempts > 100 {
		problems = append(problems, errors.New("Audit claim attempt is invalid"))
	}
	if claim.FencingToken < 1 {
		problems = append(problems, errors.New("Audit claim fencing token is invalid"))
	}
	if claim.LeaseExpiresAt.IsZero() {
		problems = append(problems, errors.New("Audit claim lease expiry is required"))
	}
	return errors.Join(problems...)
}

func terminalDeliveryError(err error) bool {
	return errors.Is(err, audit.ErrInvalid) ||
		errors.Is(err, audit.ErrUnauthenticated) ||
		errors.Is(err, audit.ErrConflict)
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

func validateClock(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) {
		return errors.New("Audit dispatcher clock must return UTC without a monotonic component")
	}
	return nil
}
