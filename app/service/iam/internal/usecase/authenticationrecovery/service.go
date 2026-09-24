// Package authenticationrecovery owns the purpose-limited IAM transaction
// used around destructive installation recovery. It is deliberately separate
// from the online identity-access use case: the normal authority is closed
// while this workflow reconciles and reopens it.
package authenticationrecovery

import (
	"context"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"strings"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

var (
	ErrInvalidArgument      = errors.New("IAM authentication recovery input is invalid")
	ErrForbidden            = errors.New("IAM authentication recovery is forbidden")
	ErrConflict             = errors.New("IAM authentication recovery conflicts with stored state")
	ErrUnavailable          = errors.New("IAM authentication recovery is unavailable")
	ErrRetryableTransaction = errors.New("IAM authentication recovery transaction is retryable")
)

const (
	defaultMaxTransactionAttempts = 5
	recoveryActorID               = "iam-authentication-recovery"
)

type Config struct {
	MaxTransactionAttempts int
}

type Repository interface {
	WithinAuthenticationRecoveryTransaction(
		context.Context,
		func(context.Context, Transaction) error,
	) error
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	CloseAuthentication(context.Context, CloseMutation) (installationv1.AuthenticationRecoveryClosure, error)
	ReconcileAuthentication(context.Context, ReconcileMutation) (installationv1.AuthenticationRecoveryClosure, error)
	ReopenAuthentication(context.Context, ReopenMutation) (installationv1.AuthenticationRecoveryCompletion, error)
}

type CloseMutation struct {
	Intent       installationv1.AuthenticationRecoveryIntent
	IntentDigest string
	ClosedEvent  auditv1.Event
}

type ReconcileMutation struct {
	Closure         installationv1.AuthenticationRecoveryClosure
	ClosureDigest   string
	ClosedEvent     auditv1.Event
	ReconciledEvent auditv1.Event
}

type ReopenMutation struct {
	Closure       installationv1.AuthenticationRecoveryClosure
	ClosureDigest string
	ReopenedEvent auditv1.Event
}

type Service struct {
	repository             Repository
	maxTransactionAttempts int
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("IAM authentication recovery repository is required")
	}
	if config.MaxTransactionAttempts == 0 {
		config.MaxTransactionAttempts = defaultMaxTransactionAttempts
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("IAM authentication recovery transaction attempts must be between one and ten")
	}
	return &Service{repository: repository, maxTransactionAttempts: config.MaxTransactionAttempts}, nil
}

func (service *Service) Close(ctx context.Context, intent installationv1.AuthenticationRecoveryIntent) (installationv1.AuthenticationRecoveryClosure, error) {
	if installationv1.ValidateAuthenticationRecoveryIntent(intent) != nil {
		return installationv1.AuthenticationRecoveryClosure{}, ErrInvalidArgument
	}
	digest, err := installationv1.AuthenticationRecoveryIntentDigest(intent)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, ErrInvalidArgument
	}
	var result installationv1.AuthenticationRecoveryClosure
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		event, err := newEvent(intent.InstallationID, intent.CommandID, digest,
			auditv1.ActionIAMAuthenticationRecoveryClosed, now)
		if err != nil {
			return err
		}
		result, err = tx.CloseAuthentication(ctx, CloseMutation{
			Intent: intent, IntentDigest: digest, ClosedEvent: event,
		})
		return err
	})
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, err
	}
	if installationv1.ValidateAuthenticationRecoveryClosureForIntent(result, intent) != nil {
		return installationv1.AuthenticationRecoveryClosure{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) Reconcile(ctx context.Context, closure installationv1.AuthenticationRecoveryClosure) (installationv1.AuthenticationRecoveryClosure, error) {
	if installationv1.ValidateAuthenticationRecoveryClosure(closure) != nil {
		return installationv1.AuthenticationRecoveryClosure{}, ErrInvalidArgument
	}
	digest, err := installationv1.AuthenticationRecoveryClosureDigest(closure)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, ErrInvalidArgument
	}
	var result installationv1.AuthenticationRecoveryClosure
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		closed, err := newEvent(closure.InstallationID, closure.CommandID, closure.RecoveryIntentDigest,
			auditv1.ActionIAMAuthenticationRecoveryClosed, closure.ClosedAt)
		if err != nil {
			return err
		}
		reconciled, err := newEvent(closure.InstallationID, closure.CommandID, digest,
			auditv1.ActionIAMAuthenticationRecoveryReconciled, now)
		if err != nil {
			return err
		}
		result, err = tx.ReconcileAuthentication(ctx, ReconcileMutation{
			Closure: closure, ClosureDigest: digest, ClosedEvent: closed, ReconciledEvent: reconciled,
		})
		return err
	})
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, err
	}
	if result != closure {
		return installationv1.AuthenticationRecoveryClosure{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) Reopen(ctx context.Context, closure installationv1.AuthenticationRecoveryClosure) (installationv1.AuthenticationRecoveryCompletion, error) {
	if installationv1.ValidateAuthenticationRecoveryClosure(closure) != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, ErrInvalidArgument
	}
	digest, err := installationv1.AuthenticationRecoveryClosureDigest(closure)
	if err != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, ErrInvalidArgument
	}
	var result installationv1.AuthenticationRecoveryCompletion
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		event, err := newEvent(closure.InstallationID, closure.CommandID, digest,
			auditv1.ActionIAMAuthenticationRecoveryReopened, now)
		if err != nil {
			return err
		}
		result, err = tx.ReopenAuthentication(ctx, ReopenMutation{
			Closure: closure, ClosureDigest: digest, ReopenedEvent: event,
		})
		return err
	})
	if err != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, err
	}
	if installationv1.ValidateAuthenticationRecoveryCompletionForClosure(result, closure) != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) withinTransaction(ctx context.Context, callback func(context.Context, Transaction) error) error {
	if service == nil || service.repository == nil {
		return ErrUnavailable
	}
	if ctx == nil || callback == nil {
		return ErrInvalidArgument
	}
	var transactionErr error
	for attempt := 0; attempt < service.maxTransactionAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		transactionErr = service.repository.WithinAuthenticationRecoveryTransaction(ctx, callback)
		if transactionErr == nil || !errors.Is(transactionErr, ErrRetryableTransaction) {
			return transactionErr
		}
		if attempt+1 < service.maxTransactionAttempts {
			ceiling := min(50*time.Millisecond<<attempt, 200*time.Millisecond)
			delay := ceiling/2 + time.Duration(randv2.Int64N(int64(ceiling/2)))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("IAM authentication recovery attempts exhausted: %w", transactionErr)
}

func transactionTime(ctx context.Context, tx Transaction) (time.Time, error) {
	if tx == nil {
		return time.Time{}, ErrUnavailable
	}
	value, err := tx.TransactionTime(ctx)
	if err != nil || value.IsZero() || value.Location() != time.UTC || value != value.Round(0) || value.Nanosecond()%1_000 != 0 {
		return time.Time{}, ErrUnavailable
	}
	return value, nil
}

func newEvent(installationID, commandID, requestDigest string, action auditv1.Action, occurredAt time.Time) (auditv1.Event, error) {
	suffix, found := strings.CutPrefix(commandID, "cmd-")
	if !found {
		return auditv1.Event{}, ErrInvalidArgument
	}
	stage := ""
	switch action {
	case auditv1.ActionIAMAuthenticationRecoveryClosed:
		stage = "closed"
	case auditv1.ActionIAMAuthenticationRecoveryReconciled:
		stage = "reconciled"
	case auditv1.ActionIAMAuthenticationRecoveryReopened:
		stage = "reopened"
	default:
		return auditv1.Event{}, ErrInvalidArgument
	}
	event := auditv1.Event{
		APIVersion:     auditv1.APIVersion,
		Kind:           "AuditEvent",
		EventID:        auditv1.EventID("event-auth-recovery-" + stage + "-" + suffix),
		InstallationID: installationID,
		Actor:          auditv1.ActorReference{Type: auditv1.ActorSystem, ID: recoveryActorID},
		Action:         action,
		Target:         auditv1.TargetReference{Kind: auditv1.TargetInstallation, ID: installationID},
		Result:         auditv1.ResultSucceeded,
		RequestDigest:  requestDigest,
		RequestID:      commandID,
		CorrelationID:  commandID,
		OccurredAt:     occurredAt,
	}
	if auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
		return auditv1.Event{}, ErrUnavailable
	}
	return event, nil
}
