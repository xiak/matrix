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
	InspectNewAuthentication(context.Context, installationv1.AuthenticationRecoveryIntent, string) (installationv1.AuthenticationRecoveryInspection, error)
	PrepareAuthenticationClose(context.Context, installationv1.AuthenticationRecoveryIntent, string) (installationv1.AuthenticationRecoverySecuritySnapshot, error)
	CloseAuthentication(context.Context, CloseMutation) (installationv1.AuthenticationRecoveryClosure, error)
	ReconcileAuthentication(context.Context, ReconcileMutation) (installationv1.AuthenticationRecoveryClosure, error)
	ReopenAuthentication(context.Context, ReopenMutation) (installationv1.AuthenticationRecoveryCompletion, error)
}

// Inspect accepts only a new, not-yet-closed command. The repository owns the
// new-only proof in the same serializable transaction as the live projection.
// Its result is intentionally smaller than the private replay snapshot and
// cannot authorize a later close or restoration without revalidation.
func (service *Service) Inspect(ctx context.Context, intent installationv1.AuthenticationRecoveryIntent) (installationv1.AuthenticationRecoveryInspection, error) {
	if installationv1.ValidateCurrentAuthenticationRecoveryIntent(intent) != nil {
		return installationv1.AuthenticationRecoveryInspection{}, ErrInvalidArgument
	}
	digest, err := installationv1.AuthenticationRecoveryIntentDigest(intent)
	if err != nil {
		return installationv1.AuthenticationRecoveryInspection{}, ErrInvalidArgument
	}
	var result installationv1.AuthenticationRecoveryInspection
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		inspection, err := tx.InspectNewAuthentication(ctx, intent, digest)
		if err != nil {
			return err
		}
		if installationv1.ValidateAuthenticationRecoveryInspectionForIntent(
			inspection, intent, inspection.BootstrapDigest,
		) != nil {
			return ErrUnavailable
		}
		result = inspection
		return nil
	})
	if err != nil {
		return installationv1.AuthenticationRecoveryInspection{}, err
	}
	return result, nil
}

type CloseMutation struct {
	Intent                 installationv1.AuthenticationRecoveryIntent
	IntentDigest           string
	ClosedEvent            auditv1.Event
	SecuritySnapshot       installationv1.AuthenticationRecoverySecuritySnapshot
	SecuritySnapshotDigest string
}

type ReconcileMutation struct {
	Closure          installationv1.AuthenticationRecoveryClosure
	ClosureDigest    string
	ClosedEvent      auditv1.Event
	ReconciledEvent  auditv1.Event
	SecuritySnapshot installationv1.AuthenticationRecoverySecuritySnapshot
}

type ReopenMutation struct {
	Closure          installationv1.AuthenticationRecoveryClosure
	ClosureDigest    string
	ReopenedEvent    auditv1.Event
	SecuritySnapshot installationv1.AuthenticationRecoverySecuritySnapshot
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

func (service *Service) Close(ctx context.Context, intent installationv1.AuthenticationRecoveryIntent) (installationv1.AuthenticationRecoveryClosureEnvelope, error) {
	if installationv1.ValidateCurrentAuthenticationRecoveryIntent(intent) != nil {
		return installationv1.AuthenticationRecoveryClosureEnvelope{}, ErrInvalidArgument
	}
	digest, err := installationv1.AuthenticationRecoveryIntentDigest(intent)
	if err != nil {
		return installationv1.AuthenticationRecoveryClosureEnvelope{}, ErrInvalidArgument
	}
	var result installationv1.AuthenticationRecoveryClosureEnvelope
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		// The SQL barrier, source qualification, unique Go encoding and seal
		// all belong to this transaction. No prepared result escapes a failed
		// commit; a serializable retry samples again with the original intent.
		snapshot, err := tx.PrepareAuthenticationClose(ctx, intent, digest)
		if err != nil {
			return err
		}
		if installationv1.ValidateAuthenticationRecoverySecuritySnapshot(snapshot) != nil ||
			snapshot.InstallationID != intent.InstallationID || snapshot.CommandID != intent.CommandID ||
			snapshot.Epoch != intent.Epoch || snapshot.RecoveryIntentDigest != digest ||
			snapshot.AuthenticationStateDigest != intent.AuthenticationStateDigest {
			return ErrUnavailable
		}
		snapshotDigest, err := installationv1.AuthenticationRecoverySecuritySnapshotDigest(snapshot)
		if err != nil {
			return ErrUnavailable
		}
		event, err := newEvent(intent.InstallationID, intent.CommandID, digest,
			auditv1.ActionIAMAuthenticationRecoveryClosed, snapshot.ClosedAt)
		if err != nil {
			return err
		}
		closure, err := tx.CloseAuthentication(ctx, CloseMutation{
			Intent: intent, IntentDigest: digest, ClosedEvent: event,
			SecuritySnapshot: snapshot, SecuritySnapshotDigest: snapshotDigest,
		})
		if err != nil {
			return err
		}
		result = installationv1.AuthenticationRecoveryClosureEnvelope{
			APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoveryClosureEnvelopeKind,
			Purpose: installationv1.AuthenticationRecoveryPurpose, Closure: closure, SecuritySnapshot: snapshot,
		}
		if installationv1.ValidateAuthenticationRecoveryClosureEnvelope(result) != nil ||
			installationv1.ValidateAuthenticationRecoveryClosureForIntent(closure, intent) != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return installationv1.AuthenticationRecoveryClosureEnvelope{}, err
	}
	return result, nil
}

func (service *Service) Reconcile(ctx context.Context, closure installationv1.AuthenticationRecoveryClosure, snapshot installationv1.AuthenticationRecoverySecuritySnapshot) (installationv1.AuthenticationRecoveryClosure, error) {
	if installationv1.ValidateAuthenticationRecoverySecuritySnapshotForClosure(snapshot, closure) != nil {
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
			Closure: closure, ClosureDigest: digest, ClosedEvent: closed, ReconciledEvent: reconciled, SecuritySnapshot: snapshot,
		})
		if err == nil && result != closure {
			return ErrUnavailable
		}
		return err
	})
	if err != nil {
		return installationv1.AuthenticationRecoveryClosure{}, err
	}
	return result, nil
}

func (service *Service) Reopen(ctx context.Context, closure installationv1.AuthenticationRecoveryClosure, snapshot installationv1.AuthenticationRecoverySecuritySnapshot) (installationv1.AuthenticationRecoveryCompletion, error) {
	if installationv1.ValidateAuthenticationRecoverySecuritySnapshotForClosure(snapshot, closure) != nil {
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
			Closure: closure, ClosureDigest: digest, ReopenedEvent: event, SecuritySnapshot: snapshot,
		})
		if err == nil && installationv1.ValidateAuthenticationRecoveryCompletionForClosure(result, closure) != nil {
			return ErrUnavailable
		}
		return err
	})
	if err != nil {
		return installationv1.AuthenticationRecoveryCompletion{}, err
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
