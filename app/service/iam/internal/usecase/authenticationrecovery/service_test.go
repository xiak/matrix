package authenticationrecovery

import (
	"context"
	"errors"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

type recoveryTestRepository struct {
	transaction *recoveryTestTransaction
	failures    int
	attempts    int
}

func (repository *recoveryTestRepository) WithinAuthenticationRecoveryTransaction(
	ctx context.Context,
	callback func(context.Context, Transaction) error,
) error {
	repository.attempts++
	if repository.failures > 0 {
		repository.failures--
		return ErrRetryableTransaction
	}
	return callback(ctx, repository.transaction)
}

type recoveryTestTransaction struct {
	now       time.Time
	close     func(CloseMutation) (installationv1.AuthenticationRecoveryClosure, error)
	reconcile func(ReconcileMutation) (installationv1.AuthenticationRecoveryClosure, error)
	reopen    func(ReopenMutation) (installationv1.AuthenticationRecoveryCompletion, error)
}

func (transaction *recoveryTestTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}

func (transaction *recoveryTestTransaction) CloseAuthentication(
	_ context.Context,
	mutation CloseMutation,
) (installationv1.AuthenticationRecoveryClosure, error) {
	if transaction.close == nil {
		return installationv1.AuthenticationRecoveryClosure{}, ErrUnavailable
	}
	return transaction.close(mutation)
}

func (transaction *recoveryTestTransaction) ReconcileAuthentication(
	_ context.Context,
	mutation ReconcileMutation,
) (installationv1.AuthenticationRecoveryClosure, error) {
	if transaction.reconcile == nil {
		return installationv1.AuthenticationRecoveryClosure{}, ErrUnavailable
	}
	return transaction.reconcile(mutation)
}

func (transaction *recoveryTestTransaction) ReopenAuthentication(
	_ context.Context,
	mutation ReopenMutation,
) (installationv1.AuthenticationRecoveryCompletion, error) {
	if transaction.reopen == nil {
		return installationv1.AuthenticationRecoveryCompletion{}, ErrUnavailable
	}
	return transaction.reopen(mutation)
}

func TestAuthenticationRecoveryCloseBindsExactIntentAndAuditFact(t *testing.T) {
	intent := validRecoveryIntent()
	now := time.Date(2026, 9, 21, 4, 5, 6, 789000, time.UTC)
	transaction := &recoveryTestTransaction{now: now}
	transaction.close = func(mutation CloseMutation) (installationv1.AuthenticationRecoveryClosure, error) {
		digest, err := installationv1.AuthenticationRecoveryIntentDigest(intent)
		if err != nil {
			t.Fatal(err)
		}
		if mutation.Intent != intent || mutation.IntentDigest != digest {
			t.Fatal("close mutation differs from the exact recovery intent")
		}
		assertRecoveryEvent(t, mutation.ClosedEvent, intent.InstallationID, intent.CommandID,
			digest, auditv1.ActionIAMAuthenticationRecoveryClosed, now)
		return closureFor(intent, digest, now), nil
	}
	service := newRecoveryTestService(t, transaction)

	closure, err := service.Close(t.Context(), intent)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := installationv1.AuthenticationRecoveryIntentDigest(intent)
	if closure != closureFor(intent, digest, now) {
		t.Fatal("close returned another closure")
	}
}

func TestAuthenticationRecoveryReconcileReplaysExactClosedFact(t *testing.T) {
	intent := validRecoveryIntent()
	intentDigest, _ := installationv1.AuthenticationRecoveryIntentDigest(intent)
	closedAt := time.Date(2026, 9, 21, 4, 5, 6, 123000, time.UTC)
	closure := closureFor(intent, intentDigest, closedAt)
	closureDigest, _ := installationv1.AuthenticationRecoveryClosureDigest(closure)
	reconciledAt := closedAt.Add(time.Minute)
	transaction := &recoveryTestTransaction{now: reconciledAt}
	transaction.reconcile = func(mutation ReconcileMutation) (installationv1.AuthenticationRecoveryClosure, error) {
		if mutation.Closure != closure || mutation.ClosureDigest != closureDigest {
			t.Fatal("reconcile mutation differs from the exact closure")
		}
		assertRecoveryEvent(t, mutation.ClosedEvent, intent.InstallationID, intent.CommandID,
			intentDigest, auditv1.ActionIAMAuthenticationRecoveryClosed, closedAt)
		assertRecoveryEvent(t, mutation.ReconciledEvent, intent.InstallationID, intent.CommandID,
			closureDigest, auditv1.ActionIAMAuthenticationRecoveryReconciled, reconciledAt)
		return closure, nil
	}
	service := newRecoveryTestService(t, transaction)

	result, err := service.Reconcile(t.Context(), closure)
	if err != nil {
		t.Fatal(err)
	}
	if result != closure {
		t.Fatal("reconcile did not return the exact source closure")
	}
}

func TestAuthenticationRecoveryReopenBindsCompletionAndFencingFact(t *testing.T) {
	intent := validRecoveryIntent()
	intentDigest, _ := installationv1.AuthenticationRecoveryIntentDigest(intent)
	closedAt := time.Date(2026, 9, 21, 4, 5, 6, 123000, time.UTC)
	closure := closureFor(intent, intentDigest, closedAt)
	closureDigest, _ := installationv1.AuthenticationRecoveryClosureDigest(closure)
	completedAt := closedAt.Add(2 * time.Minute)
	transaction := &recoveryTestTransaction{now: completedAt}
	transaction.reopen = func(mutation ReopenMutation) (installationv1.AuthenticationRecoveryCompletion, error) {
		if mutation.Closure != closure || mutation.ClosureDigest != closureDigest {
			t.Fatal("reopen mutation differs from the exact closure")
		}
		assertRecoveryEvent(t, mutation.ReopenedEvent, intent.InstallationID, intent.CommandID,
			closureDigest, auditv1.ActionIAMAuthenticationRecoveryReopened, completedAt)
		return installationv1.AuthenticationRecoveryCompletion{
			APIVersion:     installationv1.AuthenticationRecoveryAPIVersion,
			Kind:           installationv1.AuthenticationRecoveryCompletionKind,
			Purpose:        installationv1.AuthenticationRecoveryPurpose,
			InstallationID: intent.InstallationID,
			Epoch:          intent.Epoch,
			State:          installationv1.AuthenticationRecoveryStateReopened,
			CommandID:      intent.CommandID,
			ClosureDigest:  closureDigest,
			CompletedAt:    completedAt,
		}, nil
	}
	service := newRecoveryTestService(t, transaction)

	completion, err := service.Reopen(t.Context(), closure)
	if err != nil {
		t.Fatal(err)
	}
	if completion.ClosureDigest != closureDigest || completion.CompletedAt != completedAt {
		t.Fatal("reopen returned an unbound completion")
	}
}

func TestAuthenticationRecoveryRejectsInvalidInputAndForgedResults(t *testing.T) {
	intent := validRecoveryIntent()
	now := time.Date(2026, 9, 21, 4, 5, 6, 123000, time.UTC)
	repository := &recoveryTestRepository{transaction: &recoveryTestTransaction{now: now}}
	service, err := NewService(repository, Config{})
	if err != nil {
		t.Fatal(err)
	}
	invalid := intent
	invalid.CommandID = "cmd-forged"
	if _, err := service.Close(t.Context(), invalid); !errors.Is(err, ErrInvalidArgument) || repository.attempts != 0 {
		t.Fatalf("invalid close error = %v, attempts = %d", err, repository.attempts)
	}

	intentDigest, _ := installationv1.AuthenticationRecoveryIntentDigest(intent)
	repository.transaction.close = func(mutation CloseMutation) (installationv1.AuthenticationRecoveryClosure, error) {
		forged := closureFor(intent, mutation.IntentDigest, now)
		forged.InstallationID = "mxi-ffffffffffffffffffffffffffffffff"
		return forged, nil
	}
	if _, err := service.Close(t.Context(), intent); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forged close result error = %v", err)
	}

	closure := closureFor(intent, intentDigest, now)
	repository.transaction.reconcile = func(ReconcileMutation) (installationv1.AuthenticationRecoveryClosure, error) {
		forged := closure
		forged.Epoch++
		return forged, nil
	}
	if _, err := service.Reconcile(t.Context(), closure); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forged reconcile result error = %v", err)
	}

	repository.transaction.reopen = func(mutation ReopenMutation) (installationv1.AuthenticationRecoveryCompletion, error) {
		return installationv1.AuthenticationRecoveryCompletion{
			APIVersion:     installationv1.AuthenticationRecoveryAPIVersion,
			Kind:           installationv1.AuthenticationRecoveryCompletionKind,
			Purpose:        installationv1.AuthenticationRecoveryPurpose,
			InstallationID: intent.InstallationID,
			Epoch:          intent.Epoch,
			State:          installationv1.AuthenticationRecoveryStateReopened,
			CommandID:      intent.CommandID,
			ClosureDigest:  mutation.ClosureDigest,
			CompletedAt:    closure.ClosedAt,
		}, nil
	}
	if _, err := service.Reopen(t.Context(), closure); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forged reopen result error = %v", err)
	}
}

func TestAuthenticationRecoveryRetriesOnlySerializableFailures(t *testing.T) {
	intent := validRecoveryIntent()
	now := time.Date(2026, 9, 21, 4, 5, 6, 123000, time.UTC)
	repository := &recoveryTestRepository{failures: 1, transaction: &recoveryTestTransaction{now: now}}
	repository.transaction.close = func(mutation CloseMutation) (installationv1.AuthenticationRecoveryClosure, error) {
		return closureFor(intent, mutation.IntentDigest, now), nil
	}
	service, err := NewService(repository, Config{MaxTransactionAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Close(t.Context(), intent); err != nil || repository.attempts != 2 {
		t.Fatalf("retry close error = %v, attempts = %d", err, repository.attempts)
	}

	repository.attempts = 0
	repository.transaction.close = func(CloseMutation) (installationv1.AuthenticationRecoveryClosure, error) {
		return installationv1.AuthenticationRecoveryClosure{}, ErrConflict
	}
	if _, err := service.Close(t.Context(), intent); !errors.Is(err, ErrConflict) || repository.attempts != 1 {
		t.Fatalf("conflict close error = %v, attempts = %d", err, repository.attempts)
	}
}

func newRecoveryTestService(t *testing.T, transaction *recoveryTestTransaction) *Service {
	t.Helper()
	service, err := NewService(&recoveryTestRepository{transaction: transaction}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validRecoveryIntent() installationv1.AuthenticationRecoveryIntent {
	return installationv1.AuthenticationRecoveryIntent{
		APIVersion:          installationv1.AuthenticationRecoveryAPIVersion,
		Kind:                installationv1.AuthenticationRecoveryIntentKind,
		Purpose:             installationv1.AuthenticationRecoveryPurpose,
		InstallationID:      "mxi-0123456789abcdef0123456789abcdef",
		Epoch:               7,
		CommandID:           "cmd-11111111111111111111111111111111",
		BackupID:            "backup-22222222222222222222222222222222",
		BackupDigest:        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		SourceReleaseID:     "matrix-v0.0.38-444444444444",
		SourceReleaseDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		TargetReleaseID:     "matrix-v0.0.39-666666666666",
		TargetReleaseDigest: "sha256:7777777777777777777777777777777777777777777777777777777777777777",
		TOTPCustodyDigest:   "sha256:8888888888888888888888888888888888888888888888888888888888888888",
	}
}

func closureFor(
	intent installationv1.AuthenticationRecoveryIntent,
	intentDigest string,
	closedAt time.Time,
) installationv1.AuthenticationRecoveryClosure {
	return installationv1.AuthenticationRecoveryClosure{
		APIVersion:           installationv1.AuthenticationRecoveryAPIVersion,
		Kind:                 installationv1.AuthenticationRecoveryClosureKind,
		Purpose:              installationv1.AuthenticationRecoveryPurpose,
		InstallationID:       intent.InstallationID,
		Epoch:                intent.Epoch,
		State:                installationv1.AuthenticationRecoveryStateClosed,
		CommandID:            intent.CommandID,
		BackupID:             intent.BackupID,
		BackupDigest:         intent.BackupDigest,
		RecoveryIntentDigest: intentDigest,
		TOTPCustodyDigest:    intent.TOTPCustodyDigest,
		ClosedAt:             closedAt,
	}
}

func assertRecoveryEvent(
	t *testing.T,
	event auditv1.Event,
	installationID string,
	commandID string,
	requestDigest string,
	action auditv1.Action,
	occurredAt time.Time,
) {
	t.Helper()
	stage := map[auditv1.Action]string{
		auditv1.ActionIAMAuthenticationRecoveryClosed:     "closed",
		auditv1.ActionIAMAuthenticationRecoveryReconciled: "reconciled",
		auditv1.ActionIAMAuthenticationRecoveryReopened:   "reopened",
	}[action]
	wantID := auditv1.EventID("event-auth-recovery-" + stage + "-11111111111111111111111111111111")
	if event.EventID != wantID || event.InstallationID != installationID || event.TenantID != "" ||
		event.Actor != (auditv1.ActorReference{Type: auditv1.ActorSystem, ID: recoveryActorID}) ||
		event.Action != action || event.Target != (auditv1.TargetReference{Kind: auditv1.TargetInstallation, ID: installationID}) ||
		event.Result != auditv1.ResultSucceeded || event.RequestDigest != requestDigest ||
		event.RequestID != commandID || event.CorrelationID != commandID || event.OccurredAt != occurredAt ||
		event.IAMDecisionID != "" || event.OperationID != "" || event.TraceParent != "" {
		t.Fatalf("unexpected recovery event: %#v", event)
	}
	if err := auditv1.ValidateEventForSource(auditv1.SourceIAM, event); err != nil {
		t.Fatalf("recovery event rejected: %v", err)
	}
}
