package authenticationrecovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

type recoveryTestRepository struct {
	transaction    *recoveryTestTransaction
	failures       int
	attempts       int
	commits        int
	commitFailures int
	commitError    error
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
	if err := callback(ctx, repository.transaction); err != nil {
		return err
	}
	if repository.commitFailures > 0 {
		repository.commitFailures--
		return ErrRetryableTransaction
	}
	if repository.commitError != nil {
		return repository.commitError
	}
	repository.commits++
	return nil
}

type recoveryTestTransaction struct {
	now       time.Time
	prepare   func(installationv1.AuthenticationRecoveryIntent, string) (installationv1.AuthenticationRecoverySecuritySnapshot, error)
	close     func(CloseMutation) (installationv1.AuthenticationRecoveryClosure, error)
	reconcile func(ReconcileMutation) (installationv1.AuthenticationRecoveryClosure, error)
	reopen    func(ReopenMutation) (installationv1.AuthenticationRecoveryCompletion, error)
}

func (transaction *recoveryTestTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}

func (transaction *recoveryTestTransaction) PrepareAuthenticationClose(_ context.Context, intent installationv1.AuthenticationRecoveryIntent, digest string) (installationv1.AuthenticationRecoverySecuritySnapshot, error) {
	if transaction.prepare != nil {
		return transaction.prepare(intent, digest)
	}
	return snapshotFor(intent, digest, transaction.now), nil
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
	if closure.Closure != closureFor(intent, digest, now) || installationv1.ValidateAuthenticationRecoveryClosureEnvelope(closure) != nil {
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
		if mutation.Closure != closure || mutation.ClosureDigest != closureDigest || !reflect.DeepEqual(mutation.SecuritySnapshot, snapshotFor(intent, intentDigest, closedAt)) {
			t.Fatal("reconcile mutation differs from the exact closure")
		}
		assertRecoveryEvent(t, mutation.ClosedEvent, intent.InstallationID, intent.CommandID,
			intentDigest, auditv1.ActionIAMAuthenticationRecoveryClosed, closedAt)
		assertRecoveryEvent(t, mutation.ReconciledEvent, intent.InstallationID, intent.CommandID,
			closureDigest, auditv1.ActionIAMAuthenticationRecoveryReconciled, reconciledAt)
		return closure, nil
	}
	service := newRecoveryTestService(t, transaction)

	result, err := service.Reconcile(t.Context(), closure, snapshotFor(intent, intentDigest, closedAt))
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
		if mutation.Closure != closure || mutation.ClosureDigest != closureDigest || !reflect.DeepEqual(mutation.SecuritySnapshot, snapshotFor(intent, intentDigest, closedAt)) {
			t.Fatal("reopen mutation differs from the exact closure")
		}
		assertRecoveryEvent(t, mutation.ReopenedEvent, intent.InstallationID, intent.CommandID,
			closureDigest, auditv1.ActionIAMAuthenticationRecoveryReopened, completedAt)
		return installationv1.AuthenticationRecoveryCompletion{
			APIVersion:             installationv1.AuthenticationRecoveryAPIVersion,
			Kind:                   installationv1.AuthenticationRecoveryCompletionKind,
			Purpose:                installationv1.AuthenticationRecoveryPurpose,
			InstallationID:         intent.InstallationID,
			Epoch:                  intent.Epoch,
			State:                  installationv1.AuthenticationRecoveryStateReopened,
			CommandID:              intent.CommandID,
			ClosureDigest:          closureDigest,
			CompletedAt:            completedAt,
			SecuritySnapshotDigest: closure.SecuritySnapshotDigest,
		}, nil
	}
	service := newRecoveryTestService(t, transaction)

	completion, err := service.Reopen(t.Context(), closure, snapshotFor(intent, intentDigest, closedAt))
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
	if _, err := service.Reconcile(t.Context(), closure, snapshotFor(intent, intentDigest, now)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forged reconcile result error = %v", err)
	}

	repository.transaction.reopen = func(mutation ReopenMutation) (installationv1.AuthenticationRecoveryCompletion, error) {
		return installationv1.AuthenticationRecoveryCompletion{
			APIVersion:             installationv1.AuthenticationRecoveryAPIVersion,
			Kind:                   installationv1.AuthenticationRecoveryCompletionKind,
			Purpose:                installationv1.AuthenticationRecoveryPurpose,
			InstallationID:         intent.InstallationID,
			Epoch:                  intent.Epoch,
			State:                  installationv1.AuthenticationRecoveryStateReopened,
			CommandID:              intent.CommandID,
			ClosureDigest:          mutation.ClosureDigest,
			CompletedAt:            closure.ClosedAt,
			SecuritySnapshotDigest: closure.SecuritySnapshotDigest,
		}, nil
	}
	if _, err := service.Reopen(t.Context(), closure, snapshotFor(intent, intentDigest, now)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forged reopen result error = %v", err)
	}
	if repository.commits != 0 {
		t.Fatal("forged recovery result was committed before validation")
	}
}

func TestAuthenticationRecoveryRequiresOriginalSnapshotBeforeTransaction(t *testing.T) {
	intent := validRecoveryIntent()
	digest, _ := installationv1.AuthenticationRecoveryIntentDigest(intent)
	now := time.Date(2026, 9, 25, 4, 5, 6, 0, time.UTC)
	closure := closureFor(intent, digest, now)
	for _, attack := range []struct {
		name   string
		change func(*installationv1.AuthenticationRecoverySecuritySnapshot)
	}{
		{"missing", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			*s = installationv1.AuthenticationRecoverySecuritySnapshot{}
		}},
		{"installation", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			s.InstallationID = "mxi-ffffffffffffffffffffffffffffffff"
		}},
		{"bootstrap", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			s.BootstrapDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{"epoch", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) { s.Epoch++ }},
		{"qualification", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			s.AuthenticationStateDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		}},
		{"subjects", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			s.Accounts[0].Users[0].UserID = "another-user"
		}},
	} {
		t.Run(attack.name, func(t *testing.T) {
			snapshot := snapshotFor(intent, digest, now)
			attack.change(&snapshot)
			repository := &recoveryTestRepository{transaction: &recoveryTestTransaction{now: now}}
			service, err := NewService(repository, Config{})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := service.Reconcile(t.Context(), closure, snapshot); !errors.Is(err, ErrInvalidArgument) || result != (installationv1.AuthenticationRecoveryClosure{}) {
				t.Fatalf("unbound reconcile snapshot accepted: %v", err)
			}
			if result, err := service.Reopen(t.Context(), closure, snapshot); !errors.Is(err, ErrInvalidArgument) || result != (installationv1.AuthenticationRecoveryCompletion{}) {
				t.Fatalf("unbound reopen snapshot accepted: %v", err)
			}
			if repository.attempts != 0 {
				t.Fatal("unbound snapshot opened a database transaction")
			}
		})
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

func TestAuthenticationRecoveryCloseRejectsInvalidPreparedSnapshotBeforeSeal(t *testing.T) {
	for _, variant := range []struct {
		name   string
		change func(*installationv1.AuthenticationRecoverySecuritySnapshot)
	}{
		{"missing-accounts", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) { s.Accounts = nil }},
		{"different-installation", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			s.InstallationID = "mxi-ffffffffffffffffffffffffffffffff"
		}},
		{"different-command", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			s.CommandID = "cmd-ffffffffffffffffffffffffffffffff"
		}},
		{"different-epoch", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) { s.Epoch++ }},
		{"different-qualification", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			s.AuthenticationStateDigest = s.BootstrapDigest
		}},
		{"different-intent", func(s *installationv1.AuthenticationRecoverySecuritySnapshot) {
			s.RecoveryIntentDigest = s.BootstrapDigest
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			intent := validRecoveryIntent()
			tx := &recoveryTestTransaction{now: time.Date(2026, 9, 25, 1, 2, 3, 0, time.UTC)}
			tx.prepare = func(input installationv1.AuthenticationRecoveryIntent, digest string) (installationv1.AuthenticationRecoverySecuritySnapshot, error) {
				snapshot := snapshotFor(input, digest, tx.now)
				variant.change(&snapshot)
				return snapshot, nil
			}
			tx.close = func(CloseMutation) (installationv1.AuthenticationRecoveryClosure, error) {
				t.Fatal("invalid prepared snapshot reached seal")
				return installationv1.AuthenticationRecoveryClosure{}, nil
			}
			repository := &recoveryTestRepository{transaction: tx}
			service, err := NewService(repository, Config{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Close(t.Context(), intent)
			if !errors.Is(err, ErrUnavailable) || result.Closure.CommandID != "" || result.SecuritySnapshot.Accounts != nil || repository.commits != 0 {
				t.Fatal("invalid prepared state escaped rollback", err)
			}
		})
	}
}

func TestAuthenticationRecoveryCloseResamplesAfterCommitConflict(t *testing.T) {
	intent := validRecoveryIntent()
	now := time.Date(2026, 9, 25, 1, 2, 3, 0, time.UTC)
	tx := &recoveryTestTransaction{now: now}
	repository := &recoveryTestRepository{transaction: tx, commitFailures: 1}
	var sealed []installationv1.AuthenticationRecoverySecuritySnapshot
	tx.prepare = func(input installationv1.AuthenticationRecoveryIntent, digest string) (installationv1.AuthenticationRecoverySecuritySnapshot, error) {
		if input != intent {
			t.Fatal("retry changed original intent")
		}
		return snapshotFor(input, digest, now.Add(time.Duration(repository.attempts)*time.Second)), nil
	}
	tx.close = func(mutation CloseMutation) (installationv1.AuthenticationRecoveryClosure, error) {
		sealed = append(sealed, mutation.SecuritySnapshot)
		digest, err := installationv1.AuthenticationRecoverySecuritySnapshotDigest(mutation.SecuritySnapshot)
		if err != nil || digest != mutation.SecuritySnapshotDigest || mutation.ClosedEvent.OccurredAt != mutation.SecuritySnapshot.ClosedAt {
			t.Fatal("seal did not bind this attempt's exact snapshot", err)
		}
		return closureFor(intent, mutation.IntentDigest, mutation.SecuritySnapshot.ClosedAt), nil
	}
	service, err := NewService(repository, Config{MaxTransactionAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Close(t.Context(), intent)
	if err != nil || repository.commits != 1 || len(sealed) != 2 || sealed[0].ClosedAt == sealed[1].ClosedAt || result.SecuritySnapshot.ClosedAt != sealed[1].ClosedAt {
		t.Fatal("commit retry exposed or reused an uncommitted snapshot", err)
	}
	// Exhausted serialization conflicts must not expose the candidate
	// envelope or automatically change the original command.
	repository.commitFailures, repository.commits, repository.attempts = 2, 0, 0
	result, err = service.Close(t.Context(), intent)
	if !errors.Is(err, ErrRetryableTransaction) || repository.commits != 0 || result.Closure.CommandID != "" || result.SecuritySnapshot.Accounts != nil {
		t.Fatal("exhausted commits leaked the candidate snapshot", err)
	}
	repository.commitFailures, repository.attempts, repository.commitError = 0, 0, ErrUnavailable
	result, err = service.Close(t.Context(), intent)
	if !errors.Is(err, ErrUnavailable) || repository.attempts != 1 || repository.commits != 0 || result.Closure.CommandID != "" || result.SecuritySnapshot.Accounts != nil {
		t.Fatal("unknown commit was retried or exposed a candidate result", err)
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
		APIVersion:                installationv1.AuthenticationRecoveryAPIVersion,
		Kind:                      installationv1.AuthenticationRecoveryIntentKind,
		Purpose:                   installationv1.AuthenticationRecoveryPurpose,
		InstallationID:            "mxi-0123456789abcdef0123456789abcdef",
		Epoch:                     7,
		CommandID:                 "cmd-11111111111111111111111111111111",
		BackupID:                  "backup-22222222222222222222222222222222",
		BackupDigest:              "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		SourceReleaseID:           "matrix-v0.0.38-444444444444",
		SourceReleaseDigest:       "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		TargetReleaseID:           "matrix-v0.0.39-666666666666",
		TargetReleaseDigest:       "sha256:7777777777777777777777777777777777777777777777777777777777777777",
		TOTPCustodyDigest:         "sha256:8888888888888888888888888888888888888888888888888888888888888888",
		AuthenticationStateDigest: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
	}
}

func closureFor(
	intent installationv1.AuthenticationRecoveryIntent,
	intentDigest string,
	closedAt time.Time,
) installationv1.AuthenticationRecoveryClosure {
	snapshotDigest, err := installationv1.AuthenticationRecoverySecuritySnapshotDigest(snapshotFor(intent, intentDigest, closedAt))
	if err != nil {
		panic(err)
	}
	return installationv1.AuthenticationRecoveryClosure{
		APIVersion:             installationv1.AuthenticationRecoveryAPIVersion,
		Kind:                   installationv1.AuthenticationRecoveryClosureKind,
		Purpose:                installationv1.AuthenticationRecoveryPurpose,
		InstallationID:         intent.InstallationID,
		Epoch:                  intent.Epoch,
		State:                  installationv1.AuthenticationRecoveryStateClosed,
		CommandID:              intent.CommandID,
		BackupID:               intent.BackupID,
		BackupDigest:           intent.BackupDigest,
		RecoveryIntentDigest:   intentDigest,
		TOTPCustodyDigest:      intent.TOTPCustodyDigest,
		ClosedAt:               closedAt,
		SecuritySnapshotDigest: snapshotDigest,
	}
}

func snapshotFor(intent installationv1.AuthenticationRecoveryIntent, digest string, now time.Time) installationv1.AuthenticationRecoverySecuritySnapshot {
	return installationv1.AuthenticationRecoverySecuritySnapshot{
		APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoverySecuritySnapshotKind,
		Purpose: installationv1.AuthenticationRecoveryPurpose, InstallationID: intent.InstallationID,
		BootstrapDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Epoch:           intent.Epoch, CommandID: intent.CommandID, RecoveryIntentDigest: digest, ClosedAt: now,
		AuthenticationStateDigest: intent.AuthenticationStateDigest,
		Accounts:                  []installationv1.AuthenticationRecoveryAccountReplay{{AccountID: "recovery-account", Users: []installationv1.AuthenticationRecoveryUserReplay{{UserID: "original-root", LastConsumedStep: -1}}}},
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
