package accessanalysis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const testSnapshotDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestScannerCommitsEvidenceBoundTransitionsAfterClaim(t *testing.T) {
	snapshot := fixture(t)
	candidate := Candidate{Type: iamv1.AccessFindingUnusedPassword, Target: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: "user-unused"},
		TargetResourceVersion: 2, CreatedAt: snapshot.ObservedAt.Add(-200 * 24 * time.Hour), ActivityRevision: 1}
	snapshot.Candidates = []Candidate{candidate}
	repository := &scannerRepository{claims: []Claim{{AttemptID: "generated-1", WorkerID: "scanner-one", Fence: 3,
		LeaseExpiresAt: snapshot.ObservedAt.Add(time.Minute), SnapshotDigest: testSnapshotDigest, Snapshot: snapshot}}}
	sequence := 0
	scanner, err := NewScanner(repository, func(string) (string, error) {
		sequence++
		return fmt.Sprintf("generated-%d", sequence), nil
	}, "scanner-one")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.ScanOnce(t.Context())
	if err != nil || !result.Claimed || result.Detections != 1 || result.Resolutions != 0 || len(repository.completions) != 1 {
		t.Fatal("scanner result differs", result, err)
	}
	completion := repository.completions[0]
	if len(completion.Detections) != 1 || completion.Detections[0].Finding.Target.ID != "user-unused" ||
		completion.Detections[0].Finding.RecoveryEpoch != 0 || completion.Detections[0].Finding.ResourceVersion != 1 {
		t.Fatal("finding evidence differs")
	}
	event := completion.Detections[0].Event
	if event.Action != auditv1.ActionIAMAccessFindingDetected || event.Actor != (auditv1.ActorReference{Type: auditv1.ActorSystem, ID: "iam.access-analyzer"}) ||
		event.IAMDecisionID != "" || event.CorrelationID != "generated-1" ||
		event.RequestDigest != analysisEventDigest(event.Action, "generated-1", completion.Detections[0].Finding.ID, testSnapshotDigest) ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil {
		t.Fatal("detection fact differs")
	}
}

func TestScannerCompletesClosedAccessKeyDisposition(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	claim := DispositionClaim{AttemptID: "generated-1", WorkerID: "scanner-one", Fence: 4,
		LeaseExpiresAt: now.Add(30 * time.Second), SnapshotDigest: testSnapshotDigest,
		Snapshot: DispositionSnapshot{AccountID: "account-one", AnalyzerID: "analyzer-one", AnalyzerRevision: 5,
			FindingID: "finding-one", FindingResourceVersion: 2, FindingCreatedAt: now.Add(-8 * 24 * time.Hour),
			ConditionGeneration: 1, TargetResourceVersion: 3, ActivityRevision: 1, AccessKeyID: "key-one",
			AccessKeyResourceVersion: 3, UserID: "user-one", EvaluatedAt: now}}
	repository := &scannerRepository{dispositionClaims: []DispositionClaim{claim}}
	generatedByPurpose := map[string]int{}
	scanner, err := NewScanner(repository, func(purpose string) (string, error) {
		if purpose == "access-disposition-attempt" {
			return claim.AttemptID, nil
		}
		generatedByPurpose[purpose]++
		return fmt.Sprintf("%s-%d", purpose, generatedByPurpose[purpose]), nil
	}, "scanner-one")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.DisposeOnce(t.Context())
	if err != nil || !result.Claimed || !result.Applied || len(repository.dispositionCompletions) != 1 {
		t.Fatal("disposition result differs", result, err)
	}
	completion := repository.dispositionCompletions[0]
	identifiers := []string{string(completion.KeyEventID), completion.KeyRequestID, string(completion.FindingEventID), completion.FindingRequestID}
	seen := map[string]struct{}{}
	for _, identifier := range identifiers {
		if _, duplicate := seen[identifier]; duplicate {
			t.Fatal("disposition reused an identifier", completion)
		}
		seen[identifier] = struct{}{}
	}
	if !strings.HasPrefix(string(completion.KeyEventID), "audit-event-") ||
		!strings.HasPrefix(string(completion.FindingEventID), "audit-event-") ||
		!strings.HasPrefix(completion.KeyRequestID, "access-disposition-request-") ||
		!strings.HasPrefix(completion.FindingRequestID, "access-disposition-request-") {
		t.Fatal("disposition identifiers differ", completion)
	}
}

func TestScannerFailsClosedAcrossClaimAndCompletionUncertainty(t *testing.T) {
	for _, scenario := range []string{"claim-commit-unknown", "bad-claim", "incomplete-snapshot", "completion-conflict", "completion-unknown"} {
		t.Run(scenario, func(t *testing.T) {
			snapshot := fixture(t)
			repository := &scannerRepository{claims: []Claim{{AttemptID: "generated-1", WorkerID: "scanner-one", Fence: 1,
				LeaseExpiresAt: snapshot.ObservedAt.Add(time.Minute), SnapshotDigest: testSnapshotDigest, Snapshot: snapshot}}}
			switch scenario {
			case "claim-commit-unknown":
				repository.claimCommitError = ErrUnavailable
			case "bad-claim":
				repository.claims[0].WorkerID = "other-worker"
			case "incomplete-snapshot":
				repository.claims[0].Snapshot.RecoveryEpoch = 1
			case "completion-conflict":
				repository.completeError = ErrStaleLease
			case "completion-unknown":
				repository.completeCommitError = ErrUnavailable
			}
			sequence := 0
			scanner, err := NewScanner(repository, func(string) (string, error) { sequence++; return fmt.Sprintf("generated-%d", sequence), nil }, "scanner-one")
			if err != nil {
				t.Fatal(err)
			}
			result, err := scanner.ScanOnce(t.Context())
			if err == nil || (scenario == "claim-commit-unknown" && result.Claimed) || len(repository.completions) != 0 {
				t.Fatal("uncertain scanner operation was accepted", result, err)
			}
		})
	}
}

func TestScannerResolvesOldEpochWithoutGrantingTargetAuthority(t *testing.T) {
	snapshot := fixture(t)
	candidate := Candidate{Type: iamv1.AccessFindingUnusedRole, Target: iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: "role-one"},
		TargetResourceVersion: 1, CreatedAt: snapshot.ObservedAt.Add(-200 * 24 * time.Hour), ActivityRevision: 1}
	old := findingFor(snapshot, candidate, 1)
	snapshot.Findings = []iamv1.AccessFinding{old}
	activity := snapshot.ObservedAt.Add(-time.Hour)
	candidate.ActivityRevision, candidate.LastActivityAt = 2, &activity
	snapshot.Candidates = []Candidate{candidate}
	repository := &scannerRepository{claims: []Claim{{AttemptID: "generated-1", WorkerID: "scanner-one", Fence: 1,
		LeaseExpiresAt: snapshot.ObservedAt.Add(time.Minute), SnapshotDigest: testSnapshotDigest, Snapshot: snapshot}}}
	sequence := 0
	scanner, _ := NewScanner(repository, func(string) (string, error) { sequence++; return fmt.Sprintf("generated-%d", sequence), nil }, "scanner-one")
	result, err := scanner.ScanOnce(t.Context())
	if err != nil || result.Resolutions != 1 || result.Detections != 0 || len(repository.completions) != 1 {
		t.Fatal(result, err)
	}
	resolution := repository.completions[0].Resolutions[0]
	if resolution.FindingID != old.ID || resolution.ExpectedResourceVersion != old.ResourceVersion ||
		resolution.Event.Action != auditv1.ActionIAMAccessFindingResolved || resolution.Event.Target.ID != string(old.ID) ||
		resolution.Event.IAMDecisionID != "" || !strings.HasPrefix(resolution.Event.RequestDigest, "sha256:") {
		t.Fatal("resolution escaped its finding boundary")
	}
}

func TestScannerRetriesWholeSerializableTransactionsWithStableIntent(t *testing.T) {
	for _, scenario := range []string{"claim", "completion"} {
		t.Run(scenario, func(t *testing.T) {
			snapshot := fixture(t)
			candidate := Candidate{Type: iamv1.AccessFindingUnusedPassword,
				Target:                iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: "user-unused"},
				TargetResourceVersion: 2, CreatedAt: snapshot.ObservedAt.Add(-200 * 24 * time.Hour), ActivityRevision: 1}
			snapshot.Candidates = []Candidate{candidate}
			retryCall := 1
			if scenario == "completion" {
				retryCall = 2
			}
			repository := &scannerRepository{
				claims: []Claim{{AttemptID: "generated-1", WorkerID: "scanner-one", Fence: 3,
					LeaseExpiresAt: snapshot.ObservedAt.Add(time.Minute), SnapshotDigest: testSnapshotDigest, Snapshot: snapshot}},
				transactionErrors: map[int]error{retryCall: ErrRetryableTransaction},
			}
			sequence := 0
			scanner, err := NewScanner(repository, func(string) (string, error) {
				sequence++
				return fmt.Sprintf("generated-%d", sequence), nil
			}, "scanner-one")
			if err != nil {
				t.Fatal(err)
			}
			result, err := scanner.ScanOnce(t.Context())
			if err != nil || !result.Claimed || result.Detections != 1 || len(repository.completions) != 1 {
				t.Fatal("retry did not commit one complete scan", result, err, repository.calls, len(repository.completions))
			}
			if scenario == "claim" {
				if repository.calls != 3 || len(repository.claimAttemptIDs) != 2 ||
					repository.claimAttemptIDs[0] != "generated-1" || repository.claimAttemptIDs[1] != "generated-1" {
					t.Fatal("claim retry changed its immutable attempt", repository.calls, repository.claimAttemptIDs)
				}
			} else if repository.calls != 3 || len(repository.claimAttemptIDs) != 1 || repository.claimAttemptIDs[0] != "generated-1" {
				t.Fatal("completion retry reclaimed or changed the scan", repository.calls, repository.claimAttemptIDs)
			}
		})
	}
}

func TestScannerSurvivesOriginalSerializableRetryBurstWithStableCompletion(t *testing.T) {
	snapshot := fixture(t)
	candidate := Candidate{Type: iamv1.AccessFindingUnusedPassword,
		Target:                iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: "user-unused"},
		TargetResourceVersion: 2, CreatedAt: snapshot.ObservedAt.Add(-200 * 24 * time.Hour), ActivityRevision: 1}
	snapshot.Candidates = []Candidate{candidate}
	repository := &scannerRepository{
		claims: []Claim{{AttemptID: "generated-1", WorkerID: "scanner-one", Fence: 3,
			LeaseExpiresAt: snapshot.ObservedAt.Add(time.Minute), SnapshotDigest: testSnapshotDigest, Snapshot: snapshot}},
		transactionErrors: map[int]error{2: ErrRetryableTransaction, 3: ErrRetryableTransaction, 4: ErrRetryableTransaction},
	}
	sequence := 0
	scanner, err := NewScanner(repository, func(string) (string, error) {
		sequence++
		return fmt.Sprintf("generated-%d", sequence), nil
	}, "scanner-one")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.ScanOnce(t.Context())
	if err != nil || !result.Claimed || result.Detections != 1 || repository.calls != 5 ||
		len(repository.claimAttemptIDs) != 1 || repository.claimAttemptIDs[0] != "generated-1" || len(repository.completions) != 1 {
		t.Fatal("serialization burst reclaimed or changed the completed scan", result, err,
			repository.calls, repository.claimAttemptIDs, len(repository.completions))
	}
}

func TestScannerBoundsSerializableRetriesAndHonorsCancellation(t *testing.T) {
	for _, scenario := range []string{"exhausted", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			snapshot := fixture(t)
			transactionErrors := make(map[int]error, maxTransactionAttempts)
			for attempt := 1; attempt <= maxTransactionAttempts; attempt++ {
				transactionErrors[attempt] = ErrRetryableTransaction
			}
			repository := &scannerRepository{
				claims: []Claim{{AttemptID: "generated-1", WorkerID: "scanner-one", Fence: 3,
					LeaseExpiresAt: snapshot.ObservedAt.Add(time.Minute), SnapshotDigest: testSnapshotDigest, Snapshot: snapshot}},
				transactionErrors: transactionErrors,
			}
			ctx := t.Context()
			if scenario == "canceled" {
				cancelable, cancel := context.WithCancel(ctx)
				ctx, repository.cancel, repository.cancelOnCall = cancelable, cancel, 1
			}
			scanner, err := NewScanner(repository, func(string) (string, error) { return "generated-1", nil }, "scanner-one")
			if err != nil {
				t.Fatal(err)
			}
			result, err := scanner.ScanOnce(ctx)
			if result.Claimed || len(repository.completions) != 0 {
				t.Fatal("failed transaction exposed an uncommitted result", result, len(repository.completions))
			}
			if scenario == "canceled" {
				if !errors.Is(err, context.Canceled) || repository.calls != 1 {
					t.Fatal("cancellation did not stop retry", err, repository.calls)
				}
			} else if !errors.Is(err, ErrRetryableTransaction) || repository.calls != maxTransactionAttempts {
				t.Fatal("retry exhaustion boundary differs", err, repository.calls)
			}
			for _, attemptID := range repository.claimAttemptIDs {
				if attemptID != "generated-1" {
					t.Fatal("retry generated a different scan intent", repository.claimAttemptIDs)
				}
			}
		})
	}
}

type scannerRepository struct {
	claims                 []Claim
	dispositionClaims      []DispositionClaim
	claimCommitError       error
	completeError          error
	completeCommitError    error
	transactionErrors      map[int]error
	completions            []Completion
	dispositionCompletions []DispositionCompletion
	claimAttemptIDs        []string
	dispositionAttemptIDs  []string
	calls                  int
	cancel                 context.CancelFunc
	cancelOnCall           int
}

func (*scannerRepository) Ready(context.Context) error { return nil }

func (repository *scannerRepository) WithinTransaction(ctx context.Context, callback func(context.Context, Transaction) error) error {
	repository.calls++
	tx := &scannerTransaction{repository: repository}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if err := repository.transactionErrors[repository.calls]; err != nil {
		if repository.cancel != nil && repository.cancelOnCall == repository.calls {
			repository.cancel()
		}
		return err
	}
	if repository.calls == 1 && repository.claimCommitError != nil {
		return repository.claimCommitError
	}
	if repository.calls > 1 && repository.completeCommitError != nil {
		return repository.completeCommitError
	}
	if tx.completed != nil {
		repository.completions = append(repository.completions, *tx.completed)
	}
	if tx.dispositionCompleted != nil {
		repository.dispositionCompletions = append(repository.dispositionCompletions, *tx.dispositionCompleted)
	}
	if tx.claimed {
		repository.claims = repository.claims[1:]
	}
	if tx.dispositionClaimed {
		repository.dispositionClaims = repository.dispositionClaims[1:]
	}
	return nil
}

type scannerTransaction struct {
	repository           *scannerRepository
	completed            *Completion
	claimed              bool
	dispositionCompleted *DispositionCompletion
	dispositionClaimed   bool
}

func (tx *scannerTransaction) Claim(_ context.Context, _ string, attempt string) (Claim, bool, error) {
	tx.repository.claimAttemptIDs = append(tx.repository.claimAttemptIDs, attempt)
	if len(tx.repository.claims) == 0 {
		return Claim{}, false, nil
	}
	claim := tx.repository.claims[0]
	tx.claimed = true
	return claim, true, nil
}

func (tx *scannerTransaction) Complete(_ context.Context, _ Claim, completion Completion) error {
	if tx.repository.completeError != nil {
		return tx.repository.completeError
	}
	tx.completed = &completion
	return nil
}

func (tx *scannerTransaction) ClaimDisposition(_ context.Context, _ string, attempt string) (DispositionClaim, bool, error) {
	tx.repository.dispositionAttemptIDs = append(tx.repository.dispositionAttemptIDs, attempt)
	if len(tx.repository.dispositionClaims) == 0 {
		return DispositionClaim{}, false, nil
	}
	claim := tx.repository.dispositionClaims[0]
	tx.dispositionClaimed = true
	return claim, true, nil
}

func (tx *scannerTransaction) CompleteDisposition(_ context.Context, _ DispositionClaim, completion DispositionCompletion) error {
	tx.dispositionCompleted = &completion
	return nil
}
