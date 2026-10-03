package accessanalysis

import (
	"errors"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestEvaluateFindsOnlyFullyObservedUnusedTargets(t *testing.T) {
	snapshot := fixture(t)
	active := snapshot.ObservedAt.Add(-24 * time.Hour)
	snapshot.Candidates = append(snapshot.Candidates,
		Candidate{Type: iamv1.AccessFindingUnusedPassword, Target: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: "user-unused"}, TargetResourceVersion: 2,
			CreatedAt: snapshot.ObservedAt.Add(-200 * 24 * time.Hour), ActivityRevision: 1},
		Candidate{Type: iamv1.AccessFindingUnusedAccessKey, Target: iamv1.ResourceReference{Kind: iamv1.ResourceAccessKey, ID: "key-used"}, TargetResourceVersion: 3,
			CreatedAt: snapshot.ObservedAt.Add(-200 * 24 * time.Hour), ActivityRevision: 4, LastActivityAt: &active},
		Candidate{Type: iamv1.AccessFindingUnusedRole, Target: iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: "role-new"}, TargetResourceVersion: 1,
			CreatedAt: snapshot.ObservedAt.Add(-20 * 24 * time.Hour), ActivityRevision: 1},
	)
	plan, err := Evaluate(snapshot)
	if err != nil || len(plan.Detections) != 1 || plan.Detections[0].Target.ID != "user-unused" || plan.Detections[0].ConditionGeneration != 1 || len(plan.Resolutions) != 0 {
		t.Fatal("unused target plan differs", plan, err)
	}

	snapshot.Coverage[0].State = iamv1.AccessObservationInsufficientCoverage
	snapshot.Coverage[0].Reason = iamv1.AccessObservationWindowIncomplete
	plan, err = Evaluate(snapshot)
	if err != nil || len(plan.Detections) != 0 || len(plan.Resolutions) != 0 {
		t.Fatal("incomplete coverage produced a finding", plan, err)
	}
}

func TestEvaluatePreservesMatchingArchivedFindingAndReplacesStaleEvidence(t *testing.T) {
	snapshot := fixture(t)
	candidate := Candidate{Type: iamv1.AccessFindingUnusedAccessKey, Target: iamv1.ResourceReference{Kind: iamv1.ResourceAccessKey, ID: "key-one"},
		TargetResourceVersion: 3, CreatedAt: snapshot.ObservedAt.Add(-200 * 24 * time.Hour), ActivityRevision: 2}
	snapshot.Candidates = []Candidate{candidate}
	finding := findingFor(snapshot, candidate, 4)
	finding.Status, finding.ResourceVersion = iamv1.AccessFindingArchived, 2
	snapshot.Findings = []iamv1.AccessFinding{finding}
	plan, err := Evaluate(snapshot)
	if err != nil || len(plan.Detections) != 0 || len(plan.Resolutions) != 0 {
		t.Fatal("matching archived finding was changed", plan, err)
	}

	snapshot.Candidates[0].TargetResourceVersion++
	plan, err = Evaluate(snapshot)
	if err != nil || len(plan.Resolutions) != 1 || len(plan.Detections) != 1 || plan.Detections[0].ConditionGeneration != 5 {
		t.Fatal("stale evidence was not replaced", plan, err)
	}
}

func TestEvaluateRecoveryEpochRequiresFloorAndReopensObservationWindow(t *testing.T) {
	snapshot := fixture(t)
	completed := snapshot.ObservedAt.Add(-100 * 24 * time.Hour)
	snapshot.RecoveryEpoch, snapshot.RecoveryCommandID, snapshot.RecoveryCompletedAt = 2, "restore-two", &completed
	for index := range 4 {
		snapshot.Coverage[index].ObservedFrom = &completed
	}
	candidate := Candidate{Type: iamv1.AccessFindingUnusedPassword, Target: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: "user-one"},
		TargetResourceVersion: 1, CreatedAt: completed.Add(-time.Hour), ActivityRevision: 1}
	snapshot.Candidates = []Candidate{candidate}
	old := findingFor(fixture(t), candidate, 1)
	snapshot.Findings = []iamv1.AccessFinding{old}
	plan, err := Evaluate(snapshot)
	if err != nil || len(plan.Resolutions) != 1 || len(plan.Detections) != 1 || plan.Detections[0].ConditionGeneration != 2 {
		t.Fatal("new recovery epoch did not replace old evidence", plan, err)
	}

	incomplete := snapshot
	incomplete.ObservedAt = completed.Add(30 * 24 * time.Hour)
	for index := range 4 {
		through := incomplete.ObservedAt
		incomplete.Coverage[index].ObservedThrough = &through
	}
	plan, err = Evaluate(incomplete)
	if err != nil || len(plan.Detections) != 0 || len(plan.Resolutions) != 0 {
		t.Fatal("post-restore partial window produced transitions", plan, err)
	}

	snapshot.RecoveryCommandID = ""
	if _, err := Evaluate(snapshot); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatal("unbound recovery epoch was accepted", err)
	}
}

func TestEvaluateResolvesActivityAndRejectsAmbiguousSnapshots(t *testing.T) {
	snapshot := fixture(t)
	candidate := Candidate{Type: iamv1.AccessFindingUnusedRole, Target: iamv1.ResourceReference{Kind: iamv1.ResourceRole, ID: "role-one"},
		TargetResourceVersion: 1, CreatedAt: snapshot.ObservedAt.Add(-200 * 24 * time.Hour), ActivityRevision: 1}
	finding := findingFor(snapshot, candidate, 1)
	snapshot.Findings = []iamv1.AccessFinding{finding}
	activity := snapshot.ObservedAt.Add(-time.Hour)
	candidate.ActivityRevision, candidate.LastActivityAt = 2, &activity
	snapshot.Candidates = []Candidate{candidate}
	plan, err := Evaluate(snapshot)
	if err != nil || len(plan.Resolutions) != 1 || len(plan.Detections) != 0 {
		t.Fatal("new activity did not resolve finding", plan, err)
	}

	snapshot = fixture(t)
	snapshot.Candidates = []Candidate{candidate, candidate}
	if _, err := Evaluate(snapshot); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatal("duplicate candidate was accepted", err)
	}
	snapshot = fixture(t)
	snapshot.Findings = []iamv1.AccessFinding{finding, finding}
	if _, err := Evaluate(snapshot); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatal("duplicate unresolved finding was accepted", err)
	}
}

func fixture(t *testing.T) Snapshot {
	t.Helper()
	now := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	analyzer := iamv1.AccessAnalyzer{APIVersion: iamv1.APIVersion, Kind: "AccessAnalyzer", ID: "analyzer-one", AccountID: "account-one",
		Type: iamv1.AccessAnalyzerUnusedAccess, Status: iamv1.AccessAnalyzerActive, UnusedAccessAgeDays: 90, ResourceVersion: 3,
		CreatedAt: now.Add(-200 * 24 * time.Hour), UpdatedAt: now.Add(-100 * 24 * time.Hour)}
	sources := iamv1.AccessObservationCoverageSources()
	coverage := make([]iamv1.AccessObservationCoverage, 0, len(sources))
	for index, source := range sources {
		if index < 4 {
			from, through := now.Add(-100*24*time.Hour), now
			coverage = append(coverage, iamv1.AccessObservationCoverage{Source: source, State: iamv1.AccessObservationComplete, ObservedFrom: &from, ObservedThrough: &through})
		} else {
			coverage = append(coverage, iamv1.AccessObservationCoverage{Source: source, State: iamv1.AccessObservationNotIncluded,
				Reason: iamv1.AccessObservationSourceNotImplemented})
		}
	}
	return Snapshot{Analyzer: analyzer, ObservedAt: now, Coverage: coverage, Batch: BatchScope{CycleComplete: true}}
}

func findingFor(snapshot Snapshot, candidate Candidate, generation uint64) iamv1.AccessFinding {
	window := snapshot.ObservedAt.Add(-time.Duration(snapshot.Analyzer.UnusedAccessAgeDays) * 24 * time.Hour)
	created := snapshot.ObservedAt.Add(-time.Hour)
	return iamv1.AccessFinding{APIVersion: iamv1.APIVersion, Kind: "AccessFinding", ID: "finding-one", AccountID: snapshot.Analyzer.AccountID,
		AnalyzerID: snapshot.Analyzer.ID, AnalyzerRevision: snapshot.Analyzer.ResourceVersion, Type: candidate.Type, Status: iamv1.AccessFindingActive,
		Target: candidate.Target, TargetResourceVersion: candidate.TargetResourceVersion, ConditionGeneration: generation,
		ActivityRevision: candidate.ActivityRevision, RecoveryEpoch: snapshot.RecoveryEpoch, RecoveryCommandID: snapshot.RecoveryCommandID,
		RecoveryCompletedAt: snapshot.RecoveryCompletedAt, WindowStartedAt: window, ObservedAt: snapshot.ObservedAt,
		LastActivityAt: candidate.LastActivityAt, ResourceVersion: 1, CreatedAt: created, UpdatedAt: created}
}
