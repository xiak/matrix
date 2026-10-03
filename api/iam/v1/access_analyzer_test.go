package iamv1

import (
	"testing"
	"time"
)

func TestAccessAnalyzerAndFindingContractsRejectInventedAuthority(t *testing.T) {
	now := time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)
	created := now.Add(-180 * 24 * time.Hour)
	analyzer := AccessAnalyzer{APIVersion: APIVersion, Kind: "AccessAnalyzer", ID: "analyzer-one", AccountID: "account-one",
		Type: AccessAnalyzerUnusedAccess, Status: AccessAnalyzerActive, UnusedAccessAgeDays: DefaultUnusedAccessAgeDays,
		ResourceVersion: 1, CreatedAt: created, UpdatedAt: created}
	if err := ValidateAccessAnalyzer(analyzer); err != nil {
		t.Fatal("validate access analyzer", err)
	}
	finding := AccessFinding{APIVersion: APIVersion, Kind: "AccessFinding", ID: "finding-one", AccountID: analyzer.AccountID,
		AnalyzerID: analyzer.ID, AnalyzerRevision: analyzer.ResourceVersion, Type: AccessFindingUnusedAccessKey, Status: AccessFindingActive,
		Target: ResourceReference{Kind: ResourceAccessKey, ID: "key-one"}, TargetResourceVersion: 2, ConditionGeneration: 1,
		ActivityRevision: 4, WindowStartedAt: now.Add(-90 * 24 * time.Hour), ObservedAt: now, ResourceVersion: 1,
		CreatedAt: now, UpdatedAt: now}
	if err := ValidateAccessFinding(finding); err != nil {
		t.Fatal("validate access finding", err)
	}
	for name, mutate := range map[string]func(*AccessFinding){
		"wrong target":        func(value *AccessFinding) { value.Target.Kind = ResourceUser },
		"activity in window":  func(value *AccessFinding) { at := value.WindowStartedAt; value.LastActivityAt = &at },
		"invented decision":   func(value *AccessFinding) { value.Target.ID = "" },
		"resolved without at": func(value *AccessFinding) { value.Status = AccessFindingResolved },
	} {
		t.Run(name, func(t *testing.T) {
			value := finding
			mutate(&value)
			if ValidateAccessFinding(value) == nil {
				t.Fatal("invalid finding was accepted")
			}
		})
	}
}

func TestAccessObservationCoverageKeepsUnknownAndExcludedDistinct(t *testing.T) {
	now := time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)
	start := now.Add(-90 * 24 * time.Hour)
	coverage := []AccessObservationCoverage{
		{Source: "IAM_PASSWORD_SESSIONS", State: AccessObservationComplete, ObservedFrom: &start, ObservedThrough: &now},
		{Source: "IAM_ACCESS_KEY_AUTHORIZATIONS", State: AccessObservationComplete, ObservedFrom: &start, ObservedThrough: &now},
		{Source: "IAM_ROLE_SESSIONS", State: AccessObservationComplete, ObservedFrom: &start, ObservedThrough: &now},
		{Source: "IAM_ROLE_AUTHORIZATIONS", State: AccessObservationInsufficientCoverage, ObservedFrom: &start, ObservedThrough: &now, Reason: AccessObservationHistoricalUnknown},
		{Source: "PAAS_RESULTS", State: AccessObservationNotIncluded, Reason: AccessObservationSourceNotImplemented},
		{Source: "EXTERNAL_FEDERATION", State: AccessObservationNotIncluded, Reason: AccessObservationSourceNotImplemented},
	}
	if err := ValidateAccessObservationCoverage(coverage, now); err != nil {
		t.Fatal("validate access observation coverage", err)
	}
	coverage[3].State = AccessObservationComplete
	if ValidateAccessObservationCoverage(coverage, now) == nil {
		t.Fatal("complete coverage retained an uncertainty reason")
	}
}

func TestAccessAnalyzerDirectoriesAreAccountBoundAndOrdered(t *testing.T) {
	now := time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)
	start := now.Add(-90 * 24 * time.Hour)
	analyzer := AccessAnalyzer{APIVersion: APIVersion, Kind: "AccessAnalyzer", ID: "analyzer-one", AccountID: "account-one",
		Type: AccessAnalyzerUnusedAccess, Status: AccessAnalyzerActive, UnusedAccessAgeDays: DefaultUnusedAccessAgeDays,
		ResourceVersion: 1, CreatedAt: start, UpdatedAt: start}
	coverage := []AccessObservationCoverage{
		{Source: "IAM_PASSWORD_SESSIONS", State: AccessObservationComplete, ObservedFrom: &start, ObservedThrough: &now},
		{Source: "IAM_ACCESS_KEY_AUTHORIZATIONS", State: AccessObservationComplete, ObservedFrom: &start, ObservedThrough: &now},
		{Source: "IAM_ROLE_SESSIONS", State: AccessObservationComplete, ObservedFrom: &start, ObservedThrough: &now},
		{Source: "IAM_ROLE_AUTHORIZATIONS", State: AccessObservationComplete, ObservedFrom: &start, ObservedThrough: &now},
		{Source: "PAAS_RESULTS", State: AccessObservationNotIncluded, Reason: AccessObservationSourceNotImplemented},
		{Source: "EXTERNAL_FEDERATION", State: AccessObservationNotIncluded, Reason: AccessObservationSourceNotImplemented},
	}
	finding := AccessFinding{APIVersion: APIVersion, Kind: "AccessFinding", ID: "finding-one", AccountID: analyzer.AccountID,
		AnalyzerID: analyzer.ID, AnalyzerRevision: 1, Type: AccessFindingUnusedPassword, Status: AccessFindingActive,
		Target: ResourceReference{Kind: ResourceUser, ID: "user-one"}, TargetResourceVersion: 1, ConditionGeneration: 1,
		ActivityRevision: 1, WindowStartedAt: start, ObservedAt: now, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	analyzers := AccessAnalyzerList{APIVersion: APIVersion, Kind: "AccessAnalyzerList", AccountID: analyzer.AccountID, Items: []AccessAnalyzer{analyzer}}
	findings := AccessFindingList{APIVersion: APIVersion, Kind: "AccessFindingList", AccountID: analyzer.AccountID,
		AnalyzerID: analyzer.ID, ObservedAt: now, Coverage: coverage, Items: []AccessFinding{finding}}
	if ValidateAccessAnalyzerList(analyzers) != nil || ValidateAccessFindingList(findings) != nil {
		t.Fatal("valid access analyzer directories were rejected")
	}
	findings.Items[0].AccountID = "account-two"
	if ValidateAccessFindingList(findings) == nil {
		t.Fatal("finding directory accepted a cross-account row")
	}
}

func TestAccessAnalyzerMutationContractsAreVersionedAndBounded(t *testing.T) {
	if analyzerType, age, requestID, err := NormalizeCreateAccessAnalyzerRequest(CreateAccessAnalyzerRequest{Type: AccessAnalyzerUnusedAccess,
		RequestID: "create-analyzer"}); err != nil || analyzerType != AccessAnalyzerUnusedAccess || age != DefaultUnusedAccessAgeDays || requestID != "create-analyzer" ||
		ValidateUpdateAccessAnalyzerRequest(UpdateAccessAnalyzerRequest{Status: AccessAnalyzerDisabled,
			UnusedAccessAgeDays: MaxUnusedAccessAgeDays, ResourceVersion: 1, RequestID: "disable-analyzer"}) != nil {
		t.Fatal("valid access analyzer mutation contract was rejected")
	}
	for _, age := range []uint16{0, MaxUnusedAccessAgeDays + 1} {
		age := age
		if ValidateCreateAccessAnalyzerRequest(CreateAccessAnalyzerRequest{Type: AccessAnalyzerUnusedAccess,
			UnusedAccessAgeDays: &age, RequestID: "create-analyzer"}) == nil {
			t.Fatal("out-of-range unused access age was accepted", age)
		}
	}
}
