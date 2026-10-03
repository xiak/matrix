// Package accessanalysis owns the pure unused-access finding transition rules.
// Durable activity facts, leases and audit outbox writes remain PostgreSQL
// responsibilities; this package cannot grant authority or mutate a target.
package accessanalysis

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var ErrInvalidSnapshot = errors.New("IAM access analysis snapshot is invalid")

type Candidate struct {
	Type                  iamv1.AccessFindingType `json:"type"`
	Target                iamv1.ResourceReference `json:"target"`
	TargetResourceVersion uint64                  `json:"targetResourceVersion"`
	CreatedAt             time.Time               `json:"createdAt"`
	ActivityRevision      uint64                  `json:"activityRevision"`
	LastActivityAt        *time.Time              `json:"lastActivityAt,omitempty"`
}

type BatchScope struct {
	AfterType     iamv1.AccessFindingType `json:"afterType,omitempty"`
	AfterTargetID string                  `json:"afterTargetId,omitempty"`
	LastType      iamv1.AccessFindingType `json:"lastType,omitempty"`
	LastTargetID  string                  `json:"lastTargetId,omitempty"`
	CycleComplete bool                    `json:"cycleComplete"`
}

type Snapshot struct {
	Analyzer            iamv1.AccessAnalyzer              `json:"analyzer"`
	ObservedAt          time.Time                         `json:"observedAt"`
	Coverage            []iamv1.AccessObservationCoverage `json:"coverage"`
	RecoveryEpoch       uint64                            `json:"recoveryEpoch"`
	RecoveryCommandID   string                            `json:"recoveryCommandId,omitempty"`
	RecoveryCompletedAt *time.Time                        `json:"recoveryCompletedAt,omitempty"`
	Candidates          []Candidate                       `json:"candidates"`
	Findings            []iamv1.AccessFinding             `json:"findings"`
	Batch               BatchScope                        `json:"batch"`
}

type Detection struct {
	Candidate
	ConditionGeneration uint64
}

type Resolution struct {
	FindingID       iamv1.AccessFindingID
	ResourceVersion uint64
}

type Plan struct {
	WindowStartedAt time.Time
	Detections      []Detection
	Resolutions     []Resolution
}

func Evaluate(snapshot Snapshot) (Plan, error) {
	if err := iamv1.ValidateAccessAnalyzer(snapshot.Analyzer); err != nil || snapshot.Analyzer.Status != iamv1.AccessAnalyzerActive {
		return Plan{}, fmt.Errorf("%w: analyzer", ErrInvalidSnapshot)
	}
	if snapshot.ObservedAt.Location() != time.UTC || snapshot.ObservedAt.IsZero() {
		return Plan{}, fmt.Errorf("%w: observation time", ErrInvalidSnapshot)
	}
	if err := iamv1.ValidateAccessObservationCoverage(snapshot.Coverage, snapshot.ObservedAt); err != nil {
		return Plan{}, fmt.Errorf("%w: coverage", ErrInvalidSnapshot)
	}
	if !validRecovery(snapshot) {
		return Plan{}, fmt.Errorf("%w: recovery scope", ErrInvalidSnapshot)
	}
	if !validBatch(snapshot.Batch) {
		return Plan{}, fmt.Errorf("%w: batch scope", ErrInvalidSnapshot)
	}
	windowStart := snapshot.ObservedAt.Add(-time.Duration(snapshot.Analyzer.UnusedAccessAgeDays) * 24 * time.Hour)
	if !completeRequiredCoverage(snapshot.Coverage, windowStart, snapshot.ObservedAt) {
		return Plan{WindowStartedAt: windowStart}, nil
	}

	type condition struct {
		findingType iamv1.AccessFindingType
		target      iamv1.ResourceReference
	}
	key := func(findingType iamv1.AccessFindingType, target iamv1.ResourceReference) condition {
		return condition{findingType: findingType, target: target}
	}

	candidates := make(map[condition]Candidate, len(snapshot.Candidates))
	seenCandidates := make(map[condition]struct{}, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		if !validCandidate(candidate, snapshot.ObservedAt) {
			return Plan{}, fmt.Errorf("%w: candidate", ErrInvalidSnapshot)
		}
		conditionKey := key(candidate.Type, candidate.Target)
		if _, duplicate := seenCandidates[conditionKey]; duplicate {
			return Plan{}, ErrInvalidSnapshot
		}
		seenCandidates[conditionKey] = struct{}{}
		if !candidate.CreatedAt.After(windowStart) && (candidate.LastActivityAt == nil || candidate.LastActivityAt.Before(windowStart)) {
			candidates[conditionKey] = candidate
		}
	}

	latestGeneration := make(map[condition]uint64)
	unresolved := make(map[condition]iamv1.AccessFinding)
	for _, finding := range snapshot.Findings {
		if iamv1.ValidateAccessFinding(finding) != nil || finding.AccountID != snapshot.Analyzer.AccountID ||
			finding.AnalyzerID != snapshot.Analyzer.ID || finding.ObservedAt.After(snapshot.ObservedAt) {
			return Plan{}, fmt.Errorf("%w: finding", ErrInvalidSnapshot)
		}
		conditionKey := key(finding.Type, finding.Target)
		if finding.ConditionGeneration > latestGeneration[conditionKey] {
			latestGeneration[conditionKey] = finding.ConditionGeneration
		}
		if finding.Status != iamv1.AccessFindingResolved {
			if _, duplicate := unresolved[conditionKey]; duplicate {
				return Plan{}, ErrInvalidSnapshot
			}
			unresolved[conditionKey] = finding
		}
	}

	plan := Plan{WindowStartedAt: windowStart}
	for conditionKey, finding := range unresolved {
		candidate, remainsUnused := candidates[conditionKey]
		if remainsUnused && sameEvidence(snapshot, finding, candidate, windowStart) {
			delete(candidates, conditionKey)
			continue
		}
		plan.Resolutions = append(plan.Resolutions, Resolution{FindingID: finding.ID, ResourceVersion: finding.ResourceVersion})
	}
	for conditionKey, candidate := range candidates {
		plan.Detections = append(plan.Detections, Detection{Candidate: candidate, ConditionGeneration: latestGeneration[conditionKey] + 1})
	}
	slices.SortFunc(plan.Detections, func(left, right Detection) int {
		if order := cmp.Compare(left.Type, right.Type); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Target.Kind, right.Target.Kind); order != 0 {
			return order
		}
		return cmp.Compare(left.Target.ID, right.Target.ID)
	})
	slices.SortFunc(plan.Resolutions, func(left, right Resolution) int {
		return cmp.Compare(left.FindingID, right.FindingID)
	})
	if len(plan.Detections) > iamv1.DirectoryPageSize || len(plan.Resolutions) > iamv1.DirectoryPageSize {
		return Plan{}, fmt.Errorf("%w: transition batch exceeds limit", ErrInvalidSnapshot)
	}
	return plan, nil
}

func validBatch(value BatchScope) bool {
	validPosition := func(findingType iamv1.AccessFindingType, target string) bool {
		if findingType == "" && target == "" {
			return true
		}
		return (findingType == iamv1.AccessFindingUnusedPassword || findingType == iamv1.AccessFindingUnusedAccessKey || findingType == iamv1.AccessFindingUnusedRole) &&
			iamv1.ValidateID("batchTargetId", target) == nil
	}
	if !validPosition(value.AfterType, value.AfterTargetID) || !validPosition(value.LastType, value.LastTargetID) {
		return false
	}
	if value.LastType == "" {
		return value.CycleComplete
	}
	return string(value.LastType) > string(value.AfterType) ||
		(value.LastType == value.AfterType && value.LastTargetID > value.AfterTargetID)
}

func validRecovery(snapshot Snapshot) bool {
	if snapshot.RecoveryEpoch == 0 {
		return snapshot.RecoveryCommandID == "" && snapshot.RecoveryCompletedAt == nil
	}
	return iamv1.ValidateID("recoveryCommandId", snapshot.RecoveryCommandID) == nil && snapshot.RecoveryCompletedAt != nil &&
		snapshot.RecoveryCompletedAt.Location() == time.UTC && !snapshot.RecoveryCompletedAt.IsZero() && !snapshot.RecoveryCompletedAt.After(snapshot.ObservedAt)
}

func completeRequiredCoverage(coverage []iamv1.AccessObservationCoverage, windowStart, observedAt time.Time) bool {
	for index, item := range coverage {
		if index >= 4 {
			break
		}
		if item.State != iamv1.AccessObservationComplete || item.ObservedFrom == nil || item.ObservedThrough == nil ||
			item.ObservedFrom.After(windowStart) || item.ObservedThrough.Before(observedAt) {
			return false
		}
	}
	return true
}

func validCandidate(candidate Candidate, observedAt time.Time) bool {
	const maxVersion = uint64(1<<53 - 1)
	validTarget := iamv1.ValidateID("targetId", candidate.Target.ID) == nil &&
		((candidate.Type == iamv1.AccessFindingUnusedPassword && candidate.Target.Kind == iamv1.ResourceUser) ||
			(candidate.Type == iamv1.AccessFindingUnusedAccessKey && candidate.Target.Kind == iamv1.ResourceAccessKey) ||
			(candidate.Type == iamv1.AccessFindingUnusedRole && candidate.Target.Kind == iamv1.ResourceRole))
	if !validTarget || candidate.TargetResourceVersion == 0 || candidate.TargetResourceVersion > maxVersion ||
		candidate.ActivityRevision == 0 || candidate.ActivityRevision > maxVersion || candidate.CreatedAt.Location() != time.UTC ||
		candidate.CreatedAt.IsZero() || candidate.CreatedAt.After(observedAt) {
		return false
	}
	return candidate.LastActivityAt == nil || (candidate.LastActivityAt.Location() == time.UTC && !candidate.LastActivityAt.IsZero() &&
		!candidate.LastActivityAt.Before(candidate.CreatedAt) && !candidate.LastActivityAt.After(observedAt))
}

func sameEvidence(snapshot Snapshot, finding iamv1.AccessFinding, candidate Candidate, windowStart time.Time) bool {
	if finding.AnalyzerRevision != snapshot.Analyzer.ResourceVersion || finding.TargetResourceVersion != candidate.TargetResourceVersion ||
		finding.ActivityRevision != candidate.ActivityRevision || finding.RecoveryEpoch != snapshot.RecoveryEpoch ||
		finding.RecoveryCommandID != snapshot.RecoveryCommandID || !finding.WindowStartedAt.Equal(windowStart) {
		return false
	}
	if (finding.RecoveryCompletedAt == nil) != (snapshot.RecoveryCompletedAt == nil) ||
		(finding.RecoveryCompletedAt != nil && !finding.RecoveryCompletedAt.Equal(*snapshot.RecoveryCompletedAt)) ||
		(finding.LastActivityAt == nil) != (candidate.LastActivityAt == nil) {
		return false
	}
	return finding.LastActivityAt == nil || finding.LastActivityAt.Equal(*candidate.LastActivityAt)
}
