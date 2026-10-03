package iamv1

import (
	"errors"
	"time"
)

type AccessAnalyzerID string
type AccessFindingID string
type AccessAnalyzerType string
type AccessAnalyzerStatus string
type AccessFindingType string
type AccessFindingStatus string
type AccessObservationCoverageState string
type AccessObservationCoverageReason string

const (
	AccessAnalyzerUnusedAccess AccessAnalyzerType = "UNUSED_ACCESS"

	AccessAnalyzerActive   AccessAnalyzerStatus = "ACTIVE"
	AccessAnalyzerDisabled AccessAnalyzerStatus = "DISABLED"

	AccessFindingUnusedPassword  AccessFindingType = "UNUSED_PASSWORD"
	AccessFindingUnusedAccessKey AccessFindingType = "UNUSED_ACCESS_KEY"
	AccessFindingUnusedRole      AccessFindingType = "UNUSED_ROLE"

	AccessFindingActive   AccessFindingStatus = "ACTIVE"
	AccessFindingArchived AccessFindingStatus = "ARCHIVED"
	AccessFindingResolved AccessFindingStatus = "RESOLVED"

	AccessObservationComplete             AccessObservationCoverageState = "COMPLETE"
	AccessObservationInsufficientCoverage AccessObservationCoverageState = "INSUFFICIENT_COVERAGE"
	AccessObservationNotIncluded          AccessObservationCoverageState = "NOT_INCLUDED"

	AccessObservationWindowIncomplete     AccessObservationCoverageReason = "OBSERVATION_WINDOW_INCOMPLETE"
	AccessObservationHistoricalUnknown    AccessObservationCoverageReason = "HISTORICAL_PROVENANCE_UNKNOWN"
	AccessObservationRestoreGap           AccessObservationCoverageReason = "RESTORE_GAP"
	AccessObservationSourceNotReady       AccessObservationCoverageReason = "SOURCE_NOT_READY"
	AccessObservationSourceNotImplemented AccessObservationCoverageReason = "SOURCE_NOT_IMPLEMENTED"

	MinUnusedAccessAgeDays     uint16 = 1
	DefaultUnusedAccessAgeDays uint16 = 90
	MaxUnusedAccessAgeDays     uint16 = 365
)

var accessObservationSources = [...]string{
	"IAM_PASSWORD_SESSIONS",
	"IAM_ACCESS_KEY_AUTHORIZATIONS",
	"IAM_ROLE_SESSIONS",
	"IAM_ROLE_AUTHORIZATIONS",
	"PAAS_RESULTS",
	"EXTERNAL_FEDERATION",
}

func AccessObservationCoverageSources() []string {
	return append([]string(nil), accessObservationSources[:]...)
}

// AccessAnalyzer is Account-owned governance configuration. It is neither a
// Policy nor an authorization decision and cannot be used as a write permit.
type AccessAnalyzer struct {
	APIVersion          string               `json:"apiVersion"`
	Kind                string               `json:"kind"`
	ID                  AccessAnalyzerID     `json:"id"`
	AccountID           AccountID            `json:"accountId"`
	Type                AccessAnalyzerType   `json:"type"`
	Status              AccessAnalyzerStatus `json:"status"`
	UnusedAccessAgeDays uint16               `json:"unusedAccessAgeDays"`
	ResourceVersion     uint64               `json:"resourceVersion"`
	CreatedAt           time.Time            `json:"createdAt"`
	UpdatedAt           time.Time            `json:"updatedAt"`
}

type AccessObservationCoverage struct {
	Source          string                          `json:"source"`
	State           AccessObservationCoverageState  `json:"state"`
	ObservedFrom    *time.Time                      `json:"observedFrom,omitempty"`
	ObservedThrough *time.Time                      `json:"observedThrough,omitempty"`
	Reason          AccessObservationCoverageReason `json:"reason,omitempty"`
}

// AccessFinding is a reviewable observation, never authority to mutate its
// target. TargetResourceVersion and ActivityRevision make stale evidence
// explicit to a later lifecycle command.
type AccessFinding struct {
	APIVersion            string              `json:"apiVersion"`
	Kind                  string              `json:"kind"`
	ID                    AccessFindingID     `json:"id"`
	AccountID             AccountID           `json:"accountId"`
	AnalyzerID            AccessAnalyzerID    `json:"analyzerId"`
	AnalyzerRevision      uint64              `json:"analyzerRevision"`
	Type                  AccessFindingType   `json:"type"`
	Status                AccessFindingStatus `json:"status"`
	Target                ResourceReference   `json:"target"`
	TargetResourceVersion uint64              `json:"targetResourceVersion"`
	ConditionGeneration   uint64              `json:"conditionGeneration"`
	ActivityRevision      uint64              `json:"activityRevision"`
	WindowStartedAt       time.Time           `json:"windowStartedAt"`
	ObservedAt            time.Time           `json:"observedAt"`
	LastActivityAt        *time.Time          `json:"lastActivityAt,omitempty"`
	ResourceVersion       uint64              `json:"resourceVersion"`
	CreatedAt             time.Time           `json:"createdAt"`
	UpdatedAt             time.Time           `json:"updatedAt"`
	ResolvedAt            *time.Time          `json:"resolvedAt,omitempty"`
}

type AccessAnalyzerList struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	AccountID  AccountID        `json:"accountId"`
	Items      []AccessAnalyzer `json:"items"`
	NextAfter  string           `json:"nextAfter,omitempty"`
}

type AccessFindingList struct {
	APIVersion string                      `json:"apiVersion"`
	Kind       string                      `json:"kind"`
	AccountID  AccountID                   `json:"accountId"`
	AnalyzerID AccessAnalyzerID            `json:"analyzerId"`
	ObservedAt time.Time                   `json:"observedAt"`
	Coverage   []AccessObservationCoverage `json:"coverage"`
	Items      []AccessFinding             `json:"items"`
	NextAfter  string                      `json:"nextAfter,omitempty"`
}

type CreateAccessAnalyzerRequest struct {
	Type                AccessAnalyzerType `json:"type"`
	UnusedAccessAgeDays *uint16            `json:"unusedAccessAgeDays,omitempty"`
	RequestID           string             `json:"requestId"`
}

type UpdateAccessAnalyzerRequest struct {
	Status              AccessAnalyzerStatus `json:"status"`
	UnusedAccessAgeDays uint16               `json:"unusedAccessAgeDays"`
	ResourceVersion     uint64               `json:"resourceVersion"`
	RequestID           string               `json:"requestId"`
}

func ValidateAccessAnalyzer(value AccessAnalyzer) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessAnalyzer" ||
		ValidateID("accessAnalyzer.id", string(value.ID)) != nil ||
		ValidateID("accessAnalyzer.accountId", string(value.AccountID)) != nil ||
		value.Type != AccessAnalyzerUnusedAccess ||
		(value.Status != AccessAnalyzerActive && value.Status != AccessAnalyzerDisabled) ||
		validateUnusedAccessAge(value.UnusedAccessAgeDays) != nil ||
		validatePositiveVersion(value.ResourceVersion) != nil ||
		validateTime("accessAnalyzer.createdAt", value.CreatedAt) != nil ||
		validateTime("accessAnalyzer.updatedAt", value.UpdatedAt) != nil || value.UpdatedAt.Before(value.CreatedAt) {
		return errors.New("access analyzer is invalid")
	}
	return nil
}

func ValidateAccessAnalyzerList(value AccessAnalyzerList) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessAnalyzerList" || ValidateID("accessAnalyzerList.accountId", string(value.AccountID)) != nil ||
		value.Items == nil || len(value.Items) > DirectoryPageSize ||
		(value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil)) {
		return errors.New("access analyzer list is invalid")
	}
	var previous AccessAnalyzerID
	for _, item := range value.Items {
		if ValidateAccessAnalyzer(item) != nil || item.AccountID != value.AccountID || item.ID <= previous {
			return errors.New("access analyzer list items are invalid")
		}
		previous = item.ID
	}
	return nil
}

func ValidateAccessObservationCoverage(value []AccessObservationCoverage, observedAt time.Time) error {
	if len(value) != len(accessObservationSources) || validateTime("accessFindingList.observedAt", observedAt) != nil {
		return errors.New("access observation coverage is incomplete")
	}
	for index, entry := range value {
		if entry.Source != accessObservationSources[index] {
			return errors.New("access observation coverage source is invalid")
		}
		switch entry.State {
		case AccessObservationComplete:
			if entry.ObservedFrom == nil || entry.ObservedThrough == nil || entry.Reason != "" ||
				validateTime("coverage.observedFrom", *entry.ObservedFrom) != nil || validateTime("coverage.observedThrough", *entry.ObservedThrough) != nil ||
				entry.ObservedThrough.Before(*entry.ObservedFrom) || entry.ObservedThrough.After(observedAt) {
				return errors.New("complete access observation coverage is invalid")
			}
		case AccessObservationInsufficientCoverage:
			if entry.ObservedFrom == nil || entry.ObservedThrough == nil ||
				(entry.Reason != AccessObservationWindowIncomplete && entry.Reason != AccessObservationHistoricalUnknown && entry.Reason != AccessObservationRestoreGap &&
					entry.Reason != AccessObservationSourceNotReady) ||
				validateTime("coverage.observedFrom", *entry.ObservedFrom) != nil || validateTime("coverage.observedThrough", *entry.ObservedThrough) != nil ||
				entry.ObservedThrough.Before(*entry.ObservedFrom) || entry.ObservedThrough.After(observedAt) {
				return errors.New("insufficient access observation coverage is invalid")
			}
		case AccessObservationNotIncluded:
			if entry.ObservedFrom != nil || entry.ObservedThrough != nil || entry.Reason != AccessObservationSourceNotImplemented {
				return errors.New("excluded access observation coverage is invalid")
			}
		default:
			return errors.New("access observation coverage state is invalid")
		}
	}
	return nil
}

func ValidateAccessFinding(value AccessFinding) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessFinding" ||
		ValidateID("accessFinding.id", string(value.ID)) != nil || ValidateID("accessFinding.accountId", string(value.AccountID)) != nil ||
		ValidateID("accessFinding.analyzerId", string(value.AnalyzerID)) != nil || validatePositiveVersion(value.AnalyzerRevision) != nil ||
		validatePositiveVersion(value.TargetResourceVersion) != nil || validatePositiveVersion(value.ConditionGeneration) != nil ||
		validatePositiveVersion(value.ActivityRevision) != nil || validatePositiveVersion(value.ResourceVersion) != nil ||
		validateTime("accessFinding.windowStartedAt", value.WindowStartedAt) != nil || validateTime("accessFinding.observedAt", value.ObservedAt) != nil ||
		validateTime("accessFinding.createdAt", value.CreatedAt) != nil || validateTime("accessFinding.updatedAt", value.UpdatedAt) != nil ||
		!value.ObservedAt.After(value.WindowStartedAt) || value.CreatedAt.After(value.UpdatedAt) || value.UpdatedAt.After(value.ObservedAt) {
		return errors.New("access finding is invalid")
	}
	if !validAccessFindingTarget(value.Type, value.Target) {
		return errors.New("access finding target is invalid")
	}
	if value.LastActivityAt != nil && (validateTime("accessFinding.lastActivityAt", *value.LastActivityAt) != nil || !value.LastActivityAt.Before(value.WindowStartedAt)) {
		return errors.New("access finding activity is not outside its window")
	}
	switch value.Status {
	case AccessFindingActive, AccessFindingArchived:
		if value.ResolvedAt != nil {
			return errors.New("unresolved access finding has a resolution time")
		}
	case AccessFindingResolved:
		if value.ResolvedAt == nil || validateTime("accessFinding.resolvedAt", *value.ResolvedAt) != nil ||
			value.ResolvedAt.Before(value.CreatedAt) || value.ResolvedAt.Before(value.UpdatedAt) {
			return errors.New("resolved access finding is invalid")
		}
	default:
		return errors.New("access finding status is invalid")
	}
	return nil
}

func ValidateAccessFindingList(value AccessFindingList) error {
	if value.APIVersion != APIVersion || value.Kind != "AccessFindingList" ||
		ValidateID("accessFindingList.accountId", string(value.AccountID)) != nil || ValidateID("accessFindingList.analyzerId", string(value.AnalyzerID)) != nil ||
		value.Items == nil || len(value.Items) > DirectoryPageSize ||
		(value.NextAfter != "" && (len(value.Items) != DirectoryPageSize || ValidatePageCursor(value.NextAfter) != nil)) ||
		ValidateAccessObservationCoverage(value.Coverage, value.ObservedAt) != nil {
		return errors.New("access finding list is invalid")
	}
	var previous AccessFindingID
	for _, item := range value.Items {
		if ValidateAccessFinding(item) != nil || item.AccountID != value.AccountID || item.AnalyzerID != value.AnalyzerID || item.ID <= previous || item.ObservedAt.After(value.ObservedAt) {
			return errors.New("access finding list items are invalid")
		}
		previous = item.ID
	}
	return nil
}

func ValidateCreateAccessAnalyzerRequest(value CreateAccessAnalyzerRequest) error {
	if value.Type != AccessAnalyzerUnusedAccess || (value.UnusedAccessAgeDays != nil && validateUnusedAccessAge(*value.UnusedAccessAgeDays) != nil) || ValidateID("requestId", value.RequestID) != nil {
		return errors.New("access analyzer creation request is invalid")
	}
	return nil
}

func NormalizeCreateAccessAnalyzerRequest(value CreateAccessAnalyzerRequest) (AccessAnalyzerType, uint16, string, error) {
	if ValidateCreateAccessAnalyzerRequest(value) != nil {
		return "", 0, "", errors.New("access analyzer creation request is invalid")
	}
	age := DefaultUnusedAccessAgeDays
	if value.UnusedAccessAgeDays != nil {
		age = *value.UnusedAccessAgeDays
	}
	return value.Type, age, value.RequestID, nil
}

func ValidateUpdateAccessAnalyzerRequest(value UpdateAccessAnalyzerRequest) error {
	if (value.Status != AccessAnalyzerActive && value.Status != AccessAnalyzerDisabled) ||
		validateUnusedAccessAge(value.UnusedAccessAgeDays) != nil || validatePositiveVersion(value.ResourceVersion) != nil ||
		ValidateID("requestId", value.RequestID) != nil {
		return errors.New("access analyzer update request is invalid")
	}
	return nil
}

func validateUnusedAccessAge(value uint16) error {
	if value < MinUnusedAccessAgeDays || value > MaxUnusedAccessAgeDays {
		return errors.New("unused access age is out of range")
	}
	return nil
}

func validAccessFindingTarget(findingType AccessFindingType, target ResourceReference) bool {
	if ValidateID("accessFinding.target.id", target.ID) != nil {
		return false
	}
	switch findingType {
	case AccessFindingUnusedPassword:
		return target.Kind == ResourceUser
	case AccessFindingUnusedAccessKey:
		return target.Kind == ResourceAccessKey
	case AccessFindingUnusedRole:
		return target.Kind == ResourceRole
	default:
		return false
	}
}
