package identityaccess

import (
	"context"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

var ErrAccessAnalyzerNotFound = errAccessAnalyzerNotFound{}
var ErrAccessFindingNotFound = errAccessFindingNotFound{}

type errAccessAnalyzerNotFound struct{}

func (errAccessAnalyzerNotFound) Error() string { return "IAM access analyzer was not found" }

type errAccessFindingNotFound struct{}

func (errAccessFindingNotFound) Error() string { return "IAM access finding was not found" }

func (service *Authority) CreateAccessAnalyzer(ctx context.Context, credential iamv1.Secret, request iamv1.CreateAccessAnalyzerRequest) (iamv1.AccessAnalyzer, error) {
	analyzerType, age, requestID, err := iamv1.NormalizeCreateAccessAnalyzerRequest(request)
	if err != nil {
		return iamv1.AccessAnalyzer{}, ErrInvalidArgument
	}
	intent := struct {
		Type                iamv1.AccessAnalyzerType `json:"type"`
		UnusedAccessAgeDays uint16                   `json:"unusedAccessAgeDays"`
		RequestID           string                   `json:"requestId"`
	}{analyzerType, age, requestID}
	digest, err := digestSanitized("access-analyzer.create", intent)
	if err != nil {
		return iamv1.AccessAnalyzer{}, err
	}
	var analyzerID iamv1.AccessAnalyzerID
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessAnalyzerCreate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccessAnalyzer, error) {
			if analyzerID == "" {
				value, err := service.config.NewID("access-analyzer")
				if err != nil || iamv1.ValidateID("accessAnalyzerId", value) != nil {
					return iamv1.AccessAnalyzer{}, ErrUnavailable
				}
				analyzerID = iamv1.AccessAnalyzerID(value)
			}
			analyzer := iamv1.AccessAnalyzer{APIVersion: iamv1.APIVersion, Kind: "AccessAnalyzer", ID: analyzerID,
				AccountID: subject.Subject.Organization.ID, Type: analyzerType, Status: iamv1.AccessAnalyzerActive,
				UnusedAccessAgeDays: age, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMAccessAnalyzerCreated, auditv1.TargetAccessAnalyzer,
				string(analyzerID), decision.ID, digest, requestID, now)
			if err != nil {
				return iamv1.AccessAnalyzer{}, err
			}
			result, err := tx.CreateAccessAnalyzer(ctx, AccessAnalyzerCreation{AccountRead: accountRead(subject, decision),
				Session: subject.Subject.Session, RequestID: requestID, RequestDigest: digest, Analyzer: analyzer, AuditEvent: event})
			if err != nil {
				return iamv1.AccessAnalyzer{}, err
			}
			if iamv1.ValidateAccessAnalyzer(result) != nil || result.AccountID != subject.Subject.Organization.ID || result.Type != analyzerType {
				return iamv1.AccessAnalyzer{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) ListAccessAnalyzers(ctx context.Context, credential iamv1.Secret, after, requestID string) (iamv1.AccessAnalyzerList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil || (after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.AccessAnalyzerList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessAnalyzerList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccessAnalyzerList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.AccessAnalyzerList{}, err
			}
			read := accountRead(subject, decision)
			read.After = position
			result, err := tx.ListAccessAnalyzers(ctx, read)
			if err != nil {
				return iamv1.AccessAnalyzerList{}, err
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateAccessAnalyzerList(result) != nil || result.AccountID != subject.Subject.Organization.ID {
				return iamv1.AccessAnalyzerList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) AccessAnalyzer(ctx context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID, requestID string) (iamv1.AccessAnalyzer, error) {
	if iamv1.ValidateID("accessAnalyzerId", string(analyzerID)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AccessAnalyzer{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessAnalyzerRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccessAnalyzer, ID: string(analyzerID)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.AccessAnalyzer, error) {
			result, err := tx.ReadAccessAnalyzer(ctx, AccessAnalyzerRead{AccountRead: accountRead(subject, decision), AnalyzerID: analyzerID})
			if err != nil {
				return iamv1.AccessAnalyzer{}, err
			}
			if iamv1.ValidateAccessAnalyzer(result) != nil || result.ID != analyzerID || result.AccountID != subject.Subject.Organization.ID {
				return iamv1.AccessAnalyzer{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) UpdateAccessAnalyzer(ctx context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID, request iamv1.UpdateAccessAnalyzerRequest) (iamv1.AccessAnalyzer, error) {
	if iamv1.ValidateID("accessAnalyzerId", string(analyzerID)) != nil || iamv1.ValidateUpdateAccessAnalyzerRequest(request) != nil {
		return iamv1.AccessAnalyzer{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("access-analyzer.update", struct {
		AnalyzerID iamv1.AccessAnalyzerID            `json:"analyzerId"`
		Request    iamv1.UpdateAccessAnalyzerRequest `json:"request"`
	}{analyzerID, request})
	if err != nil {
		return iamv1.AccessAnalyzer{}, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessAnalyzerUpdate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccessAnalyzer, ID: string(analyzerID)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccessAnalyzer, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMAccessAnalyzerUpdated, auditv1.TargetAccessAnalyzer,
				string(analyzerID), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.AccessAnalyzer{}, err
			}
			result, err := tx.UpdateAccessAnalyzer(ctx, AccessAnalyzerMutation{AccessAnalyzerRead: AccessAnalyzerRead{
				AccountRead: accountRead(subject, decision), AnalyzerID: analyzerID}, Session: subject.Subject.Session,
				RequestID: request.RequestID, RequestDigest: digest, Request: request, AuditEvent: event})
			if err != nil {
				return iamv1.AccessAnalyzer{}, err
			}
			if iamv1.ValidateAccessAnalyzer(result) != nil || result.ID != analyzerID || result.AccountID != subject.Subject.Organization.ID {
				return iamv1.AccessAnalyzer{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) ListAccessFindings(ctx context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID,
	filter iamv1.AccessFindingFilter, after, requestID string) (iamv1.AccessFindingList, error) {
	filter, filterErr := iamv1.NormalizeAccessFindingFilter(filter)
	if filterErr != nil || iamv1.ValidateID("accessAnalyzerId", string(analyzerID)) != nil || iamv1.ValidateID("requestId", requestID) != nil ||
		(after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.AccessFindingList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessFindingList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccessAnalyzer, ID: string(analyzerID)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccessFindingList, error) {
			if service.cursors == nil {
				return iamv1.AccessFindingList{}, ErrUnavailable
			}
			read := AccessFindingRead{AccountRead: accountRead(subject, decision), AnalyzerID: analyzerID, Filter: filter}
			revision, err := tx.ReadAccessFindingDirectoryRevision(ctx, read)
			if err != nil {
				return iamv1.AccessFindingList{}, err
			}
			if authority.ValidateAccessFindingDirectoryRevision(revision) != nil {
				return iamv1.AccessFindingList{}, ErrUnavailable
			}
			status, err := tx.BootstrapStatus(ctx)
			if err != nil || iamv1.ValidateBootstrapStatus(status) != nil || status.State != iamv1.BootstrapReady {
				return iamv1.AccessFindingList{}, ErrUnavailable
			}
			query := authority.DirectoryQuery{InstallationID: status.InstallationID, Action: decision.Action, Resource: decision.Resource,
				AccessFindings: &authority.AccessFindingDirectoryQuery{Revision: revision, Filter: filter}}
			if after != "" {
				read.After, err = service.cursors.Decode(after, subject.Subject, query, now)
				if err != nil {
					return iamv1.AccessFindingList{}, ErrInvalidArgument
				}
			}
			result, err := tx.ListAccessFindings(ctx, read)
			if err != nil {
				return iamv1.AccessFindingList{}, err
			}
			result.NextAfter, err = service.sealDirectoryPage(subject, query, result.NextAfter, now)
			if err != nil || iamv1.ValidateAccessFindingList(result) != nil || result.AccountID != subject.Subject.Organization.ID ||
				result.AnalyzerID != analyzerID || !result.ObservedAt.Equal(now) {
				return iamv1.AccessFindingList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) AccessFinding(ctx context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID,
	findingID iamv1.AccessFindingID, requestID string) (iamv1.AccessFinding, error) {
	if iamv1.ValidateID("accessAnalyzerId", string(analyzerID)) != nil || iamv1.ValidateID("accessFindingId", string(findingID)) != nil ||
		iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AccessFinding{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessFindingRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccessFinding, ID: string(findingID)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, _ time.Time) (iamv1.AccessFinding, error) {
			result, err := tx.ReadAccessFinding(ctx, AccessFindingRead{AccountRead: accountRead(subject, decision), AnalyzerID: analyzerID, FindingID: findingID})
			if err != nil {
				return iamv1.AccessFinding{}, err
			}
			if iamv1.ValidateAccessFinding(result) != nil || result.AccountID != subject.Subject.Organization.ID ||
				result.AnalyzerID != analyzerID || result.ID != findingID {
				return iamv1.AccessFinding{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) ArchiveAccessFinding(ctx context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID,
	findingID iamv1.AccessFindingID, request iamv1.AccessFindingDispositionRequest) (iamv1.AccessFinding, error) {
	return service.setAccessFindingArchived(ctx, credential, analyzerID, findingID, request, true)
}

func (service *Authority) UnarchiveAccessFinding(ctx context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID,
	findingID iamv1.AccessFindingID, request iamv1.AccessFindingDispositionRequest) (iamv1.AccessFinding, error) {
	return service.setAccessFindingArchived(ctx, credential, analyzerID, findingID, request, false)
}

func (service *Authority) setAccessFindingArchived(ctx context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID,
	findingID iamv1.AccessFindingID, request iamv1.AccessFindingDispositionRequest, archived bool) (iamv1.AccessFinding, error) {
	if iamv1.ValidateID("accessAnalyzerId", string(analyzerID)) != nil || iamv1.ValidateID("accessFindingId", string(findingID)) != nil ||
		iamv1.ValidateAccessFindingDispositionRequest(request) != nil {
		return iamv1.AccessFinding{}, ErrInvalidArgument
	}
	action, eventAction, domain := iamv1.ActionIAMAccessFindingUnarchive, auditv1.ActionIAMAccessFindingUnarchived, "access-finding.unarchive"
	if archived {
		action, eventAction, domain = iamv1.ActionIAMAccessFindingArchive, auditv1.ActionIAMAccessFindingArchived, "access-finding.archive"
	}
	digest, err := digestSanitized(domain, struct {
		AnalyzerID iamv1.AccessAnalyzerID                `json:"analyzerId"`
		FindingID  iamv1.AccessFindingID                 `json:"findingId"`
		Request    iamv1.AccessFindingDispositionRequest `json:"request"`
	}{analyzerID, findingID, request})
	if err != nil {
		return iamv1.AccessFinding{}, err
	}
	return withAccountAuthorization(service, ctx, credential, action, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccessFinding, ID: string(findingID)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccessFinding, error) {
			event, err := service.newManagementEvent(subject, eventAction, auditv1.TargetAccessFinding,
				string(findingID), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.AccessFinding{}, err
			}
			result, err := tx.SetAccessFindingArchived(ctx, AccessFindingMutation{AccessFindingRead: AccessFindingRead{
				AccountRead: accountRead(subject, decision), AnalyzerID: analyzerID, FindingID: findingID}, Session: subject.Subject.Session,
				RequestID: request.RequestID, RequestDigest: digest, ExpectedVersion: request.ResourceVersion, Archived: archived, AuditEvent: event})
			if err != nil {
				return iamv1.AccessFinding{}, err
			}
			if iamv1.ValidateAccessFinding(result) != nil || result.AccountID != subject.Subject.Organization.ID ||
				result.AnalyzerID != analyzerID || result.ID != findingID {
				return iamv1.AccessFinding{}, ErrUnavailable
			}
			return result, nil
		})
}

func accountRead(subject SessionCredential, decision iamv1.AuthorizationDecision) AccountRead {
	return AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
		ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID}
}
