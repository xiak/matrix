package identityaccess

import (
	"context"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var ErrAccessAnalyzerNotFound = errAccessAnalyzerNotFound{}

type errAccessAnalyzerNotFound struct{}

func (errAccessAnalyzerNotFound) Error() string { return "IAM access analyzer was not found" }

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

func (service *Authority) ListAccessFindings(ctx context.Context, credential iamv1.Secret, analyzerID iamv1.AccessAnalyzerID, after, requestID string) (iamv1.AccessFindingList, error) {
	if iamv1.ValidateID("accessAnalyzerId", string(analyzerID)) != nil || iamv1.ValidateID("requestId", requestID) != nil ||
		(after != "" && iamv1.ValidatePageCursor(after) != nil) {
		return iamv1.AccessFindingList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessFindingList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccessAnalyzer, ID: string(analyzerID)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccessFindingList, error) {
			position, query, err := service.directoryPosition(ctx, tx, subject, decision, after, now)
			if err != nil {
				return iamv1.AccessFindingList{}, err
			}
			read := accountRead(subject, decision)
			read.After = position
			result, err := tx.ListAccessFindings(ctx, AccessFindingRead{AccountRead: read, AnalyzerID: analyzerID})
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

func accountRead(subject SessionCredential, decision iamv1.AuthorizationDecision) AccountRead {
	return AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
		ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID}
}
