package identityaccess

import (
	"context"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var ErrSecurityReportNotFound = errSecurityReportNotFound{}

type errSecurityReportNotFound struct{}

func (errSecurityReportNotFound) Error() string { return "IAM security report was not found" }

func (service *Authority) CreateAccountSecurityReport(ctx context.Context, credential iamv1.Secret, request iamv1.CreateAccountSecurityReportRequest) (iamv1.CreateAccountSecurityReportResponse, error) {
	if iamv1.ValidateCreateAccountSecurityReportRequest(request) != nil {
		return iamv1.CreateAccountSecurityReportResponse{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("security-report.create", request)
	if err != nil {
		return iamv1.CreateAccountSecurityReportResponse{}, err
	}
	var reportID iamv1.SecurityReportID
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMSecurityReportCreate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.CreateAccountSecurityReportResponse, error) {
			read := AccountRead{AccountID: subject.Subject.Organization.ID, ActorPrincipalID: subject.Subject.Principal.ID,
				ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID}
			completed, found, err := tx.ReadSecurityReportByRequest(ctx, read, request.RequestID, digest)
			if err != nil {
				return iamv1.CreateAccountSecurityReportResponse{}, err
			}
			if found {
				response := iamv1.CreateAccountSecurityReportResponse{Outcome: "EQUAL_REPLAY", Metadata: completed}
				if iamv1.ValidateCreateAccountSecurityReportResponse(response) != nil || completed.AccountID != read.AccountID {
					return iamv1.CreateAccountSecurityReportResponse{}, ErrUnavailable
				}
				return response, nil
			}
			if reportID == "" {
				value, err := service.config.NewID("security-report")
				if err != nil || iamv1.ValidateID("securityReportId", value) != nil {
					return iamv1.CreateAccountSecurityReportResponse{}, ErrUnavailable
				}
				reportID = iamv1.SecurityReportID(value)
			}
			snapshot, err := tx.ReadSecurityReportSnapshot(ctx, read)
			if err != nil {
				return iamv1.CreateAccountSecurityReportResponse{}, err
			}
			if !snapshot.ObservedAt.Equal(now) {
				return iamv1.CreateAccountSecurityReportResponse{}, ErrUnavailable
			}
			metadata := iamv1.AccountSecurityReportMetadata{APIVersion: iamv1.APIVersion, Kind: "AccountSecurityReportMetadata",
				ID: reportID, AccountID: read.AccountID, FormatVersion: request.FormatVersion, ObservedAt: now, ExpiresAt: now.Add(iamv1.SecurityReportRetention),
				DocumentDigest: "sha256:" + strings.Repeat("0", 64), CSVContentDigest: "sha256:" + strings.Repeat("0", 64),
				UserCount: uint32(len(snapshot.Users)), AccessKeyCount: uint32(len(snapshot.AccessKeys)),
				RowCount: uint32(1 + len(snapshot.Users) + len(snapshot.AccessKeys)), CSVBytes: 1}
			report := iamv1.AccountSecurityReport{Metadata: metadata, AccountSecuritySettingsVersion: snapshot.AccountSecuritySettingsVersion,
				Coverage: iamv1.SecurityReportCoverageContract(), Users: snapshot.Users, AccessKeys: snapshot.AccessKeys}
			_, documentDigest, err := iamv1.CanonicalizeAccountSecurityReportDocument(report)
			if err != nil {
				return iamv1.CreateAccountSecurityReportResponse{}, ErrConflict
			}
			csvDocument, csvDigest, err := iamv1.EncodeAccountSecurityReportCSV(report)
			if err != nil {
				return iamv1.CreateAccountSecurityReportResponse{}, ErrConflict
			}
			report.Metadata.DocumentDigest, report.Metadata.CSVContentDigest, report.Metadata.CSVBytes = documentDigest, csvDigest, uint32(len(csvDocument))
			if iamv1.ValidateAccountSecurityReport(report) != nil {
				return iamv1.CreateAccountSecurityReportResponse{}, ErrUnavailable
			}
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMSecurityReportCreated, auditv1.TargetSecurityReport,
				string(reportID), decision.ID, digest, request.RequestID, now)
			if err != nil {
				return iamv1.CreateAccountSecurityReportResponse{}, err
			}
			response, err := tx.CreateSecurityReport(ctx, SecurityReportCreation{AccountRead: read, Session: subject.Subject.Session,
				RequestID: request.RequestID, RequestDigest: digest, Report: report, CSV: csvDocument, AuditEvent: event})
			if err != nil {
				return iamv1.CreateAccountSecurityReportResponse{}, err
			}
			if iamv1.ValidateCreateAccountSecurityReportResponse(response) != nil || response.Outcome != "APPLIED" || response.Metadata != report.Metadata {
				return iamv1.CreateAccountSecurityReportResponse{}, ErrUnavailable
			}
			return response, nil
		})
}

func (service *Authority) AccountSecurityReport(ctx context.Context, credential iamv1.Secret, reportID iamv1.SecurityReportID, requestID string) (iamv1.AccountSecurityReport, error) {
	if iamv1.ValidateID("securityReportId", string(reportID)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AccountSecurityReport{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMSecurityReportRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceSecurityReport, ID: string(reportID)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccountSecurityReport, error) {
			result, err := tx.ReadSecurityReport(ctx, AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID}, reportID)
			if err != nil {
				return iamv1.AccountSecurityReport{}, err
			}
			if iamv1.ValidateAccountSecurityReport(result) != nil || result.Metadata.ID != reportID ||
				result.Metadata.AccountID != subject.Subject.Organization.ID || !result.Metadata.ObservedAt.Before(result.Metadata.ExpiresAt) ||
				!now.Before(result.Metadata.ExpiresAt) {
				return iamv1.AccountSecurityReport{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) DownloadAccountSecurityReport(ctx context.Context, credential iamv1.Secret, reportID iamv1.SecurityReportID, requestID string) ([]byte, error) {
	if iamv1.ValidateID("securityReportId", string(reportID)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return nil, ErrInvalidArgument
	}
	digest, err := digestSanitized("security-report.download", struct {
		ReportID  iamv1.SecurityReportID `json:"reportId"`
		RequestID string                 `json:"requestId"`
	}{reportID, requestID})
	if err != nil {
		return nil, err
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMSecurityReportDownload, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceSecurityReport, ID: string(reportID)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) ([]byte, error) {
			event, err := service.newManagementEvent(subject, auditv1.ActionIAMSecurityReportDownloadStarted, auditv1.TargetSecurityReport,
				string(reportID), decision.ID, digest, requestID, now)
			if err != nil {
				return nil, err
			}
			result, err := tx.DownloadSecurityReport(ctx, SecurityReportDownload{AccountRead: AccountRead{AccountID: subject.Subject.Organization.ID,
				ActorPrincipalID: subject.Subject.Principal.ID, ActorSessionID: subject.Subject.Session.ID, DecisionID: decision.ID}, Session: subject.Subject.Session,
				ReportID: reportID, RequestID: requestID, AuditEvent: event})
			if err != nil {
				return nil, err
			}
			if result.Metadata.ID != reportID || result.Metadata.AccountID != subject.Subject.Organization.ID || !now.Before(result.Metadata.ExpiresAt) ||
				iamv1.ValidateAccountSecurityReportCSV(result.Metadata, result.CSV) != nil {
				return nil, ErrUnavailable
			}
			return result.CSV, nil
		})
}
