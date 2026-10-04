package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

const maxStoredSecurityReportBytes = iamv1.MaxSecurityReportCSVBytes + 512*1024

func (value *transaction) ReadSecurityReportSnapshot(ctx context.Context, read identityaccess.AccountRead) (identityaccess.SecurityReportSnapshot, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.security_report_snapshot($1,$2,$3,$4)", read.AccountID,
		read.ActorPrincipalID, read.ActorSessionID, read.DecisionID).Scan(&encoded); err != nil {
		return identityaccess.SecurityReportSnapshot{}, mapAuthorizationDatabaseError("read IAM security report snapshot", err)
	}
	defer clear(encoded)
	var result identityaccess.SecurityReportSnapshot
	if contractjson.DecodeObjectBytes(encoded, maxStoredSecurityReportBytes, &result) != nil {
		return identityaccess.SecurityReportSnapshot{}, identityaccess.ErrUnavailable
	}
	result.ObservedAt = result.ObservedAt.UTC()
	if result.ObservedAt.IsZero() ||
		result.AccountSecuritySettingsVersion == 0 || result.AccountSecuritySettingsVersion > 9007199254740991 ||
		result.Users == nil || result.AccessKeys == nil || len(result.Users) == 0 || len(result.Users) > iamv1.MaxSecurityReportUsers ||
		len(result.AccessKeys) > iamv1.MaxSecurityReportAccessKeys {
		return identityaccess.SecurityReportSnapshot{}, identityaccess.ErrUnavailable
	}
	users := make(map[iamv1.PrincipalID]struct{}, len(result.Users))
	for index := range result.Users {
		entry := &result.Users[index]
		normalizeSecurityReportUser(entry)
		if iamv1.ValidateSecurityReportUser(*entry, result.ObservedAt) != nil || (index > 0 && result.Users[index-1].ID >= entry.ID) {
			return identityaccess.SecurityReportSnapshot{}, identityaccess.ErrUnavailable
		}
		users[entry.ID] = struct{}{}
	}
	for index := range result.AccessKeys {
		entry := &result.AccessKeys[index]
		normalizeSecurityReportAccessKey(entry)
		_, found := users[entry.UserID]
		if !found || iamv1.ValidateSecurityReportAccessKey(*entry, result.ObservedAt) != nil ||
			(index > 0 && result.AccessKeys[index-1].ID >= entry.ID) {
			return identityaccess.SecurityReportSnapshot{}, identityaccess.ErrUnavailable
		}
	}
	return result, nil
}

func (value *transaction) ReadSecurityReportByRequest(ctx context.Context, read identityaccess.AccountRead, requestID, requestDigest string) (iamv1.AccountSecurityReportMetadata, bool, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_security_report_by_request($1,$2,$3,$4,$5,$6)", read.AccountID,
		read.ActorPrincipalID, read.ActorSessionID, read.DecisionID, requestID, requestDigest).Scan(&encoded); err != nil {
		return iamv1.AccountSecurityReportMetadata{}, false, mapAuthorizationDatabaseError("read IAM security report completion", err)
	}
	defer clear(encoded)
	if encoded == nil || bytes.Equal(encoded, []byte("null")) {
		return iamv1.AccountSecurityReportMetadata{}, false, nil
	}
	var result iamv1.AccountSecurityReportMetadata
	if contractjson.DecodeObjectBytes(encoded, 4096, &result) != nil {
		return iamv1.AccountSecurityReportMetadata{}, false, identityaccess.ErrUnavailable
	}
	normalizeSecurityReportMetadata(&result)
	if iamv1.ValidateAccountSecurityReportMetadata(result) != nil || result.AccountID != read.AccountID {
		return iamv1.AccountSecurityReportMetadata{}, false, identityaccess.ErrUnavailable
	}
	return result, true, nil
}

func (value *transaction) CreateSecurityReport(ctx context.Context, mutation identityaccess.SecurityReportCreation) (iamv1.CreateAccountSecurityReportResponse, error) {
	document, digest, err := iamv1.CanonicalizeAccountSecurityReportDocument(mutation.Report)
	if err != nil || digest != mutation.Report.Metadata.DocumentDigest || iamv1.ValidateAccountSecurityReportCSV(mutation.Report.Metadata, mutation.CSV) != nil {
		return iamv1.CreateAccountSecurityReportResponse{}, identityaccess.ErrInvalidArgument
	}
	report, err := json.Marshal(mutation.Report)
	if err != nil || len(report) > maxStoredSecurityReportBytes {
		return iamv1.CreateAccountSecurityReportResponse{}, identityaccess.ErrUnavailable
	}
	defer clear(report)
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return iamv1.CreateAccountSecurityReportResponse{}, err
	}
	defer clear(event)
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.create_security_report($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.ActorSessionID, mutation.DecisionID, mutation.RequestID,
		mutation.RequestDigest, mutation.Report.Metadata.ID, report, document, mutation.CSV, event).Scan(&encoded); err != nil {
		return iamv1.CreateAccountSecurityReportResponse{}, mapAuthorizationDatabaseError("create IAM security report", err)
	}
	defer clear(encoded)
	var result iamv1.CreateAccountSecurityReportResponse
	if contractjson.DecodeObjectBytes(encoded, 8192, &result) != nil {
		return iamv1.CreateAccountSecurityReportResponse{}, identityaccess.ErrUnavailable
	}
	normalizeSecurityReportMetadata(&result.Metadata)
	if iamv1.ValidateCreateAccountSecurityReportResponse(result) != nil || result.Metadata.AccountID != mutation.AccountID {
		return iamv1.CreateAccountSecurityReportResponse{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadSecurityReport(ctx context.Context, read identityaccess.AccountRead, reportID iamv1.SecurityReportID) (iamv1.AccountSecurityReport, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_security_report($1,$2,$3,$4,$5)", read.AccountID,
		read.ActorPrincipalID, read.ActorSessionID, read.DecisionID, reportID).Scan(&encoded); err != nil {
		return iamv1.AccountSecurityReport{}, mapSecurityReportError("read IAM security report", err)
	}
	return decodeSecurityReport(encoded, read.AccountID, reportID)
}

func (value *transaction) DownloadSecurityReport(ctx context.Context, mutation identityaccess.SecurityReportDownload) (identityaccess.SecurityReportDownloadResult, error) {
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return identityaccess.SecurityReportDownloadResult{}, err
	}
	defer clear(event)
	var metadata, csv []byte
	if err := value.tx.QueryRow(ctx, "SELECT * FROM iam.download_security_report($1,$2,$3,$4,$5,$6,$7::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.ActorSessionID, mutation.DecisionID,
		mutation.ReportID, mutation.RequestID, event).Scan(&metadata, &csv); err != nil {
		return identityaccess.SecurityReportDownloadResult{}, mapSecurityReportError("download IAM security report", err)
	}
	defer clear(metadata)
	var result identityaccess.SecurityReportDownloadResult
	if contractjson.DecodeObjectBytes(metadata, 4096, &result.Metadata) != nil {
		return identityaccess.SecurityReportDownloadResult{}, identityaccess.ErrUnavailable
	}
	normalizeSecurityReportMetadata(&result.Metadata)
	result.CSV = append([]byte(nil), csv...)
	clear(csv)
	if result.Metadata.ID != mutation.ReportID || result.Metadata.AccountID != mutation.AccountID ||
		iamv1.ValidateAccountSecurityReportCSV(result.Metadata, result.CSV) != nil {
		clear(result.CSV)
		return identityaccess.SecurityReportDownloadResult{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func decodeSecurityReport(encoded []byte, account iamv1.AccountID, reportID iamv1.SecurityReportID) (iamv1.AccountSecurityReport, error) {
	defer clear(encoded)
	var result iamv1.AccountSecurityReport
	if iamv1.DecodeRequest(bytes.NewReader(encoded), &result) != nil {
		return iamv1.AccountSecurityReport{}, identityaccess.ErrUnavailable
	}
	normalizeSecurityReportMetadata(&result.Metadata)
	for index := range result.Users {
		normalizeSecurityReportUser(&result.Users[index])
	}
	for index := range result.AccessKeys {
		normalizeSecurityReportAccessKey(&result.AccessKeys[index])
	}
	if len(encoded) > maxStoredSecurityReportBytes || result.Metadata.ID != reportID || result.Metadata.AccountID != account ||
		iamv1.ValidateAccountSecurityReport(result) != nil {
		return iamv1.AccountSecurityReport{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func normalizeSecurityReportMetadata(value *iamv1.AccountSecurityReportMetadata) {
	value.ObservedAt, value.ExpiresAt = value.ObservedAt.UTC(), value.ExpiresAt.UTC()
}

func normalizeSecurityReportUser(value *iamv1.SecurityReportUser) {
	value.CreatedAt = value.CreatedAt.UTC()
	if value.LastPasswordLogin.ObservedAt != nil {
		normalized := value.LastPasswordLogin.ObservedAt.UTC()
		value.LastPasswordLogin.ObservedAt = &normalized
	}
}

func normalizeSecurityReportAccessKey(value *iamv1.SecurityReportAccessKey) {
	value.CreatedAt = value.CreatedAt.UTC()
	if value.NetworkRestrictions.AllowedSourceCIDRs == nil {
		value.NetworkRestrictions.AllowedSourceCIDRs = []string{}
	}
	if value.LastAuthorization != nil {
		value.LastAuthorization.EvaluatedAt = value.LastAuthorization.EvaluatedAt.UTC()
	}
}

func mapSecurityReportError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "P0002" {
		return identityaccess.ErrSecurityReportNotFound
	}
	return mapAuthorizationDatabaseError(operation, err)
}
