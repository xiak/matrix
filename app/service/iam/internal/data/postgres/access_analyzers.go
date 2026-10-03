package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) CreateAccessAnalyzer(ctx context.Context, mutation identityaccess.AccessAnalyzerCreation) (iamv1.AccessAnalyzer, error) {
	if iamv1.ValidateAccessAnalyzer(mutation.Analyzer) != nil || mutation.Analyzer.AccountID != mutation.AccountID ||
		iamv1.ValidateID("actorSessionId", string(mutation.Session.ID)) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.AccessAnalyzer{}, identityaccess.ErrInvalidArgument
	}
	analyzer, err := json.Marshal(mutation.Analyzer)
	if err != nil {
		return iamv1.AccessAnalyzer{}, identityaccess.ErrUnavailable
	}
	defer clear(analyzer)
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.AccessAnalyzer{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.create_access_analyzer($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.ActorSessionID, mutation.DecisionID,
		mutation.RequestID, mutation.RequestDigest, analyzer, event).Scan(&encoded)
	if err != nil {
		return iamv1.AccessAnalyzer{}, mapAccessAnalyzerError("create IAM access analyzer", err)
	}
	return decodeAccessAnalyzer(encoded, mutation.AccountID, "")
}

func (value *transaction) ListAccessAnalyzers(ctx context.Context, read identityaccess.AccountRead) (iamv1.AccessAnalyzerList, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_access_analyzers($1,$2,$3,$4,$5)", read.AccountID,
		read.ActorPrincipalID, read.ActorSessionID, read.DecisionID, read.After).Scan(&encoded); err != nil {
		return iamv1.AccessAnalyzerList{}, mapAccessAnalyzerError("list IAM access analyzers", err)
	}
	result := iamv1.AccessAnalyzerList{APIVersion: iamv1.APIVersion, Kind: "AccessAnalyzerList", AccountID: read.AccountID}
	if len(encoded) > 256*1024 || json.Unmarshal(encoded, &result.Items) != nil || result.Items == nil || len(result.Items) > iamv1.DirectoryPageSize+1 {
		return iamv1.AccessAnalyzerList{}, identityaccess.ErrUnavailable
	}
	for index := range result.Items {
		normalizeAccessAnalyzer(&result.Items[index])
		if iamv1.ValidateAccessAnalyzer(result.Items[index]) != nil || result.Items[index].AccountID != read.AccountID ||
			string(result.Items[index].ID) <= read.After || (index > 0 && result.Items[index-1].ID >= result.Items[index].ID) {
			return iamv1.AccessAnalyzerList{}, identityaccess.ErrUnavailable
		}
	}
	if len(result.Items) > iamv1.DirectoryPageSize {
		result.Items = result.Items[:iamv1.DirectoryPageSize]
		result.NextAfter = string(result.Items[iamv1.DirectoryPageSize-1].ID)
	}
	return result, nil
}

func (value *transaction) ReadAccessAnalyzer(ctx context.Context, read identityaccess.AccessAnalyzerRead) (iamv1.AccessAnalyzer, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_access_analyzer($1,$2,$3,$4,$5)", read.AccountID,
		read.ActorPrincipalID, read.ActorSessionID, read.DecisionID, read.AnalyzerID).Scan(&encoded); err != nil {
		return iamv1.AccessAnalyzer{}, mapAccessAnalyzerError("read IAM access analyzer", err)
	}
	return decodeAccessAnalyzer(encoded, read.AccountID, read.AnalyzerID)
}

func (value *transaction) UpdateAccessAnalyzer(ctx context.Context, mutation identityaccess.AccessAnalyzerMutation) (iamv1.AccessAnalyzer, error) {
	if iamv1.ValidateUpdateAccessAnalyzerRequest(mutation.Request) != nil || iamv1.ValidateID("actorSessionId", string(mutation.Session.ID)) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.AccessAnalyzer{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.AccessAnalyzer{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.update_access_analyzer($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.ActorSessionID, mutation.DecisionID, mutation.AnalyzerID,
		mutation.RequestID, mutation.RequestDigest, mutation.Request.Status, mutation.Request.UnusedAccessAgeDays,
		mutation.Request.ResourceVersion, event).Scan(&encoded)
	if err != nil {
		return iamv1.AccessAnalyzer{}, mapAccessAnalyzerError("update IAM access analyzer", err)
	}
	return decodeAccessAnalyzer(encoded, mutation.AccountID, mutation.AnalyzerID)
}

func (value *transaction) ListAccessFindings(ctx context.Context, read identityaccess.AccessFindingRead) (iamv1.AccessFindingList, error) {
	filter, err := iamv1.NormalizeAccessFindingFilter(read.Filter)
	if err != nil || filter != read.Filter {
		return iamv1.AccessFindingList{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.list_access_findings($1,$2,$3,$4,$5,$6,$7)", read.AccountID,
		read.ActorPrincipalID, read.ActorSessionID, read.DecisionID, read.AnalyzerID, read.After, read.Filter.Status).Scan(&encoded); err != nil {
		return iamv1.AccessFindingList{}, mapAccessAnalyzerError("list IAM access findings", err)
	}
	var result iamv1.AccessFindingList
	if contractjson.DecodeObjectBytes(encoded, 256*1024, &result) != nil {
		return iamv1.AccessFindingList{}, identityaccess.ErrUnavailable
	}
	result.ObservedAt = result.ObservedAt.UTC()
	for index := range result.Coverage {
		if result.Coverage[index].ObservedFrom != nil {
			observed := result.Coverage[index].ObservedFrom.UTC()
			result.Coverage[index].ObservedFrom = &observed
		}
		if result.Coverage[index].ObservedThrough != nil {
			observed := result.Coverage[index].ObservedThrough.UTC()
			result.Coverage[index].ObservedThrough = &observed
		}
	}
	if len(result.Items) > iamv1.DirectoryPageSize+1 {
		return iamv1.AccessFindingList{}, identityaccess.ErrUnavailable
	}
	previous := read.After
	for index := range result.Items {
		normalizeAccessFinding(&result.Items[index])
		if iamv1.ValidateAccessFinding(result.Items[index]) != nil || result.Items[index].AccountID != read.AccountID ||
			result.Items[index].AnalyzerID != read.AnalyzerID || string(result.Items[index].ID) <= previous ||
			(filter.Status != iamv1.AccessFindingStatusAll && string(result.Items[index].Status) != string(filter.Status)) {
			return iamv1.AccessFindingList{}, identityaccess.ErrUnavailable
		}
		previous = string(result.Items[index].ID)
	}
	if len(result.Items) > iamv1.DirectoryPageSize {
		result.Items = result.Items[:iamv1.DirectoryPageSize]
		result.NextAfter = string(result.Items[iamv1.DirectoryPageSize-1].ID)
	}
	validation := result
	validation.NextAfter = ""
	if iamv1.ValidateAccessFindingList(validation) != nil || result.AccountID != read.AccountID || result.AnalyzerID != read.AnalyzerID {
		return iamv1.AccessFindingList{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadAccessFindingDirectoryRevision(ctx context.Context, read identityaccess.AccessFindingRead) (authority.AccessFindingDirectoryRevision, error) {
	var analyzerVersion, recoveryEpoch int64
	if err := value.tx.QueryRow(ctx, "SELECT analyzer_resource_version,recovery_epoch FROM iam.read_access_finding_directory_revision($1,$2,$3,$4,$5)",
		read.AccountID, read.ActorPrincipalID, read.ActorSessionID, read.DecisionID, read.AnalyzerID).Scan(&analyzerVersion, &recoveryEpoch); err != nil {
		return authority.AccessFindingDirectoryRevision{}, mapAccessAnalyzerError("read IAM access finding directory revision", err)
	}
	if analyzerVersion <= 0 || recoveryEpoch < 0 {
		return authority.AccessFindingDirectoryRevision{}, identityaccess.ErrUnavailable
	}
	result := authority.AccessFindingDirectoryRevision{AnalyzerResourceVersion: uint64(analyzerVersion), RecoveryEpoch: uint64(recoveryEpoch)}
	if authority.ValidateAccessFindingDirectoryRevision(result) != nil {
		return authority.AccessFindingDirectoryRevision{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadAccessFinding(ctx context.Context, read identityaccess.AccessFindingRead) (iamv1.AccessFinding, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_access_finding($1,$2,$3,$4,$5,$6)", read.AccountID,
		read.ActorPrincipalID, read.ActorSessionID, read.DecisionID, read.AnalyzerID, read.FindingID).Scan(&encoded); err != nil {
		return iamv1.AccessFinding{}, mapAccessFindingError("read IAM access finding", err)
	}
	return decodeAccessFinding(encoded, read.AccountID, read.AnalyzerID, read.FindingID)
}

func (value *transaction) SetAccessFindingArchived(ctx context.Context, mutation identityaccess.AccessFindingMutation) (iamv1.AccessFinding, error) {
	if iamv1.ValidateID("actorSessionId", string(mutation.Session.ID)) != nil || mutation.ExpectedVersion == 0 ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.AccessFinding{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.AccessFinding{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.set_access_finding_archived($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)",
		mutation.AccountID, mutation.ActorPrincipalID, mutation.ActorSessionID, mutation.DecisionID, mutation.AnalyzerID,
		mutation.FindingID, mutation.RequestID, mutation.RequestDigest, mutation.ExpectedVersion, mutation.Archived, event).Scan(&encoded)
	if err != nil {
		return iamv1.AccessFinding{}, mapAccessFindingError("set IAM access finding disposition", err)
	}
	return decodeAccessFinding(encoded, mutation.AccountID, mutation.AnalyzerID, mutation.FindingID)
}

func decodeAccessFinding(encoded []byte, account iamv1.AccountID, analyzer iamv1.AccessAnalyzerID,
	expected iamv1.AccessFindingID) (iamv1.AccessFinding, error) {
	var result iamv1.AccessFinding
	if contractjson.DecodeObjectBytes(encoded, 16*1024, &result) != nil {
		return iamv1.AccessFinding{}, identityaccess.ErrUnavailable
	}
	normalizeAccessFinding(&result)
	if iamv1.ValidateAccessFinding(result) != nil || result.AccountID != account || result.AnalyzerID != analyzer || result.ID != expected {
		return iamv1.AccessFinding{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func decodeAccessAnalyzer(encoded []byte, account iamv1.AccountID, expected iamv1.AccessAnalyzerID) (iamv1.AccessAnalyzer, error) {
	var result iamv1.AccessAnalyzer
	if contractjson.DecodeObjectBytes(encoded, 8192, &result) != nil {
		return iamv1.AccessAnalyzer{}, identityaccess.ErrUnavailable
	}
	normalizeAccessAnalyzer(&result)
	if iamv1.ValidateAccessAnalyzer(result) != nil || result.AccountID != account || (expected != "" && result.ID != expected) {
		return iamv1.AccessAnalyzer{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func normalizeAccessAnalyzer(value *iamv1.AccessAnalyzer) {
	value.CreatedAt, value.UpdatedAt = value.CreatedAt.UTC(), value.UpdatedAt.UTC()
}

func mapAccessAnalyzerError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "P0002" {
		return identityaccess.ErrAccessAnalyzerNotFound
	}
	return mapAuthorizationDatabaseError(operation, err)
}

func mapAccessFindingError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "P0002" {
		return identityaccess.ErrAccessFindingNotFound
	}
	return mapAuthorizationDatabaseError(operation, err)
}
