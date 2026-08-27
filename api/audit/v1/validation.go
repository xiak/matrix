package auditv1

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	problemCodePattern = regexp.MustCompile(`^[a-z][a-z0-9.]{2,127}$`)
	cursorPattern      = regexp.MustCompile(`^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`)
	traceParentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

func ValidateID(name, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func ValidateDigest(name, value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

// ValidateAuthority requires exactly one explicit resource authority. A
// platform installation is never represented by an organization's tenant ID.
func ValidateAuthority(tenantID TenantID, installationID string) error {
	if (tenantID == "") == (installationID == "") {
		return errors.New("Audit authority must be exactly one tenant or installation")
	}
	if installationID != "" {
		return ValidateID("installationId", installationID)
	}
	return ValidateID("tenantId", string(tenantID))
}

func ValidateEvent(value Event) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "AuditEvent" {
		problems = append(problems, errors.New("Audit event type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("eventId", string(value.EventID)),
		ValidateAuthority(value.TenantID, value.InstallationID),
		ValidateActor(value.Actor),
		ValidateID("target.id", value.Target.ID),
		ValidateDigest("requestDigest", value.RequestDigest),
		ValidateID("requestId", value.RequestID),
		ValidateID("correlationId", value.CorrelationID),
		validateTimestamp("occurredAt", value.OccurredAt),
	)
	contract, known := ContractForAction(value.Action)
	if !known {
		problems = append(problems, errors.New("Audit action is invalid"))
	} else {
		if contract.PlatformOnly != (value.InstallationID != "") ||
			contract.PlatformOnly && value.Actor.Type != ActorUser {
			problems = append(problems, errors.New("Audit action and authority differ"))
		}
		if value.Target.Kind != contract.Target {
			problems = append(problems, errors.New("Audit action and target kind differ"))
		}
		if !containsResult(contract.Results, value.Result) {
			problems = append(problems, errors.New("Audit action and result differ"))
		}
		if contract.IAMDecisionRequired && value.IAMDecisionID == "" {
			problems = append(problems, errors.New("Audit action requires an IAM decision"))
		}
		if !contract.IAMDecisionPermitted && value.IAMDecisionID != "" {
			problems = append(problems, errors.New("Audit action cannot contain an IAM decision"))
		}
		if contract.OperationRequired && value.OperationID == "" {
			problems = append(problems, errors.New("Audit action requires an Operation"))
		}
		if !contract.OperationRequired && value.OperationID != "" {
			problems = append(problems, errors.New("Audit action cannot contain an Operation"))
		}
	}
	if value.IAMDecisionID != "" {
		problems = append(problems, ValidateID("iamDecisionId", string(value.IAMDecisionID)))
	}
	if value.Action == ActionIAMAuthorizationDecided &&
		string(value.IAMDecisionID) != value.Target.ID {
		problems = append(problems, errors.New("authorization event target differs from its IAM decision"))
	}
	if value.OperationID != "" {
		problems = append(problems, ValidateID("operationId", string(value.OperationID)))
	}
	if value.TraceParent != "" {
		problems = append(problems, validateTraceParent(value.TraceParent))
	}
	return errors.Join(problems...)
}

func ValidateEventForSource(source Source, value Event) error {
	var problems []error
	problems = append(problems, ValidateEvent(value))
	contract, known := ContractForAction(value.Action)
	if !known || source != contract.Source {
		problems = append(problems, errors.New("authenticated source cannot emit this Audit action"))
	}
	return errors.Join(problems...)
}

func ValidateActor(value ActorReference) error {
	var problems []error
	if value.Type != ActorUser && value.Type != ActorServiceAccount && value.Type != ActorSystem {
		problems = append(problems, errors.New("actor type is invalid"))
	}
	problems = append(problems, ValidateID("actor.id", string(value.ID)))
	return errors.Join(problems...)
}

func ValidateAuditRecord(value AuditRecord) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "AuditRecord" {
		problems = append(problems, errors.New("Audit record type metadata is invalid"))
	}
	if !knownSource(value.Source) {
		problems = append(problems, errors.New("Audit source is invalid"))
	}
	problems = append(problems,
		ValidateEventForSource(value.Source, value.Event),
		validatePositiveSequence("sequence", value.Sequence),
		ValidateDigest("contentDigest", value.ContentDigest),
		ValidateDigest("previousHash", value.PreviousHash),
		ValidateDigest("recordHash", value.RecordHash),
		validateTimestamp("ingestedAt", value.IngestedAt),
	)
	if value.Retention != RetentionIndefinite {
		problems = append(problems, errors.New("Audit retention is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateIngestionResult(value IngestionResult) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "IngestionResult" {
		problems = append(problems, errors.New("ingestion result type metadata is invalid"))
	}
	if value.Outcome != IngestionAccepted && value.Outcome != IngestionDuplicate {
		problems = append(problems, errors.New("ingestion outcome is invalid"))
	}
	problems = append(problems, ValidateAuditRecord(value.Record))
	return errors.Join(problems...)
}

func ValidateQueryRecordsRequest(value QueryRecordsRequest) error {
	var problems []error
	if value.PageSize < 1 || value.PageSize > MaxPageSize {
		problems = append(problems, errors.New("pageSize is invalid"))
	}
	if value.Cursor != "" {
		problems = append(problems, validateCursor("cursor", value.Cursor))
	}
	if value.From != nil {
		problems = append(problems, validateTimestamp("from", *value.From))
	}
	if value.To != nil {
		problems = append(problems, validateTimestamp("to", *value.To))
	}
	if value.From != nil && value.To != nil && value.To.Before(*value.From) {
		problems = append(problems, errors.New("query time range is invalid"))
	}
	if value.Action != "" {
		if _, known := ContractForAction(value.Action); !known {
			problems = append(problems, errors.New("query action is invalid"))
		}
	}
	if value.Actor != nil {
		problems = append(problems, ValidateActor(*value.Actor))
	}
	return errors.Join(problems...)
}

func ValidateRecordPage(value RecordPage) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "AuditRecordPage" {
		problems = append(problems, errors.New("Audit record page type metadata is invalid"))
	}
	problems = append(problems, ValidateAuthority(value.TenantID, value.InstallationID))
	if len(value.Records) > MaxPageSize {
		problems = append(problems, errors.New("Audit record page is too large"))
	}
	for index, record := range value.Records {
		problems = append(problems, ValidateAuditRecord(record))
		if record.Event.TenantID != value.TenantID || record.Event.InstallationID != value.InstallationID {
			problems = append(problems, errors.New("Audit page contains another authority"))
		}
		if index > 0 && value.Records[index-1].Sequence <= record.Sequence {
			problems = append(problems, errors.New("Audit page sequence order is invalid"))
		}
	}
	if value.NextCursor != "" {
		problems = append(problems, validateCursor("nextCursor", value.NextCursor))
	}
	return errors.Join(problems...)
}

func ValidateVerifyChainRequest(value VerifyChainRequest) error {
	var problems []error
	problems = append(problems, validatePositiveSequence("fromSequence", value.FromSequence))
	if value.MaximumRecords < 1 || value.MaximumRecords > MaxVerifyRecords {
		problems = append(problems, errors.New("maximumRecords is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateChainVerification(value ChainVerification) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ChainVerification" {
		problems = append(problems, errors.New("chain verification type metadata is invalid"))
	}
	if value.State != VerificationVerified {
		problems = append(problems, errors.New("chain verification state is invalid"))
	}
	problems = append(problems,
		ValidateAuthority(value.TenantID, value.InstallationID),
		validatePositiveSequence("fromSequence", value.FromSequence),
		validatePositiveSequence("toSequence", value.ToSequence),
		ValidateDigest("firstPreviousHash", value.FirstPreviousHash),
		ValidateDigest("lastRecordHash", value.LastRecordHash),
		validateTimestamp("verifiedAt", value.VerifiedAt),
	)
	if value.ToSequence < value.FromSequence || value.ToSequence-value.FromSequence >= MaxVerifyRecords ||
		value.RecordCount != int(value.ToSequence-value.FromSequence+1) {
		problems = append(problems, errors.New("chain verification range is invalid"))
	}
	if value.Complete {
		if value.NextSequence != nil {
			problems = append(problems, errors.New("complete verification contains nextSequence"))
		}
	} else if value.NextSequence == nil || *value.NextSequence != value.ToSequence+1 {
		problems = append(problems, errors.New("partial verification nextSequence is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateVerifyInstallationRequest(value VerifyInstallationRequest) error {
	return errors.Join(
		ValidateID("installationId", value.InstallationID),
		ValidateID("operationId", string(value.OperationID)),
		ValidateID("deploymentId", value.DeploymentID),
	)
}

func ValidateInstallationVerification(value InstallationVerification) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "InstallationVerification" {
		problems = append(problems, errors.New("installation verification type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("installationId", value.InstallationID),
		ValidateID("operationId", string(value.OperationID)),
		ValidateID("deploymentId", value.DeploymentID),
		validateTimestamp("checkedAt", value.CheckedAt),
	)
	switch value.State {
	case InstallationVerificationPending:
		if value.EventID != "" || value.IAMDecisionID != "" ||
			value.RecordSequence != 0 || value.FromSequence != 0 ||
			value.ToSequence != 0 || value.RecordHash != "" {
			problems = append(problems, errors.New("pending installation verification cannot claim an Audit record"))
		}
	case InstallationVerificationVerified:
		problems = append(problems,
			ValidateID("eventId", string(value.EventID)),
			ValidateID("iamDecisionId", string(value.IAMDecisionID)),
			ValidateDigest("recordHash", value.RecordHash),
		)
		if value.RecordSequence == 0 || value.FromSequence == 0 ||
			value.ToSequence != value.RecordSequence || value.RecordSequence < value.FromSequence {
			problems = append(problems, errors.New("verified installation Audit range is invalid"))
		}
	default:
		problems = append(problems, errors.New("installation verification state is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateReadiness(value Readiness) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Readiness" {
		problems = append(problems, errors.New("readiness type metadata is invalid"))
	}
	if value.State != ReadinessReady && value.State != ReadinessNotReady {
		problems = append(problems, errors.New("readiness state is invalid"))
	}
	problems = append(problems,
		validatePositiveSequence("schemaVersion", value.SchemaVersion),
		validateTimestamp("checkedAt", value.CheckedAt),
	)
	return errors.Join(problems...)
}

func ValidateProblem(value Problem) error {
	var problems []error
	parsed, err := url.Parse(value.Type)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" {
		problems = append(problems, errors.New("problem type is invalid"))
	}
	if value.Status < 400 || value.Status > 599 {
		problems = append(problems, errors.New("problem status is invalid"))
	}
	if !problemCodePattern.MatchString(value.Code) {
		problems = append(problems, errors.New("problem code is invalid"))
	}
	problems = append(problems,
		validateText("problem.title", value.Title, 1, 128),
		validateText("problem.requestId", value.RequestID, 1, 128),
	)
	if value.Detail != "" {
		problems = append(problems, validateText("problem.detail", value.Detail, 1, 256))
	}
	return errors.Join(problems...)
}

func knownSource(value Source) bool {
	return value == SourceIAM || value == SourcePaaS || value == SourceAudit
}

func containsResult(values []Result, target Result) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validateTraceParent(value string) error {
	if !traceParentPattern.MatchString(value) {
		return errors.New("traceparent is invalid")
	}
	parts := strings.Split(value, "-")
	if parts[1] == strings.Repeat("0", 32) || parts[2] == strings.Repeat("0", 16) {
		return errors.New("traceparent is invalid")
	}
	return nil
}

func validateCursor(name string, value Cursor) error {
	encoded := string(value)
	parts := strings.Split(encoded, ".")
	if len(encoded) > 4096 || !cursorPattern.MatchString(encoded) || len(parts) != 3 ||
		len(parts[1]) < 16 || len(parts[1]) > 2048 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateTimestamp(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) || value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf("%s must use UTC microsecond precision", name)
	}
	return nil
}

func validatePositiveSequence(name string, value uint64) error {
	if value == 0 || value > 9007199254740991 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateText(name, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is invalid", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}
