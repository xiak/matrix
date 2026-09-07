package devopsv1

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	idPattern                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	namePattern              = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	digestPattern            = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	fieldPattern             = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.\[\]-]{0,127}$`)
	hostPattern              = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	repositorySegmentPattern = regexp.MustCompile(
		`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`,
	)
	branchPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	deliveryIDPattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	gitObjectIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

func ValidateID(name, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s must be an opaque 1-128 character identifier", name)
	}
	return nil
}

func ValidateDigest(name, value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("%s must be a lowercase sha256 digest", name)
	}
	return nil
}

func ValidateResourceScope(value ResourceScope) error {
	return ValidateID("scope.tenantId", string(value.TenantID))
}

func ValidateResourceMetadata(value ResourceMetadata) error {
	var problems []error
	problems = append(problems,
		ValidateID("metadata.id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		validateContractTime("metadata.createdAt", value.CreatedAt),
		validateContractTime("metadata.updatedAt", value.UpdatedAt),
	)
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("metadata.name must be a DNS label"))
	}
	if value.ResourceVersion == 0 || value.ResourceVersion > MaximumContractInteger {
		problems = append(problems, errors.New("metadata.resourceVersion is invalid"))
	}
	if value.UpdatedAt.Before(value.CreatedAt) {
		problems = append(problems, errors.New("metadata.updatedAt cannot precede createdAt"))
	}
	return errors.Join(problems...)
}

func ValidateDevOpsProject(value DevOpsProject) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "DevOpsProject" {
		problems = append(problems, errors.New("DevOps project type metadata is invalid"))
	}
	problems = append(problems, ValidateResourceMetadata(value.Metadata))
	return errors.Join(problems...)
}

func ValidateCreateDevOpsProjectRequest(value CreateDevOpsProjectRequest) error {
	var problems []error
	problems = append(problems, ValidateID("id", string(value.ID)))
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("name must be a DNS label"))
	}
	return errors.Join(problems...)
}

func ValidateSourceConnectionSpec(value SourceConnectionSpec) error {
	var problems []error
	problems = append(problems,
		ValidateID("spec.adapterId", string(value.AdapterID)),
		ValidateID("spec.webhookSecretRef", string(value.WebhookSecretRef)),
		ValidateID("spec.fetchCredentialRef", string(value.FetchCredentialRef)),
		ValidateID("spec.reportCredentialRef", string(value.ReportCredentialRef)),
		validateEndpointOrigins(value.AllowedEndpointOrigins),
	)
	if value.WebhookSecretRef == value.FetchCredentialRef ||
		value.WebhookSecretRef == value.ReportCredentialRef ||
		value.FetchCredentialRef == value.ReportCredentialRef {
		problems = append(problems, errors.New("source connection credential references must be distinct"))
	}
	return errors.Join(problems...)
}

func ValidateSourceConnectionStatus(value SourceConnectionStatus) error {
	if !contains(SourceConnectionHealthStates(), value.Health) {
		return errors.New("source connection health is invalid")
	}
	return validateContractTime("status.observedAt", value.ObservedAt)
}

func ValidateSourceConnection(value SourceConnection) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "SourceConnection" {
		problems = append(problems, errors.New("source connection type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateSourceConnectionSpec(value.Spec),
		ValidateSourceConnectionStatus(value.Status),
	)
	if value.Status.ObservedAt.Before(value.Metadata.CreatedAt) ||
		value.Status.ObservedAt.After(value.Metadata.UpdatedAt) {
		problems = append(problems, errors.New("source connection observation time is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateCreateSourceConnectionRequest(value CreateSourceConnectionRequest) error {
	var problems []error
	problems = append(problems,
		ValidateID("id", string(value.ID)),
		ValidateSourceConnectionSpec(value.Spec),
	)
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("name must be a DNS label"))
	}
	return errors.Join(problems...)
}

func ValidateUpdateSourceConnectionRequest(value UpdateSourceConnectionRequest) error {
	return ValidateSourceConnectionSpec(value.Spec)
}

func ValidateRepositoryBindingSpec(value RepositoryBindingSpec) error {
	return errors.Join(
		ValidateID("spec.sourceConnectionId", string(value.SourceConnectionID)),
		ValidateID("spec.externalRepositoryId", string(value.ExternalRepositoryID)),
		validateRepositoryPath(value.RepositoryPath),
		validateTrustedBranch(value.TrustedDefaultBranch),
	)
}

// ValidateTrustedDefaultBranch exposes the same closed branch-name contract to
// provider adapters without making provider payload types part of this API.
func ValidateTrustedDefaultBranch(value string) error {
	return validateTrustedBranch(value)
}

func ValidateRepositoryBindingStatus(value RepositoryBindingStatus) error {
	if !contains(RepositoryBindingHealthStates(), value.Health) {
		return errors.New("repository binding health is invalid")
	}
	return validateContractTime("status.observedAt", value.ObservedAt)
}

func ValidateRepositoryBinding(value RepositoryBinding) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "RepositoryBinding" {
		problems = append(problems, errors.New("repository binding type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("projectId", string(value.ProjectID)),
		ValidateRepositoryBindingSpec(value.Spec),
		validateExactDigest(
			"contentDigest", value.ContentDigest, RepositoryBindingSpecDigest(value.Spec),
		),
		ValidateRepositoryBindingStatus(value.Status),
	)
	if value.Status.ObservedAt.Before(value.Metadata.CreatedAt) ||
		value.Status.ObservedAt.After(value.Metadata.UpdatedAt) {
		problems = append(problems, errors.New("repository binding observation time is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateCreateRepositoryBindingRequest(value CreateRepositoryBindingRequest) error {
	var problems []error
	problems = append(problems,
		ValidateID("id", string(value.ID)),
		ValidateID("projectId", string(value.ProjectID)),
		ValidateRepositoryBindingSpec(value.Spec),
	)
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("name must be a DNS label"))
	}
	return errors.Join(problems...)
}

func ValidateUpdateRepositoryBindingRequest(value UpdateRepositoryBindingRequest) error {
	return ValidateRepositoryBindingSpec(value.Spec)
}

func ValidatePipelineDraftSpec(value PipelineDraftSpec) error {
	var problems []error
	problems = append(problems, ValidateID("repositoryBindingId", string(value.RepositoryBindingID)))
	if !contains(TriggerPolicies(), value.TriggerPolicy) {
		problems = append(problems, errors.New("triggerPolicy is not supported"))
	}
	if !contains(VerificationProfiles(), value.VerificationProfile) {
		problems = append(problems, errors.New("verificationProfile is not supported"))
	}
	if !contains(DependencyEgressPolicies(), value.DependencyEgress) {
		problems = append(problems, errors.New("dependencyEgress is not supported"))
	}
	if !contains(ReporterPolicies(), value.ReporterPolicy) {
		problems = append(problems, errors.New("reporterPolicy is not supported"))
	}
	return errors.Join(problems...)
}

func ValidatePipelineDraft(value PipelineDraft) error {
	return errors.Join(
		ValidatePipelineDraftSpec(value.Spec),
		validateExactDigest("draft.contentDigest", value.ContentDigest, PipelineDraftSpecDigest(value.Spec)),
	)
}

func ValidatePipelineRevisionReference(value PipelineRevisionReference) error {
	var problems []error
	problems = append(problems,
		ValidateID("activeRevision.id", string(value.ID)),
		ValidateDigest("activeRevision.contentDigest", value.ContentDigest),
	)
	if value.Revision == 0 || value.Revision > MaximumContractInteger {
		problems = append(problems, errors.New("activeRevision.revision is invalid"))
	}
	return errors.Join(problems...)
}

func ValidatePipeline(value Pipeline) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Pipeline" {
		problems = append(problems, errors.New("Pipeline type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("projectId", string(value.ProjectID)),
		ValidatePipelineDraft(value.Draft),
	)
	if value.ActiveRevision != nil {
		problems = append(problems, ValidatePipelineRevisionReference(*value.ActiveRevision))
	}
	return errors.Join(problems...)
}

func ValidateCreatePipelineRequest(value CreatePipelineRequest) error {
	var problems []error
	problems = append(problems,
		ValidateID("id", string(value.ID)),
		ValidateID("projectId", string(value.ProjectID)),
		ValidatePipelineDraftSpec(value.Draft),
	)
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("name must be a DNS label"))
	}
	return errors.Join(problems...)
}

func ValidateUpdatePipelineDraftRequest(value UpdatePipelineDraftRequest) error {
	return ValidatePipelineDraftSpec(value.Draft)
}

func ValidateVerificationLimits(value VerificationLimits) error {
	if value != FixedVerificationLimits() {
		return errors.New("verification limits do not match the approved profile")
	}
	return nil
}

func ValidatePipelineRevisionSpec(value PipelineRevisionSpec) error {
	var problems []error
	problems = append(problems,
		ValidateID("spec.repositoryBindingId", string(value.RepositoryBindingID)),
		ValidateDigest("spec.repositoryBindingDigest", value.RepositoryBindingDigest),
		ValidateDigest("spec.toolchainImageDigest", value.ToolchainImageDigest),
		ValidateVerificationLimits(value.Limits),
	)
	if value.TriggerPolicy != TriggerChange ||
		value.VerificationProfile != VerificationGo126OfflineV1 ||
		value.ExecutorProfile != ExecutorMatrixNativeIsolatedV1 ||
		value.ToolchainImageDigest != Go126OfflineToolchainImageDigest ||
		value.DependencyEgress != DependencyEgressNone ||
		value.ReporterPolicy != ReporterChangeCheckV1 {
		problems = append(problems, errors.New("revision does not match the approved execution profile"))
	}
	wantSteps := FixedVerificationSteps()
	if !slices.Equal(value.Steps, wantSteps) {
		problems = append(problems, errors.New("verification steps do not match the approved profile"))
	}
	return errors.Join(problems...)
}

func ValidateSubjectRef(value SubjectRef) error {
	var problems []error
	if !contains(SubjectKinds(), value.Kind) {
		problems = append(problems, errors.New("subject kind is invalid"))
	}
	problems = append(problems, ValidateID("subject.id", value.ID))
	return errors.Join(problems...)
}

func ValidatePipelineRevision(value PipelineRevision) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "PipelineRevision" {
		problems = append(problems, errors.New("Pipeline revision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		ValidateID("pipelineId", string(value.PipelineID)),
		ValidateID("projectId", string(value.ProjectID)),
		ValidatePipelineRevisionSpec(value.Spec),
		ValidateSubjectRef(value.ActivatedBy),
		validateContractTime("activatedAt", value.ActivatedAt),
	)
	if value.Revision == 0 || value.Revision > MaximumContractInteger {
		problems = append(problems, errors.New("revision is invalid"))
	}
	contentDigest := PipelineRevisionSpecDigest(value.Spec)
	problems = append(problems, validateExactDigest("contentDigest", value.ContentDigest, contentDigest))
	expectedID, err := PipelineRevisionID(value.Scope, value.PipelineID, value.Revision, contentDigest)
	if err != nil || value.ID != expectedID {
		problems = append(problems, errors.New("Pipeline revision identity is invalid"))
	}
	return errors.Join(problems...)
}

func ValidatePipelineActivation(value PipelineActivation) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "PipelineActivation" {
		problems = append(problems, errors.New("Pipeline activation type metadata is invalid"))
	}
	problems = append(problems, ValidatePipeline(value.Pipeline), ValidatePipelineRevision(value.Revision))
	active := value.Pipeline.ActiveRevision
	if active == nil || active.ID != value.Revision.ID ||
		active.Revision != value.Revision.Revision ||
		active.ContentDigest != value.Revision.ContentDigest ||
		value.Pipeline.Metadata.Scope != value.Revision.Scope ||
		value.Pipeline.Metadata.ID != value.Revision.PipelineID ||
		value.Pipeline.ProjectID != value.Revision.ProjectID {
		problems = append(problems, errors.New("Pipeline activation does not bind one exact revision"))
	}
	return errors.Join(problems...)
}

func ValidateChangeIdentity(value ChangeIdentity) error {
	var problems []error
	if value.Number == 0 || value.Number > MaximumContractInteger {
		problems = append(problems, errors.New("change number is invalid"))
	}
	if !contains(ChangeActions(), value.Action) {
		problems = append(problems, errors.New("change action is invalid"))
	}
	if !gitObjectIDPattern.MatchString(value.HeadCommit) {
		problems = append(problems, errors.New("head commit is invalid"))
	}
	if !gitObjectIDPattern.MatchString(value.TrustedBaseCommit) {
		problems = append(problems, errors.New("trusted base commit is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateSourceEventSpec(value SourceEventSpec) error {
	return errors.Join(
		ValidateID("spec.projectId", string(value.ProjectID)),
		ValidateID("spec.sourceConnectionId", string(value.SourceConnectionID)),
		ValidateID("spec.repositoryBindingId", string(value.RepositoryBindingID)),
		ValidateDigest("spec.repositoryBindingDigest", value.RepositoryBindingDigest),
		ValidateID("spec.externalRepositoryId", string(value.ExternalRepositoryID)),
		validateDeliveryID(value.DeliveryID),
		ValidateDigest("spec.canonicalPayloadDigest", value.CanonicalPayloadDigest),
		ValidateChangeIdentity(value.Change),
	)
}

func ValidateSourceEvent(value SourceEvent) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "SourceEvent" {
		problems = append(problems, errors.New("source event type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		ValidateSourceEventSpec(value.Spec),
		validateExactDigest("contentDigest", value.ContentDigest, SourceEventSpecDigest(value.Spec)),
		validateContractTime("receivedAt", value.ReceivedAt),
	)
	expectedID, err := SourceEventID(value.Scope, value.Spec.SourceConnectionID, value.Spec.DeliveryID)
	if err != nil || value.ID != expectedID {
		problems = append(problems, errors.New("source event identity is invalid"))
	}
	return errors.Join(problems...)
}

func ValidatePipelineRunInput(value PipelineRunInput) error {
	return errors.Join(
		ValidateID("input.sourceEventId", string(value.SourceEventID)),
		ValidateDigest("input.sourceEventDigest", value.SourceEventDigest),
		ValidateID("input.pipelineRevisionId", string(value.PipelineRevisionID)),
		ValidateDigest("input.pipelineRevisionDigest", value.PipelineRevisionDigest),
		ValidateID("input.repositoryBindingId", string(value.RepositoryBindingID)),
		ValidateDigest("input.repositoryBindingDigest", value.RepositoryBindingDigest),
		ValidateChangeIdentity(value.Change),
	)
}

func ValidatePipelineRunStatus(value PipelineRunStatus) error {
	var problems []error
	if !contains(PipelineRunStates(), value.State) {
		problems = append(problems, errors.New("PipelineRun state is invalid"))
	}
	if !contains(PipelineRunStages(), value.Stage) {
		problems = append(problems, errors.New("PipelineRun stage is invalid"))
	}
	if value.Reason != "" && !contains(PipelineRunReasons(), value.Reason) {
		problems = append(problems, errors.New("PipelineRun reason is invalid"))
	}
	if value.ResourceVersion == 0 || value.ResourceVersion > MaximumContractInteger {
		problems = append(problems, errors.New("PipelineRun status resourceVersion is invalid"))
	}
	problems = append(problems, validateContractTime("status.observedAt", value.ObservedAt))
	if value.CompletedAt != nil {
		problems = append(problems, validateContractTime("status.completedAt", *value.CompletedAt))
		if value.CompletedAt.After(value.ObservedAt) {
			problems = append(problems, errors.New("PipelineRun completion exceeds its observation time"))
		}
	}

	switch value.State {
	case PipelineRunQueued:
		if value.Stage != PipelineRunStageReceive ||
			value.Reason != PipelineRunReasonEventAdmitted ||
			value.ResourceVersion != 1 || value.CompletedAt != nil {
			problems = append(problems, errors.New("queued PipelineRun status is invalid"))
		}
	case PipelineRunFetching:
		if value.Stage != PipelineRunStageFetch || value.Reason != "" || value.CompletedAt != nil {
			problems = append(problems, errors.New("fetching PipelineRun status is invalid"))
		}
	case PipelineRunVerifying:
		if value.Stage != PipelineRunStageVerify || value.Reason != "" || value.CompletedAt != nil {
			problems = append(problems, errors.New("verifying PipelineRun status is invalid"))
		}
	case PipelineRunReporting:
		if value.Stage != PipelineRunStageReport || value.Reason != "" || value.CompletedAt != nil {
			problems = append(problems, errors.New("reporting PipelineRun status is invalid"))
		}
	case PipelineRunSucceeded:
		if value.Stage != PipelineRunStageReport || value.Reason != PipelineRunReasonCompleted ||
			value.CompletedAt == nil {
			problems = append(problems, errors.New("succeeded PipelineRun status is invalid"))
		}
	case PipelineRunFailed:
		if !pipelineRunFailureReason(value.Reason) || value.CompletedAt == nil {
			problems = append(problems, errors.New("failed PipelineRun status is invalid"))
		}
	case PipelineRunCancelled:
		if value.Reason != PipelineRunReasonCancelled || value.CompletedAt == nil {
			problems = append(problems, errors.New("cancelled PipelineRun status is invalid"))
		}
	case PipelineRunReconciling:
		if value.Stage != PipelineRunStageReport ||
			value.Reason != PipelineRunReasonExternalEffectUncertain || value.CompletedAt != nil {
			problems = append(problems, errors.New("reconciling PipelineRun status is invalid"))
		}
	case PipelineRunManualIntervention:
		if value.Stage != PipelineRunStageReport ||
			value.Reason != PipelineRunReasonReconciliationExhausted || value.CompletedAt == nil {
			problems = append(problems, errors.New("manual-intervention PipelineRun status is invalid"))
		}
	}
	return errors.Join(problems...)
}

func ValidatePipelineRun(value PipelineRun) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "PipelineRun" {
		problems = append(problems, errors.New("PipelineRun type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		ValidateID("projectId", string(value.ProjectID)),
		ValidateID("pipelineId", string(value.PipelineID)),
		ValidatePipelineRunInput(value.Input),
		validateExactDigest("inputDigest", value.InputDigest, PipelineRunInputDigest(value.Input)),
		ValidatePipelineRunStatus(value.Status),
		validateContractTime("createdAt", value.CreatedAt),
		validateContractTime("updatedAt", value.UpdatedAt),
	)
	expectedID, err := PipelineRunID(
		value.Scope,
		value.Input.SourceEventID,
		value.Input.PipelineRevisionID,
		value.InputDigest,
	)
	if err != nil || value.ID != expectedID {
		problems = append(problems, errors.New("PipelineRun identity is invalid"))
	}
	if value.UpdatedAt.Before(value.CreatedAt) || !value.UpdatedAt.Equal(value.Status.ObservedAt) {
		problems = append(problems, errors.New("PipelineRun observation time is invalid"))
	}
	if value.Status.State == PipelineRunQueued && !value.CreatedAt.Equal(value.UpdatedAt) {
		problems = append(problems, errors.New("queued PipelineRun timestamps are invalid"))
	}
	if value.Status.CompletedAt != nil && !value.Status.CompletedAt.Equal(value.UpdatedAt) {
		problems = append(problems, errors.New("terminal PipelineRun timestamp is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateReadiness(value Readiness) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Readiness" {
		problems = append(problems, errors.New("readiness type metadata is invalid"))
	}
	if !contains(ReadinessStates(), value.State) {
		problems = append(problems, errors.New("readiness state is invalid"))
	}
	if value.SchemaVersion == 0 || value.SchemaVersion > MaximumContractInteger {
		problems = append(problems, errors.New("readiness schemaVersion is invalid"))
	}
	problems = append(problems, validateContractTime("readiness.checkedAt", value.CheckedAt))
	return errors.Join(problems...)
}

func validateDeliveryID(value string) error {
	if !deliveryIDPattern.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" {
		return errors.New("deliveryId must be a canonical non-zero UUID")
	}
	return nil
}

func pipelineRunFailureReason(value PipelineRunReason) bool {
	switch value {
	case PipelineRunReasonSourceUnavailable,
		PipelineRunReasonCommitMismatch,
		PipelineRunReasonExecutorUnavailable,
		PipelineRunReasonVerificationFailed,
		PipelineRunReasonDeadlineExceeded,
		PipelineRunReasonReportUnavailable,
		PipelineRunReasonReportConflict:
		return true
	default:
		return false
	}
}

func ValidateProblem(value Problem) error {
	var problems []error
	parsed, err := url.Parse(value.Type)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host != "errors.matrix.xiak.com" {
		problems = append(problems, errors.New("problem type is invalid"))
	}
	if value.Status < 400 || value.Status > 599 || !contains(ErrorCodes(), value.Code) ||
		!errorCodeAcceptsStatus(value.Code, value.Status) {
		problems = append(problems, errors.New("problem status or code is invalid"))
	}
	problems = append(problems,
		validateSafeText("title", value.Title, 1, 160),
		ValidateID("traceId", value.TraceID),
	)
	if value.Detail != "" {
		problems = append(problems, validateSafeText("detail", value.Detail, 1, 512))
	}
	if value.Instance != "" && (!strings.HasPrefix(value.Instance, "/") ||
		validateSafeText("instance", value.Instance, 1, 256) != nil) {
		problems = append(problems, errors.New("problem instance is invalid"))
	}
	if len(value.Violations) > 32 {
		problems = append(problems, errors.New("too many field violations"))
	}
	previous := ""
	for _, violation := range value.Violations {
		if !fieldPattern.MatchString(violation.Field) || violation.Field <= previous {
			problems = append(problems, errors.New("field violations are invalid, duplicated, or unsorted"))
		}
		problems = append(problems, validateSafeText("violation.description", violation.Description, 1, 256))
		previous = violation.Field
	}
	return errors.Join(problems...)
}

func errorCodeAcceptsStatus(code ErrorCode, status int) bool {
	switch code {
	case ErrorInvalidArgument:
		return status == 400 || status == 422
	case ErrorUnauthenticated:
		return status == 401
	case ErrorForbidden:
		return status == 403
	case ErrorNotFound:
		return status == 404
	case ErrorMethodNotAllowed:
		return status == 405
	case ErrorConflict:
		return status == 409
	case ErrorResourceExhausted:
		return status == 429
	case ErrorPayloadTooLarge:
		return status == 413
	case ErrorUnsupportedMediaType:
		return status == 415
	case ErrorPreconditionRequired:
		return status == 428
	case ErrorPreconditionFailed:
		return status == 412
	case ErrorInternal:
		return status == 500
	case ErrorUnavailable:
		return status == 503
	default:
		return false
	}
}

func validateExactDigest(name, value, expected string) error {
	if ValidateDigest(name, value) != nil || value != expected {
		return fmt.Errorf("%s does not match canonical content", name)
	}
	return nil
}

func validateContractTime(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateEndpointOrigins(values []string) error {
	if len(values) == 0 || len(values) > 8 {
		return errors.New("allowedEndpointOrigins must contain between one and eight origins")
	}
	var problems []error
	previous := ""
	for index, value := range values {
		if value <= previous {
			problems = append(problems, errors.New("allowedEndpointOrigins must be sorted and unique"))
		}
		previous = value
		if validateEndpointOrigin(value) != nil {
			problems = append(problems, fmt.Errorf("allowedEndpointOrigins[%d] is invalid", index))
		}
	}
	return errors.Join(problems...)
}

func validateEndpointOrigin(value string) error {
	if validateSafeText("endpoint origin", value, 1, 512) != nil {
		return errors.New("endpoint origin is invalid")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.String() != value {
		return errors.New("endpoint origin must be a canonical HTTPS origin")
	}
	host := parsed.Hostname()
	if host == "" || host != strings.ToLower(host) || !hostPattern.MatchString(host) ||
		strings.Contains(host, "..") || host == "localhost" ||
		strings.HasSuffix(host, ".localhost") {
		return errors.New("endpoint origin host is invalid")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") ||
			strings.HasSuffix(label, "-") {
			return errors.New("endpoint origin host is invalid")
		}
	}
	port := parsed.Port()
	if port != "" {
		numeric, err := strconv.Atoi(port)
		if err != nil || numeric < 1 || numeric > 65535 ||
			strconv.Itoa(numeric) != port {
			return errors.New("endpoint origin port is invalid")
		}
	}
	return nil
}

func validateRepositoryPath(value string) error {
	if validateSafeText("repositoryPath", value, 3, 257) != nil {
		return errors.New("repositoryPath is invalid")
	}
	segments := strings.Split(value, "/")
	if len(segments) != 2 {
		return errors.New("repositoryPath must contain exactly owner and repository")
	}
	for _, segment := range segments {
		if !repositorySegmentPattern.MatchString(segment) || segment == "." ||
			segment == ".." || strings.Contains(segment, "..") {
			return errors.New("repositoryPath contains an invalid segment")
		}
	}
	return nil
}

func validateTrustedBranch(value string) error {
	if !branchPattern.MatchString(value) || strings.Contains(value, "..") ||
		strings.Contains(value, "//") || strings.Contains(value, "@{") ||
		strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") {
		return errors.New("trustedDefaultBranch is invalid")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || strings.HasPrefix(segment, ".") ||
			strings.HasSuffix(segment, ".lock") {
			return errors.New("trustedDefaultBranch is invalid")
		}
	}
	return nil
}

func validateSafeText(name, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum ||
		strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is invalid", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == unicode.ReplacementChar {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}

func contains[T comparable](values []T, target T) bool {
	return slices.Contains(values, target)
}
