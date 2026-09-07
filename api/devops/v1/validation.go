package devopsv1

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	fieldPattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.\[\]-]{0,127}$`)
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
	if value.ResourceVersion == 0 {
		problems = append(problems, errors.New("metadata.resourceVersion must be positive"))
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
	if value.Revision == 0 {
		problems = append(problems, errors.New("activeRevision.revision must be positive"))
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
	if value.Revision == 0 {
		problems = append(problems, errors.New("revision must be positive"))
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
	case ErrorConflict:
		return status == 409
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
