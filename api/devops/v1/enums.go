package devopsv1

type TriggerPolicy string
type VerificationProfile string
type ExecutorProfile string
type DependencyEgressPolicy string
type ReporterPolicy string
type VerificationStepKind string
type SubjectKind string
type SourceConnectionHealth string
type SourceConnectionHealthReason string
type RepositoryBindingHealth string
type RepositoryBindingHealthReason string
type ReadinessState string
type ErrorCode string
type ChangeAction string
type PipelineRunState string
type PipelineRunStage string
type PipelineRunReason string

const (
	TriggerChange TriggerPolicy = "CHANGE"
)

const (
	VerificationGo126OfflineV1 VerificationProfile = "GO_1_26_OFFLINE_V1"
)

const (
	ExecutorMatrixNativeIsolatedV1 ExecutorProfile = "MATRIX_NATIVE_ISOLATED_V1"
)

const (
	DependencyEgressNone DependencyEgressPolicy = "NONE"
)

const (
	ReporterChangeCheckV1 ReporterPolicy = "CHANGE_CHECK_V1"
)

const (
	VerificationStepGoTest VerificationStepKind = "GO_TEST"
	VerificationStepGoVet  VerificationStepKind = "GO_VET"
)

const (
	SubjectUser           SubjectKind = "USER"
	SubjectServiceAccount SubjectKind = "SERVICE_ACCOUNT"
)

const (
	SourceConnectionPending     SourceConnectionHealth = "PENDING"
	SourceConnectionReady       SourceConnectionHealth = "READY"
	SourceConnectionUnavailable SourceConnectionHealth = "UNAVAILABLE"
)

const (
	SourceConnectionReasonConfigurationChanged SourceConnectionHealthReason = "CONFIGURATION_CHANGED"
	SourceConnectionReasonObserved             SourceConnectionHealthReason = "OBSERVED"
	SourceConnectionReasonSecretUnavailable    SourceConnectionHealthReason = "SECRET_UNAVAILABLE"
	SourceConnectionReasonProviderUnavailable  SourceConnectionHealthReason = "PROVIDER_UNAVAILABLE"
	SourceConnectionReasonProviderUnsupported  SourceConnectionHealthReason = "PROVIDER_UNSUPPORTED"
	SourceConnectionReasonCredentialRejected   SourceConnectionHealthReason = "CREDENTIAL_REJECTED"
)

const (
	RepositoryBindingPending     RepositoryBindingHealth = "PENDING"
	RepositoryBindingReady       RepositoryBindingHealth = "READY"
	RepositoryBindingUnavailable RepositoryBindingHealth = "UNAVAILABLE"
)

const (
	RepositoryBindingReasonConfigurationChanged   RepositoryBindingHealthReason = "CONFIGURATION_CHANGED"
	RepositoryBindingReasonConnectionNotReady     RepositoryBindingHealthReason = "CONNECTION_NOT_READY"
	RepositoryBindingReasonObserved               RepositoryBindingHealthReason = "OBSERVED"
	RepositoryBindingReasonRepositoryUnavailable  RepositoryBindingHealthReason = "REPOSITORY_UNAVAILABLE"
	RepositoryBindingReasonIdentityMismatch       RepositoryBindingHealthReason = "IDENTITY_MISMATCH"
	RepositoryBindingReasonFetchPermissionDenied  RepositoryBindingHealthReason = "FETCH_PERMISSION_DENIED"
	RepositoryBindingReasonReportPermissionDenied RepositoryBindingHealthReason = "REPORT_PERMISSION_DENIED"
)

const (
	ReadinessReady    ReadinessState = "READY"
	ReadinessNotReady ReadinessState = "NOT_READY"
)

const (
	ChangeOpened   ChangeAction = "OPENED"
	ChangeReopened ChangeAction = "REOPENED"
	ChangeUpdated  ChangeAction = "UPDATED"
)

const (
	PipelineRunQueued             PipelineRunState = "QUEUED"
	PipelineRunFetching           PipelineRunState = "FETCHING"
	PipelineRunVerifying          PipelineRunState = "VERIFYING"
	PipelineRunReporting          PipelineRunState = "REPORTING"
	PipelineRunSucceeded          PipelineRunState = "SUCCEEDED"
	PipelineRunFailed             PipelineRunState = "FAILED"
	PipelineRunCancelled          PipelineRunState = "CANCELLED"
	PipelineRunReconciling        PipelineRunState = "RECONCILING"
	PipelineRunManualIntervention PipelineRunState = "MANUAL_INTERVENTION"
)

const (
	PipelineRunStageReceive PipelineRunStage = "RECEIVE"
	PipelineRunStageFetch   PipelineRunStage = "FETCH"
	PipelineRunStageVerify  PipelineRunStage = "VERIFY"
	PipelineRunStageReport  PipelineRunStage = "REPORT"
)

const (
	PipelineRunReasonEventAdmitted           PipelineRunReason = "EVENT_ADMITTED"
	PipelineRunReasonCompleted               PipelineRunReason = "COMPLETED"
	PipelineRunReasonSourceUnavailable       PipelineRunReason = "SOURCE_UNAVAILABLE"
	PipelineRunReasonCommitMismatch          PipelineRunReason = "COMMIT_MISMATCH"
	PipelineRunReasonExecutorUnavailable     PipelineRunReason = "EXECUTOR_UNAVAILABLE"
	PipelineRunReasonVerificationFailed      PipelineRunReason = "VERIFICATION_FAILED"
	PipelineRunReasonDeadlineExceeded        PipelineRunReason = "DEADLINE_EXCEEDED"
	PipelineRunReasonReportUnavailable       PipelineRunReason = "REPORT_UNAVAILABLE"
	PipelineRunReasonReportConflict          PipelineRunReason = "REPORT_CONFLICT"
	PipelineRunReasonCancelled               PipelineRunReason = "CANCELLED"
	PipelineRunReasonExternalEffectUncertain PipelineRunReason = "EXTERNAL_EFFECT_UNCERTAIN"
	PipelineRunReasonReconciliationExhausted PipelineRunReason = "RECONCILIATION_EXHAUSTED"
)

const (
	ErrorInvalidArgument      ErrorCode = "INVALID_ARGUMENT"
	ErrorUnauthenticated      ErrorCode = "UNAUTHENTICATED"
	ErrorForbidden            ErrorCode = "FORBIDDEN"
	ErrorNotFound             ErrorCode = "NOT_FOUND"
	ErrorMethodNotAllowed     ErrorCode = "METHOD_NOT_ALLOWED"
	ErrorConflict             ErrorCode = "CONFLICT"
	ErrorResourceExhausted    ErrorCode = "RESOURCE_EXHAUSTED"
	ErrorPayloadTooLarge      ErrorCode = "PAYLOAD_TOO_LARGE"
	ErrorUnsupportedMediaType ErrorCode = "UNSUPPORTED_MEDIA_TYPE"
	ErrorPreconditionRequired ErrorCode = "PRECONDITION_REQUIRED"
	ErrorPreconditionFailed   ErrorCode = "PRECONDITION_FAILED"
	ErrorInternal             ErrorCode = "INTERNAL"
	ErrorUnavailable          ErrorCode = "UNAVAILABLE"
)

func TriggerPolicies() []TriggerPolicy {
	return []TriggerPolicy{TriggerChange}
}

func VerificationProfiles() []VerificationProfile {
	return []VerificationProfile{VerificationGo126OfflineV1}
}

func ExecutorProfiles() []ExecutorProfile {
	return []ExecutorProfile{ExecutorMatrixNativeIsolatedV1}
}

func DependencyEgressPolicies() []DependencyEgressPolicy {
	return []DependencyEgressPolicy{DependencyEgressNone}
}

func ReporterPolicies() []ReporterPolicy {
	return []ReporterPolicy{ReporterChangeCheckV1}
}

func VerificationStepKinds() []VerificationStepKind {
	return []VerificationStepKind{VerificationStepGoTest, VerificationStepGoVet}
}

func SubjectKinds() []SubjectKind {
	return []SubjectKind{SubjectUser, SubjectServiceAccount}
}

func SourceConnectionHealthStates() []SourceConnectionHealth {
	return []SourceConnectionHealth{
		SourceConnectionPending,
		SourceConnectionReady,
		SourceConnectionUnavailable,
	}
}

func SourceConnectionHealthReasons() []SourceConnectionHealthReason {
	return []SourceConnectionHealthReason{
		SourceConnectionReasonConfigurationChanged,
		SourceConnectionReasonObserved,
		SourceConnectionReasonSecretUnavailable,
		SourceConnectionReasonProviderUnavailable,
		SourceConnectionReasonProviderUnsupported,
		SourceConnectionReasonCredentialRejected,
	}
}

func RepositoryBindingHealthStates() []RepositoryBindingHealth {
	return []RepositoryBindingHealth{
		RepositoryBindingPending,
		RepositoryBindingReady,
		RepositoryBindingUnavailable,
	}
}

func RepositoryBindingHealthReasons() []RepositoryBindingHealthReason {
	return []RepositoryBindingHealthReason{
		RepositoryBindingReasonConfigurationChanged,
		RepositoryBindingReasonConnectionNotReady,
		RepositoryBindingReasonObserved,
		RepositoryBindingReasonRepositoryUnavailable,
		RepositoryBindingReasonIdentityMismatch,
		RepositoryBindingReasonFetchPermissionDenied,
		RepositoryBindingReasonReportPermissionDenied,
	}
}

func ReadinessStates() []ReadinessState {
	return []ReadinessState{ReadinessReady, ReadinessNotReady}
}

func ChangeActions() []ChangeAction {
	return []ChangeAction{ChangeOpened, ChangeReopened, ChangeUpdated}
}

func PipelineRunStates() []PipelineRunState {
	return []PipelineRunState{
		PipelineRunQueued,
		PipelineRunFetching,
		PipelineRunVerifying,
		PipelineRunReporting,
		PipelineRunSucceeded,
		PipelineRunFailed,
		PipelineRunCancelled,
		PipelineRunReconciling,
		PipelineRunManualIntervention,
	}
}

func PipelineRunStages() []PipelineRunStage {
	return []PipelineRunStage{
		PipelineRunStageReceive,
		PipelineRunStageFetch,
		PipelineRunStageVerify,
		PipelineRunStageReport,
	}
}

func PipelineRunReasons() []PipelineRunReason {
	return []PipelineRunReason{
		PipelineRunReasonEventAdmitted,
		PipelineRunReasonCompleted,
		PipelineRunReasonSourceUnavailable,
		PipelineRunReasonCommitMismatch,
		PipelineRunReasonExecutorUnavailable,
		PipelineRunReasonVerificationFailed,
		PipelineRunReasonDeadlineExceeded,
		PipelineRunReasonReportUnavailable,
		PipelineRunReasonReportConflict,
		PipelineRunReasonCancelled,
		PipelineRunReasonExternalEffectUncertain,
		PipelineRunReasonReconciliationExhausted,
	}
}

func ErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrorInvalidArgument,
		ErrorUnauthenticated,
		ErrorForbidden,
		ErrorNotFound,
		ErrorMethodNotAllowed,
		ErrorConflict,
		ErrorResourceExhausted,
		ErrorPayloadTooLarge,
		ErrorUnsupportedMediaType,
		ErrorPreconditionRequired,
		ErrorPreconditionFailed,
		ErrorInternal,
		ErrorUnavailable,
	}
}
