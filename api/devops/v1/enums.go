package devopsv1

type TriggerPolicy string
type VerificationProfile string
type ExecutorProfile string
type DependencyEgressPolicy string
type ReporterPolicy string
type VerificationStepKind string
type SubjectKind string
type SourceConnectionHealth string
type RepositoryBindingHealth string
type ErrorCode string

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
	RepositoryBindingPending     RepositoryBindingHealth = "PENDING"
	RepositoryBindingReady       RepositoryBindingHealth = "READY"
	RepositoryBindingUnavailable RepositoryBindingHealth = "UNAVAILABLE"
)

const (
	ErrorInvalidArgument    ErrorCode = "INVALID_ARGUMENT"
	ErrorUnauthenticated    ErrorCode = "UNAUTHENTICATED"
	ErrorForbidden          ErrorCode = "FORBIDDEN"
	ErrorNotFound           ErrorCode = "NOT_FOUND"
	ErrorConflict           ErrorCode = "CONFLICT"
	ErrorPreconditionFailed ErrorCode = "PRECONDITION_FAILED"
	ErrorInternal           ErrorCode = "INTERNAL"
	ErrorUnavailable        ErrorCode = "UNAVAILABLE"
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

func RepositoryBindingHealthStates() []RepositoryBindingHealth {
	return []RepositoryBindingHealth{
		RepositoryBindingPending,
		RepositoryBindingReady,
		RepositoryBindingUnavailable,
	}
}

func ErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrorInvalidArgument,
		ErrorUnauthenticated,
		ErrorForbidden,
		ErrorNotFound,
		ErrorConflict,
		ErrorPreconditionFailed,
		ErrorInternal,
		ErrorUnavailable,
	}
}
