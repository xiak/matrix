package paasv1

type AuthorityKind string

const (
	AuthorityPlatform AuthorityKind = "PLATFORM"
	AuthorityTenant   AuthorityKind = "TENANT"
)

type TenantStatus string

const (
	TenantActive      TenantStatus = "ACTIVE"
	TenantSuspended   TenantStatus = "SUSPENDED"
	TenantDeactivated TenantStatus = "DEACTIVATED"
)

type ResourcePoolPhase string

const (
	ResourcePoolReady       ResourcePoolPhase = "READY"
	ResourcePoolDegraded    ResourcePoolPhase = "DEGRADED"
	ResourcePoolUnavailable ResourcePoolPhase = "UNAVAILABLE"
)

type TargetHealth string

const (
	TargetHealthUnknown     TargetHealth = "UNKNOWN"
	TargetHealthReady       TargetHealth = "READY"
	TargetHealthDegraded    TargetHealth = "DEGRADED"
	TargetHealthUnavailable TargetHealth = "UNAVAILABLE"
)

type TargetDesiredState string

const (
	TargetActive   TargetDesiredState = "ACTIVE"
	TargetDraining TargetDesiredState = "DRAINING"
)

type IsolationClass string

const (
	IsolationSharedCompose    IsolationClass = "SHARED_COMPOSE"
	IsolationDedicatedCompose IsolationClass = "DEDICATED_COMPOSE"
	IsolationDedicatedHost    IsolationClass = "DEDICATED_HOST"
	IsolationKubernetesNS     IsolationClass = "K8S_NAMESPACE"
	IsolationPhysicalHost     IsolationClass = "PHYSICAL_HOST"
)

func IsolationClasses() []IsolationClass {
	return []IsolationClass{
		IsolationSharedCompose,
		IsolationDedicatedCompose,
		IsolationDedicatedHost,
		IsolationKubernetesNS,
		IsolationPhysicalHost,
	}
}

type PlacementStrategy string

const (
	PlacementFirstFit PlacementStrategy = "FIRST_FIT"
	PlacementSpread   PlacementStrategy = "SPREAD"
	PlacementBinPack  PlacementStrategy = "BIN_PACK"
)

type PlacementOutcome string

const (
	PlacementScheduled     PlacementOutcome = "SCHEDULED"
	PlacementUnschedulable PlacementOutcome = "UNSCHEDULABLE"
)

type ReleasePhase string

const (
	ReleasePending  ReleasePhase = "PENDING"
	ReleasePlacing  ReleasePhase = "PLACING"
	ReleaseApplying ReleasePhase = "APPLYING"
	ReleaseReady    ReleasePhase = "READY"
	ReleaseDegraded ReleasePhase = "DEGRADED"
	ReleaseFailed   ReleasePhase = "FAILED"
	ReleaseStopping ReleasePhase = "STOPPING"
	ReleaseStopped  ReleasePhase = "STOPPED"
)

func ReleasePhases() []ReleasePhase {
	return []ReleasePhase{
		ReleasePending,
		ReleasePlacing,
		ReleaseApplying,
		ReleaseReady,
		ReleaseDegraded,
		ReleaseFailed,
		ReleaseStopping,
		ReleaseStopped,
	}
}

type OperationAction string

const (
	OperationCreateResourcePool OperationAction = "CREATE_RESOURCE_POOL"
	OperationRegisterTarget     OperationAction = "REGISTER_TARGET"
	OperationCreatePlacement    OperationAction = "CREATE_PLACEMENT"
	OperationDeploy             OperationAction = "DEPLOY"
	OperationUpdate             OperationAction = "UPDATE"
	OperationStop               OperationAction = "STOP"
	OperationRollback           OperationAction = "ROLLBACK"
)

type OperationState string

const (
	OperationAccepted           OperationState = "ACCEPTED"
	OperationPlanning           OperationState = "PLANNING"
	OperationQueued             OperationState = "QUEUED"
	OperationExecuting          OperationState = "EXECUTING"
	OperationVerifying          OperationState = "VERIFYING"
	OperationReconciling        OperationState = "RECONCILING"
	OperationSucceeded          OperationState = "SUCCEEDED"
	OperationFailed             OperationState = "FAILED"
	OperationCancelled          OperationState = "CANCELLED"
	OperationManualIntervention OperationState = "MANUAL_INTERVENTION"
)

func OperationStates() []OperationState {
	return []OperationState{
		OperationAccepted,
		OperationPlanning,
		OperationQueued,
		OperationExecuting,
		OperationVerifying,
		OperationReconciling,
		OperationSucceeded,
		OperationFailed,
		OperationCancelled,
		OperationManualIntervention,
	}
}

type EvidenceType string

const (
	EvidencePolicyDecision    EvidenceType = "POLICY_DECISION"
	EvidencePlacementDecision EvidenceType = "PLACEMENT_DECISION"
	EvidenceAdapterCommand    EvidenceType = "ADAPTER_COMMAND"
	EvidenceAdapterResult     EvidenceType = "ADAPTER_RESULT"
	EvidenceObservation       EvidenceType = "OBSERVATION"
	EvidenceVerification      EvidenceType = "VERIFICATION"
	EvidenceAuditDispatch     EvidenceType = "AUDIT_DISPATCH"
)

type EvidenceSeverity string

const (
	EvidenceInfo    EvidenceSeverity = "INFO"
	EvidenceWarning EvidenceSeverity = "WARNING"
	EvidenceError   EvidenceSeverity = "ERROR"
)

type SubjectType string

const (
	SubjectUser           SubjectType = "USER"
	SubjectServiceAccount SubjectType = "SERVICE_ACCOUNT"
	SubjectAgent          SubjectType = "AGENT"
	SubjectSystemUser     SubjectType = "SYSTEM_USER"
)

type ErrorCode string

const (
	ErrorInvalidArgument         ErrorCode = "INVALID_ARGUMENT"
	ErrorUnauthenticated         ErrorCode = "UNAUTHENTICATED"
	ErrorPermissionDenied        ErrorCode = "PERMISSION_DENIED"
	ErrorNotFound                ErrorCode = "NOT_FOUND"
	ErrorAlreadyExists           ErrorCode = "ALREADY_EXISTS"
	ErrorConflict                ErrorCode = "CONFLICT"
	ErrorResourceVersionConflict ErrorCode = "RESOURCE_VERSION_CONFLICT"
	ErrorIdempotencyConflict     ErrorCode = "IDEMPOTENCY_CONFLICT"
	ErrorUnschedulable           ErrorCode = "UNSCHEDULABLE"
	ErrorCapabilityUnsupported   ErrorCode = "CAPABILITY_UNSUPPORTED"
	ErrorTargetUnavailable       ErrorCode = "TARGET_UNAVAILABLE"
	ErrorAdapterUnavailable      ErrorCode = "ADAPTER_UNAVAILABLE"
	ErrorAdapterRejected         ErrorCode = "ADAPTER_REJECTED"
	ErrorAdapterOutcomeUnknown   ErrorCode = "ADAPTER_OUTCOME_UNKNOWN"
	ErrorDeadlineExceeded        ErrorCode = "DEADLINE_EXCEEDED"
	ErrorOperationFailed         ErrorCode = "OPERATION_FAILED"
	ErrorManualIntervention      ErrorCode = "MANUAL_INTERVENTION_REQUIRED"
	ErrorRateLimited             ErrorCode = "RATE_LIMITED"
	ErrorInternal                ErrorCode = "INTERNAL"
)

func ErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrorInvalidArgument,
		ErrorUnauthenticated,
		ErrorPermissionDenied,
		ErrorNotFound,
		ErrorAlreadyExists,
		ErrorConflict,
		ErrorResourceVersionConflict,
		ErrorIdempotencyConflict,
		ErrorUnschedulable,
		ErrorCapabilityUnsupported,
		ErrorTargetUnavailable,
		ErrorAdapterUnavailable,
		ErrorAdapterRejected,
		ErrorAdapterOutcomeUnknown,
		ErrorDeadlineExceeded,
		ErrorOperationFailed,
		ErrorManualIntervention,
		ErrorRateLimited,
		ErrorInternal,
	}
}

type AdapterKind string

const (
	AdapterInfrastructure AdapterKind = "INFRASTRUCTURE"
	AdapterRuntime        AdapterKind = "RUNTIME"
	AdapterGateway        AdapterKind = "GATEWAY"
)

type AdapterAction string

const (
	AdapterCapabilities    AdapterAction = "CAPABILITIES"
	AdapterInspectTarget   AdapterAction = "INSPECT_TARGET"
	AdapterObserveTarget   AdapterAction = "OBSERVE_TARGET"
	AdapterValidateRelease AdapterAction = "VALIDATE_RELEASE"
	AdapterApply           AdapterAction = "APPLY"
	AdapterObserve         AdapterAction = "OBSERVE"
	AdapterStop            AdapterAction = "STOP"
	AdapterRollback        AdapterAction = "ROLLBACK"
	AdapterReconcileRoutes AdapterAction = "RECONCILE_ROUTES"
	AdapterObserveRoutes   AdapterAction = "OBSERVE_ROUTES"
	AdapterDeleteRoutes    AdapterAction = "DELETE_ROUTES"
)

type AdapterResultState string

const (
	AdapterResultSucceeded  AdapterResultState = "SUCCEEDED"
	AdapterResultInProgress AdapterResultState = "IN_PROGRESS"
	AdapterResultFailed     AdapterResultState = "FAILED"
	AdapterResultUnknown    AdapterResultState = "UNKNOWN"
)

type AdapterErrorClass string

const (
	AdapterErrorValidation       AdapterErrorClass = "VALIDATION"
	AdapterErrorConflict         AdapterErrorClass = "CONFLICT"
	AdapterErrorPermissionDenied AdapterErrorClass = "PERMISSION_DENIED"
	AdapterErrorQuotaExceeded    AdapterErrorClass = "QUOTA_EXCEEDED"
	AdapterErrorRateLimited      AdapterErrorClass = "RATE_LIMITED"
	AdapterErrorTransient        AdapterErrorClass = "TRANSIENT"
	AdapterErrorUnavailable      AdapterErrorClass = "UNAVAILABLE"
	AdapterErrorTimeout          AdapterErrorClass = "TIMEOUT"
	AdapterErrorNotFound         AdapterErrorClass = "NOT_FOUND"
	AdapterErrorUnknownOutcome   AdapterErrorClass = "UNKNOWN_OUTCOME"
	AdapterErrorInternal         AdapterErrorClass = "INTERNAL"
)

type ArtifactKind string

const (
	ArtifactOCIImage      ArtifactKind = "OCI_IMAGE"
	ArtifactOCIArtifact   ArtifactKind = "OCI_ARTIFACT"
	ArtifactReleaseBundle ArtifactKind = "RELEASE_BUNDLE"
)

type EndpointProtocol string

const (
	EndpointHTTP EndpointProtocol = "HTTP"
	EndpointGRPC EndpointProtocol = "GRPC"
	EndpointTCP  EndpointProtocol = "TCP"
)

type EndpointVisibility string

const (
	EndpointPrivate EndpointVisibility = "PRIVATE"
	EndpointPublic  EndpointVisibility = "PUBLIC"
)
