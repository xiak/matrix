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

type ExecutionPoolPhase string

const (
	ExecutionPoolReady       ExecutionPoolPhase = "READY"
	ExecutionPoolDegraded    ExecutionPoolPhase = "DEGRADED"
	ExecutionPoolUnavailable ExecutionPoolPhase = "UNAVAILABLE"
)

type ExecutionTargetHealth string

const (
	ExecutionTargetHealthUnknown     ExecutionTargetHealth = "UNKNOWN"
	ExecutionTargetHealthReady       ExecutionTargetHealth = "READY"
	ExecutionTargetHealthDegraded    ExecutionTargetHealth = "DEGRADED"
	ExecutionTargetHealthUnavailable ExecutionTargetHealth = "UNAVAILABLE"
)

type ExecutionTargetDesiredState string

type MeasurementState string

const (
	MeasurementAvailable   MeasurementState = "AVAILABLE"
	MeasurementWarmingUp   MeasurementState = "WARMING_UP"
	MeasurementUnavailable MeasurementState = "UNAVAILABLE"
	MeasurementUnsupported MeasurementState = "UNSUPPORTED"
	MeasurementStale       MeasurementState = "STALE"
)

const (
	ExecutionTargetActive   ExecutionTargetDesiredState = "ACTIVE"
	ExecutionTargetDraining ExecutionTargetDesiredState = "DRAINING"
	ExecutionTargetRemoved  ExecutionTargetDesiredState = "REMOVED"
)

type IsolationGuarantee string

const (
	IsolationWorkload IsolationGuarantee = "WORKLOAD"
	IsolationTenant   IsolationGuarantee = "TENANT"
	IsolationHost     IsolationGuarantee = "HOST"
)

func IsolationGuarantees() []IsolationGuarantee {
	return []IsolationGuarantee{
		IsolationWorkload,
		IsolationTenant,
		IsolationHost,
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

type DeploymentDesiredState string

const (
	DeploymentDesiredRunning DeploymentDesiredState = "RUNNING"
	DeploymentDesiredStopped DeploymentDesiredState = "STOPPED"
)

type DeploymentPhase string

const (
	DeploymentPending  DeploymentPhase = "PENDING"
	DeploymentPlacing  DeploymentPhase = "PLACING"
	DeploymentApplying DeploymentPhase = "APPLYING"
	DeploymentReady    DeploymentPhase = "READY"
	DeploymentDegraded DeploymentPhase = "DEGRADED"
	DeploymentFailed   DeploymentPhase = "FAILED"
	DeploymentStopping DeploymentPhase = "STOPPING"
	DeploymentStopped  DeploymentPhase = "STOPPED"
)

func DeploymentPhases() []DeploymentPhase {
	return []DeploymentPhase{
		DeploymentPending,
		DeploymentPlacing,
		DeploymentApplying,
		DeploymentReady,
		DeploymentDegraded,
		DeploymentFailed,
		DeploymentStopping,
		DeploymentStopped,
	}
}

// DeploymentInstanceState is the provider-neutral lifecycle exposed for one
// current Deployment instance. Provider-native names and identifiers never
// enter the northbound contract.
type DeploymentInstanceState string

const (
	DeploymentInstanceCreated    DeploymentInstanceState = "CREATED"
	DeploymentInstanceRunning    DeploymentInstanceState = "RUNNING"
	DeploymentInstanceRestarting DeploymentInstanceState = "RESTARTING"
	DeploymentInstanceRemoving   DeploymentInstanceState = "REMOVING"
	DeploymentInstancePaused     DeploymentInstanceState = "PAUSED"
	DeploymentInstanceExited     DeploymentInstanceState = "EXITED"
	DeploymentInstanceDead       DeploymentInstanceState = "DEAD"
)

func DeploymentInstanceStates() []DeploymentInstanceState {
	return []DeploymentInstanceState{
		DeploymentInstanceCreated,
		DeploymentInstanceRunning,
		DeploymentInstanceRestarting,
		DeploymentInstanceRemoving,
		DeploymentInstancePaused,
		DeploymentInstanceExited,
		DeploymentInstanceDead,
	}
}

type DeploymentInstanceHealth string

const (
	DeploymentInstanceHealthNone      DeploymentInstanceHealth = "NONE"
	DeploymentInstanceHealthStarting  DeploymentInstanceHealth = "STARTING"
	DeploymentInstanceHealthHealthy   DeploymentInstanceHealth = "HEALTHY"
	DeploymentInstanceHealthUnhealthy DeploymentInstanceHealth = "UNHEALTHY"
)

func DeploymentInstanceHealthStates() []DeploymentInstanceHealth {
	return []DeploymentInstanceHealth{
		DeploymentInstanceHealthNone,
		DeploymentInstanceHealthStarting,
		DeploymentInstanceHealthHealthy,
		DeploymentInstanceHealthUnhealthy,
	}
}

// TerminalSessionState is independent of Deployment Operations. A session is
// single-use: once it leaves PENDING its connection ticket cannot be reused.
type TerminalSessionState string

const (
	TerminalSessionPending    TerminalSessionState = "PENDING"
	TerminalSessionConnecting TerminalSessionState = "CONNECTING"
	TerminalSessionActive     TerminalSessionState = "ACTIVE"
	TerminalSessionEnded      TerminalSessionState = "ENDED"
)

func TerminalSessionStates() []TerminalSessionState {
	return []TerminalSessionState{
		TerminalSessionPending,
		TerminalSessionConnecting,
		TerminalSessionActive,
		TerminalSessionEnded,
	}
}

// TerminalSessionOutcome is present only after a session has ended. It is a
// sanitized lifecycle result and never contains terminal input or output.
type TerminalSessionOutcome string

const (
	TerminalSessionCompleted    TerminalSessionOutcome = "COMPLETED"
	TerminalSessionUnsupported  TerminalSessionOutcome = "UNSUPPORTED"
	TerminalSessionExpired      TerminalSessionOutcome = "EXPIRED"
	TerminalSessionDisconnected TerminalSessionOutcome = "DISCONNECTED"
	TerminalSessionRevoked      TerminalSessionOutcome = "REVOKED"
	TerminalSessionReplaced     TerminalSessionOutcome = "REPLACED"
	TerminalSessionFailed       TerminalSessionOutcome = "FAILED"
)

func TerminalSessionOutcomes() []TerminalSessionOutcome {
	return []TerminalSessionOutcome{
		TerminalSessionCompleted,
		TerminalSessionUnsupported,
		TerminalSessionExpired,
		TerminalSessionDisconnected,
		TerminalSessionRevoked,
		TerminalSessionReplaced,
		TerminalSessionFailed,
	}
}

type OperationAction string

const (
	OperationCreateExecutionPool         OperationAction = "CREATE_EXECUTION_POOL"
	OperationRegisterExecutionTarget     OperationAction = "REGISTER_EXECUTION_TARGET"
	OperationDrainExecutionTarget        OperationAction = "DRAIN_EXECUTION_TARGET"
	OperationActivateExecutionTarget     OperationAction = "ACTIVATE_EXECUTION_TARGET"
	OperationRemoveExecutionTarget       OperationAction = "REMOVE_EXECUTION_TARGET"
	OperationCreatePlacement             OperationAction = "CREATE_PLACEMENT"
	OperationCreateApplication           OperationAction = "CREATE_APPLICATION"
	OperationCreateConfiguration         OperationAction = "CREATE_CONFIGURATION"
	OperationCreateConfigurationRevision OperationAction = "CREATE_CONFIGURATION_REVISION"
	OperationCreateApplicationRevision   OperationAction = "CREATE_APPLICATION_REVISION"
	OperationDeploy                      OperationAction = "DEPLOY"
	OperationUpdate                      OperationAction = "UPDATE"
	OperationStop                        OperationAction = "STOP"
	OperationRollback                    OperationAction = "ROLLBACK"
)

func OperationActions() []OperationAction {
	return []OperationAction{
		OperationCreateExecutionPool,
		OperationRegisterExecutionTarget,
		OperationDrainExecutionTarget,
		OperationActivateExecutionTarget,
		OperationRemoveExecutionTarget,
		OperationCreatePlacement,
		OperationCreateApplication,
		OperationCreateConfiguration,
		OperationCreateConfigurationRevision,
		OperationCreateApplicationRevision,
		OperationDeploy,
		OperationUpdate,
		OperationStop,
		OperationRollback,
	}
}

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

type ReadinessState string

const (
	ReadinessReady    ReadinessState = "READY"
	ReadinessNotReady ReadinessState = "NOT_READY"
)

// InstallationVerificationState is intentionally smaller than the generic
// Deployment state machine. The fixed verifier endpoint either waits for its
// built-in probe, establishes the complete probe result, or reports a
// terminal probe failure.
type InstallationVerificationState string

const (
	InstallationVerificationPending InstallationVerificationState = "PENDING"
	InstallationVerificationReady   InstallationVerificationState = "READY"
	InstallationVerificationFailed  InstallationVerificationState = "FAILED"
)

type ErrorCode string

const (
	ErrorInvalidArgument            ErrorCode = "INVALID_ARGUMENT"
	ErrorUnauthenticated            ErrorCode = "UNAUTHENTICATED"
	ErrorPermissionDenied           ErrorCode = "PERMISSION_DENIED"
	ErrorIdentityUnavailable        ErrorCode = "IDENTITY_PROVIDER_UNAVAILABLE"
	ErrorNotFound                   ErrorCode = "NOT_FOUND"
	ErrorAlreadyExists              ErrorCode = "ALREADY_EXISTS"
	ErrorConflict                   ErrorCode = "CONFLICT"
	ErrorResourceVersionConflict    ErrorCode = "RESOURCE_VERSION_CONFLICT"
	ErrorIdempotencyConflict        ErrorCode = "IDEMPOTENCY_CONFLICT"
	ErrorUnschedulable              ErrorCode = "UNSCHEDULABLE"
	ErrorCapabilityUnsupported      ErrorCode = "CAPABILITY_UNSUPPORTED"
	ErrorExecutionTargetUnavailable ErrorCode = "EXECUTION_TARGET_UNAVAILABLE"
	ErrorAdapterUnavailable         ErrorCode = "ADAPTER_UNAVAILABLE"
	ErrorAdapterRejected            ErrorCode = "ADAPTER_REJECTED"
	ErrorAdapterOutcomeUnknown      ErrorCode = "ADAPTER_OUTCOME_UNKNOWN"
	ErrorDeadlineExceeded           ErrorCode = "DEADLINE_EXCEEDED"
	ErrorOperationFailed            ErrorCode = "OPERATION_FAILED"
	ErrorManualIntervention         ErrorCode = "MANUAL_INTERVENTION_REQUIRED"
	ErrorRateLimited                ErrorCode = "RATE_LIMITED"
	ErrorInternal                   ErrorCode = "INTERNAL"
)

func ErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrorInvalidArgument,
		ErrorUnauthenticated,
		ErrorPermissionDenied,
		ErrorIdentityUnavailable,
		ErrorNotFound,
		ErrorAlreadyExists,
		ErrorConflict,
		ErrorResourceVersionConflict,
		ErrorIdempotencyConflict,
		ErrorUnschedulable,
		ErrorCapabilityUnsupported,
		ErrorExecutionTargetUnavailable,
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
	AdapterInfrastructure     AdapterKind = "INFRASTRUCTURE"
	AdapterDeploymentExecutor AdapterKind = "DEPLOYMENT_EXECUTOR"
	AdapterGateway            AdapterKind = "GATEWAY"
)

type AdapterAction string

const (
	AdapterCapabilities           AdapterAction = "CAPABILITIES"
	AdapterInspectExecutionTarget AdapterAction = "INSPECT_EXECUTION_TARGET"
	AdapterObserveExecutionTarget AdapterAction = "OBSERVE_EXECUTION_TARGET"
	AdapterValidateDeployment     AdapterAction = "VALIDATE_DEPLOYMENT"
	AdapterApplyDeployment        AdapterAction = "APPLY_DEPLOYMENT"
	AdapterObserveDeployment      AdapterAction = "OBSERVE_DEPLOYMENT"
	AdapterStopDeployment         AdapterAction = "STOP_DEPLOYMENT"
	AdapterRollbackDeployment     AdapterAction = "ROLLBACK_DEPLOYMENT"
	AdapterReconcileRoutes        AdapterAction = "RECONCILE_ROUTES"
	AdapterObserveRoutes          AdapterAction = "OBSERVE_ROUTES"
	AdapterDeleteRoutes           AdapterAction = "DELETE_ROUTES"
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

type InputKind string

const (
	InputConfiguration InputKind = "CONFIGURATION"
	InputSecret        InputKind = "SECRET"
)

type InjectionMode string

const (
	InjectionEnvironment InjectionMode = "ENV"
	InjectionFile        InjectionMode = "FILE"
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
