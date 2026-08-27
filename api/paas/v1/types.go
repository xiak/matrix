package paasv1

import (
	"slices"
	"time"
)

type TenantID string
type ResourceID string
type OperationID string
type CommandID string

type ResourceScope struct {
	Kind     AuthorityKind `json:"kind"`
	TenantID TenantID      `json:"tenantId,omitempty"`
}

type ResourceMetadata struct {
	ID              ResourceID        `json:"id"`
	Name            string            `json:"name"`
	Scope           ResourceScope     `json:"scope"`
	Labels          map[string]string `json:"labels,omitempty"`
	ResourceVersion uint64            `json:"resourceVersion"`
	CreatedAt       time.Time         `json:"createdAt"`
	UpdatedAt       time.Time         `json:"updatedAt"`
}

type Tenant struct {
	APIVersion         string       `json:"apiVersion"`
	Kind               string       `json:"kind"`
	ID                 TenantID     `json:"id"`
	DisplayName        string       `json:"displayName"`
	Status             TenantStatus `json:"status"`
	IAMResourceVersion string       `json:"iamResourceVersion"`
	ObservedAt         time.Time    `json:"observedAt"`
}

type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type ExecutionPoolSpec struct {
	ExecutionTargetSelector    LabelSelector        `json:"executionTargetSelector"`
	AllowedIsolationGuarantees []IsolationGuarantee `json:"allowedIsolationGuarantees"`
}

type ExecutionPoolStatus struct {
	Phase                     ExecutionPoolPhase `json:"phase"`
	ExecutionTargetCount      uint32             `json:"executionTargetCount"`
	ReadyExecutionTargetCount uint32             `json:"readyExecutionTargetCount"`
	ObservedAt                time.Time          `json:"observedAt"`
}

type ExecutionPool struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Metadata   ResourceMetadata    `json:"metadata"`
	Spec       ExecutionPoolSpec   `json:"spec"`
	Status     ExecutionPoolStatus `json:"status"`
}

type AdapterRef struct {
	Kind            AdapterKind `json:"kind"`
	Name            string      `json:"name"`
	ContractVersion string      `json:"contractVersion"`
}

type Capacity struct {
	CPUMillis     int64 `json:"cpuMillis"`
	MemoryBytes   int64 `json:"memoryBytes"`
	StorageBytes  int64 `json:"storageBytes"`
	WorkloadSlots int64 `json:"workloadSlots"`
}

// ExecutionTargetUsage is measured OS usage, never placement capacity or a
// reservation. Missing measurements have no value; expired values retain their
// original timestamps and must not be presented as current.
type ExecutionTargetUsage struct {
	ObservedAt       time.Time         `json:"observedAt"`
	ValidUntil       time.Time         `json:"validUntil"`
	CPU              CPUUsage          `json:"cpu"`
	Memory           MemoryUsage       `json:"memory"`
	FilesystemsState MeasurementState  `json:"filesystemsState"`
	Filesystems      []FilesystemUsage `json:"filesystems,omitempty"`
}

// Snapshot returns an independent value for a reader. It never renews the
// source timestamp, including after a control-plane or node disconnection.
func (usage ExecutionTargetUsage) Snapshot(now time.Time) ExecutionTargetUsage {
	if usage.CPU.Value != nil {
		value := *usage.CPU.Value
		usage.CPU.Value = &value
	}
	if usage.Memory.Value != nil {
		value := *usage.Memory.Value
		usage.Memory.Value = &value
	}
	usage.Filesystems = slices.Clone(usage.Filesystems)
	for index := range usage.Filesystems {
		if usage.Filesystems[index].Value != nil {
			value := *usage.Filesystems[index].Value
			if value.TotalInodes != nil {
				total := *value.TotalInodes
				value.TotalInodes = &total
			}
			if value.FreeInodes != nil {
				free := *value.FreeInodes
				value.FreeInodes = &free
			}
			usage.Filesystems[index].Value = &value
		}
	}
	if now.Before(usage.ObservedAt) || !now.Before(usage.ValidUntil) {
		usage.CPU.State, usage.Memory.State = MeasurementStale, MeasurementStale
		usage.FilesystemsState = MeasurementStale
		for index := range usage.Filesystems {
			usage.Filesystems[index].State = MeasurementStale
			if value := usage.Filesystems[index].Value; value != nil && value.InodesState == MeasurementAvailable {
				value.InodesState = MeasurementStale
			}
		}
	}
	return usage
}

type CPUUsage struct {
	State MeasurementState `json:"state"`
	Value *CPUUsageValue   `json:"value,omitempty"`
}

type CPUUsageValue struct {
	LogicalCPUs      int64   `json:"logicalCpus"`
	WindowMillis     int64   `json:"windowMillis"`
	UtilizationRatio float64 `json:"utilizationRatio"`
	IOWaitRatio      float64 `json:"ioWaitRatio"`
	Load1            float64 `json:"load1"`
	Load5            float64 `json:"load5"`
	Load15           float64 `json:"load15"`
}

type MemoryUsage struct {
	State MeasurementState  `json:"state"`
	Value *MemoryUsageValue `json:"value,omitempty"`
}

type MemoryUsageValue struct {
	TotalBytes     int64 `json:"totalBytes"`
	AvailableBytes int64 `json:"availableBytes"`
	UsedBytes      int64 `json:"usedBytes"`
	SwapTotalBytes int64 `json:"swapTotalBytes"`
	SwapFreeBytes  int64 `json:"swapFreeBytes"`
}

type FilesystemUsage struct {
	Device         string                `json:"device"`
	MountPoint     string                `json:"mountPoint"`
	FilesystemType string                `json:"filesystemType"`
	State          MeasurementState      `json:"state"`
	Value          *FilesystemUsageValue `json:"value,omitempty"`
}

type FilesystemUsageValue struct {
	TotalBytes     int64            `json:"totalBytes"`
	UsedBytes      int64            `json:"usedBytes"`
	AvailableBytes int64            `json:"availableBytes"`
	InodesState    MeasurementState `json:"inodesState"`
	TotalInodes    *int64           `json:"totalInodes,omitempty"`
	FreeInodes     *int64           `json:"freeInodes,omitempty"`
	ReadOnly       bool             `json:"readOnly"`
}

type ExecutionTargetSpec struct {
	ExecutionPoolID       ResourceID                  `json:"executionPoolId"`
	InfrastructureAdapter AdapterRef                  `json:"infrastructureAdapter"`
	DeploymentExecutor    AdapterRef                  `json:"deploymentExecutor"`
	GatewayAdapter        *AdapterRef                 `json:"gatewayAdapter,omitempty"`
	DesiredState          ExecutionTargetDesiredState `json:"desiredState"`
}

type ExecutionTargetStatus struct {
	Health                       ExecutionTargetHealth `json:"health"`
	Capacity                     Capacity              `json:"capacity"`
	Allocatable                  Capacity              `json:"allocatable"`
	SupportedIsolationGuarantees []IsolationGuarantee  `json:"supportedIsolationGuarantees"`
	ObservedAt                   time.Time             `json:"observedAt"`
	Usage                        *ExecutionTargetUsage `json:"usage,omitempty"`
}

type ExecutionTarget struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   ResourceMetadata      `json:"metadata"`
	Spec       ExecutionTargetSpec   `json:"spec"`
	Status     ExecutionTargetStatus `json:"status"`
}

type PlacementPolicySpec struct {
	RequiredIsolationGuarantee IsolationGuarantee `json:"requiredIsolationGuarantee"`
	EligibleExecutionPoolIDs   []ResourceID       `json:"eligibleExecutionPoolIds"`
	ExecutionTargetSelector    LabelSelector      `json:"executionTargetSelector"`
	Strategy                   PlacementStrategy  `json:"strategy"`
}

type PlacementPolicy struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Metadata   ResourceMetadata    `json:"metadata"`
	Spec       PlacementPolicySpec `json:"spec"`
}

type PlacementDecision struct {
	APIVersion                     string             `json:"apiVersion"`
	Kind                           string             `json:"kind"`
	Metadata                       ResourceMetadata   `json:"metadata"`
	DeploymentID                   ResourceID         `json:"deploymentId"`
	DeploymentGeneration           uint64             `json:"deploymentGeneration"`
	DeploymentResourceVersion      uint64             `json:"deploymentResourceVersion"`
	ApplicationRevisionID          ResourceID         `json:"applicationRevisionId"`
	PlacementPolicyID              ResourceID         `json:"placementPolicyId"`
	PolicyResourceVersion          uint64             `json:"policyResourceVersion"`
	RequestedIsolationGuarantee    IsolationGuarantee `json:"requestedIsolationGuarantee"`
	Outcome                        PlacementOutcome   `json:"outcome"`
	ExecutionTargetID              ResourceID         `json:"executionTargetId,omitempty"`
	ExecutionTargetResourceVersion uint64             `json:"executionTargetResourceVersion,omitempty"`
	GrantedIsolationGuarantee      IsolationGuarantee `json:"grantedIsolationGuarantee,omitempty"`
	CandidateSetDigest             string             `json:"candidateSetDigest"`
	Reason                         *Problem           `json:"reason,omitempty"`
	DecidedAt                      time.Time          `json:"decidedAt"`
}

type ArtifactRef struct {
	Kind    ArtifactKind `json:"kind"`
	Locator string       `json:"locator"`
	Digest  string       `json:"digest"`
}

type ResourceRequirements struct {
	CPUMillis   int64 `json:"cpuMillis"`
	MemoryBytes int64 `json:"memoryBytes"`
}

type ApplicationEndpoint struct {
	Name       string             `json:"name"`
	Port       uint16             `json:"port"`
	Protocol   EndpointProtocol   `json:"protocol"`
	Visibility EndpointVisibility `json:"visibility"`
}

// ComponentInput declares one allowlisted, SDK-free injection slot. Executors
// derive the environment variable or fixed mount path from Name; callers
// cannot supply a host path or provider-native document.
type ComponentInput struct {
	Name      string        `json:"name"`
	Kind      InputKind     `json:"kind"`
	Injection InjectionMode `json:"injection"`
	Required  bool          `json:"required"`
}

type SecretVersionReference struct {
	SecretID ResourceID `json:"secretId"`
	Version  string     `json:"version"`
}

type ComponentBinding struct {
	Name                    string                  `json:"name"`
	ConfigurationRevisionID ResourceID              `json:"configurationRevisionId,omitempty"`
	SecretVersion           *SecretVersionReference `json:"secretVersion,omitempty"`
}

type Application struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ResourceMetadata `json:"metadata"`
}

// CreateApplicationRequest contains only caller-owned desired fields. Scope,
// resource version, timestamps, requester, and Audit identity come from the
// server-side authorization and transaction boundaries.
type CreateApplicationRequest struct {
	ID     ResourceID        `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
}

type Configuration struct {
	APIVersion    string           `json:"apiVersion"`
	Kind          string           `json:"kind"`
	Metadata      ResourceMetadata `json:"metadata"`
	ApplicationID ResourceID       `json:"applicationId"`
}

type CreateConfigurationRequest struct {
	ID            ResourceID        `json:"id"`
	Name          string            `json:"name"`
	Labels        map[string]string `json:"labels,omitempty"`
	ApplicationID ResourceID        `json:"applicationId"`
}

type ConfigurationRevisionSpec struct {
	ConfigurationID ResourceID        `json:"configurationId"`
	Values          map[string]string `json:"values"`
	ContentDigest   string            `json:"contentDigest"`
}

type ConfigurationRevision struct {
	APIVersion string                    `json:"apiVersion"`
	Kind       string                    `json:"kind"`
	Metadata   ResourceMetadata          `json:"metadata"`
	Spec       ConfigurationRevisionSpec `json:"spec"`
}

type CreateConfigurationRevisionRequest struct {
	ID     ResourceID                `json:"id"`
	Name   string                    `json:"name"`
	Labels map[string]string         `json:"labels,omitempty"`
	Spec   ConfigurationRevisionSpec `json:"spec"`
}

type ApplicationRevisionComponent struct {
	Name      string                `json:"name"`
	Artifact  ArtifactRef           `json:"artifact"`
	Resources ResourceRequirements  `json:"resources"`
	Endpoints []ApplicationEndpoint `json:"endpoints,omitempty"`
	Inputs    []ComponentInput      `json:"inputs,omitempty"`
}

type ApplicationRevisionSpec struct {
	ApplicationID ResourceID                     `json:"applicationId"`
	Revision      string                         `json:"revision"`
	ContentDigest string                         `json:"contentDigest"`
	Components    []ApplicationRevisionComponent `json:"components"`
}

type ApplicationRevision struct {
	APIVersion string                  `json:"apiVersion"`
	Kind       string                  `json:"kind"`
	Metadata   ResourceMetadata        `json:"metadata"`
	Spec       ApplicationRevisionSpec `json:"spec"`
}

type CreateApplicationRevisionRequest struct {
	ID     ResourceID              `json:"id"`
	Name   string                  `json:"name"`
	Labels map[string]string       `json:"labels,omitempty"`
	Spec   ApplicationRevisionSpec `json:"spec"`
}

type DeploymentComponent struct {
	Name     string             `json:"name"`
	Replicas uint32             `json:"replicas"`
	Bindings []ComponentBinding `json:"bindings,omitempty"`
}

type DeploymentSpec struct {
	ApplicationRevisionID ResourceID             `json:"applicationRevisionId"`
	PlacementPolicyID     ResourceID             `json:"placementPolicyId"`
	DesiredState          DeploymentDesiredState `json:"desiredState"`
	Components            []DeploymentComponent  `json:"components"`
}

type DeploymentStatus struct {
	Phase                         DeploymentPhase `json:"phase"`
	ObservedGeneration            uint64          `json:"observedGeneration"`
	PlacementDecisionID           ResourceID      `json:"placementDecisionId,omitempty"`
	CurrentOperationID            OperationID     `json:"currentOperationId,omitempty"`
	ObservedApplicationRevisionID ResourceID      `json:"observedApplicationRevisionId,omitempty"`
	ReadyComponents               uint32          `json:"readyComponents"`
	ObservedAt                    time.Time       `json:"observedAt"`
}

type Deployment struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ResourceMetadata `json:"metadata"`
	Generation uint64           `json:"generation"`
	Spec       DeploymentSpec   `json:"spec"`
	Status     DeploymentStatus `json:"status"`
}

type CreateDeploymentRequest struct {
	ID   ResourceID     `json:"id"`
	Name string         `json:"name"`
	Spec DeploymentSpec `json:"spec"`
}

type RollbackDeploymentRequest struct {
	SourceGeneration uint64 `json:"sourceGeneration"`
}

// DeploymentGeneration is the immutable desired-state snapshot executed by
// an adapter. ResourceVersion remains on the mutable Deployment and is not an
// execution identity.
type DeploymentGeneration struct {
	APIVersion           string         `json:"apiVersion"`
	Kind                 string         `json:"kind"`
	Scope                ResourceScope  `json:"scope"`
	DeploymentID         ResourceID     `json:"deploymentId"`
	Generation           uint64         `json:"generation"`
	Spec                 DeploymentSpec `json:"spec"`
	ContentDigest        string         `json:"contentDigest"`
	CreatedByOperationID OperationID    `json:"createdByOperationId"`
	CreatedAt            time.Time      `json:"createdAt"`
}

type SubjectRef struct {
	Type SubjectType `json:"type"`
	ID   string      `json:"id"`
}

type ResourceRef struct {
	Kind string     `json:"kind"`
	ID   ResourceID `json:"id"`
}

type FieldViolation struct {
	Field       string `json:"field"`
	Description string `json:"description"`
}

type Readiness struct {
	APIVersion    string         `json:"apiVersion"`
	Kind          string         `json:"kind"`
	State         ReadinessState `json:"state"`
	SchemaVersion uint64         `json:"schemaVersion"`
	CheckedAt     time.Time      `json:"checkedAt"`
}

// VerifyInstallationRequest selects only the installation/release already
// bound into the running PaaS process by the authenticated offline release.
// Artifact, workload, configuration, placement, and provider controls are not
// caller input.
type VerifyInstallationRequest struct {
	InstallationID string `json:"installationId"`
	ReleaseID      string `json:"releaseId"`
}

type InstallationVerification struct {
	APIVersion      string                        `json:"apiVersion"`
	Kind            string                        `json:"kind"`
	InstallationID  string                        `json:"installationId"`
	ReleaseID       string                        `json:"releaseId"`
	State           InstallationVerificationState `json:"state"`
	DeploymentID    ResourceID                    `json:"deploymentId"`
	Generation      uint64                        `json:"generation"`
	OperationID     OperationID                   `json:"operationId"`
	OperationState  OperationState                `json:"operationState"`
	DeploymentPhase DeploymentPhase               `json:"deploymentPhase"`
	CheckedAt       time.Time                     `json:"checkedAt"`
}

type Problem struct {
	Type       string           `json:"type"`
	Title      string           `json:"title"`
	Status     int              `json:"status"`
	Code       ErrorCode        `json:"code"`
	Detail     string           `json:"detail"`
	Instance   string           `json:"instance,omitempty"`
	TraceID    string           `json:"traceId"`
	Retryable  bool             `json:"retryable"`
	Violations []FieldViolation `json:"violations,omitempty"`
}

type Operation struct {
	APIVersion             string          `json:"apiVersion"`
	Kind                   string          `json:"kind"`
	ID                     OperationID     `json:"id"`
	Scope                  ResourceScope   `json:"scope"`
	Action                 OperationAction `json:"action"`
	Target                 ResourceRef     `json:"target"`
	RequestedBy            SubjectRef      `json:"requestedBy"`
	IdempotencyFingerprint string          `json:"idempotencyFingerprint"`
	RequestDigest          string          `json:"requestDigest"`
	State                  OperationState  `json:"state"`
	Attempt                uint32          `json:"attempt"`
	Error                  *Problem        `json:"error,omitempty"`
	CreatedAt              time.Time       `json:"createdAt"`
	UpdatedAt              time.Time       `json:"updatedAt"`
	TerminalAt             *time.Time      `json:"terminalAt,omitempty"`
}

type Evidence struct {
	APIVersion     string            `json:"apiVersion"`
	Kind           string            `json:"kind"`
	ID             ResourceID        `json:"id"`
	Scope          ResourceScope     `json:"scope"`
	OperationID    OperationID       `json:"operationId"`
	Sequence       uint64            `json:"sequence"`
	Type           EvidenceType      `json:"type"`
	Source         string            `json:"source"`
	Severity       EvidenceSeverity  `json:"severity"`
	Code           string            `json:"code"`
	Message        string            `json:"message"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	PreviousDigest string            `json:"previousDigest,omitempty"`
	ContentDigest  string            `json:"contentDigest"`
	OccurredAt     time.Time         `json:"occurredAt"`
}

type AdapterCapabilitiesContract struct {
	Adapter             AdapterRef           `json:"adapter"`
	Actions             []AdapterAction      `json:"actions"`
	IsolationGuarantees []IsolationGuarantee `json:"isolationGuarantees,omitempty"`
	ObservedAt          time.Time            `json:"observedAt"`
}

type AdapterCommandEnvelope struct {
	OperationID           OperationID   `json:"operationId"`
	CommandID             CommandID     `json:"commandId"`
	Attempt               uint32        `json:"attempt"`
	Action                AdapterAction `json:"action"`
	Scope                 ResourceScope `json:"scope"`
	ApplicationID         ResourceID    `json:"applicationId,omitempty"`
	ApplicationRevisionID ResourceID    `json:"applicationRevisionId,omitempty"`
	DeploymentID          ResourceID    `json:"deploymentId,omitempty"`
	ExecutionTargetID     ResourceID    `json:"executionTargetId"`
	RequestDigest         string        `json:"requestDigest"`
	BindingRef            string        `json:"bindingRef"`
	Deadline              time.Time     `json:"deadline"`
	TraceParent           string        `json:"traceparent,omitempty"`
}

type InspectExecutionTargetRequest struct {
	Command AdapterCommandEnvelope `json:"command"`
}

type ObserveExecutionTargetRequest struct {
	Command AdapterCommandEnvelope `json:"command"`
}

// DeploymentExecutionRequest is internal-visible adapter input. It contains
// exact immutable references and resolved ordinary configuration documents,
// but never secret material or provider-native options.
type DeploymentExecutionRequest struct {
	Command                AdapterCommandEnvelope  `json:"command"`
	Generation             DeploymentGeneration    `json:"generation"`
	ApplicationRevision    ApplicationRevision     `json:"applicationRevision"`
	ConfigurationRevisions []ConfigurationRevision `json:"configurationRevisions"`
	Placement              PlacementDecision       `json:"placement"`
}

type ObserveDeploymentRequest struct {
	Command               AdapterCommandEnvelope `json:"command"`
	Generation            uint64                 `json:"generation"`
	ExpectedContentDigest string                 `json:"expectedContentDigest"`
}

type DeploymentEndpointObservation struct {
	ComponentName string           `json:"componentName"`
	EndpointName  string           `json:"endpointName"`
	Protocol      EndpointProtocol `json:"protocol"`
	Address       string           `json:"address"`
	Port          uint16           `json:"port"`
}

type DeploymentObservation struct {
	DeploymentID          ResourceID                      `json:"deploymentId"`
	Generation            uint64                          `json:"generation"`
	ApplicationRevisionID ResourceID                      `json:"applicationRevisionId"`
	Phase                 DeploymentPhase                 `json:"phase"`
	ReadyComponents       uint32                          `json:"readyComponents"`
	Endpoints             []DeploymentEndpointObservation `json:"endpoints,omitempty"`
	ReceiptDigest         string                          `json:"receiptDigest"`
	Evidence              []Evidence                      `json:"evidence,omitempty"`
	ObservedAt            time.Time                       `json:"observedAt"`
}

type ExecutionTargetObservation struct {
	ExecutionTargetID            ResourceID            `json:"executionTargetId"`
	IdentityFingerprint          string                `json:"identityFingerprint"`
	Labels                       map[string]string     `json:"labels"`
	Capacity                     Capacity              `json:"capacity"`
	Allocatable                  Capacity              `json:"allocatable"`
	Health                       ExecutionTargetHealth `json:"health"`
	SupportedIsolationGuarantees []IsolationGuarantee  `json:"supportedIsolationGuarantees"`
	ObservedAt                   time.Time             `json:"observedAt"`
	Usage                        *ExecutionTargetUsage `json:"usage,omitempty"`
}

type NormalizedAdapterError struct {
	Class             AdapterErrorClass `json:"class"`
	Code              ErrorCode         `json:"code"`
	Message           string            `json:"message"`
	Retryable         bool              `json:"retryable"`
	RetryAfterSeconds *uint32           `json:"retryAfterSeconds,omitempty"`
}

type AdapterResult struct {
	CommandID  CommandID               `json:"commandId"`
	State      AdapterResultState      `json:"state"`
	Receipt    string                  `json:"receipt,omitempty"`
	Replayed   bool                    `json:"replayed"`
	Error      *NormalizedAdapterError `json:"error,omitempty"`
	Evidence   []Evidence              `json:"evidence,omitempty"`
	ObservedAt time.Time               `json:"observedAt"`
}
