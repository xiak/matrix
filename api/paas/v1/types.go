package paasv1

import "time"

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

type ResourcePoolSpec struct {
	TargetSelector          LabelSelector    `json:"targetSelector"`
	AllowedIsolationClasses []IsolationClass `json:"allowedIsolationClasses"`
}

type ResourcePoolStatus struct {
	Phase            ResourcePoolPhase `json:"phase"`
	TargetCount      uint32            `json:"targetCount"`
	ReadyTargetCount uint32            `json:"readyTargetCount"`
	ObservedAt       time.Time         `json:"observedAt"`
}

type ResourcePool struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Metadata   ResourceMetadata   `json:"metadata"`
	Spec       ResourcePoolSpec   `json:"spec"`
	Status     ResourcePoolStatus `json:"status"`
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

type RuntimeTargetSpec struct {
	ResourcePoolID        ResourceID         `json:"resourcePoolId"`
	InfrastructureAdapter AdapterRef         `json:"infrastructureAdapter"`
	RuntimeAdapter        AdapterRef         `json:"runtimeAdapter"`
	GatewayAdapter        *AdapterRef        `json:"gatewayAdapter,omitempty"`
	DesiredState          TargetDesiredState `json:"desiredState"`
}

type RuntimeTargetStatus struct {
	Health                    TargetHealth     `json:"health"`
	Capacity                  Capacity         `json:"capacity"`
	Allocatable               Capacity         `json:"allocatable"`
	SupportedIsolationClasses []IsolationClass `json:"supportedIsolationClasses"`
	ObservedAt                time.Time        `json:"observedAt"`
}

type RuntimeTarget struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Metadata   ResourceMetadata    `json:"metadata"`
	Spec       RuntimeTargetSpec   `json:"spec"`
	Status     RuntimeTargetStatus `json:"status"`
}

type PlacementPolicySpec struct {
	RequiredIsolationClass IsolationClass    `json:"requiredIsolationClass"`
	EligibleResourcePools  []ResourceID      `json:"eligibleResourcePoolIds"`
	TargetSelector         LabelSelector     `json:"targetSelector"`
	Strategy               PlacementStrategy `json:"strategy"`
}

type PlacementPolicy struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Metadata   ResourceMetadata    `json:"metadata"`
	Spec       PlacementPolicySpec `json:"spec"`
}

type PlacementDecision struct {
	APIVersion            string           `json:"apiVersion"`
	Kind                  string           `json:"kind"`
	Metadata              ResourceMetadata `json:"metadata"`
	WorkloadReleaseID     ResourceID       `json:"workloadReleaseId"`
	PlacementPolicyID     ResourceID       `json:"placementPolicyId"`
	PolicyResourceVersion uint64           `json:"policyResourceVersion"`
	RequestedIsolation    IsolationClass   `json:"requestedIsolationClass"`
	Outcome               PlacementOutcome `json:"outcome"`
	RuntimeTargetID       ResourceID       `json:"runtimeTargetId,omitempty"`
	GrantedIsolation      IsolationClass   `json:"grantedIsolationClass,omitempty"`
	CandidateSetDigest    string           `json:"candidateSetDigest"`
	Reason                *Problem         `json:"reason,omitempty"`
	DecidedAt             time.Time        `json:"decidedAt"`
}

type ArtifactRef struct {
	Kind    ArtifactKind `json:"kind"`
	Locator string       `json:"locator"`
	Digest  string       `json:"digest"`
}

type SecretReference struct {
	Name       string     `json:"name"`
	ResourceID ResourceID `json:"resourceId"`
}

type ResourceRequirements struct {
	CPUMillis   int64 `json:"cpuMillis"`
	MemoryBytes int64 `json:"memoryBytes"`
}

type WorkloadEndpoint struct {
	Name       string             `json:"name"`
	Port       uint16             `json:"port"`
	Protocol   EndpointProtocol   `json:"protocol"`
	Visibility EndpointVisibility `json:"visibility"`
}

type WorkloadComponent struct {
	Name              string               `json:"name"`
	Artifact          ArtifactRef          `json:"artifact"`
	Replicas          uint32               `json:"replicas"`
	Resources         ResourceRequirements `json:"resources"`
	ConfigurationRefs []ResourceID         `json:"configurationRefs,omitempty"`
	SecretReferences  []SecretReference    `json:"secretReferences,omitempty"`
	Endpoints         []WorkloadEndpoint   `json:"endpoints,omitempty"`
}

type WorkloadReleaseSpec struct {
	WorkloadID    ResourceID          `json:"workloadId"`
	Revision      string              `json:"revision"`
	ContentDigest string              `json:"contentDigest"`
	Components    []WorkloadComponent `json:"components"`
}

type WorkloadReleaseStatus struct {
	Phase               ReleasePhase `json:"phase"`
	PlacementDecisionID ResourceID   `json:"placementDecisionId,omitempty"`
	CurrentOperationID  OperationID  `json:"currentOperationId,omitempty"`
	ReadyComponents     uint32       `json:"readyComponents"`
	ObservedAt          time.Time    `json:"observedAt"`
}

type WorkloadRelease struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   ResourceMetadata      `json:"metadata"`
	Spec       WorkloadReleaseSpec   `json:"spec"`
	Status     WorkloadReleaseStatus `json:"status"`
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
	Adapter          AdapterRef       `json:"adapter"`
	Actions          []AdapterAction  `json:"actions"`
	IsolationClasses []IsolationClass `json:"isolationClasses,omitempty"`
	ObservedAt       time.Time        `json:"observedAt"`
}

type AdapterCommandEnvelope struct {
	OperationID     OperationID   `json:"operationId"`
	CommandID       CommandID     `json:"commandId"`
	Attempt         uint32        `json:"attempt"`
	Action          AdapterAction `json:"action"`
	Scope           ResourceScope `json:"scope"`
	WorkloadID      ResourceID    `json:"workloadId,omitempty"`
	ReleaseID       ResourceID    `json:"releaseId,omitempty"`
	RuntimeTargetID ResourceID    `json:"runtimeTargetId"`
	RequestDigest   string        `json:"requestDigest"`
	BindingRef      string        `json:"bindingRef"`
	Deadline        time.Time     `json:"deadline"`
	TraceParent     string        `json:"traceparent,omitempty"`
}

type InspectTargetRequest struct {
	Command AdapterCommandEnvelope `json:"command"`
}

type ObserveTargetRequest struct {
	Command AdapterCommandEnvelope `json:"command"`
}

type TargetObservation struct {
	RuntimeTargetID           ResourceID        `json:"runtimeTargetId"`
	IdentityFingerprint       string            `json:"identityFingerprint"`
	Labels                    map[string]string `json:"labels"`
	Capacity                  Capacity          `json:"capacity"`
	Allocatable               Capacity          `json:"allocatable"`
	Health                    TargetHealth      `json:"health"`
	SupportedIsolationClasses []IsolationClass  `json:"supportedIsolationClasses"`
	ObservedAt                time.Time         `json:"observedAt"`
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
