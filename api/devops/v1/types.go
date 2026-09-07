package devopsv1

import "time"

type TenantID string
type ResourceID string

type ResourceScope struct {
	TenantID TenantID `json:"tenantId"`
}

type ResourceMetadata struct {
	ID              ResourceID    `json:"id"`
	Name            string        `json:"name"`
	Scope           ResourceScope `json:"scope"`
	ResourceVersion uint64        `json:"resourceVersion"`
	CreatedAt       time.Time     `json:"createdAt"`
	UpdatedAt       time.Time     `json:"updatedAt"`
}

type DevOpsProject struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ResourceMetadata `json:"metadata"`
}

// CreateDevOpsProjectRequest contains only caller-owned desired fields. The
// tenant, resource version, timestamps, actor, and Audit correlation come from
// authenticated server-side boundaries.
type CreateDevOpsProjectRequest struct {
	ID   ResourceID `json:"id"`
	Name string     `json:"name"`
}

// SourceConnectionSpec binds one installed source adapter to an exact endpoint
// allowlist and secret-store references. Secret values never cross this
// contract. Adapter and endpoint identity are immutable after creation;
// update replaces only credential references.
type SourceConnectionSpec struct {
	AdapterID              ResourceID `json:"adapterId"`
	AllowedEndpointOrigins []string   `json:"allowedEndpointOrigins"`
	WebhookSecretRef       ResourceID `json:"webhookSecretRef"`
	FetchCredentialRef     ResourceID `json:"fetchCredentialRef"`
	ReportCredentialRef    ResourceID `json:"reportCredentialRef"`
}

type SourceConnectionStatus struct {
	Health     SourceConnectionHealth `json:"health"`
	ObservedAt time.Time              `json:"observedAt"`
}

type SourceConnection struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   ResourceMetadata       `json:"metadata"`
	Spec       SourceConnectionSpec   `json:"spec"`
	Status     SourceConnectionStatus `json:"status"`
}

type CreateSourceConnectionRequest struct {
	ID   ResourceID           `json:"id"`
	Name string               `json:"name"`
	Spec SourceConnectionSpec `json:"spec"`
}

type UpdateSourceConnectionRequest struct {
	Spec SourceConnectionSpec `json:"spec"`
}

// RepositoryBindingSpec contains the stable normalized repository identity.
// RepositoryPath is safe display/configuration data; ExternalRepositoryID and
// the canonical content digest are authority.
type RepositoryBindingSpec struct {
	SourceConnectionID   ResourceID `json:"sourceConnectionId"`
	ExternalRepositoryID ResourceID `json:"externalRepositoryId"`
	RepositoryPath       string     `json:"repositoryPath"`
	TrustedDefaultBranch string     `json:"trustedDefaultBranch"`
}

type RepositoryBindingStatus struct {
	Health     RepositoryBindingHealth `json:"health"`
	ObservedAt time.Time               `json:"observedAt"`
}

type RepositoryBinding struct {
	APIVersion    string                  `json:"apiVersion"`
	Kind          string                  `json:"kind"`
	Metadata      ResourceMetadata        `json:"metadata"`
	ProjectID     ResourceID              `json:"projectId"`
	Spec          RepositoryBindingSpec   `json:"spec"`
	ContentDigest string                  `json:"contentDigest"`
	Status        RepositoryBindingStatus `json:"status"`
}

type CreateRepositoryBindingRequest struct {
	ID        ResourceID            `json:"id"`
	Name      string                `json:"name"`
	ProjectID ResourceID            `json:"projectId"`
	Spec      RepositoryBindingSpec `json:"spec"`
}

type UpdateRepositoryBindingRequest struct {
	Spec RepositoryBindingSpec `json:"spec"`
}

// PipelineDraftSpec contains only choices available to a tenant. It cannot
// carry commands, images, host paths, credentials, or provider-native data.
type PipelineDraftSpec struct {
	RepositoryBindingID ResourceID             `json:"repositoryBindingId"`
	TriggerPolicy       TriggerPolicy          `json:"triggerPolicy"`
	VerificationProfile VerificationProfile    `json:"verificationProfile"`
	DependencyEgress    DependencyEgressPolicy `json:"dependencyEgress"`
	ReporterPolicy      ReporterPolicy         `json:"reporterPolicy"`
}

type PipelineDraft struct {
	Spec          PipelineDraftSpec `json:"spec"`
	ContentDigest string            `json:"contentDigest"`
}

type PipelineRevisionReference struct {
	ID            ResourceID `json:"id"`
	Revision      uint64     `json:"revision"`
	ContentDigest string     `json:"contentDigest"`
}

type Pipeline struct {
	APIVersion     string                     `json:"apiVersion"`
	Kind           string                     `json:"kind"`
	Metadata       ResourceMetadata           `json:"metadata"`
	ProjectID      ResourceID                 `json:"projectId"`
	Draft          PipelineDraft              `json:"draft"`
	ActiveRevision *PipelineRevisionReference `json:"activeRevision,omitempty"`
}

type CreatePipelineRequest struct {
	ID        ResourceID        `json:"id"`
	Name      string            `json:"name"`
	ProjectID ResourceID        `json:"projectId"`
	Draft     PipelineDraftSpec `json:"draft"`
}

type UpdatePipelineDraftRequest struct {
	Draft PipelineDraftSpec `json:"draft"`
}

type VerificationStep struct {
	Ordinal uint32               `json:"ordinal"`
	Kind    VerificationStepKind `json:"kind"`
}

type VerificationLimits struct {
	StepTimeoutSeconds uint32 `json:"stepTimeoutSeconds"`
	RunTimeoutSeconds  uint32 `json:"runTimeoutSeconds"`
	CPUMillis          int64  `json:"cpuMillis"`
	MemoryBytes        int64  `json:"memoryBytes"`
	WritableBytes      int64  `json:"writableBytes"`
	ProcessLimit       uint32 `json:"processLimit"`
	MaxLogBytes        int64  `json:"maxLogBytes"`
}

// PipelineRevisionSpec is the fully resolved, immutable execution contract.
// Human-readable command text and executor-vendor details are deliberately
// absent; closed step and profile identities carry those semantics.
type PipelineRevisionSpec struct {
	RepositoryBindingID     ResourceID             `json:"repositoryBindingId"`
	RepositoryBindingDigest string                 `json:"repositoryBindingDigest"`
	TriggerPolicy           TriggerPolicy          `json:"triggerPolicy"`
	VerificationProfile     VerificationProfile    `json:"verificationProfile"`
	ExecutorProfile         ExecutorProfile        `json:"executorProfile"`
	ToolchainImageDigest    string                 `json:"toolchainImageDigest"`
	DependencyEgress        DependencyEgressPolicy `json:"dependencyEgress"`
	ReporterPolicy          ReporterPolicy         `json:"reporterPolicy"`
	Steps                   []VerificationStep     `json:"steps"`
	Limits                  VerificationLimits     `json:"limits"`
}

type SubjectRef struct {
	Kind SubjectKind `json:"kind"`
	ID   string      `json:"id"`
}

type PipelineRevision struct {
	APIVersion    string               `json:"apiVersion"`
	Kind          string               `json:"kind"`
	ID            ResourceID           `json:"id"`
	Scope         ResourceScope        `json:"scope"`
	PipelineID    ResourceID           `json:"pipelineId"`
	ProjectID     ResourceID           `json:"projectId"`
	Revision      uint64               `json:"revision"`
	Spec          PipelineRevisionSpec `json:"spec"`
	ContentDigest string               `json:"contentDigest"`
	ActivatedBy   SubjectRef           `json:"activatedBy"`
	ActivatedAt   time.Time            `json:"activatedAt"`
}

// PipelineActivation is the atomic result of activating one draft. The
// Pipeline points at the exact immutable revision returned alongside it.
type PipelineActivation struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Pipeline   Pipeline         `json:"pipeline"`
	Revision   PipelineRevision `json:"revision"`
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
	Detail     string           `json:"detail,omitempty"`
	Instance   string           `json:"instance,omitempty"`
	TraceID    string           `json:"traceId"`
	Retryable  bool             `json:"retryable"`
	Violations []FieldViolation `json:"violations,omitempty"`
}
