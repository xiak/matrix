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

type CreateExecutionPoolRequest struct {
	ID     ResourceID        `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Spec   ExecutionPoolSpec `json:"spec"`
}

// ExecutionPoolList is the bounded installation-scoped set available to the
// host-enrollment form. It contains no provider or credential material.
type ExecutionPoolList struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Items      []ExecutionPool `json:"items"`
}

type NodeEnrollmentDiagnostic struct {
	Code       NodeEnrollmentDiagnosticCode `json:"code"`
	Retryable  bool                         `json:"retryable"`
	OccurredAt time.Time                    `json:"occurredAt"`
}

// NodeEnrollment owns only the short-lived admission ceremony. A READY value
// points at the existing ExecutionTarget, which owns all subsequent host state.
type NodeEnrollment struct {
	APIVersion           string                    `json:"apiVersion"`
	Kind                 string                    `json:"kind"`
	Metadata             ResourceMetadata          `json:"metadata"`
	ExecutionTargetID    ResourceID                `json:"executionTargetId"`
	ExecutionPoolID      ResourceID                `json:"executionPoolId"`
	OperationID          OperationID               `json:"operationId"`
	State                NodeEnrollmentState       `json:"state"`
	ExpiresAt            time.Time                 `json:"expiresAt"`
	CredentialConsumedAt *time.Time                `json:"credentialConsumedAt,omitempty"`
	ReadyAt              *time.Time                `json:"readyAt,omitempty"`
	ReplacedByID         ResourceID                `json:"replacedById,omitempty"`
	Diagnostic           *NodeEnrollmentDiagnostic `json:"diagnostic,omitempty"`
}

type NodeEnrollmentList struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Items      []NodeEnrollment `json:"items"`
}

// CreateNodeEnrollmentRequest contains only operator intent and an ephemeral
// browser wrapping key. It never accepts a target address, host path, shell,
// provider option, certificate, private key, or raw join credential.
type CreateNodeEnrollmentRequest struct {
	Name              string            `json:"name"`
	Labels            map[string]string `json:"labels,omitempty"`
	ExecutionPoolID   ResourceID        `json:"executionPoolId"`
	WrappingPublicKey string            `json:"wrappingPublicKey"`
}

type RegenerateNodeEnrollmentRequest struct {
	WrappingPublicKey string `json:"wrappingPublicKey"`
}

// NodeEnrollmentJoin is public integrity-bound metadata used to assemble the
// offline join file. Its URL never contains the one-time credential.
type NodeEnrollmentJoin struct {
	APIVersion         string                     `json:"apiVersion"`
	Kind               string                     `json:"kind"`
	EnrollmentID       ResourceID                 `json:"enrollmentId"`
	InstallationID     string                     `json:"installationId"`
	ExecutionTargetID  ResourceID                 `json:"executionTargetId"`
	ControlPlaneURL    string                     `json:"controlPlaneUrl"`
	CredentialDigest   string                     `json:"credentialDigest"`
	ExpiresAt          time.Time                  `json:"expiresAt"`
	IssuerCertificate  string                     `json:"issuerCertificate"`
	SignatureAlgorithm NodeJoinSignatureAlgorithm `json:"signatureAlgorithm"`
	Signature          string                     `json:"signature"`
}

// WrappedJoinCredential is the only creation-time representation of the join
// credential in an HTTP response. Ciphertext is RSA-3072 OAEP-SHA256 output;
// the raw credential is never returned or persisted by this contract.
type WrappedJoinCredential struct {
	Algorithm  JoinCredentialWrappingAlgorithm `json:"algorithm"`
	Ciphertext string                          `json:"ciphertext"`
}

type CreateNodeEnrollmentResponse struct {
	Enrollment        NodeEnrollment        `json:"enrollment"`
	Join              NodeEnrollmentJoin    `json:"join"`
	WrappedCredential WrappedJoinCredential `json:"wrappedCredential"`
}

// NodeEnrollmentListenerClaim is the provider-neutral network surface that
// the locally installed node intends to bind. The control plane supplies the
// addresses from trusted installation policy and the observed TLS peer; a
// caller can select neither a host name nor an arbitrary endpoint.
type NodeEnrollmentListenerClaim struct {
	ManagementPort uint16 `json:"managementPort"`
	CollectorPort  uint16 `json:"collectorPort"`
}

// ExchangeNodeEnrollmentRequest is the one bounded bootstrap message that may
// carry the raw one-time credential. Both private keys remain on the target;
// only signed PKCS#10 public-key requests cross the node boundary.
type ExchangeNodeEnrollmentRequest struct {
	APIVersion                  string                      `json:"apiVersion"`
	Kind                        string                      `json:"kind"`
	EnrollmentID                ResourceID                  `json:"enrollmentId"`
	InstallationID              string                      `json:"installationId"`
	ExecutionTargetID           ResourceID                  `json:"executionTargetId"`
	ExchangeID                  string                      `json:"exchangeId"`
	Credential                  string                      `json:"credential"`
	MachineFingerprint          string                      `json:"machineFingerprint"`
	RuntimeContractDigest       string                      `json:"runtimeContractDigest"`
	Listener                    NodeEnrollmentListenerClaim `json:"listener"`
	NodeCertificateRequest      string                      `json:"nodeCertificateRequest"`
	CollectorCertificateRequest string                      `json:"collectorCertificateRequest"`
}

func (ExchangeNodeEnrollmentRequest) String() string {
	return "node enrollment exchange request <redacted>"
}

func (ExchangeNodeEnrollmentRequest) GoString() string {
	return "node enrollment exchange request <redacted>"
}

// NodeEnrollmentExchangeResponse is public certificate material returned only
// by the bootstrap exchange route. It contains no join credential or private
// key and is sealed before persistence for exact lost-response recovery.
type NodeEnrollmentExchangeResponse struct {
	APIVersion            string     `json:"apiVersion"`
	Kind                  string     `json:"kind"`
	EnrollmentID          ResourceID `json:"enrollmentId"`
	InstallationID        string     `json:"installationId"`
	ExecutionTargetID     ResourceID `json:"executionTargetId"`
	ExchangeID            string     `json:"exchangeId"`
	MachineFingerprint    string     `json:"machineFingerprint"`
	RuntimeContractDigest string     `json:"runtimeContractDigest"`
	ControllerID          string     `json:"controllerId"`
	BindingRef            string     `json:"bindingRef"`
	NodeListenAddress     string     `json:"nodeListenAddress"`
	CollectorEndpoint     string     `json:"collectorEndpoint"`
	NodeCertificate       string     `json:"nodeCertificate"`
	CollectorCertificate  string     `json:"collectorCertificate"`
	IssuerCertificate     string     `json:"issuerCertificate"`
	CertificateNotBefore  time.Time  `json:"certificateNotBefore"`
	CertificateNotAfter   time.Time  `json:"certificateNotAfter"`
}

// CreateNodeEnrollmentRecoveryChallengeRequest identifies the exact local
// exchange intent whose success response was lost. It contains neither the
// consumed join credential nor either target-host private key.
type CreateNodeEnrollmentRecoveryChallengeRequest struct {
	APIVersion                    string     `json:"apiVersion"`
	Kind                          string     `json:"kind"`
	EnrollmentID                  ResourceID `json:"enrollmentId"`
	InstallationID                string     `json:"installationId"`
	ExecutionTargetID             ResourceID `json:"executionTargetId"`
	ExchangeID                    string     `json:"exchangeId"`
	MachineFingerprint            string     `json:"machineFingerprint"`
	RuntimeContractDigest         string     `json:"runtimeContractDigest"`
	NodePublicKeyFingerprint      string     `json:"nodePublicKeyFingerprint"`
	CollectorPublicKeyFingerprint string     `json:"collectorPublicKeyFingerprint"`
}

// NodeEnrollmentRecoveryChallenge is a short-lived, installation-authenticated
// public challenge. It is safe to replay within its bounded lifetime because
// recovery is read-only and can return only the already sealed exchange result.
type NodeEnrollmentRecoveryChallenge struct {
	APIVersion                    string     `json:"apiVersion"`
	Kind                          string     `json:"kind"`
	EnrollmentID                  ResourceID `json:"enrollmentId"`
	InstallationID                string     `json:"installationId"`
	ExecutionTargetID             ResourceID `json:"executionTargetId"`
	ExchangeID                    string     `json:"exchangeId"`
	MachineFingerprint            string     `json:"machineFingerprint"`
	RuntimeContractDigest         string     `json:"runtimeContractDigest"`
	NodePublicKeyFingerprint      string     `json:"nodePublicKeyFingerprint"`
	CollectorPublicKeyFingerprint string     `json:"collectorPublicKeyFingerprint"`
	Challenge                     string     `json:"challenge"`
	IssuedAt                      time.Time  `json:"issuedAt"`
	ExpiresAt                     time.Time  `json:"expiresAt"`
	Authenticator                 string     `json:"authenticator"`
}

// RecoverNodeEnrollmentExchangeRequest proves simultaneous possession of the
// two distinct private keys fixed by the consumed exchange. The signatures
// cover the complete authenticated challenge and never disclose either key.
type RecoverNodeEnrollmentExchangeRequest struct {
	APIVersion         string                          `json:"apiVersion"`
	Kind               string                          `json:"kind"`
	Challenge          NodeEnrollmentRecoveryChallenge `json:"challenge"`
	NodeSignature      string                          `json:"nodeSignature"`
	CollectorSignature string                          `json:"collectorSignature"`
}

func (RecoverNodeEnrollmentExchangeRequest) String() string {
	return "node enrollment recovery proof <redacted>"
}

func (RecoverNodeEnrollmentExchangeRequest) GoString() string {
	return "node enrollment recovery proof <redacted>"
}

// CompleteNodeEnrollmentRequest repeats only the exact public commitments
// fixed by the consumed exchange. It cannot select a pool, labels, endpoint,
// identity or provider; the control plane compares every field before probing
// the already fixed node over mutually authenticated TLS.
type CompleteNodeEnrollmentRequest struct {
	APIVersion                    string     `json:"apiVersion"`
	Kind                          string     `json:"kind"`
	EnrollmentID                  ResourceID `json:"enrollmentId"`
	InstallationID                string     `json:"installationId"`
	ExecutionTargetID             ResourceID `json:"executionTargetId"`
	ExchangeID                    string     `json:"exchangeId"`
	MachineFingerprint            string     `json:"machineFingerprint"`
	RuntimeContractDigest         string     `json:"runtimeContractDigest"`
	ControllerID                  string     `json:"controllerId"`
	BindingRef                    string     `json:"bindingRef"`
	NodeListenAddress             string     `json:"nodeListenAddress"`
	CollectorEndpoint             string     `json:"collectorEndpoint"`
	NodePublicKeyFingerprint      string     `json:"nodePublicKeyFingerprint"`
	CollectorPublicKeyFingerprint string     `json:"collectorPublicKeyFingerprint"`
}

func (CompleteNodeEnrollmentRequest) String() string {
	return "node enrollment completion request <redacted>"
}

func (CompleteNodeEnrollmentRequest) GoString() string {
	return "node enrollment completion request <redacted>"
}

type CompleteNodeEnrollmentResponse struct {
	Enrollment      NodeEnrollment  `json:"enrollment"`
	ExecutionTarget ExecutionTarget `json:"executionTarget"`
	Operation       Operation       `json:"operation"`
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

// ExecutionTargetList is the bounded installation-scoped platform inventory.
// Its items are normalized target documents; connection bindings and provider
// credentials never enter this contract.
type ExecutionTargetList struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Items      []ExecutionTarget `json:"items"`
}

// RegisterExecutionTargetRequest selects one protected installation binding.
// Endpoints, identity pins, certificates and host paths are never caller input.
type RegisterExecutionTargetRequest struct {
	ID              ResourceID        `json:"id"`
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels,omitempty"`
	ExecutionPoolID ResourceID        `json:"executionPoolId"`
	BindingRef      string            `json:"bindingRef"`
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

// DeploymentList is one bounded tenant-scoped page ordered by stable resource
// identity. When present, NextAfter is exactly the final returned identity;
// callers cannot select a target, binding or host.
type DeploymentList struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Scope      ResourceScope `json:"scope"`
	Items      []Deployment  `json:"items"`
	NextAfter  ResourceID    `json:"nextAfter,omitempty"`
}

const (
	MaximumDeploymentListItems        = 100
	MaximumDeploymentRuntimeInstances = 64
)

// DeploymentRuntimeInstance is deliberately provider neutral. ID is derived
// by the node from the exact tenant, Deployment generation, application
// revision, execution target and provider instance; it is not a Docker ID and
// cannot be used as a provider selector.
type DeploymentRuntimeInstance struct {
	ID            ResourceID               `json:"id"`
	ComponentName string                   `json:"componentName"`
	State         DeploymentInstanceState  `json:"state"`
	Health        DeploymentInstanceHealth `json:"health"`
	ExitCode      *uint32                  `json:"exitCode,omitempty"`
}

// DeploymentRuntimeObservation is one source-timestamped node proof. The
// control plane persists it independently of Operations and never restamps it.
type DeploymentRuntimeObservation struct {
	DeploymentID          ResourceID                  `json:"deploymentId"`
	Generation            uint64                      `json:"generation"`
	ApplicationRevisionID ResourceID                  `json:"applicationRevisionId"`
	ExecutionTargetID     ResourceID                  `json:"executionTargetId"`
	Instances             []DeploymentRuntimeInstance `json:"instances"`
	ObservedAt            time.Time                   `json:"observedAt"`
}

type DeploymentInstanceCPUUsage struct {
	State MeasurementState                 `json:"state"`
	Value *DeploymentInstanceCPUUsageValue `json:"value,omitempty"`
}

type DeploymentInstanceCPUUsageValue struct {
	WindowMillis   int64   `json:"windowMillis"`
	UsedCores      float64 `json:"usedCores"`
	LimitCPUMillis int64   `json:"limitCpuMillis"`
}

type DeploymentInstanceMemoryUsage struct {
	State MeasurementState                    `json:"state"`
	Value *DeploymentInstanceMemoryUsageValue `json:"value,omitempty"`
}

type DeploymentInstanceMemoryUsageValue struct {
	UsedBytes  int64 `json:"usedBytes"`
	LimitBytes int64 `json:"limitBytes"`
}

type DeploymentInstanceNetworkUsage struct {
	State MeasurementState                     `json:"state"`
	Value *DeploymentInstanceNetworkUsageValue `json:"value,omitempty"`
}

type DeploymentInstanceNetworkUsageValue struct {
	ReceivedBytes    int64 `json:"receivedBytes"`
	TransmittedBytes int64 `json:"transmittedBytes"`
	ReceiveErrors    int64 `json:"receiveErrors"`
	TransmitErrors   int64 `json:"transmitErrors"`
	ReceiveDrops     int64 `json:"receiveDrops"`
	TransmitDrops    int64 `json:"transmitDrops"`
}

type DeploymentInstanceBlockIOUsage struct {
	State MeasurementState                     `json:"state"`
	Value *DeploymentInstanceBlockIOUsageValue `json:"value,omitempty"`
}

type DeploymentInstanceBlockIOUsageValue struct {
	ReadBytes       int64 `json:"readBytes"`
	WriteBytes      int64 `json:"writeBytes"`
	ReadOperations  int64 `json:"readOperations"`
	WriteOperations int64 `json:"writeOperations"`
}

type DeploymentInstanceVolumeUsage struct {
	Count       uint32 `json:"count"`
	Bytes       int64  `json:"bytes"`
	SharedCount uint32 `json:"sharedCount"`
	SharedBytes int64  `json:"sharedBytes"`
}

type DeploymentInstanceStorageUsage struct {
	State MeasurementState                     `json:"state"`
	Value *DeploymentInstanceStorageUsageValue `json:"value,omitempty"`
}

type DeploymentInstanceStorageUsageValue struct {
	ObservedAt         time.Time                      `json:"observedAt"`
	ValidUntil         time.Time                      `json:"validUntil"`
	WritableLayerBytes int64                          `json:"writableLayerBytes"`
	ImageTotalBytes    int64                          `json:"imageTotalBytes"`
	ImageSharedBytes   int64                          `json:"imageSharedBytes"`
	ImageUniqueBytes   int64                          `json:"imageUniqueBytes"`
	VolumesState       MeasurementState               `json:"volumesState"`
	Volumes            *DeploymentInstanceVolumeUsage `json:"volumes,omitempty"`
}

// DeploymentResourceInstance uses the same opaque identity as the lifecycle
// observation. Provider identifiers and storage names never enter this model.
type DeploymentResourceInstance struct {
	ID      ResourceID                     `json:"id"`
	CPU     DeploymentInstanceCPUUsage     `json:"cpu"`
	Memory  DeploymentInstanceMemoryUsage  `json:"memory"`
	Network DeploymentInstanceNetworkUsage `json:"network"`
	BlockIO DeploymentInstanceBlockIOUsage `json:"blockIo"`
	Storage DeploymentInstanceStorageUsage `json:"storage"`
}

// DeploymentResourceObservation is persisted separately from the immutable
// lifecycle observation so each proof can retain its own validity and rollback
// boundary.
type DeploymentResourceObservation struct {
	DeploymentID          ResourceID                   `json:"deploymentId"`
	Generation            uint64                       `json:"generation"`
	ApplicationRevisionID ResourceID                   `json:"applicationRevisionId"`
	ExecutionTargetID     ResourceID                   `json:"executionTargetId"`
	Instances             []DeploymentResourceInstance `json:"instances"`
	ObservedAt            time.Time                    `json:"observedAt"`
}

type DeploymentResourceValue struct {
	Observation DeploymentResourceObservation `json:"observation"`
	ValidUntil  time.Time                     `json:"validUntil"`
}

// DeploymentResourceSnapshot is joined by the control plane after loading the
// lifecycle snapshot. UNAVAILABLE contains no fabricated zero values.
type DeploymentResourceSnapshot struct {
	State MeasurementState         `json:"state"`
	Value *DeploymentResourceValue `json:"value,omitempty"`
}

func (snapshot DeploymentResourceSnapshot) Snapshot(now time.Time) DeploymentResourceSnapshot {
	if snapshot.Value == nil {
		return snapshot
	}
	value := *snapshot.Value
	value.Observation.Instances = slices.Clone(value.Observation.Instances)
	for index := range value.Observation.Instances {
		instance := &value.Observation.Instances[index]
		if instance.CPU.Value != nil {
			copy := *instance.CPU.Value
			instance.CPU.Value = &copy
		}
		if instance.Memory.Value != nil {
			copy := *instance.Memory.Value
			instance.Memory.Value = &copy
		}
		if instance.Network.Value != nil {
			copy := *instance.Network.Value
			instance.Network.Value = &copy
		}
		if instance.BlockIO.Value != nil {
			copy := *instance.BlockIO.Value
			instance.BlockIO.Value = &copy
		}
		if instance.Storage.Value != nil {
			copy := *instance.Storage.Value
			if copy.Volumes != nil {
				volumes := *copy.Volumes
				copy.Volumes = &volumes
			}
			if now.Before(copy.ObservedAt) || !now.Before(copy.ValidUntil) {
				instance.Storage.State = MeasurementStale
			}
			instance.Storage.Value = &copy
		}
	}
	snapshot.Value = &value
	if snapshot.State == MeasurementAvailable &&
		(now.Before(value.Observation.ObservedAt) || !now.Before(value.ValidUntil)) {
		snapshot.State = MeasurementStale
	}
	return snapshot
}

// DeploymentRuntimeValue adds the control-plane freshness boundary to the
// immutable node observation.
type DeploymentRuntimeValue struct {
	Observation DeploymentRuntimeObservation `json:"observation"`
	ValidUntil  time.Time                    `json:"validUntil"`
}

// DeploymentRuntimeSnapshot is the tenant read model. AVAILABLE and STALE
// retain the exact source value; UNAVAILABLE has no value.
type DeploymentRuntimeSnapshot struct {
	APIVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Scope      ResourceScope              `json:"scope"`
	State      MeasurementState           `json:"state"`
	Value      *DeploymentRuntimeValue    `json:"value,omitempty"`
	Resources  DeploymentResourceSnapshot `json:"resources"`
}

// Snapshot returns an independent value and projects expiry to STALE without
// changing source timestamps.
func (snapshot DeploymentRuntimeSnapshot) Snapshot(now time.Time) DeploymentRuntimeSnapshot {
	if snapshot.Value == nil {
		return snapshot
	}
	value := *snapshot.Value
	value.Observation.Instances = slices.Clone(value.Observation.Instances)
	snapshot.Value = &value
	if snapshot.State == MeasurementAvailable &&
		(now.Before(value.Observation.ObservedAt) || !now.Before(value.ValidUntil)) {
		snapshot.State = MeasurementStale
	}
	snapshot.Resources = snapshot.Resources.Snapshot(now)
	return snapshot
}

const (
	MinimumTerminalColumns         = 2
	MaximumTerminalColumns         = 512
	MinimumTerminalRows            = 2
	MaximumTerminalRows            = 256
	MaximumTerminalFrameBytes      = 64 * 1024
	TerminalSessionConnectTimeout  = 30 * time.Second
	TerminalSessionIdleTimeout     = 2 * time.Minute
	MaximumTerminalSessionDuration = 15 * time.Minute
)

type TerminalSize struct {
	Columns uint16 `json:"columns"`
	Rows    uint16 `json:"rows"`
}

// CreateTerminalSessionRequest contains no provider selector, command, user,
// environment or host identity. InstanceID is the opaque node-derived value
// from the current Deployment runtime snapshot.
type CreateTerminalSessionRequest struct {
	InstanceID ResourceID   `json:"instanceId"`
	Size       TerminalSize `json:"size"`
}

// TerminalSession is a sanitized, tenant-scoped lifecycle resource. The
// one-time connection ticket is delivered only by an HttpOnly cookie and is
// never part of this document.
type TerminalSession struct {
	APIVersion            string                 `json:"apiVersion"`
	Kind                  string                 `json:"kind"`
	ID                    ResourceID             `json:"id"`
	Scope                 ResourceScope          `json:"scope"`
	DeploymentID          ResourceID             `json:"deploymentId"`
	Generation            uint64                 `json:"generation"`
	ApplicationRevisionID ResourceID             `json:"applicationRevisionId"`
	InstanceID            ResourceID             `json:"instanceId"`
	Size                  TerminalSize           `json:"size"`
	State                 TerminalSessionState   `json:"state"`
	Outcome               TerminalSessionOutcome `json:"outcome,omitempty"`
	CreatedAt             time.Time              `json:"createdAt"`
	ConnectBefore         time.Time              `json:"connectBefore"`
	ExpiresAt             time.Time              `json:"expiresAt"`
	ConnectedAt           *time.Time             `json:"connectedAt,omitempty"`
	EndedAt               *time.Time             `json:"endedAt,omitempty"`
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
	InstallationID         string          `json:"installationId,omitempty"`
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

// ObserveDeploymentRuntimeRequest is a read-only, Operation-independent node
// request. The worker resolves every identity from persisted placement state;
// callers cannot supply a host or binding selector.
type ObserveDeploymentRuntimeRequest struct {
	RequestID             CommandID     `json:"requestId"`
	Scope                 ResourceScope `json:"scope"`
	DeploymentID          ResourceID    `json:"deploymentId"`
	Generation            uint64        `json:"generation"`
	ApplicationRevisionID ResourceID    `json:"applicationRevisionId"`
	ExecutionTargetID     ResourceID    `json:"executionTargetId"`
	ExpectedContentDigest string        `json:"expectedContentDigest"`
	Deadline              time.Time     `json:"deadline"`
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
