package auditv1

import "time"

type EventID string
type TenantID string
type ActorID string
type DecisionID string
type OperationID string
type Cursor string

type ActorReference struct {
	Type ActorType `json:"type"`
	ID   ActorID   `json:"id"`
}

type TargetReference struct {
	Kind TargetKind `json:"kind"`
	ID   string     `json:"id"`
	// Only primary recovery needs this resource namespace; it is not chain authority.
	TenantID TenantID `json:"tenantId,omitempty"`
}

// Event contains one sanitized fact. Source is deliberately absent: the
// ingestion boundary derives it exclusively from the service credential.
type Event struct {
	APIVersion     string          `json:"apiVersion"`
	Kind           string          `json:"kind"`
	EventID        EventID         `json:"eventId"`
	TenantID       TenantID        `json:"tenantId,omitempty"`
	InstallationID string          `json:"installationId,omitempty"`
	Actor          ActorReference  `json:"actor"`
	IAMDecisionID  DecisionID      `json:"iamDecisionId,omitempty"`
	Action         Action          `json:"action"`
	Target         TargetReference `json:"target"`
	Result         Result          `json:"result"`
	RequestDigest  string          `json:"requestDigest"`
	RequestID      string          `json:"requestId"`
	CorrelationID  string          `json:"correlationId"`
	OperationID    OperationID     `json:"operationId,omitempty"`
	TraceParent    string          `json:"traceparent,omitempty"`
	OccurredAt     time.Time       `json:"occurredAt"`
}

type AuditRecord struct {
	APIVersion    string          `json:"apiVersion"`
	Kind          string          `json:"kind"`
	Source        Source          `json:"source"`
	Sequence      uint64          `json:"sequence"`
	Event         Event           `json:"event"`
	ContentDigest string          `json:"contentDigest"`
	PreviousHash  string          `json:"previousHash"`
	RecordHash    string          `json:"recordHash"`
	IngestedAt    time.Time       `json:"ingestedAt"`
	Retention     RetentionPolicy `json:"retention"`
}

type IngestionResult struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Outcome    IngestionOutcome `json:"outcome"`
	Record     AuditRecord      `json:"record"`
}

type QueryRecordsRequest struct {
	PageSize int             `json:"pageSize"`
	Cursor   Cursor          `json:"cursor,omitempty"`
	From     *time.Time      `json:"from,omitempty"`
	To       *time.Time      `json:"to,omitempty"`
	Action   Action          `json:"action,omitempty"`
	Actor    *ActorReference `json:"actor,omitempty"`
}

type RecordPage struct {
	APIVersion     string        `json:"apiVersion"`
	Kind           string        `json:"kind"`
	TenantID       TenantID      `json:"tenantId,omitempty"`
	InstallationID string        `json:"installationId,omitempty"`
	Records        []AuditRecord `json:"records"`
	NextCursor     Cursor        `json:"nextCursor,omitempty"`
}

type VerifyChainRequest struct {
	FromSequence   uint64 `json:"fromSequence"`
	MaximumRecords int    `json:"maximumRecords"`
}

type ChainVerification struct {
	APIVersion        string            `json:"apiVersion"`
	Kind              string            `json:"kind"`
	TenantID          TenantID          `json:"tenantId,omitempty"`
	InstallationID    string            `json:"installationId,omitempty"`
	State             VerificationState `json:"state"`
	FromSequence      uint64            `json:"fromSequence"`
	ToSequence        uint64            `json:"toSequence"`
	RecordCount       int               `json:"recordCount"`
	FirstPreviousHash string            `json:"firstPreviousHash"`
	LastRecordHash    string            `json:"lastRecordHash"`
	Complete          bool              `json:"complete"`
	NextSequence      *uint64           `json:"nextSequence,omitempty"`
	VerifiedAt        time.Time         `json:"verifiedAt"`
}

// VerifyInstallationRequest identifies one exact PaaS Deployment acceptance
// fact. Tenant and verifier actor remain IAM authority.
type VerifyInstallationRequest struct {
	InstallationID string      `json:"installationId"`
	OperationID    OperationID `json:"operationId"`
	DeploymentID   string      `json:"deploymentId"`
}

type InstallationVerification struct {
	APIVersion     string                        `json:"apiVersion"`
	Kind           string                        `json:"kind"`
	InstallationID string                        `json:"installationId"`
	OperationID    OperationID                   `json:"operationId"`
	DeploymentID   string                        `json:"deploymentId"`
	State          InstallationVerificationState `json:"state"`
	EventID        EventID                       `json:"eventId,omitempty"`
	IAMDecisionID  DecisionID                    `json:"iamDecisionId,omitempty"`
	RecordSequence uint64                        `json:"recordSequence,omitempty"`
	FromSequence   uint64                        `json:"fromSequence,omitempty"`
	ToSequence     uint64                        `json:"toSequence,omitempty"`
	RecordHash     string                        `json:"recordHash,omitempty"`
	CheckedAt      time.Time                     `json:"checkedAt"`
}

type Readiness struct {
	APIVersion    string         `json:"apiVersion"`
	Kind          string         `json:"kind"`
	State         ReadinessState `json:"state"`
	SchemaVersion uint64         `json:"schemaVersion"`
	CheckedAt     time.Time      `json:"checkedAt"`
}

type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"requestId"`
}
