package managedservicev1

import (
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

type QuotaShape struct {
	ID            string `json:"id"`
	DisplayName   string `json:"displayName"`
	CPUMillicores uint32 `json:"cpuMillicores"`
	MemoryMiB     uint32 `json:"memoryMiB"`
	StorageGiB    uint32 `json:"storageGiB"`
}

type ServiceOffering struct {
	ID            string        `json:"id"`
	Kind          OfferingKind  `json:"kind"`
	DisplayName   string        `json:"displayName"`
	Description   string        `json:"description"`
	EngineFamily  string        `json:"engineFamily"`
	EngineVersion string        `json:"engineVersion"`
	State         OfferingState `json:"state"`
	QuotaShapes   []QuotaShape  `json:"quotaShapes"`
}

type ServiceOfferingList struct {
	Kind  string            `json:"kind"`
	Items []ServiceOffering `json:"items"`
}

type RegionCapacity struct {
	CPUMillicores uint32 `json:"cpuMillicores"`
	MemoryMiB     uint32 `json:"memoryMiB"`
	StorageGiB    uint32 `json:"storageGiB"`
}

type Region struct {
	ID          string         `json:"id"`
	DisplayName string         `json:"displayName"`
	Profile     RegionProfile  `json:"profile"`
	State       RegionState    `json:"state"`
	InspectedAt *time.Time     `json:"inspectedAt"`
	Capacity    RegionCapacity `json:"capacity"`
}

type RegionList struct {
	Kind  string   `json:"kind"`
	Items []Region `json:"items"`
}

type QuotaEntitlement struct {
	ID              string    `json:"id"`
	OfferingID      string    `json:"offeringId"`
	QuotaShapeID    string    `json:"quotaShapeId"`
	PurchasedCount  uint32    `json:"purchasedCount"`
	ReservedCount   uint32    `json:"reservedCount"`
	ConsumedCount   uint32    `json:"consumedCount"`
	ResourceVersion uint64    `json:"resourceVersion"`
	ActivatedAt     time.Time `json:"activatedAt"`
}

type QuotaEntitlementList struct {
	Kind  string             `json:"kind"`
	Items []QuotaEntitlement `json:"items"`
}

type InstallationOperation struct {
	ID              string            `json:"id"`
	Phase           InstallationPhase `json:"phase"`
	SafeFailureCode *string           `json:"safeFailureCode"`
	ObservedAt      time.Time         `json:"observedAt"`
}

type ServiceInstallation struct {
	ID                  string                `json:"id"`
	Name                string                `json:"name"`
	OfferingID          string                `json:"offeringId"`
	EngineVersion       string                `json:"engineVersion"`
	QuotaEntitlementID  string                `json:"quotaEntitlementId"`
	RegionID            string                `json:"regionId"`
	Phase               InstallationPhase     `json:"phase"`
	Endpoint            *string               `json:"endpoint"`
	CredentialReference *string               `json:"credentialReference"`
	Operation           InstallationOperation `json:"operation"`
	CreatedAt           time.Time             `json:"createdAt"`
}

type ServiceInstallationList struct {
	Kind  string                `json:"kind"`
	Items []ServiceInstallation `json:"items"`
}

type ActivateQuotaRequest struct {
	OfferingID    string `json:"offeringId"`
	QuotaShapeID  string `json:"quotaShapeId"`
	InstanceCount uint32 `json:"instanceCount"`
}

type CreateInstallationRequest struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	OfferingID         string `json:"offeringId"`
	QuotaEntitlementID string `json:"quotaEntitlementId"`
	RegionID           string `json:"regionId"`
}

// BindServiceRoleRequest selects one exact release-owned template. The
// installation, Account, Role, service principal and purpose are derived by
// the product and IAM authorities rather than accepted as caller selectors.
type BindServiceRoleRequest struct {
	Template iamv1.ServiceRoleTemplateReference `json:"template"`
}

// UnbindServiceRoleRequest protects the single terminal transition. The
// installation and binding identities are path resources; all remaining IAM
// authority is recovered from the existing binding rather than caller input.
type UnbindServiceRoleRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
}

// ServiceRoleBindingReceipt is the non-secret product result for one exact
// ServiceInstallation. IAM remains the authority for the complete Role,
// relation and binding history exposed by its separately authorized directory.
type ServiceRoleBindingReceipt struct {
	Kind                  string                             `json:"kind"`
	ServiceInstallationID string                             `json:"serviceInstallationId"`
	BindingID             iamv1.WorkloadRoleBindingID        `json:"bindingId"`
	RoleID                iamv1.RoleID                       `json:"roleId"`
	Template              iamv1.ServiceRoleTemplateReference `json:"template"`
	Status                iamv1.WorkloadRoleBindingStatus    `json:"status"`
	ResourceVersion       uint64                             `json:"resourceVersion"`
	CreatedAt             time.Time                          `json:"createdAt"`
}

// ServiceRoleUnbindingReceipt is the non-secret terminal projection returned
// by the product API. IAM retains the full relation, decisions and audit
// history; this receipt cannot be used as an authorization permit.
type ServiceRoleUnbindingReceipt struct {
	Kind                  string                             `json:"kind"`
	ServiceInstallationID string                             `json:"serviceInstallationId"`
	BindingID             iamv1.WorkloadRoleBindingID        `json:"bindingId"`
	RoleID                iamv1.RoleID                       `json:"roleId"`
	Template              iamv1.ServiceRoleTemplateReference `json:"template"`
	Status                iamv1.WorkloadRoleBindingStatus    `json:"status"`
	ResourceVersion       uint64                             `json:"resourceVersion"`
	CreatedAt             time.Time                          `json:"createdAt"`
	RevokedAt             time.Time                          `json:"revokedAt"`
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
	TraceID    string           `json:"traceId"`
	Retryable  bool             `json:"retryable"`
	Violations []FieldViolation `json:"violations,omitempty"`
}
