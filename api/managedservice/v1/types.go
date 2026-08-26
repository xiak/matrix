package managedservicev1

import "time"

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
