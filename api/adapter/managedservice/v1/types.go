package managedserviceadapterv1

import managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"

type ProvisionRequest struct {
	TenantID       string
	InstallationID string
	OperationID    string
	OfferingID     string
	EngineVersion  string
	RegionID       string
	QuotaShape     managedservicev1.QuotaShape
}

type ProvisionResult struct {
	Endpoint            string
	CredentialReference string
}
