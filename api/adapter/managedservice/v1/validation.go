package managedserviceadapterv1

import (
	"errors"
	"strings"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
)

func ValidateProvisionRequest(value ProvisionRequest) error {
	var problems []error
	problems = append(problems,
		managedservicev1.ValidateID("tenantId", value.TenantID),
		managedservicev1.ValidateInstallationID(value.InstallationID),
		managedservicev1.ValidateID("operationId", value.OperationID),
		managedservicev1.ValidateQuotaShape(value.QuotaShape),
	)
	if value.OfferingID != managedservicev1.PostgreSQLOfferingID ||
		value.EngineVersion != "18" || value.RegionID != "local-primary" {
		problems = append(problems, errors.New("managed-service installation profile is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateProvisionResult(value ProvisionResult) error {
	if len(value.Endpoint) == 0 || len(value.Endpoint) > 256 ||
		strings.TrimSpace(value.Endpoint) != value.Endpoint ||
		strings.ContainsAny(value.Endpoint, "\x00\r\n") {
		return errors.New("managed-service endpoint is invalid")
	}
	return managedservicev1.ValidateID("credentialReference", value.CredentialReference)
}
