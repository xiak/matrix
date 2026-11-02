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
		managedservicev1.ValidateID("offeringId", value.OfferingID),
		managedservicev1.ValidateID("engineVersion", value.EngineVersion),
		managedservicev1.ValidateID("regionId", value.RegionID),
		managedservicev1.ValidateQuotaShape(value.QuotaShape),
		validateElasticsearchDependency(value.OfferingID, value.InstallationID, value.EngineVersion, value.RegionID, value.Elasticsearch),
	)
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

func ValidateDeprovisionRequest(value DeprovisionRequest) error {
	return errors.Join(
		managedservicev1.ValidateID("tenantId", value.TenantID),
		managedservicev1.ValidateInstallationID(value.InstallationID),
		managedservicev1.ValidateID("operationId", value.OperationID),
		managedservicev1.ValidateID("offeringId", value.OfferingID),
		managedservicev1.ValidateID("engineVersion", value.EngineVersion),
		managedservicev1.ValidateID("regionId", value.RegionID),
		validateElasticsearchDependency(value.OfferingID, value.InstallationID, value.EngineVersion, value.RegionID, value.Elasticsearch),
	)
}

func validateElasticsearchDependency(offering, installation, version, region string, dependency *ElasticsearchDependency) error {
	if offering != managedservicev1.KibanaOfferingID {
		if dependency != nil {
			return errors.New("this product does not admit an Elasticsearch dependency")
		}
		return nil
	}
	if dependency == nil || managedservicev1.ValidateInstallationID(dependency.InstallationID) != nil ||
		dependency.InstallationID == installation || dependency.ResourceVersion == 0 || dependency.ResourceVersion > 9007199254740991 ||
		dependency.EngineVersion != version || dependency.RegionID != region {
		return errors.New("managed-service Elasticsearch dependency is invalid")
	}
	return nil
}
