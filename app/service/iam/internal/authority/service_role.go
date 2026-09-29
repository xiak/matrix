package authority

import (
	"slices"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const managedServiceInstallationReaderTemplateID iamv1.ServiceRoleTemplateID = "managedservice.installation-reader"

// ServiceRoleTemplates returns the release-owned current template catalog.
// A template references an immutable policy version; it never grants a
// service identity access without a later account consent and workload bind.
func ServiceRoleTemplates() ([]iamv1.ServiceRoleTemplate, error) {
	ceiling, err := SystemPolicyVersion(iamv1.SystemPolicyManagedServiceInstallationReader)
	if err != nil {
		return nil, ErrInvalidPolicyState
	}
	spec := iamv1.ServiceRoleTemplateSpec{
		Product:        iamv1.ProductManagedService,
		ServicePurpose: iamv1.ServicePaaS,
		PolicyVersion: iamv1.PolicyVersionReference{
			PolicyID: ceiling.PolicyID, VersionID: ceiling.ID, ContentDigest: ceiling.ContentDigest,
		},
		WorkloadResourceKinds:     []iamv1.ResourceKind{iamv1.ResourceServiceInstallation},
		MaxSessionDurationSeconds: 15 * 60,
	}
	_, digest, err := iamv1.CanonicalizeServiceRoleTemplateSpec(spec)
	if err != nil {
		return nil, ErrInvalidPolicyState
	}
	result := []iamv1.ServiceRoleTemplate{{
		APIVersion: iamv1.APIVersion, Kind: "ServiceRoleTemplate", ID: managedServiceInstallationReaderTemplateID,
		Version: 1, Spec: spec, ContentDigest: digest, Status: iamv1.ServiceRoleTemplateActive,
	}}
	if iamv1.ValidateServiceRoleTemplateList(iamv1.ServiceRoleTemplateList{
		APIVersion: iamv1.APIVersion, Kind: "ServiceRoleTemplateList", Items: result,
	}) != nil {
		return nil, ErrInvalidPolicyState
	}
	return cloneServiceRoleTemplates(result), nil
}

// LookupServiceRoleTemplate resolves an exact immutable reference. Selecting
// only an ID or a current head is deliberately not an account-consent input.
func LookupServiceRoleTemplate(reference iamv1.ServiceRoleTemplateReference) (iamv1.ServiceRoleTemplate, bool, error) {
	if iamv1.ValidateServiceRoleTemplateReference(reference) != nil {
		return iamv1.ServiceRoleTemplate{}, false, ErrInvalidPolicyState
	}
	templates, err := ServiceRoleTemplates()
	if err != nil {
		return iamv1.ServiceRoleTemplate{}, false, err
	}
	for _, template := range templates {
		if template.Reference() == reference {
			return template, true, nil
		}
	}
	return iamv1.ServiceRoleTemplate{}, false, nil
}

func cloneServiceRoleTemplates(values []iamv1.ServiceRoleTemplate) []iamv1.ServiceRoleTemplate {
	result := slices.Clone(values)
	for index := range result {
		result[index].Spec.WorkloadResourceKinds = slices.Clone(result[index].Spec.WorkloadResourceKinds)
	}
	return result
}
