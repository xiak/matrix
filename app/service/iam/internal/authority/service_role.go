package authority

import (
	"slices"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const managedServiceInstallationReaderTemplateID iamv1.ServiceRoleTemplateID = "managedservice.installation-reader"

// BuiltInServiceRoleTemplates returns only templates owned by this executable.
// Additional signed product templates are migration data and must be resolved
// from IAM storage rather than from product-name branches in this package.
func BuiltInServiceRoleTemplates() ([]iamv1.ServiceRoleTemplate, error) {
	ceiling, err := SystemPolicyVersion(iamv1.SystemPolicyManagedServiceInstallationReader)
	if err != nil {
		return nil, ErrInvalidPolicyState
	}
	spec := iamv1.ServiceRoleTemplateSpec{
		Product:         iamv1.ProductManagedService,
		ServicePurpose:  iamv1.ServicePaaS,
		RoleName:        "ManagedServiceInstallationReader",
		RoleDescription: "Allows the managed service controller to read one explicitly bound service installation.",
		PolicyVersion: iamv1.PolicyVersionReference{
			PolicyID: ceiling.PolicyID, VersionID: ceiling.ID, ContentDigest: ceiling.ContentDigest,
		},
		Workloads: []iamv1.ServiceRoleWorkloadSpec{{
			ResourceKind: iamv1.ResourceServiceInstallation,
			BindAction:   iamv1.ActionManagedServiceInstallationRoleBind,
			UnbindAction: iamv1.ActionManagedServiceInstallationRoleUnbind,
		}},
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
	if iamv1.CheckServiceRoleTemplate(result[0], iamv1.AllAuthorizationProfiles()) != nil ||
		iamv1.ValidateServiceRoleTemplateList(iamv1.ServiceRoleTemplateList{
			APIVersion: iamv1.APIVersion, Kind: "ServiceRoleTemplateList", Items: result,
		}) != nil {
		return nil, ErrInvalidPolicyState
	}
	return cloneServiceRoleTemplates(result), nil
}

func cloneServiceRoleTemplates(values []iamv1.ServiceRoleTemplate) []iamv1.ServiceRoleTemplate {
	result := slices.Clone(values)
	for index := range result {
		result[index].Spec.Workloads = slices.Clone(result[index].Spec.Workloads)
	}
	return result
}
