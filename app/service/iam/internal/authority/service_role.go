package authority

import (
	"slices"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const managedServiceInstallationReaderTemplateID iamv1.ServiceRoleTemplateID = "managedservice.installation-reader"

// Advancing this Profile requires a new immutable template version.
const managedServiceInstallationReaderCurrentProfileRevision uint64 = 8

// Published template versions 1 and 2 bind Profiles 4 and 7 respectively.
// Their bytes remain fixed when the current product Profile advances.
var managedServiceInstallationReaderHistoricalProfileRevisions = []uint64{4, 7}

// BuiltInServiceRoleTemplates returns only templates owned by this executable.
// Additional signed product templates are migration data and must be resolved
// from IAM storage rather than from product-name branches in this package.
func BuiltInServiceRoleTemplates() ([]iamv1.ServiceRoleTemplate, error) {
	archive, err := BuiltInServiceRoleTemplateArchive()
	if err != nil {
		return nil, err
	}
	result := []iamv1.ServiceRoleTemplate{archive[len(archive)-1]}
	if iamv1.ValidateServiceRoleTemplateList(iamv1.ServiceRoleTemplateList{
		APIVersion: iamv1.APIVersion, Kind: "ServiceRoleTemplateList", Items: result,
	}) != nil {
		return nil, ErrInvalidPolicyState
	}
	return cloneServiceRoleTemplates(result), nil
}

// BuiltInServiceRoleTemplateArchive returns every still-supported immutable
// built-in template version. Migration seeds consume the archive; the public
// directory above exposes only its current head so new consent cannot silently
// select a historical permission ceiling.
func BuiltInServiceRoleTemplateArchive() ([]iamv1.ServiceRoleTemplate, error) {
	policies, profiles, err := builtInServiceRolePolicyVersions()
	if err != nil || len(policies) != 3 || len(profiles) != 3 {
		return nil, ErrInvalidPolicyState
	}
	result := make([]iamv1.ServiceRoleTemplate, 0, len(policies))
	for index, ceiling := range policies {
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
		_, digest, canonicalErr := iamv1.CanonicalizeServiceRoleTemplateSpec(spec)
		if canonicalErr != nil {
			return nil, ErrInvalidPolicyState
		}
		template := iamv1.ServiceRoleTemplate{
			APIVersion: iamv1.APIVersion, Kind: "ServiceRoleTemplate", ID: managedServiceInstallationReaderTemplateID,
			Version: uint64(index + 1), Spec: spec, ContentDigest: digest, Status: iamv1.ServiceRoleTemplateActive,
		}
		if iamv1.CheckServiceRoleTemplate(template, []iamv1.AuthorizationProfile{profiles[index]}) != nil {
			return nil, ErrInvalidPolicyState
		}
		result = append(result, template)
	}
	return cloneServiceRoleTemplates(result), nil
}

func builtInServiceRolePolicyVersions() ([]iamv1.PolicyVersion, []iamv1.AuthorizationProfile, error) {
	currentProfile, found := iamv1.LookupAuthorizationProfile(iamv1.ProductManagedService)
	if !found || currentProfile.Revision != managedServiceInstallationReaderCurrentProfileRevision {
		return nil, nil, ErrInvalidPolicyState
	}
	profiles := make([]iamv1.AuthorizationProfile, 0, 3)
	for _, revision := range managedServiceInstallationReaderHistoricalProfileRevisions {
		var historical iamv1.AuthorizationProfile
		for _, candidate := range iamv1.HistoricalAuthorizationProfiles() {
			if candidate.Product == iamv1.ProductManagedService && candidate.Revision == revision {
				historical = candidate
				break
			}
		}
		if historical.Product == "" || historical.Revision >= currentProfile.Revision {
			return nil, nil, ErrInvalidPolicyState
		}
		profiles = append(profiles, historical)
	}
	profiles = append(profiles, currentProfile)
	policies := make([]iamv1.PolicyVersion, 0, len(profiles))
	for _, profile := range profiles {
		version, err := systemPolicyVersion(iamv1.SystemPolicyManagedServiceInstallationReader,
			[]iamv1.AuthorizationProfile{profile})
		if err != nil {
			return nil, nil, err
		}
		policies = append(policies, version)
	}
	return policies, profiles, nil
}

func cloneServiceRoleTemplates(values []iamv1.ServiceRoleTemplate) []iamv1.ServiceRoleTemplate {
	result := slices.Clone(values)
	for index := range result {
		result[index].Spec.Workloads = slices.Clone(result[index].Spec.Workloads)
	}
	return result
}
