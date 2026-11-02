package authority

import (
	"reflect"
	"slices"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestServiceRoleTemplateCatalogBindsAnExactLeastPrivilegePolicyVersion(t *testing.T) {
	templates, err := BuiltInServiceRoleTemplates()
	if err != nil || len(templates) != 1 {
		t.Fatal("release-owned service role template catalog is invalid", err)
	}
	template := templates[0]
	ceiling, err := SystemPolicyVersion(iamv1.SystemPolicyManagedServiceInstallationReader)
	if err != nil || iamv1.CheckServiceRoleTemplate(template, iamv1.AllAuthorizationProfiles()) != nil || template.Status != iamv1.ServiceRoleTemplateActive ||
		template.Version != 3 ||
		template.Spec.Product != iamv1.ProductManagedService || template.Spec.ServicePurpose != iamv1.ServicePaaS ||
		template.Spec.RoleName != "ManagedServiceInstallationReader" || template.Spec.RoleDescription == "" ||
		template.Spec.PolicyVersion != (iamv1.PolicyVersionReference{PolicyID: ceiling.PolicyID, VersionID: ceiling.ID, ContentDigest: ceiling.ContentDigest}) ||
		!slices.Equal(template.Spec.Workloads, []iamv1.ServiceRoleWorkloadSpec{{
			ResourceKind: iamv1.ResourceServiceInstallation,
			BindAction:   iamv1.ActionManagedServiceInstallationRoleBind,
			UnbindAction: iamv1.ActionManagedServiceInstallationRoleUnbind,
		}}) ||
		template.Spec.MaxSessionDurationSeconds != 15*60 {
		t.Fatal("template lost its exact product, service, policy, workload or session ceiling")
	}
	if len(ceiling.Document.Statements) != 1 ||
		!slices.Equal(ceiling.Document.Statements[0].Actions, []iamv1.Action{iamv1.ActionManagedServiceInstallationRead}) ||
		!slices.Equal(ceiling.Document.Statements[0].Resources, []iamv1.PolicyResourceSelector{{
			Kind: iamv1.ResourceServiceInstallation, Match: iamv1.PolicyResourceAnyInAuthority,
		}}) {
		t.Fatal("service role policy ceiling includes authority outside installation read")
	}
}

func TestServiceRoleTemplateArchivePreservesPublishedConsentWithoutPublishingItAsCurrent(t *testing.T) {
	directory, err := BuiltInServiceRoleTemplates()
	archive, archiveErr := BuiltInServiceRoleTemplateArchive()
	policies, profiles, policyErr := builtInServiceRolePolicyVersions()
	if err != nil || archiveErr != nil || policyErr != nil || len(directory) != 1 || len(archive) != 3 || len(policies) != 3 {
		t.Fatal("service role template archive is unavailable", err, archiveErr, policyErr)
	}
	if !reflect.DeepEqual(archive[2], directory[0]) {
		t.Fatal("directory did not select the current immutable template")
	}
	for index, template := range archive {
		policy := policies[index]
		if template.ID != directory[0].ID || template.Version != uint64(index+1) ||
			template.Status != iamv1.ServiceRoleTemplateActive ||
			template.Spec.PolicyVersion != (iamv1.PolicyVersionReference{PolicyID: policy.PolicyID,
				VersionID: policy.ID, ContentDigest: policy.ContentDigest}) ||
			policy.Compilation == nil || len(policy.Compilation.Profiles) != 1 ||
			policy.Compilation.Profiles[0].Product != iamv1.ProductManagedService ||
			policy.Compilation.Profiles[0].Revision != profiles[index].Revision {
			t.Fatal("service role version lost its exact policy/profile lineage")
		}
	}
	// Version 2 is retained by the fixed IAM86 predecessor and real consent.
	// Adding the USER-only dependency Use action must not rewrite this ceiling.
	if profiles[0].Revision != 4 || profiles[1].Revision != 7 || profiles[2].Revision <= 7 ||
		archive[1].ContentDigest != "sha256:88631b8f2a7de9df63ec417ad7453454aa88eaa6a2ee9b86297558e2bc372e0f" ||
		archive[2].ContentDigest == archive[1].ContentDigest {
		t.Fatal("published service role consent changed when the Profile advanced")
	}
}

func TestServiceRoleTemplateCatalogReturnsIsolatedCopies(t *testing.T) {
	first, err := BuiltInServiceRoleTemplates()
	if err != nil {
		t.Fatal(err)
	}
	first[0].Spec.Workloads[0].ResourceKind = iamv1.ResourceApplication
	second, err := BuiltInServiceRoleTemplates()
	if err != nil || second[0].Spec.Workloads[0].ResourceKind != iamv1.ResourceServiceInstallation {
		t.Fatal("caller mutation changed the release-owned service role template")
	}
}
