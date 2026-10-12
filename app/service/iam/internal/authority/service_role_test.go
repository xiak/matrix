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
		template.Version != 2 ||
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

func TestServiceRoleTemplateArchivePreservesTheExactPredecessorWithoutPublishingItAsCurrent(t *testing.T) {
	directory, err := BuiltInServiceRoleTemplates()
	archive, archiveErr := BuiltInServiceRoleTemplateArchive()
	policies, _, policyErr := builtInServiceRolePolicyVersions()
	if err != nil || archiveErr != nil || policyErr != nil || len(directory) != 1 || len(archive) != 2 || len(policies) != 2 {
		t.Fatal("service role template archive is unavailable", err, archiveErr, policyErr)
	}
	if archive[0].ID != directory[0].ID || archive[1].ID != directory[0].ID ||
		archive[0].Version != 1 || archive[1].Version != 2 || !reflect.DeepEqual(archive[1], directory[0]) ||
		archive[0].Status != iamv1.ServiceRoleTemplateActive || archive[1].Status != iamv1.ServiceRoleTemplateActive ||
		archive[0].ContentDigest == archive[1].ContentDigest ||
		archive[0].Spec.PolicyVersion != (iamv1.PolicyVersionReference{PolicyID: policies[0].PolicyID,
			VersionID: policies[0].ID, ContentDigest: policies[0].ContentDigest}) ||
		archive[1].Spec.PolicyVersion != (iamv1.PolicyVersionReference{PolicyID: policies[1].PolicyID,
			VersionID: policies[1].ID, ContentDigest: policies[1].ContentDigest}) ||
		policies[0].Compilation == nil || policies[1].Compilation == nil ||
		len(policies[0].Compilation.Profiles) != 1 || len(policies[1].Compilation.Profiles) != 1 ||
		policies[0].Compilation.Profiles[0].Product != iamv1.ProductManagedService ||
		policies[1].Compilation.Profiles[0].Revision <= policies[0].Compilation.Profiles[0].Revision ||
		policies[0].Compilation.Profiles[0].Revision != managedServiceInstallationReaderHistoricalProfileRevision {
		t.Fatal("current and retained service role versions lost their exact policy/profile lineage")
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
