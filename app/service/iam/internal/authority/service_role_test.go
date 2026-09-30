package authority

import (
	"errors"
	"slices"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestServiceRoleTemplateCatalogBindsAnExactLeastPrivilegePolicyVersion(t *testing.T) {
	templates, err := ServiceRoleTemplates()
	if err != nil || len(templates) != 1 {
		t.Fatal("release-owned service role template catalog is invalid", err)
	}
	template := templates[0]
	ceiling, err := SystemPolicyVersion(iamv1.SystemPolicyManagedServiceInstallationReader)
	if err != nil || iamv1.ValidateServiceRoleTemplate(template) != nil || template.Status != iamv1.ServiceRoleTemplateActive ||
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

	resolved, found, err := LookupServiceRoleTemplate(template.Reference())
	if err != nil || !found || resolved.ContentDigest != template.ContentDigest {
		t.Fatal("exact service role template reference did not resolve", err)
	}
	other := template.Reference()
	other.ContentDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, found, err = LookupServiceRoleTemplate(other); err != nil || found {
		t.Fatal("changed template reference resolved")
	}
	if _, _, err = LookupServiceRoleTemplate(iamv1.ServiceRoleTemplateReference{}); !errors.Is(err, ErrInvalidPolicyState) {
		t.Fatal("invalid template reference was treated as registered")
	}
}

func TestServiceRoleTemplateCatalogReturnsIsolatedCopies(t *testing.T) {
	first, err := ServiceRoleTemplates()
	if err != nil {
		t.Fatal(err)
	}
	first[0].Spec.Workloads[0].ResourceKind = iamv1.ResourceApplication
	second, err := ServiceRoleTemplates()
	if err != nil || second[0].Spec.Workloads[0].ResourceKind != iamv1.ResourceServiceInstallation {
		t.Fatal("caller mutation changed the release-owned service role template")
	}
}
