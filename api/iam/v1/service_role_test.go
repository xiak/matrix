package iamv1

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func serviceRoleTemplateForTest(t *testing.T) ServiceRoleTemplate {
	t.Helper()
	spec := ServiceRoleTemplateSpec{
		Product:        ProductManagedService,
		ServicePurpose: ServicePaaS,
		PolicyVersion: PolicyVersionReference{
			PolicyID:      "system.managedservice-installation-reader",
			VersionID:     "version-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ContentDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		WorkloadResourceKinds:     []ResourceKind{ResourceServiceInstallation},
		MaxSessionDurationSeconds: 900,
	}
	_, digest, err := CanonicalizeServiceRoleTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ServiceRoleTemplate{APIVersion: APIVersion, Kind: "ServiceRoleTemplate", ID: "managedservice.installation-reader",
		Version: 1, Spec: spec, ContentDigest: digest, Status: ServiceRoleTemplateActive}
}

func serviceLinkedRoleAccessForTest(t *testing.T) ServiceLinkedRoleAccess {
	t.Helper()
	template := serviceRoleTemplateForTest(t)
	createdAt := time.Date(2026, 9, 30, 3, 0, 0, 0, time.UTC)
	relation := ServiceLinkedRole{
		APIVersion: APIVersion,
		Kind:       "ServiceLinkedRole",
		Role: Role{
			APIVersion: APIVersion, Kind: "Role", ID: "role-managedservice-installation-reader", AccountID: "account-a",
			Name: "ManagedServiceInstallationReader", Description: "Managed service installation reader", Tags: []RoleTag{},
			Management: RoleServiceLinked, Status: RoleActive, MaxSessionDurationSeconds: 900,
			ResourceVersion: 1, CurrentTrustVersionID: "trust-version-a", CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Template:          template.Reference(),
		ServicePrincipal:  ServicePrincipalReference{InstallationID: "installation-a", PrincipalID: "service-paas-a", Purpose: ServicePaaS},
		PermissionCeiling: template.Spec.PolicyVersion,
	}
	binding := WorkloadRoleBinding{
		APIVersion: APIVersion, Kind: "WorkloadRoleBinding", ID: "binding-a", AccountID: relation.Role.AccountID,
		RoleID: relation.Role.ID, Template: template.Reference(),
		Workload: ResourceReference{Kind: ResourceServiceInstallation, ID: "service-installation-a"},
		Status:   WorkloadRoleBindingActive, ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	return ServiceLinkedRoleAccess{APIVersion: APIVersion, Kind: "ServiceLinkedRoleAccess", Relation: relation, Bindings: []WorkloadRoleBinding{binding}}
}

func TestServiceRoleTemplateCanonicalizesReleaseOwnedAuthority(t *testing.T) {
	template := serviceRoleTemplateForTest(t)
	if ValidateServiceRoleTemplate(template) != nil || ValidateServiceRoleTemplateReference(template.Reference()) != nil {
		t.Fatal("valid service role template rejected")
	}
	left := template.Spec
	left.WorkloadResourceKinds = []ResourceKind{ResourceRegion, ResourceServiceInstallation}
	right := left
	right.WorkloadResourceKinds = []ResourceKind{ResourceServiceInstallation, ResourceRegion}
	leftDocument, leftDigest, leftErr := CanonicalizeServiceRoleTemplateSpec(left)
	rightDocument, rightDigest, rightErr := CanonicalizeServiceRoleTemplateSpec(right)
	if leftErr != nil || rightErr != nil || leftDocument != rightDocument || leftDigest != rightDigest {
		t.Fatal("template authority depends on caller array order")
	}

	for name, mutate := range map[string]func(*ServiceRoleTemplate){
		"tenant supplied product": func(value *ServiceRoleTemplate) { value.Spec.Product = "managedservice.other" },
		"unknown service":         func(value *ServiceRoleTemplate) { value.Spec.ServicePurpose = "PROBE" },
		"duplicate workload": func(value *ServiceRoleTemplate) {
			value.Spec.WorkloadResourceKinds = []ResourceKind{ResourceServiceInstallation, ResourceServiceInstallation}
		},
		"empty workload":    func(value *ServiceRoleTemplate) { value.Spec.WorkloadResourceKinds = nil },
		"unbounded session": func(value *ServiceRoleTemplate) { value.Spec.MaxSessionDurationSeconds = 0 },
		"changed policy":    func(value *ServiceRoleTemplate) { value.Spec.PolicyVersion.PolicyID = SystemPolicyPaaSViewer },
		"changed digest": func(value *ServiceRoleTemplate) {
			value.ContentDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"unknown lifecycle":   func(value *ServiceRoleTemplate) { value.Status = "DISABLED" },
		"missing template ID": func(value *ServiceRoleTemplate) { value.ID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := template
			changed.Spec.WorkloadResourceKinds = append([]ResourceKind(nil), template.Spec.WorkloadResourceKinds...)
			mutate(&changed)
			if ValidateServiceRoleTemplate(changed) == nil {
				t.Fatal("invalid service role template accepted")
			}
		})
	}
}

func TestServiceRoleTemplateStrictDecodingAndBoundedList(t *testing.T) {
	template := serviceRoleTemplateForTest(t)
	encoded, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ServiceRoleTemplate
	if json.Unmarshal(encoded, &decoded) != nil || ValidateServiceRoleTemplate(decoded) != nil {
		t.Fatal("valid service role template did not round trip")
	}
	attacks := []string{
		string(encoded[:len(encoded)-1]) + `,"accountId":"account-a"}`,
		string(encoded[:len(encoded)-1]) + `,"id":"other"}`,
		`{"apiVersion":"iam.matrix.xiak.com/v1","kind":"ServiceRoleTemplate","id":"x","version":1,"spec":{},"contentDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","status":"ACTIVE"}`,
	}
	for _, attack := range attacks {
		if json.Unmarshal([]byte(attack), &decoded) == nil {
			t.Fatal("strict decoder accepted an authority selector or duplicate identity")
		}
	}
	list := ServiceRoleTemplateList{APIVersion: APIVersion, Kind: "ServiceRoleTemplateList", Items: []ServiceRoleTemplate{template}}
	if ValidateServiceRoleTemplateList(list) != nil {
		t.Fatal("valid template list rejected")
	}
	list.Items = []ServiceRoleTemplate{template, template}
	if ValidateServiceRoleTemplateList(list) == nil {
		t.Fatal("duplicate or unordered template list accepted")
	}
}

func TestServiceLinkedRoleAndBindingPreserveExactConsent(t *testing.T) {
	access := serviceLinkedRoleAccessForTest(t)
	if ValidateServiceLinkedRoleAccess(access) != nil {
		t.Fatal("valid service-linked role access rejected")
	}
	encoded, err := json.Marshal(access)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ServiceLinkedRoleAccess
	if json.Unmarshal(encoded, &decoded) != nil || !reflect.DeepEqual(decoded, access) {
		t.Fatal("valid service-linked role access did not strictly round trip")
	}

	for name, mutate := range map[string]func(*ServiceLinkedRoleAccess){
		"customer role": func(value *ServiceLinkedRoleAccess) { value.Relation.Role.Management = RoleCustomerManaged },
		"wrong account": func(value *ServiceLinkedRoleAccess) { value.Bindings[0].AccountID = "account-b" },
		"wrong role":    func(value *ServiceLinkedRoleAccess) { value.Bindings[0].RoleID = "role-b" },
		"wrong template version": func(value *ServiceLinkedRoleAccess) {
			value.Bindings[0].Template.Version++
		},
		"unknown purpose": func(value *ServiceLinkedRoleAccess) { value.Relation.ServicePrincipal.Purpose = "PROBE" },
		"empty workload":  func(value *ServiceLinkedRoleAccess) { value.Bindings[0].Workload.ID = "" },
		"forged revocation": func(value *ServiceLinkedRoleAccess) {
			value.Bindings[0].Status = WorkloadRoleBindingRevoked
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := access
			changed.Bindings = append([]WorkloadRoleBinding(nil), access.Bindings...)
			mutate(&changed)
			if ValidateServiceLinkedRoleAccess(changed) == nil {
				t.Fatal("invalid service-linked role access accepted")
			}
		})
	}

	attacks := []string{
		string(encoded[:len(encoded)-1]) + `,"accountId":"account-b"}`,
		string(encoded[:len(encoded)-1]) + `,"kind":"Other"}`,
	}
	for _, attack := range attacks {
		if json.Unmarshal([]byte(attack), &decoded) == nil {
			t.Fatal("strict decoder accepted selector or duplicate identity")
		}
	}
}

func TestWorkloadRoleBindingTerminalStateIsExact(t *testing.T) {
	createdAt := time.Date(2026, 9, 30, 3, 0, 0, 0, time.UTC)
	revokedAt := createdAt.Add(time.Minute)
	binding := WorkloadRoleBinding{
		APIVersion: APIVersion, Kind: "WorkloadRoleBinding", ID: "binding-a", AccountID: "account-a", RoleID: "role-a",
		Template: serviceRoleTemplateForTest(t).Reference(), Workload: ResourceReference{Kind: ResourceServiceInstallation, ID: "service-installation-a"},
		Status: WorkloadRoleBindingRevoked, ResourceVersion: 2, CreatedAt: createdAt, UpdatedAt: revokedAt, RevokedAt: &revokedAt,
	}
	if ValidateWorkloadRoleBinding(binding) != nil {
		t.Fatal("valid terminal workload binding rejected")
	}
	for name, mutate := range map[string]func(*WorkloadRoleBinding){
		"old version":       func(value *WorkloadRoleBinding) { value.ResourceVersion = 1 },
		"active terminal":   func(value *WorkloadRoleBinding) { value.Status = WorkloadRoleBindingActive },
		"mismatched update": func(value *WorkloadRoleBinding) { value.UpdatedAt = value.UpdatedAt.Add(time.Second) },
		"missing revocation": func(value *WorkloadRoleBinding) {
			value.RevokedAt = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			if ValidateWorkloadRoleBinding(changed) == nil {
				t.Fatal("invalid terminal workload binding accepted")
			}
		})
	}
}
