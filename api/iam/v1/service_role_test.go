package iamv1

import (
	"encoding/json"
	"testing"
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
