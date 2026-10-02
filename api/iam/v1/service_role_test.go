package iamv1

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func serviceRoleTemplateForTest(t *testing.T) ServiceRoleTemplate {
	t.Helper()
	spec := ServiceRoleTemplateSpec{
		Product:         ProductManagedService,
		ServicePurpose:  ServicePaaS,
		RoleName:        "ManagedServiceInstallationReader",
		RoleDescription: "Allows the managed service controller to read one explicitly bound service installation.",
		PolicyVersion: PolicyVersionReference{
			PolicyID:      "system.managedservice-installation-reader",
			VersionID:     "version-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ContentDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Workloads: []ServiceRoleWorkloadSpec{{
			ResourceKind: ResourceServiceInstallation,
			BindAction:   ActionManagedServiceInstallationRoleBind,
			UnbindAction: ActionManagedServiceInstallationRoleUnbind,
		}},
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

func TestServiceRoleTemplateValidatesReleaseOwnedAuthority(t *testing.T) {
	template := serviceRoleTemplateForTest(t)
	if ValidateServiceRoleTemplate(template) != nil || ValidateServiceRoleTemplateReference(template.Reference()) != nil {
		t.Fatal("valid service role template rejected")
	}
	document, digest, err := CanonicalizeServiceRoleTemplateSpec(template.Spec)
	if err != nil || document == "" || digest != template.ContentDigest ||
		!json.Valid([]byte(document)) {
		t.Fatal("template authority did not preserve its registered product actions")
	}

	for name, mutate := range map[string]func(*ServiceRoleTemplate){
		"tenant supplied product": func(value *ServiceRoleTemplate) { value.Spec.Product = "managedservice.other" },
		"unknown service":         func(value *ServiceRoleTemplate) { value.Spec.ServicePurpose = "PROBE" },
		"empty role name":         func(value *ServiceRoleTemplate) { value.Spec.RoleName = "" },
		"duplicate workload": func(value *ServiceRoleTemplate) {
			value.Spec.Workloads = append(value.Spec.Workloads, value.Spec.Workloads[0])
		},
		"empty workload": func(value *ServiceRoleTemplate) { value.Spec.Workloads = nil },
		"foreign bind action": func(value *ServiceRoleTemplate) {
			value.Spec.Workloads[0].BindAction = ActionPaaSApplicationRead
		},
		"same product actions": func(value *ServiceRoleTemplate) {
			value.Spec.Workloads[0].UnbindAction = value.Spec.Workloads[0].BindAction
		},
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
			changed.Spec.Workloads = append([]ServiceRoleWorkloadSpec(nil), template.Spec.Workloads...)
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
	for _, offset := range []string{"+00:00", "+01:00", "+08:00"} {
		databaseWire := []byte(strings.ReplaceAll(string(encoded), `Z"`, offset+`"`))
		if json.Unmarshal(databaseWire, &decoded) == nil {
			t.Fatalf("public contract accepted non-canonical timestamp offset %s", offset)
		}
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

func TestServiceRoleSessionIntentAndLineageAreClosed(t *testing.T) {
	duration := uint32(900)
	request := AssumeServiceRoleRequest{
		BindingID:       WorkloadRoleBindingID("wrb-" + strings.Repeat("a", 64)),
		DurationSeconds: &duration,
		RequestID:       "assume-service-role-a",
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AssumeServiceRoleRequest
	if json.Unmarshal(encoded, &decoded) != nil || ValidateAssumeServiceRoleRequest(decoded) != nil || !reflect.DeepEqual(request, decoded) {
		t.Fatal("valid service role intent did not strictly round trip")
	}
	for name, attack := range map[string]string{
		"account selector":      strings.TrimSuffix(string(encoded), "}") + `,"accountId":"account-b"}`,
		"role selector":         strings.TrimSuffix(string(encoded), "}") + `,"roleId":"role-b"}`,
		"installation selector": strings.TrimSuffix(string(encoded), "}") + `,"installationId":"install-b"}`,
		"purpose selector":      strings.TrimSuffix(string(encoded), "}") + `,"purpose":"AUDIT"}`,
		"policy selector":       strings.TrimSuffix(string(encoded), "}") + `,"policyId":"policy-b"}`,
		"null duration":         strings.Replace(string(encoded), `"durationSeconds":900`, `"durationSeconds":null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if json.Unmarshal([]byte(attack), &decoded) == nil {
				t.Fatal("service role intent accepted caller-owned authority")
			}
		})
	}

	issuedAt := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	base := RoleSession{APIVersion: APIVersion, Kind: "RoleSession", ID: "role-session-a", AccountID: "account-a", RoleID: "role-a",
		Status: SessionActive, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(15 * time.Minute)}
	user := base
	user.SourceUserID = "user-a"
	service := base
	service.SourceServicePrincipalID = "service-a"
	if ValidateRoleSession(user) != nil || ValidateRoleSession(service) != nil {
		t.Fatal("valid USER or SERVICE role lineage rejected")
	}
	for name, session := range map[string]RoleSession{
		"missing source": base,
		"mixed source": func() RoleSession {
			value := user
			value.SourceServicePrincipalID = "service-a"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if ValidateRoleSession(session) == nil {
				t.Fatal("role session accepted ambiguous source lineage")
			}
		})
	}
	userReference := RoleSessionReference{SessionID: user.ID, SourceUserID: user.SourceUserID}
	userWire, err := json.Marshal(userReference)
	if err != nil {
		t.Fatal(err)
	}
	var userReferenceDocument map[string]json.RawMessage
	var decodedUserReference RoleSessionReference
	if json.Unmarshal(userWire, &userReferenceDocument) != nil || json.Unmarshal(userWire, &decodedUserReference) != nil ||
		!reflect.DeepEqual(decodedUserReference, userReference) || len(userReferenceDocument) != 2 {
		t.Fatal("USER lineage did not preserve its semantic JSON contract", string(userWire))
	}
	if _, exists := userReferenceDocument["sourceServicePrincipalId"]; exists {
		t.Fatal("USER lineage exposed service-source identity")
	}
	legacySessionWire, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	var legacySessionDocument map[string]json.RawMessage
	var decodedUser RoleSession
	if json.Unmarshal(legacySessionWire, &legacySessionDocument) != nil || json.Unmarshal(legacySessionWire, &decodedUser) != nil ||
		!reflect.DeepEqual(decodedUser, user) || len(legacySessionDocument) != 9 {
		t.Fatal("USER role session did not preserve its semantic JSON contract", string(legacySessionWire))
	}
	if _, exists := legacySessionDocument["sourceServicePrincipalId"]; exists {
		t.Fatal("USER role session exposed service-source identity")
	}
	for _, reference := range []RoleSessionReference{
		userReference,
		{SessionID: service.ID, SourceServicePrincipalID: service.SourceServicePrincipalID},
	} {
		subject := Subject{Type: SubjectRole, ID: string(base.RoleID), RoleSession: &reference}
		if ValidateSubject(subject) != nil {
			t.Fatal("valid role source reference rejected")
		}
	}
}

func TestServiceLinkedRoleDirectorySeparatesSummaryFromBindingDetail(t *testing.T) {
	access := serviceLinkedRoleAccessForTest(t)
	list := ServiceLinkedRoleList{
		APIVersion: APIVersion,
		Kind:       "ServiceLinkedRoleList",
		AccountID:  access.Relation.Role.AccountID,
		Items: []ServiceLinkedRoleListing{{
			Relation: access.Relation, BindingCount: 2, ActiveBindingCount: 1,
		}},
	}
	if ValidateServiceLinkedRoleList(list) != nil {
		t.Fatal("valid service-linked role summary rejected")
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ServiceLinkedRoleList
	if json.Unmarshal(encoded, &decoded) != nil || !reflect.DeepEqual(decoded, list) {
		t.Fatal("valid service-linked role directory did not strictly round trip")
	}
	for name, mutate := range map[string]func(*ServiceLinkedRoleList){
		"foreign account": func(value *ServiceLinkedRoleList) { value.AccountID = "account-b" },
		"no history":      func(value *ServiceLinkedRoleList) { value.Items[0].BindingCount = 0 },
		"active overflow": func(value *ServiceLinkedRoleList) { value.Items[0].ActiveBindingCount = 3 },
		"unsafe count":    func(value *ServiceLinkedRoleList) { value.Items[0].BindingCount = 9007199254740992 },
		"duplicate role": func(value *ServiceLinkedRoleList) {
			value.Items = append(value.Items, value.Items[0])
		},
		"cursor without full page": func(value *ServiceLinkedRoleList) { value.NextAfter = "ic1.valid" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := list
			changed.Items = append([]ServiceLinkedRoleListing(nil), list.Items...)
			mutate(&changed)
			if ValidateServiceLinkedRoleList(changed) == nil {
				t.Fatal("invalid service-linked role directory accepted")
			}
		})
	}
	for _, attack := range []string{
		string(encoded[:len(encoded)-1]) + `,"accountId":"account-b"}`,
		string(encoded[:len(encoded)-1]) + `,"tenantId":"account-b"}`,
	} {
		if json.Unmarshal([]byte(attack), &decoded) == nil {
			t.Fatal("strict directory decoder accepted duplicate identity or tenant selector")
		}
	}
	access.NextAfter = "ic1.valid"
	if ValidateServiceLinkedRoleAccess(access) == nil {
		t.Fatal("binding detail accepted a continuation without a full page")
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

func TestCreateWorkloadRoleBindingRequestHasOneWorkloadAndCommandIdentity(t *testing.T) {
	template := serviceRoleTemplateForTest(t)
	authorization, err := NewAuthorizationRequest(ActionManagedServiceInstallationRoleBind,
		ResourceReference{Kind: ResourceServiceInstallation, ID: "service-installation-a"},
		AuthorizationResourceInstance, "", "bind-service-installation-a", "bind-service-installation-a")
	if err != nil {
		t.Fatal(err)
	}
	request := CreateWorkloadRoleBindingRequest{Template: template.Reference(), Authorization: authorization}
	if ValidateCreateWorkloadRoleBindingRequest(request) != nil {
		t.Fatal("valid workload role binding command rejected")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CreateWorkloadRoleBindingRequest
	if json.Unmarshal(encoded, &decoded) != nil || !reflect.DeepEqual(decoded, request) {
		t.Fatal("workload role binding command did not strictly round trip")
	}
	for _, attack := range []string{
		string(encoded[:len(encoded)-1]) + `,"accountId":"account-b"}`,
		string(encoded[:len(encoded)-1]) + `,"roleId":"role-b"}`,
		string(encoded[:len(encoded)-1]) + `,"servicePrincipalId":"service-b"}`,
		string(encoded[:len(encoded)-1]) + `,"template":` + string(mustServiceRoleJSON(t, template.Reference())) + `}`,
	} {
		if json.Unmarshal([]byte(attack), &decoded) == nil {
			t.Fatal("strict decoder accepted a derived authority selector or duplicate template")
		}
	}
	mutations := []func(*CreateWorkloadRoleBindingRequest){
		func(value *CreateWorkloadRoleBindingRequest) {
			value.Authorization.ResourceMode = AuthorizationResourceCollection
		},
		func(value *CreateWorkloadRoleBindingRequest) {
			value.Authorization.CollectionUsage = AuthorizationCollectionCreate
		},
		func(value *CreateWorkloadRoleBindingRequest) { value.Authorization.Resource.ID = "" },
	}
	for _, mutate := range mutations {
		changed := request
		mutate(&changed)
		if ValidateCreateWorkloadRoleBindingRequest(changed) == nil {
			t.Fatal("invalid workload role binding command accepted")
		}
	}
}

func TestRevokeWorkloadRoleBindingRequestUsesRecordedBindingAuthority(t *testing.T) {
	authorization, err := NewAuthorizationRequest(ActionManagedServiceInstallationRoleUnbind,
		ResourceReference{Kind: ResourceServiceInstallation, ID: "service-installation-a"},
		AuthorizationResourceInstance, "", "unbind-service-installation-a", "unbind-service-installation-a")
	if err != nil {
		t.Fatal(err)
	}
	request := RevokeWorkloadRoleBindingRequest{Authorization: authorization, ResourceVersion: 1}
	if ValidateRevokeWorkloadRoleBindingRequest(request) != nil {
		t.Fatal("valid workload role binding revocation rejected")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RevokeWorkloadRoleBindingRequest
	if json.Unmarshal(encoded, &decoded) != nil || !reflect.DeepEqual(decoded, request) {
		t.Fatal("workload role binding revocation did not strictly round trip")
	}
	for _, attack := range []string{
		string(encoded[:len(encoded)-1]) + `,"accountId":"account-b"}`,
		string(encoded[:len(encoded)-1]) + `,"roleId":"role-b"}`,
		string(encoded[:len(encoded)-1]) + `,"template":{"id":"template-b"}}`,
		string(encoded[:len(encoded)-1]) + `,"workload":{"kind":"SERVICE_INSTALLATION","id":"other"}}`,
	} {
		if json.Unmarshal([]byte(attack), &decoded) == nil {
			t.Fatal("strict revocation decoder accepted a derived authority selector")
		}
	}
	for _, mutate := range []func(*RevokeWorkloadRoleBindingRequest){
		func(value *RevokeWorkloadRoleBindingRequest) { value.ResourceVersion = 2 },
		func(value *RevokeWorkloadRoleBindingRequest) {
			value.Authorization.ResourceMode = AuthorizationResourceCollection
		},
		func(value *RevokeWorkloadRoleBindingRequest) {
			value.Authorization.CollectionUsage = AuthorizationCollectionCreate
		},
		func(value *RevokeWorkloadRoleBindingRequest) { value.Authorization.Resource.ID = "" },
	} {
		changed := request
		mutate(&changed)
		if ValidateRevokeWorkloadRoleBindingRequest(changed) == nil {
			t.Fatal("invalid workload role binding revocation accepted")
		}
	}
}

func mustServiceRoleJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
