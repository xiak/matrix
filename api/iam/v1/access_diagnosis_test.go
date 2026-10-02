package iamv1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCurrentAccessDiagnosisIsAClosedNonPermitContract(t *testing.T) {
	request, err := NewAuthorizationRequest(ActionPaaSApplicationRead,
		ResourceReference{Kind: ResourceApplication, ID: "application-one"}, AuthorizationResourceInstance, "",
		"diagnosis-request", "diagnosis-correlation")
	if err != nil {
		t.Fatal(err)
	}
	value := CurrentAccessDiagnosis{
		APIVersion: APIVersion, Kind: "CurrentAccessDiagnosis", Outcome: AccessDiagnosisDenied,
		Reasons: []AccessDiagnosisReason{AccessDiagnosisExplicitDeny}, TenantID: "account-one",
		Subject: Subject{Type: SubjectUser, ID: "user-one"}, Action: request.Action, Resource: request.Resource,
		Profile: request.Profile, ResourceMode: request.ResourceMode, RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, EvaluatedAt: time.Date(2026, 10, 3, 1, 2, 3, 0, time.UTC),
		Sources: []AccessDiagnosisSource{{Kind: AccessDiagnosisSourceDirect, Effect: AccessDiagnosisEffectDeny,
			Version:      PolicyVersionReference{PolicyID: "policy-one", VersionID: "version-one", ContentDigest: "sha256:" + strings.Repeat("a", 64)},
			AttachmentID: "attachment-one"}},
		Restrictions:      []AccessDiagnosisRestriction{{Kind: AccessDiagnosisRestrictionUserBoundary, State: AccessDiagnosisRestrictionNotApplicable}},
		ResourceExistence: AccessDiagnosisNotEvaluated, BusinessOutcome: AccessDiagnosisNotEvaluated,
	}
	if ValidateCurrentAccessDiagnosis(value) != nil {
		t.Fatal("valid diagnosis rejected")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"decisionId"`, `"allowed"`, `"permit"`, `"policyDocument"`, `"compilation"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("diagnosis exposes permit/private field %s: %s", forbidden, encoded)
		}
	}
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "CurrentAccessDiagnosis")
	instance := func(candidate CurrentAccessDiagnosis) any {
		encoded, marshalErr := json.Marshal(candidate)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var decoded any
		if json.Unmarshal(encoded, &decoded) != nil {
			t.Fatal("decode diagnosis instance")
		}
		return decoded
	}
	if schema.Validate(instance(value)) != nil {
		t.Fatal("OpenAPI rejected valid diagnosis")
	}

	invalid := []CurrentAccessDiagnosis{}
	changed := value
	changed.InstallationID = "installation-forged"
	invalid = append(invalid, changed)
	changed = value
	changed.Outcome, changed.Reasons = AccessDiagnosisAllowed, value.Reasons
	invalid = append(invalid, changed)
	changed = value
	changed.Reasons = []AccessDiagnosisReason{AccessDiagnosisExplicitDeny, AccessDiagnosisExplicitDeny}
	invalid = append(invalid, changed)
	changed = value
	changed.Sources = append([]AccessDiagnosisSource(nil), value.Sources...)
	changed.Sources[0].MembershipID = "membership-forged"
	invalid = append(invalid, changed)
	changed = value
	changed.ResourceExistence = "EXISTS"
	invalid = append(invalid, changed)
	for index, candidate := range invalid {
		if ValidateCurrentAccessDiagnosis(candidate) == nil || schema.Validate(instance(candidate)) == nil {
			t.Fatalf("invalid diagnosis %d accepted: %#v", index, candidate)
		}
	}
}
