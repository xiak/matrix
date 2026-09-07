package port

import (
	"strings"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestAuthorizationIsBoundToExactMutation(t *testing.T) {
	value := Authorization{
		TenantID:   "tenant-one",
		Subject:    devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-one"},
		DecisionID: "decision-one",
		Action:     iamv1.ActionDevOpsPipelineActivate,
		Resource:   iamv1.ResourceReference{Kind: iamv1.ResourcePipeline, ID: "pipeline-one"},
		RequestID:  "request-one", CorrelationID: "correlation-one",
		TraceParent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
	}
	if err := ValidateAuthorizationForMutation(
		value, iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, "pipeline-one",
	); err != nil {
		t.Fatalf("validate matching authorization: %v", err)
	}
	for name, mutate := range map[string]func(*Authorization){
		"action":   func(value *Authorization) { value.Action = iamv1.ActionDevOpsPipelineUpdate },
		"kind":     func(value *Authorization) { value.Resource.Kind = iamv1.ResourcePipelineRun },
		"resource": func(value *Authorization) { value.Resource.ID = "pipeline-other" },
		"tenant":   func(value *Authorization) { value.TenantID = "invalid tenant" },
		"trace":    func(value *Authorization) { value.TraceParent = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := value
			mutate(&changed)
			if ValidateAuthorizationForMutation(
				changed, iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, "pipeline-one",
			) == nil {
				t.Fatal("mismatched authorization was accepted")
			}
		})
	}
}

func TestAuthorizationRequestRejectsUnsafeCredentialWithoutEchoingIt(t *testing.T) {
	secret := " bearer-secret\n"
	err := ValidateAuthorizationRequest(AuthorizationRequest{
		Credential: secret, Action: iamv1.ActionDevOpsProjectCreate,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceDevOpsProject, ID: "project-one"},
		RequestID: "request-one", CorrelationID: "correlation-one",
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe credential error=%v", err)
	}
}
