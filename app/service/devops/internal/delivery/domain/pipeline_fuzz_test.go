package domain

import (
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func FuzzPipelineActivationFailsClosedForUntrustedBinding(f *testing.F) {
	f.Add("repository-binding-api")
	f.Add("")
	f.Add("../../host")
	f.Fuzz(func(t *testing.T, binding string) {
		request := validCreatePipelineRequest()
		request.Draft.RepositoryBindingID = devopsv1.ResourceID(binding)
		pipeline, err := NewPipeline(
			request,
			devopsv1.ResourceScope{TenantID: "organization-acme"},
			domainTime(),
		)
		if err != nil {
			return
		}
		activation, err := ActivatePipeline(
			pipeline,
			pipeline.Metadata.ResourceVersion,
			devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"},
			pipeline.Metadata.UpdatedAt.Add(time.Minute),
		)
		if err != nil {
			t.Fatalf("activate validated Pipeline: %v", err)
		}
		if err := devopsv1.ValidatePipelineActivation(activation); err != nil {
			t.Fatalf("activation escaped validation: %v", err)
		}
	})
}
