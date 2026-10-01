package applicationlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestCreateApplicationCommitsTerminalOperationAndSanitizedAudit(t *testing.T) {
	transaction := &fakeLifecycleTransaction{
		now: lifecycleTime, acceptedGenerations: make(map[uint64]paasv1.DeploymentGeneration),
	}
	usecase := mustLifecycleUsecase(t, &fakeLifecycleRepository{transaction: transaction})
	command := CreateApplicationCommand{
		Authorization: lifecycleAuthorization(),
		Request: paasv1.CreateApplicationRequest{
			ID: "application-new", Name: "application-new",
			Labels: map[string]string{"environment": "production", "team": "platform"},
		},
		IdempotencyKey: "create-application-new",
	}
	command.Authorization.RequestTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
	resource, operation, replayed, err := usecase.CreateApplication(context.Background(), command)
	if err != nil {
		t.Fatalf("create Application: %v", err)
	}
	if replayed || resource.Metadata.Scope.TenantID != command.Authorization.TenantID ||
		resource.Metadata.ResourceVersion != 1 ||
		operation.Action != paasv1.OperationCreateApplication ||
		operation.State != paasv1.OperationSucceeded || operation.TerminalAt == nil {
		t.Fatalf("created Application result = %#v / %#v", resource, operation)
	}
	if transaction.resourceSubmission == nil {
		t.Fatal("resource creation was not persisted")
	}
	auditEvent := transaction.resourceSubmission.AuditEvent
	if auditEvent.OperationID != operation.ID || auditEvent.Actor != command.Authorization.Subject ||
		auditEvent.IAMDecisionID != command.Authorization.DecisionID ||
		auditEvent.Action != "paas.application.created" || auditEvent.Result != "SUCCEEDED" {
		t.Fatalf("Audit event = %#v", auditEvent)
	}
	encoded, err := json.Marshal(auditEvent)
	if err != nil {
		t.Fatalf("encode Audit event: %v", err)
	}
	for _, forbidden := range []string{"credential", "authorization", "requestBody", "attributes"} {
		if strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(forbidden)) {
			t.Fatalf("Audit event exposes forbidden field %q: %s", forbidden, encoded)
		}
	}

	transaction.storedOperation = operation
	transaction.operationFound = true
	transaction.resourceSubmission = nil
	replayedResource, replayedOperation, replayed, err := usecase.CreateApplication(context.Background(), command)
	if err != nil {
		t.Fatalf("replay Application creation: %v", err)
	}
	if !replayed || replayedResource.Metadata.ID != resource.Metadata.ID ||
		replayedOperation.ID != operation.ID || transaction.resourceSubmission != nil {
		t.Fatalf("replayed Application = %#v / %#v", replayedResource, replayedOperation)
	}

	changed := command
	changed.Request.Name = "changed-name"
	if _, _, _, err := usecase.CreateApplication(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v, want idempotency conflict", err)
	}

	changed = command
	changed.Request.Labels = map[string]string{"environment": "staging", "team": "platform"}
	if _, _, _, err := usecase.CreateApplication(context.Background(), changed); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("changed authorization label error = %v, want invalid argument", err)
	}
	if transaction.resourceSubmission != nil {
		t.Fatal("changed authorization label reached the transaction")
	}
}

func TestApplicationLabelMutationsBindCurrentAndRequestedState(t *testing.T) {
	transaction := &fakeLifecycleTransaction{
		now: lifecycleTime,
		application: paasv1.Application{APIVersion: paasv1.APIVersion, Kind: "Application",
			Metadata: paasv1.ResourceMetadata{ID: "application-labels", Name: "application-labels",
				Scope:  paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"},
				Labels: map[string]string{"environment": "production", "team": "platform"}, ResourceVersion: 1,
				CreatedAt: lifecycleTime, UpdatedAt: lifecycleTime}},
		applicationFound: true, acceptedGenerations: make(map[uint64]paasv1.DeploymentGeneration),
	}
	usecase := mustLifecycleUsecase(t, &fakeLifecycleRepository{transaction: transaction})
	authorization := lifecycleAuthorization()
	authorization.ResourceTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
	authorization.RequestTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "staging"}}
	command := SetApplicationLabelCommand{Authorization: authorization, ApplicationID: "application-labels",
		LabelKey: "environment", Value: "staging", ExpectedResourceVersion: 1, IdempotencyKey: "set-application-environment"}
	result, err := usecase.SetApplicationLabel(context.Background(), command)
	operation := result.Operation
	if err != nil || result.Replayed || result.ResourceVersion != 2 || operation.Action != paasv1.OperationSetApplicationLabel ||
		transaction.application.Metadata.ResourceVersion != 2 ||
		transaction.application.Metadata.Labels["environment"] != "staging" ||
		transaction.application.Metadata.Labels["team"] != "platform" {
		t.Fatalf("set Application label = %#v / %#v, replayed=%t err=%v", transaction.application, operation, result.Replayed, err)
	}
	if transaction.applicationLabelSubmission == nil ||
		transaction.applicationLabelSubmission.ExpectedResourceVersion != 1 ||
		transaction.applicationLabelSubmission.AuditEvent.Action != "paas.application-label.updated" ||
		transaction.applicationLabelSubmission.AuditEvent.IAMDecisionID != authorization.DecisionID {
		t.Fatalf("set Application label submission = %#v", transaction.applicationLabelSubmission)
	}

	transaction.storedOperation, transaction.operationFound = operation, true
	transaction.applicationLabelSubmission = nil
	replayedResult, err := usecase.SetApplicationLabel(context.Background(), command)
	if err != nil || !replayedResult.Replayed || replayedResult.ResourceVersion != 2 ||
		replayedResult.Operation.ID != operation.ID || transaction.applicationLabelSubmission != nil {
		t.Fatalf("set label replay = %#v err=%v", replayedResult, err)
	}
	changed := command
	changed.Value = "restricted"
	changed.Authorization.RequestTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "restricted"}}
	if _, err := usecase.SetApplicationLabel(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed set replay error = %v", err)
	}

	transaction.operationFound = false
	deleteAuthorization := lifecycleAuthorization()
	deleteAuthorization.ResourceTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "staging"}}
	deleteAuthorization.RequestTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "staging"}}
	deleted, err := usecase.DeleteApplicationLabel(context.Background(), DeleteApplicationLabelCommand{
		Authorization: deleteAuthorization, ApplicationID: "application-labels", LabelKey: "environment",
		ExpectedResourceVersion: 2, IdempotencyKey: "delete-application-environment",
	})
	if err != nil || deleted.Replayed || deleted.ResourceVersion != 3 || deleted.Operation.Action != paasv1.OperationDeleteApplicationLabel ||
		transaction.application.Metadata.ResourceVersion != 3 ||
		transaction.application.Metadata.Labels["environment"] != "" ||
		transaction.application.Metadata.Labels["team"] != "platform" ||
		transaction.applicationLabelSubmission.AuditEvent.Action != "paas.application-label.deleted" {
		t.Fatalf("delete Application label = %#v / %#v, err=%v", transaction.application, deleted, err)
	}
}

func TestApplicationLabelMutationRejectsStaleEvidenceAndNoChange(t *testing.T) {
	transaction := &fakeLifecycleTransaction{
		now: lifecycleTime,
		application: paasv1.Application{APIVersion: paasv1.APIVersion, Kind: "Application",
			Metadata: paasv1.ResourceMetadata{ID: "application-labels", Name: "application-labels",
				Scope:  paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"},
				Labels: map[string]string{"environment": "production"}, ResourceVersion: 4,
				CreatedAt: lifecycleTime, UpdatedAt: lifecycleTime}},
		applicationFound: true, acceptedGenerations: make(map[uint64]paasv1.DeploymentGeneration),
	}
	usecase := mustLifecycleUsecase(t, &fakeLifecycleRepository{transaction: transaction})
	authorization := lifecycleAuthorization()
	authorization.ResourceTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "staging"}}
	authorization.RequestTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "restricted"}}
	_, err := usecase.SetApplicationLabel(context.Background(), SetApplicationLabelCommand{
		Authorization: authorization, ApplicationID: "application-labels", LabelKey: "environment",
		Value: "restricted", ExpectedResourceVersion: 4, IdempotencyKey: "stale-label-evidence",
	})
	if !errors.Is(err, ErrResourceVersionConflict) || transaction.applicationLabelSubmission != nil {
		t.Fatalf("stale label evidence error=%v submission=%#v", err, transaction.applicationLabelSubmission)
	}

	authorization.ResourceTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
	authorization.RequestTags = []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}
	_, err = usecase.SetApplicationLabel(context.Background(), SetApplicationLabelCommand{
		Authorization: authorization, ApplicationID: "application-labels", LabelKey: "environment",
		Value: "production", ExpectedResourceVersion: 4, IdempotencyKey: "same-label-value",
	})
	if !errors.Is(err, ErrNoDesiredChange) || transaction.applicationLabelSubmission != nil {
		t.Fatalf("same label value error=%v submission=%#v", err, transaction.applicationLabelSubmission)
	}
}

func TestCreateResourceChainValidatesParentsAndImmutableDocuments(t *testing.T) {
	transaction := &fakeLifecycleTransaction{
		now: lifecycleTime, acceptedGenerations: make(map[uint64]paasv1.DeploymentGeneration),
	}
	usecase := mustLifecycleUsecase(t, &fakeLifecycleRepository{transaction: transaction})
	authorization := lifecycleAuthorization()
	application, _, _, err := usecase.CreateApplication(context.Background(), CreateApplicationCommand{
		Authorization:  authorization,
		Request:        paasv1.CreateApplicationRequest{ID: "application-chain", Name: "application-chain"},
		IdempotencyKey: "create-application-chain",
	})
	if err != nil {
		t.Fatalf("create parent Application: %v", err)
	}
	configuration, _, _, err := usecase.CreateConfiguration(context.Background(), CreateConfigurationCommand{
		Authorization: authorization,
		Request: paasv1.CreateConfigurationRequest{
			ID: "configuration-chain", Name: "configuration-chain", ApplicationID: application.Metadata.ID,
		},
		IdempotencyKey: "create-configuration-chain",
	})
	if err != nil {
		t.Fatalf("create Configuration: %v", err)
	}
	values := map[string]string{"MESSAGE": "ordinary-value"}
	configurationRevision, operation, _, err := usecase.CreateConfigurationRevision(
		context.Background(),
		CreateConfigurationRevisionCommand{
			Authorization: authorization,
			Request: paasv1.CreateConfigurationRevisionRequest{
				ID: "configuration-revision-chain", Name: "configuration-revision-chain",
				Spec: paasv1.ConfigurationRevisionSpec{
					ConfigurationID: configuration.Metadata.ID,
					Values:          values, ContentDigest: paasv1.ConfigurationValuesDigest(values),
				},
			},
			IdempotencyKey: "create-configuration-revision-chain",
		},
	)
	if err != nil {
		t.Fatalf("create ConfigurationRevision: %v", err)
	}
	if operation.Action != paasv1.OperationCreateConfigurationRevision ||
		configurationRevision.Spec.ContentDigest != paasv1.ConfigurationValuesDigest(values) {
		t.Fatalf("ConfigurationRevision result = %#v / %#v", configurationRevision, operation)
	}
	if encoded, _ := json.Marshal(transaction.resourceSubmission.AuditEvent); strings.Contains(string(encoded), "ordinary-value") {
		t.Fatalf("Audit event leaked configuration value: %s", encoded)
	}

	transaction.revisionFound = false
	applicationRevision, operation, _, err := usecase.CreateApplicationRevision(
		context.Background(),
		CreateApplicationRevisionCommand{
			Authorization: authorization,
			Request: paasv1.CreateApplicationRevisionRequest{
				ID: "application-revision-chain", Name: "application-revision-chain",
				Spec: paasv1.ApplicationRevisionSpec{
					ApplicationID: application.Metadata.ID,
					Revision:      "v1", ContentDigest: lifecycleDigest('c'),
					Components: lifecycleRevision().Spec.Components,
				},
			},
			IdempotencyKey: "create-application-revision-chain",
		},
	)
	if err != nil {
		t.Fatalf("create ApplicationRevision: %v", err)
	}
	if applicationRevision.Metadata.ResourceVersion != 1 ||
		operation.Action != paasv1.OperationCreateApplicationRevision {
		t.Fatalf("ApplicationRevision result = %#v / %#v", applicationRevision, operation)
	}

	invalidValues := map[string]string{"MESSAGE": "changed"}
	_, _, _, err = usecase.CreateConfigurationRevision(
		context.Background(),
		CreateConfigurationRevisionCommand{
			Authorization: authorization,
			Request: paasv1.CreateConfigurationRevisionRequest{
				ID: "invalid-configuration-revision", Name: "invalid-configuration-revision",
				Spec: paasv1.ConfigurationRevisionSpec{
					ConfigurationID: configuration.Metadata.ID,
					Values:          invalidValues, ContentDigest: paasv1.ConfigurationValuesDigest(values),
				},
			},
			IdempotencyKey: "create-invalid-configuration-revision",
		},
	)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("invalid ConfigurationRevision error = %v", err)
	}
}

func TestCreateConfigurationRejectsMissingParent(t *testing.T) {
	transaction := &fakeLifecycleTransaction{
		now: lifecycleTime, acceptedGenerations: make(map[uint64]paasv1.DeploymentGeneration),
	}
	_, _, _, err := mustLifecycleUsecase(
		t,
		&fakeLifecycleRepository{transaction: transaction},
	).CreateConfiguration(context.Background(), CreateConfigurationCommand{
		Authorization: lifecycleAuthorization(),
		Request: paasv1.CreateConfigurationRequest{
			ID: "configuration-orphan", Name: "configuration-orphan", ApplicationID: "missing-application",
		},
		IdempotencyKey: "create-configuration-orphan",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing parent error = %v, want not found", err)
	}
}
