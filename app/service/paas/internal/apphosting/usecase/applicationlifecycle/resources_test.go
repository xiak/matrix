package applicationlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
			Labels: map[string]string{"team": "platform"},
		},
		IdempotencyKey: "create-application-new",
	}
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
