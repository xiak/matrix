package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	devopsmigration "github.com/xiak/matrix/app/service/devops/migration"
)

const integrationDSNEnvironment = "MATRIX_DEVOPS_POSTGRES_TEST_DSN"

func TestPostgresConfigurationJourneyAndAuthority(t *testing.T) {
	adminDSN := os.Getenv(integrationDSNEnvironment)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", integrationDSNEnvironment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	adminConfig, err := pgx.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(adminConfig.Database, "matrix_devops_") {
		t.Fatal("DevOps integration database configuration is unsafe")
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect DevOps integration database")
	}
	defer admin.Close(context.Background())
	var clean bool
	if err := admin.QueryRow(ctx, `SELECT to_regnamespace('delivery') IS NULL AND NOT EXISTS (
		SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN ('matrix_devops_api_login', 'matrix_devops_worker_login')
	)`).Scan(&clean); err != nil || !clean {
		t.Fatal("DevOps integration database is not clean")
	}

	apiDSN := runtimeDSN(t, adminDSN, "matrix_devops_api_login", "mxp1.devops-api-000000000000000000000000000000")
	workerDSN := runtimeDSN(t, adminDSN, "matrix_devops_worker_login", "mxp1.devops-worker-0000000000000000000000000000")
	for attempt := 1; attempt <= 2; attempt++ {
		if err := devopsmigration.Apply(ctx, adminDSN, apiDSN, workerDSN); err != nil {
			t.Fatalf("apply DevOps migration attempt %d: %v", attempt, err)
		}
	}
	if err := devopsmigration.VerifyInstalled(ctx, adminDSN, apiDSN, workerDSN); err != nil {
		t.Fatalf("verify DevOps migration: %v", err)
	}
	pool, err := pgxpool.New(ctx, apiDSN)
	if err != nil {
		t.Fatal("open DevOps API pool")
	}
	defer pool.Close()
	repository, err := devopspostgres.NewConfigurationRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	usecase, err := pipelineconfiguration.NewUsecase(repository, pipelineconfiguration.Config{MaxTransactionAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}

	projectID := devopsv1.ResourceID("project-integration")
	projectRequest := devopsv1.CreateDevOpsProjectRequest{ID: projectID, Name: "project-integration"}
	project, err := usecase.CreateProject(ctx, pipelineconfiguration.CreateProjectCommand{
		Authorization: auth(iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, projectID),
		Request:       projectRequest, IdempotencyKey: "create-project-integration",
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	connectionID := devopsv1.ResourceID("connection-integration")
	connectionSpec := devopsv1.SourceConnectionSpec{
		AdapterID: "source-adapter-gitea-v1", AllowedEndpointOrigins: []string{"https://gitea.example.com"},
		WebhookSecretRef: "secret-webhook-v1", FetchCredentialRef: "secret-fetch-v1", ReportCredentialRef: "secret-report-v1",
	}
	connection, err := usecase.CreateSourceConnection(ctx, pipelineconfiguration.CreateSourceConnectionCommand{
		Authorization:  auth(iamv1.ActionDevOpsSourceConnectionCreate, iamv1.ResourceSourceConnection, connectionID),
		Request:        devopsv1.CreateSourceConnectionRequest{ID: connectionID, Name: "connection-integration", Spec: connectionSpec},
		IdempotencyKey: "create-connection-integration",
	})
	if err != nil {
		t.Fatalf("create source connection: %v", err)
	}
	rotated := connectionSpec
	rotated.WebhookSecretRef, rotated.FetchCredentialRef, rotated.ReportCredentialRef = "secret-webhook-v2", "secret-fetch-v2", "secret-report-v2"
	if _, err := usecase.UpdateSourceConnection(ctx, pipelineconfiguration.UpdateSourceConnectionCommand{
		Authorization:      auth(iamv1.ActionDevOpsSourceConnectionUpdate, iamv1.ResourceSourceConnection, connectionID),
		SourceConnectionID: connectionID, ExpectedResourceVersion: connection.Value.Metadata.ResourceVersion,
		Request: devopsv1.UpdateSourceConnectionRequest{Spec: rotated}, IdempotencyKey: "rotate-connection-integration",
	}); err != nil {
		t.Fatalf("update source connection: %v", err)
	}

	bindingOne := bindingRequest("binding-integration-one", projectID, connectionID, "matrix/service")
	bindingOneResult, err := usecase.CreateRepositoryBinding(ctx, pipelineconfiguration.CreateRepositoryBindingCommand{
		Authorization: auth(iamv1.ActionDevOpsRepositoryBindingCreate, iamv1.ResourceRepositoryBinding, bindingOne.ID),
		Request:       bindingOne, IdempotencyKey: "create-binding-integration-one",
	})
	if err != nil {
		t.Fatalf("create first repository binding: %v", err)
	}
	bindingTwo := bindingRequest("binding-integration-two", projectID, connectionID, "matrix/other")
	if _, err := usecase.CreateRepositoryBinding(ctx, pipelineconfiguration.CreateRepositoryBindingCommand{
		Authorization: auth(iamv1.ActionDevOpsRepositoryBindingCreate, iamv1.ResourceRepositoryBinding, bindingTwo.ID),
		Request:       bindingTwo, IdempotencyKey: "create-binding-integration-two",
	}); err != nil {
		t.Fatalf("create second repository binding: %v", err)
	}

	pipelineID := devopsv1.ResourceID("pipeline-integration")
	pipelineRequest := devopsv1.CreatePipelineRequest{ID: pipelineID, Name: "pipeline-integration", ProjectID: projectID, Draft: draft(bindingOne.ID)}
	pipeline, err := usecase.CreatePipeline(ctx, pipelineconfiguration.CreatePipelineCommand{
		Authorization: auth(iamv1.ActionDevOpsPipelineCreate, iamv1.ResourcePipeline, pipelineID),
		Request:       pipelineRequest, IdempotencyKey: "create-pipeline-integration",
	})
	if err != nil {
		t.Fatalf("create Pipeline: %v", err)
	}
	firstActivation, err := usecase.ActivatePipeline(ctx, pipelineconfiguration.ActivatePipelineCommand{
		Authorization: auth(iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, pipelineID),
		PipelineID:    pipelineID, ExpectedResourceVersion: pipeline.Value.Metadata.ResourceVersion,
		IdempotencyKey: "activate-pipeline-integration-one",
	})
	if err != nil {
		t.Fatalf("activate first Pipeline revision: %v", err)
	}

	updatedBindingSpec := bindingOne.Spec
	updatedBindingSpec.TrustedDefaultBranch = "release"
	updatedBinding, err := usecase.UpdateRepositoryBinding(ctx, pipelineconfiguration.UpdateRepositoryBindingCommand{
		Authorization:       auth(iamv1.ActionDevOpsRepositoryBindingUpdate, iamv1.ResourceRepositoryBinding, bindingOne.ID),
		RepositoryBindingID: bindingOne.ID, ExpectedResourceVersion: bindingOneResult.Value.Metadata.ResourceVersion,
		Request: devopsv1.UpdateRepositoryBindingRequest{Spec: updatedBindingSpec}, IdempotencyKey: "update-binding-integration",
	})
	if err != nil {
		t.Fatalf("update repository binding: %v", err)
	}
	secondActivation, err := usecase.ActivatePipeline(ctx, pipelineconfiguration.ActivatePipelineCommand{
		Authorization: auth(iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, pipelineID),
		PipelineID:    pipelineID, ExpectedResourceVersion: firstActivation.Value.Pipeline.Metadata.ResourceVersion,
		IdempotencyKey: "activate-pipeline-integration-two",
	})
	if err != nil {
		t.Fatalf("activate changed binding snapshot: %v", err)
	}
	if firstActivation.Value.Revision.Spec.RepositoryBindingDigest == secondActivation.Value.Revision.Spec.RepositoryBindingDigest {
		t.Fatal("binding update retargeted instead of creating a new snapshot")
	}

	draftUpdate := devopsv1.UpdatePipelineDraftRequest{Draft: draft(bindingTwo.ID)}
	draftResult, err := usecase.UpdatePipelineDraft(ctx, pipelineconfiguration.UpdatePipelineDraftCommand{
		Authorization: auth(iamv1.ActionDevOpsPipelineUpdate, iamv1.ResourcePipeline, pipelineID),
		PipelineID:    pipelineID, ExpectedResourceVersion: secondActivation.Value.Pipeline.Metadata.ResourceVersion,
		Request: draftUpdate, IdempotencyKey: "update-pipeline-integration",
	})
	if err != nil {
		t.Fatalf("update Pipeline draft: %v", err)
	}
	thirdActivation, err := usecase.ActivatePipeline(ctx, pipelineconfiguration.ActivatePipelineCommand{
		Authorization: auth(iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, pipelineID),
		PipelineID:    pipelineID, ExpectedResourceVersion: draftResult.Value.Metadata.ResourceVersion,
		IdempotencyKey: "activate-pipeline-integration-three",
	})
	if err != nil || thirdActivation.Value.Revision.Revision != 3 {
		t.Fatalf("activate third revision=%#v err=%v", thirdActivation, err)
	}

	replayedDraft, err := usecase.UpdatePipelineDraft(ctx, pipelineconfiguration.UpdatePipelineDraftCommand{
		Authorization: auth(iamv1.ActionDevOpsPipelineUpdate, iamv1.ResourcePipeline, pipelineID),
		PipelineID:    pipelineID, ExpectedResourceVersion: secondActivation.Value.Pipeline.Metadata.ResourceVersion,
		Request: draftUpdate, IdempotencyKey: "update-pipeline-integration",
	})
	if err != nil || !replayedDraft.Replayed || replayedDraft.Value.Metadata.ResourceVersion != draftResult.Value.Metadata.ResourceVersion ||
		replayedDraft.Value.Metadata.ResourceVersion == thirdActivation.Value.Pipeline.Metadata.ResourceVersion {
		t.Fatalf("stored replay snapshot=%#v err=%v", replayedDraft, err)
	}
	projectReplay, err := usecase.CreateProject(ctx, pipelineconfiguration.CreateProjectCommand{
		Authorization: auth(iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, projectID),
		Request:       projectRequest, IdempotencyKey: "create-project-integration",
	})
	if err != nil || !projectReplay.Replayed || projectReplay.Value != project.Value {
		t.Fatalf("project replay=%#v err=%v", projectReplay, err)
	}
	if updatedBinding.Value.ContentDigest == firstActivation.Value.Revision.Spec.RepositoryBindingDigest {
		t.Fatal("updated binding digest did not change")
	}

	err = repository.WithinTransaction(ctx, "tenant-other", func(ctx context.Context, tx pipelineconfiguration.Transaction) error {
		_, found, err := tx.LoadProject(ctx, projectID)
		if err != nil {
			return err
		}
		if found {
			return errors.New("cross-tenant Project was visible")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("forced RLS cross-tenant read: %v", err)
	}

	assertDenied(t, func() error {
		_, err := pool.Exec(ctx, `INSERT INTO delivery.projects (tenant_id,id,resource_version,document) VALUES ('tenant-one','forbidden',1,'{}')`)
		return err
	})
	assertDenied(t, func() error { _, err := pool.Exec(ctx, `SELECT count(*) FROM delivery.audit_outbox`); return err })
	worker, err := pgx.Connect(ctx, workerDSN)
	if err != nil {
		t.Fatal("connect DevOps worker role")
	}
	defer worker.Close(context.Background())
	assertDenied(t, func() error { _, err := worker.Exec(ctx, `SELECT count(*) FROM delivery.projects`); return err })

	var mutationCount, auditCount, bindingRevisionCount, pipelineRevisionCount int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM delivery.mutations),
		(SELECT count(*) FROM delivery.audit_outbox),
		(SELECT count(*) FROM delivery.repository_binding_revisions WHERE binding_id = 'binding-integration-one'),
		(SELECT count(*) FROM delivery.pipeline_revisions WHERE pipeline_id = 'pipeline-integration')`).Scan(
		&mutationCount, &auditCount, &bindingRevisionCount, &pipelineRevisionCount,
	); err != nil {
		t.Fatalf("read delivery evidence: %v", err)
	}
	if mutationCount != 11 || auditCount != 11 || bindingRevisionCount != 2 || pipelineRevisionCount != 3 {
		t.Fatalf("evidence counts mutation=%d audit=%d binding=%d pipeline=%d", mutationCount, auditCount, bindingRevisionCount, pipelineRevisionCount)
	}
	rows, err := admin.Query(ctx, `SELECT document FROM delivery.audit_outbox ORDER BY event_id`)
	if err != nil {
		t.Fatalf("read Audit outbox: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			t.Fatal(err)
		}
		var event auditv1.Event
		if err := json.Unmarshal(document, &event); err != nil {
			t.Fatalf("decode Audit event: %v", err)
		}
		if err := auditv1.ValidateEventForSource(auditv1.SourceDevOps, event); err != nil {
			t.Fatalf("validate Audit event: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func runtimeDSN(t *testing.T, adminDSN, role, password string) string {
	t.Helper()
	value, err := url.Parse(adminDSN)
	if err != nil || value.Scheme != "postgresql" {
		t.Fatal("parse DevOps integration DSN")
	}
	value.User = url.UserPassword(role, password)
	return value.String()
}

func auth(action iamv1.Action, kind iamv1.ResourceKind, id devopsv1.ResourceID) port.Authorization {
	return port.Authorization{
		TenantID: "tenant-one", Subject: devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-one"},
		DecisionID: "decision-" + string(id), Action: action,
		Resource:  iamv1.ResourceReference{Kind: kind, ID: string(id)},
		RequestID: "request-integration", CorrelationID: "correlation-integration",
	}
}

func bindingRequest(id, projectID, connectionID devopsv1.ResourceID, path string) devopsv1.CreateRepositoryBindingRequest {
	return devopsv1.CreateRepositoryBindingRequest{ID: id, Name: string(id), ProjectID: projectID,
		Spec: devopsv1.RepositoryBindingSpec{SourceConnectionID: connectionID, ExternalRepositoryID: "external-" + id, RepositoryPath: path, TrustedDefaultBranch: "main"}}
}

func draft(bindingID devopsv1.ResourceID) devopsv1.PipelineDraftSpec {
	return devopsv1.PipelineDraftSpec{RepositoryBindingID: bindingID, TriggerPolicy: devopsv1.TriggerChange,
		VerificationProfile: devopsv1.VerificationGo126OfflineV1, DependencyEgress: devopsv1.DependencyEgressNone,
		ReporterPolicy: devopsv1.ReporterChangeCheckV1}
}

func assertDenied(t *testing.T, action func() error) {
	t.Helper()
	err := action()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "42501" {
		t.Fatalf("database action error=%v, want permission denied", err)
	}
}
