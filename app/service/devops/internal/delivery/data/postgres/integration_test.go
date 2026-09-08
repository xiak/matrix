package postgres_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/gitea"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/webhooksecretfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/auditdispatch"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
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
	repository, err := devopspostgres.NewControlPlaneRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	usecase, err := pipelineconfiguration.NewUsecase(repository, pipelineconfiguration.Config{MaxTransactionAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}
	runController, err := runcontrol.NewService(repository, runcontrol.Config{MaxTransactionAttempts: 5})
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
	bindingOne.Spec.ExternalRepositoryID = "42"
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

	duplicateBinding := bindingRequest("binding-integration-duplicate", projectID, connectionID, "matrix/duplicate")
	duplicateBinding.Spec.ExternalRepositoryID = updatedBinding.Value.Spec.ExternalRepositoryID
	if _, err := usecase.CreateRepositoryBinding(ctx, pipelineconfiguration.CreateRepositoryBindingCommand{
		Authorization: auth(iamv1.ActionDevOpsRepositoryBindingCreate, iamv1.ResourceRepositoryBinding, duplicateBinding.ID),
		Request:       duplicateBinding, IdempotencyKey: "create-binding-integration-duplicate",
	}); !errors.Is(err, pipelineconfiguration.ErrAlreadyExists) {
		t.Fatalf("duplicate source repository mapping error=%v", err)
	}

	secondaryPipelineID := devopsv1.ResourceID("pipeline-integration-secondary")
	secondaryPipeline, err := usecase.CreatePipeline(ctx, pipelineconfiguration.CreatePipelineCommand{
		Authorization: auth(iamv1.ActionDevOpsPipelineCreate, iamv1.ResourcePipeline, secondaryPipelineID),
		Request: devopsv1.CreatePipelineRequest{
			ID: secondaryPipelineID, Name: "pipeline-integration-secondary",
			ProjectID: projectID, Draft: draft(bindingOne.ID),
		},
		IdempotencyKey: "create-pipeline-integration-secondary",
	})
	if err != nil {
		t.Fatalf("create secondary Pipeline: %v", err)
	}
	if _, err := usecase.ActivatePipeline(ctx, pipelineconfiguration.ActivatePipelineCommand{
		Authorization: auth(iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, secondaryPipelineID),
		PipelineID:    secondaryPipelineID, ExpectedResourceVersion: secondaryPipeline.Value.Metadata.ResourceVersion,
		IdempotencyKey: "activate-pipeline-integration-secondary",
	}); err != nil {
		t.Fatalf("activate secondary Pipeline: %v", err)
	}

	if _, err := admin.Exec(ctx, `UPDATE delivery.source_connections
		SET document = jsonb_set(document, '{status,health}', '"READY"')
		WHERE tenant_id = 'tenant-one' AND id = $1`, connectionID); err != nil {
		t.Fatalf("mark source connection fixture ready: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE delivery.repository_bindings
		SET document = jsonb_set(document, '{status,health}', '"READY"')
		WHERE tenant_id = 'tenant-one' AND id = $1`, bindingOne.ID); err != nil {
		t.Fatalf("mark repository binding fixture ready: %v", err)
	}
	ingressConnection, found, err := repository.ReadSourceConnection(
		ctx, devopsv1.ResourceScope{TenantID: "tenant-one"}, connectionID,
	)
	if err != nil || !found || ingressConnection.Metadata.ResourceVersion != 2 ||
		ingressConnection.Spec.WebhookSecretRef != rotated.WebhookSecretRef ||
		ingressConnection.Status.Health != devopsv1.SourceConnectionReady {
		t.Fatalf("read endpoint-bound SourceConnection=%#v found=%t err=%v", ingressConnection, found, err)
	}
	if _, found, err := repository.ReadSourceConnection(
		ctx, devopsv1.ResourceScope{TenantID: "tenant-other"}, connectionID,
	); err != nil || found {
		t.Fatalf("cross-tenant source ingress read found=%t err=%v", found, err)
	}
	admissionUsecase, err := runadmission.NewUsecase(
		repository,
		runadmission.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	secretRoot := t.TempDir()
	secretDirectory, err := webhooksecretfile.DirectoryName(
		devopsv1.ResourceScope{TenantID: "tenant-one"}, rotated.WebhookSecretRef,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(secretRoot, secretDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	webhookSecret := []byte("integration-webhook-secret-000000001")
	if err := os.WriteFile(filepath.Join(secretRoot, secretDirectory, "current"), webhookSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	secretResolver, err := webhooksecretfile.NewResolver(secretRoot)
	if err != nil {
		t.Fatal(err)
	}
	ingressUsecase, err := sourceingress.NewUsecase(
		repository, secretResolver, admissionUsecase, gitea.NewAdapter(),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstAdmissionCommand := signedGiteaIngressCommand(webhookSecret, false)
	firstAdmission, err := ingressUsecase.Receive(ctx, firstAdmissionCommand)
	if err != nil || firstAdmission.Replayed || len(firstAdmission.Admission.Runs) != 2 {
		t.Fatalf("admit first source event=%#v err=%v", firstAdmission, err)
	}
	if firstAdmission.Admission.Runs[0].PipelineID != pipelineID ||
		firstAdmission.Admission.Runs[1].PipelineID != secondaryPipelineID {
		t.Fatalf("persisted run fan-out=%#v", firstAdmission.Admission.Runs)
	}
	equalReplay, err := ingressUsecase.Receive(ctx, firstAdmissionCommand)
	if err != nil || !equalReplay.Replayed ||
		equalReplay.Admission.Event != firstAdmission.Admission.Event ||
		len(equalReplay.Admission.Runs) != len(firstAdmission.Admission.Runs) {
		t.Fatalf("equal source replay=%#v err=%v", equalReplay, err)
	}
	changedReplay := signedGiteaIngressCommand(webhookSecret, true)
	if _, err := ingressUsecase.Receive(ctx, changedReplay); !errors.Is(err, runadmission.ErrReplayConflict) {
		t.Fatalf("changed source replay error=%v", err)
	}

	for index := 2; index <= 15; index++ {
		command := sourceAdmissionCommand(
			connectionID,
			updatedBinding.Value.Spec.ExternalRepositoryID,
			fmt.Sprintf("123e4567-e89b-42d3-a456-%012d", index),
		)
		admitted, err := admissionUsecase.Admit(ctx, command)
		if err != nil || len(admitted.Admission.Runs) != 2 {
			t.Fatalf("fill queued run capacity at %d=%#v err=%v", index, admitted, err)
		}
	}
	type concurrentAdmissionOutcome struct {
		index  int
		result runadmission.Result
		err    error
	}
	startAdmissions := make(chan struct{})
	admissionOutcomes := make(chan concurrentAdmissionOutcome, 2)
	for _, index := range []int{16, 17} {
		index := index
		go func() {
			<-startAdmissions
			command := sourceAdmissionCommand(
				connectionID,
				updatedBinding.Value.Spec.ExternalRepositoryID,
				fmt.Sprintf("123e4567-e89b-42d3-a456-%012d", index),
			)
			result, err := admissionUsecase.Admit(ctx, command)
			admissionOutcomes <- concurrentAdmissionOutcome{index: index, result: result, err: err}
		}()
	}
	close(startAdmissions)
	succeededAdmissions, capacityRejectedAdmissions := 0, 0
	for range 2 {
		outcome := <-admissionOutcomes
		switch {
		case outcome.err == nil:
			if outcome.result.Replayed || len(outcome.result.Admission.Runs) != 2 {
				t.Fatalf("concurrent capacity admission %d=%#v", outcome.index, outcome.result)
			}
			succeededAdmissions++
		case errors.Is(outcome.err, runadmission.ErrQueueCapacityExceeded):
			capacityRejectedAdmissions++
		default:
			t.Fatalf("concurrent capacity admission %d error=%v", outcome.index, outcome.err)
		}
	}
	if succeededAdmissions != 1 || capacityRejectedAdmissions != 1 {
		t.Fatalf(
			"concurrent capacity outcomes succeeded=%d rejected=%d",
			succeededAdmissions, capacityRejectedAdmissions,
		)
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
	if _, err := admin.Exec(ctx, `UPDATE delivery.source_connections
		SET document = jsonb_set(document, '{status,health}', '"PENDING"')
		WHERE tenant_id = 'tenant-one' AND id = $1`, connectionID); err != nil {
		t.Fatalf("make current source connection unavailable: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE delivery.repository_bindings
		SET document = jsonb_set(document, '{status,health}', '"PENDING"')
		WHERE tenant_id = 'tenant-one' AND id = $1`, bindingOne.ID); err != nil {
		t.Fatalf("make admitted repository binding unavailable: %v", err)
	}
	replayAfterDraftReplacement, err := ingressUsecase.Receive(ctx, firstAdmissionCommand)
	if err != nil || !replayAfterDraftReplacement.Replayed ||
		len(replayAfterDraftReplacement.Admission.Runs) != 2 {
		t.Fatalf("replay after mutable draft replacement=%#v err=%v", replayAfterDraftReplacement, err)
	}
	readPipeline, err := usecase.GetPipeline(ctx, pipelineconfiguration.GetPipelineQuery{
		Authorization: auth(iamv1.ActionDevOpsPipelineRead, iamv1.ResourcePipeline, pipelineID),
		PipelineID:    pipelineID,
	})
	if err != nil || readPipeline.Metadata.ResourceVersion != thirdActivation.Value.Pipeline.Metadata.ResourceVersion {
		t.Fatalf("read current Pipeline=%#v err=%v", readPipeline, err)
	}
	readRevision, err := usecase.GetPipelineRevision(ctx, pipelineconfiguration.GetPipelineRevisionQuery{
		Authorization: auth(iamv1.ActionDevOpsPipelineRead, iamv1.ResourcePipeline, pipelineID),
		PipelineID:    pipelineID, PipelineRevisionID: firstActivation.Value.Revision.ID,
	})
	if err != nil || readRevision.ID != firstActivation.Value.Revision.ID ||
		readRevision.ContentDigest != firstActivation.Value.Revision.ContentDigest {
		t.Fatalf("read immutable PipelineRevision=%#v err=%v", readRevision, err)
	}
	_, err = usecase.GetPipelineRevision(ctx, pipelineconfiguration.GetPipelineRevisionQuery{
		Authorization: auth(iamv1.ActionDevOpsPipelineRead, iamv1.ResourcePipeline, "pipeline-other"),
		PipelineID:    "pipeline-other", PipelineRevisionID: firstActivation.Value.Revision.ID,
	})
	if !errors.Is(err, pipelineconfiguration.ErrNotFound) {
		t.Fatalf("cross-parent PipelineRevision error=%v", err)
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
	err = repository.WithinAdmissionTransaction(ctx, "tenant-other", func(
		ctx context.Context,
		tx runadmission.Transaction,
	) error {
		_, found, err := tx.LoadAdmission(ctx, firstAdmission.Admission.Event.ID)
		if err != nil {
			return err
		}
		if found {
			return errors.New("cross-tenant SourceEvent was visible")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("forced RLS cross-tenant admission read: %v", err)
	}
	queuedRun := firstAdmission.Admission.Runs[0]
	if readRun, err := runController.Get(ctx, runcontrol.GetQuery{
		Authorization: auth(iamv1.ActionDevOpsRunRead, iamv1.ResourcePipelineRun, queuedRun.ID),
		RunID:         queuedRun.ID,
	}); err != nil || readRun != queuedRun {
		t.Fatalf("read authorized PipelineRun=%#v err=%v", readRun, err)
	}
	otherTenantRead := auth(iamv1.ActionDevOpsRunRead, iamv1.ResourcePipelineRun, queuedRun.ID)
	otherTenantRead.TenantID = "tenant-other"
	if _, err := runController.Get(ctx, runcontrol.GetQuery{
		Authorization: otherTenantRead, RunID: queuedRun.ID,
	}); !errors.Is(err, runcontrol.ErrNotFound) {
		t.Fatalf("cross-tenant PipelineRun read error=%v", err)
	}
	queuedCancellation := runcontrol.CancelCommand{
		Authorization: auth(iamv1.ActionDevOpsRunCancel, iamv1.ResourcePipelineRun, queuedRun.ID),
		RunID:         queuedRun.ID, ExpectedResourceVersion: queuedRun.Status.ResourceVersion,
		IdempotencyKey: "cancel-queued-integration",
	}
	cancelledQueued, err := runController.Cancel(ctx, queuedCancellation)
	if err != nil || cancelledQueued.Replayed ||
		cancelledQueued.Value.Status.State != devopsv1.PipelineRunCancelled ||
		cancelledQueued.Value.Status.CancellationRequestedAt == nil ||
		cancelledQueued.Value.Status.CompletedAt == nil {
		t.Fatalf("cancel queued PipelineRun=%#v err=%v", cancelledQueued, err)
	}
	replayedQueued, err := runController.Cancel(ctx, queuedCancellation)
	if err != nil || !replayedQueued.Replayed || !reflect.DeepEqual(replayedQueued.Value, cancelledQueued.Value) {
		t.Fatalf("replay queued PipelineRun cancellation=%#v err=%v", replayedQueued, err)
	}
	changedQueued := queuedCancellation
	changedQueued.ExpectedResourceVersion++
	if _, err := runController.Cancel(ctx, changedQueued); !errors.Is(err, runcontrol.ErrIdempotencyConflict) {
		t.Fatalf("changed PipelineRun cancellation replay error=%v", err)
	}

	runReplay := runcontrol.ReplayCommand{
		Authorization: auth(
			iamv1.ActionDevOpsRunReplay, iamv1.ResourcePipelineRun,
			cancelledQueued.Value.ID,
		),
		SourceRunID:             cancelledQueued.Value.ID,
		ExpectedResourceVersion: cancelledQueued.Value.Status.ResourceVersion,
		IdempotencyKey:          "replay-terminal-integration",
	}
	replayedRun, err := runController.Replay(ctx, runReplay)
	if err != nil || replayedRun.Replayed || replayedRun.Value.Replay == nil ||
		replayedRun.Value.Replay.SourceRunID != cancelledQueued.Value.ID ||
		replayedRun.Value.Replay.RequestedBy != runReplay.Authorization.Subject ||
		!reflect.DeepEqual(replayedRun.Value.Input, cancelledQueued.Value.Input) ||
		replayedRun.Value.InputDigest != cancelledQueued.Value.InputDigest ||
		replayedRun.Value.Status.State != devopsv1.PipelineRunQueued ||
		replayedRun.Value.Status.ResourceVersion != 1 {
		t.Fatalf("replay terminal PipelineRun=%#v err=%v", replayedRun, err)
	}
	readReplayedRun, err := runController.Get(ctx, runcontrol.GetQuery{
		Authorization: auth(
			iamv1.ActionDevOpsRunRead, iamv1.ResourcePipelineRun, replayedRun.Value.ID,
		),
		RunID: replayedRun.Value.ID,
	})
	if err != nil || !reflect.DeepEqual(readReplayedRun, replayedRun.Value) {
		t.Fatalf("read replayed PipelineRun=%#v err=%v", readReplayedRun, err)
	}
	exactRunReplay, err := runController.Replay(ctx, runReplay)
	if err != nil || !exactRunReplay.Replayed ||
		!reflect.DeepEqual(exactRunReplay.Value, replayedRun.Value) {
		t.Fatalf("equal manual replay=%#v err=%v", exactRunReplay, err)
	}
	changedRunReplay := runReplay
	changedRunReplay.ExpectedResourceVersion++
	if _, err := runController.Replay(ctx, changedRunReplay); !errors.Is(err, runcontrol.ErrIdempotencyConflict) {
		t.Fatalf("changed manual replay error=%v", err)
	}
	capacityRunReplay := runReplay
	capacityRunReplay.IdempotencyKey = "replay-terminal-at-capacity"
	if _, err := runController.Replay(ctx, capacityRunReplay); !errors.Is(err, runcontrol.ErrQueueCapacityExceeded) {
		t.Fatalf("manual replay queue-capacity error=%v", err)
	}
	nonterminalRun := firstAdmission.Admission.Runs[1]
	if _, err := runController.Replay(ctx, runcontrol.ReplayCommand{
		Authorization: auth(
			iamv1.ActionDevOpsRunReplay, iamv1.ResourcePipelineRun, nonterminalRun.ID,
		),
		SourceRunID:             nonterminalRun.ID,
		ExpectedResourceVersion: nonterminalRun.Status.ResourceVersion,
		IdempotencyKey:          "replay-nonterminal-integration",
	}); !errors.Is(err, runcontrol.ErrNotTerminal) {
		t.Fatalf("nonterminal manual replay error=%v", err)
	}
	staleRunReplay := runReplay
	staleRunReplay.ExpectedResourceVersion--
	staleRunReplay.IdempotencyKey = "replay-stale-integration"
	if _, err := runController.Replay(ctx, staleRunReplay); !errors.Is(err, runcontrol.ErrResourceVersionConflict) {
		t.Fatalf("stale manual replay error=%v", err)
	}
	otherTenantReplay := runReplay
	otherTenantReplay.Authorization.TenantID = "tenant-other"
	otherTenantReplay.IdempotencyKey = "replay-other-tenant-integration"
	if _, err := runController.Replay(ctx, otherTenantReplay); !errors.Is(err, runcontrol.ErrNotFound) {
		t.Fatalf("cross-tenant manual replay error=%v", err)
	}
	cancelledReplay, err := runController.Cancel(ctx, runcontrol.CancelCommand{
		Authorization: auth(
			iamv1.ActionDevOpsRunCancel, iamv1.ResourcePipelineRun, replayedRun.Value.ID,
		),
		RunID:                   replayedRun.Value.ID,
		ExpectedResourceVersion: replayedRun.Value.Status.ResourceVersion,
		IdempotencyKey:          "cancel-replayed-run-integration",
	})
	if err != nil || cancelledReplay.Value.Replay == nil ||
		cancelledReplay.Value.Replay.SourceRunID != cancelledQueued.Value.ID ||
		cancelledReplay.Value.Status.State != devopsv1.PipelineRunCancelled {
		t.Fatalf("cancel replayed PipelineRun=%#v err=%v", cancelledReplay, err)
	}
	exactReplayAfterTransition, err := runController.Replay(ctx, runReplay)
	if err != nil || !exactReplayAfterTransition.Replayed ||
		!reflect.DeepEqual(exactReplayAfterTransition.Value, replayedRun.Value) {
		t.Fatalf("equal replay after result transition=%#v err=%v", exactReplayAfterTransition, err)
	}
	descendantReplay, err := runController.Replay(ctx, runcontrol.ReplayCommand{
		Authorization: auth(
			iamv1.ActionDevOpsRunReplay, iamv1.ResourcePipelineRun,
			cancelledReplay.Value.ID,
		),
		SourceRunID:             cancelledReplay.Value.ID,
		ExpectedResourceVersion: cancelledReplay.Value.Status.ResourceVersion,
		IdempotencyKey:          "replay-replayed-run-integration",
	})
	if err != nil || descendantReplay.Value.Replay == nil ||
		descendantReplay.Value.Replay.SourceRunID != replayedRun.Value.ID ||
		descendantReplay.Value.Replay.SourceRunID == cancelledQueued.Value.ID ||
		!reflect.DeepEqual(descendantReplay.Value.Input, cancelledQueued.Value.Input) ||
		descendantReplay.Value.InputDigest != cancelledQueued.Value.InputDigest {
		t.Fatalf("replay descendant=%#v err=%v", descendantReplay, err)
	}
	var prematureTaskCount int
	if err := admin.QueryRow(ctx, `SELECT count(*)
		FROM delivery.pipeline_run_tasks
		WHERE run_id IN ($1, $2)`, replayedRun.Value.ID, descendantReplay.Value.ID).Scan(
		&prematureTaskCount,
	); err != nil || prematureTaskCount != 0 {
		t.Fatalf("manual replay created executor intent count=%d err=%v", prematureTaskCount, err)
	}
	admissionAfterManualReplay, err := ingressUsecase.Receive(ctx, firstAdmissionCommand)
	if err != nil || !admissionAfterManualReplay.Replayed ||
		len(admissionAfterManualReplay.Admission.Runs) != 2 ||
		admissionAfterManualReplay.Admission.Runs[0].Replay != nil ||
		admissionAfterManualReplay.Admission.Runs[1].Replay != nil {
		t.Fatalf("source replay included manual descendants=%#v err=%v", admissionAfterManualReplay, err)
	}
	forgedReplayTransaction, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forgedReplayTransaction.Exec(
		ctx, `SELECT set_config('matrix.devops_tenant_id', 'tenant-one', true)`,
	); err != nil {
		t.Fatal(err)
	}
	_, err = forgedReplayTransaction.Exec(
		ctx, `SELECT delivery.commit_pipeline_run_replay(1, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb)`,
	)
	assertPostgresCode(t, err, "22023")
	if err := forgedReplayTransaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	assertDenied(t, func() error {
		_, err := pool.Exec(ctx, `INSERT INTO delivery.projects (tenant_id,id,resource_version,document) VALUES ('tenant-one','forbidden',1,'{}')`)
		return err
	})
	assertDenied(t, func() error {
		_, err := pool.Exec(ctx, `INSERT INTO delivery.source_events DEFAULT VALUES`)
		return err
	})
	assertDenied(t, func() error { _, err := pool.Exec(ctx, `SELECT count(*) FROM delivery.audit_operations`); return err })
	assertDenied(t, func() error { _, err := pool.Exec(ctx, `SELECT count(*) FROM delivery.audit_outbox`); return err })
	readiness, err := repository.Readiness(ctx)
	if err != nil || readiness.State != devopsv1.ReadinessReady {
		t.Fatalf("DevOps API readiness=%#v err=%v", readiness, err)
	}
	workerPool, err := pgxpool.New(ctx, workerDSN)
	if err != nil {
		t.Fatal("connect DevOps worker pool")
	}
	defer workerPool.Close()
	assertDenied(t, func() error { _, err := workerPool.Exec(ctx, `SELECT count(*) FROM delivery.projects`); return err })
	assertDenied(t, func() error {
		_, err := workerPool.Exec(ctx, `SELECT count(*) FROM delivery.source_events`)
		return err
	})
	assertDenied(t, func() error {
		_, err := workerPool.Exec(ctx, `SELECT count(*) FROM delivery.pipeline_run_tasks`)
		return err
	})
	assertDenied(t, func() error {
		_, err := workerPool.Exec(
			ctx, `SELECT * FROM delivery.lock_pipeline_run_for_replay($1, $2)`,
			queuedRun.ID, queuedRun.Status.ResourceVersion,
		)
		return err
	})
	assertDenied(t, func() error {
		_, err := workerPool.Exec(
			ctx, `SELECT delivery.commit_pipeline_run_replay(1, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb)`,
		)
		return err
	})
	assertDenied(t, func() error {
		_, err := pool.Exec(ctx, `SELECT count(*) FROM delivery.pipeline_run_tasks`)
		return err
	})
	assertRunLifecyclePersistenceAndFencing(t, ctx, admin, workerPool, runController)
	assertTerminalAuditFacts(t, ctx, admin)
	assertCancellationAuditFacts(t, ctx, admin)
	assertReplayAuditFacts(t, ctx, admin)
	outbox, err := devopspostgres.NewAuditOutboxRepository(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	workerReadiness, err := outbox.Readiness(ctx)
	if err != nil || workerReadiness.State != devopsv1.ReadinessReady {
		t.Fatalf("DevOps Audit worker readiness=%#v err=%v", workerReadiness, err)
	}
	snapshot, err := outbox.Snapshot(ctx)
	if err != nil || snapshot.Pending != 75 || snapshot.Delivered != 0 {
		t.Fatalf("initial Audit outbox snapshot=%#v err=%v", snapshot, err)
	}
	for index := 0; index < 75; index++ {
		claim, found, err := outbox.Claim(ctx, "audit-worker-integration", 30*time.Second)
		if err != nil || !found {
			t.Fatalf("claim Audit event %d=%#v found=%t err=%v", index, claim, found, err)
		}
		if err := auditv1.ValidateEventForSource(auditv1.SourceDevOps, claim.Event); err != nil {
			t.Fatalf("claimed Audit event %d: %v", index, err)
		}
		if index == 0 {
			err = outbox.Complete(ctx, auditdispatch.Completion{
				TenantID: claim.TenantID, EventID: claim.EventID, WorkerID: "audit-worker-integration",
				FencingToken: claim.FencingToken + 1, Outcome: auditdispatch.OutcomeDelivered,
			})
			if !errors.Is(err, auditdispatch.ErrStaleLease) {
				t.Fatalf("stale Audit fence error=%v", err)
			}
		}
		if err := outbox.Complete(ctx, auditdispatch.Completion{
			TenantID: claim.TenantID, EventID: claim.EventID, WorkerID: "audit-worker-integration",
			FencingToken: claim.FencingToken, Outcome: auditdispatch.OutcomeDelivered,
		}); err != nil {
			t.Fatalf("complete Audit event %d: %v", index, err)
		}
	}
	if claim, found, err := outbox.Claim(ctx, "audit-worker-integration", 30*time.Second); err != nil || found {
		t.Fatalf("empty Audit claim=%#v found=%t err=%v", claim, found, err)
	}
	snapshot, err = outbox.Snapshot(ctx)
	if err != nil || snapshot.Delivered != 75 || snapshot.Pending != 0 || snapshot.Leased != 0 ||
		snapshot.Retry != 0 || snapshot.DeadLetter != 0 || snapshot.ExpiredLease != 0 {
		t.Fatalf("delivered Audit outbox snapshot=%#v err=%v", snapshot, err)
	}
	if err := devopsmigration.Apply(ctx, adminDSN, apiDSN, workerDSN); err != nil {
		t.Fatalf("reapply DevOps migration with durable admission data: %v", err)
	}
	if err := devopsmigration.VerifyInstalled(ctx, adminDSN, apiDSN, workerDSN); err != nil {
		t.Fatalf("verify reapplied DevOps migration with durable admission data: %v", err)
	}

	var mutationCount, sourceEventCount, runCount, runTaskCount, operationCount int
	var auditCount, bindingRevisionCount, pipelineRevisionCount int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM delivery.mutations),
		(SELECT count(*) FROM delivery.source_events),
		(SELECT count(*) FROM delivery.pipeline_runs),
		(SELECT count(*) FROM delivery.pipeline_run_tasks),
		(SELECT count(*) FROM delivery.audit_operations),
		(SELECT count(*) FROM delivery.audit_outbox),
		(SELECT count(*) FROM delivery.repository_binding_revisions WHERE binding_id = 'binding-integration-one'),
		(SELECT count(*) FROM delivery.pipeline_revisions WHERE pipeline_id = 'pipeline-integration')`).Scan(
		&mutationCount, &sourceEventCount, &runCount, &runTaskCount, &operationCount,
		&auditCount, &bindingRevisionCount, &pipelineRevisionCount,
	); err != nil {
		t.Fatalf("read delivery evidence: %v", err)
	}
	if mutationCount != 20 || sourceEventCount != 16 || runCount != 34 || runTaskCount != 9 ||
		operationCount != 75 || auditCount != 75 ||
		bindingRevisionCount != 2 || pipelineRevisionCount != 3 {
		t.Fatalf(
			"evidence counts mutation=%d event=%d run=%d task=%d operation=%d audit=%d binding=%d pipeline=%d",
			mutationCount, sourceEventCount, runCount, runTaskCount, operationCount,
			auditCount, bindingRevisionCount, pipelineRevisionCount,
		)
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

func assertTerminalAuditFacts(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT operation.operation_kind, operation.target_id, outbox.document
		FROM delivery.audit_operations AS operation
		JOIN delivery.audit_outbox AS outbox
		  ON outbox.tenant_id = operation.tenant_id AND outbox.operation_id = operation.id
		WHERE operation.operation_kind = 'PIPELINE_RUN_TERMINAL'
		ORDER BY operation.id`)
	if err != nil {
		t.Fatalf("read PipelineRun terminal Audit facts: %v", err)
	}
	defer rows.Close()
	counts := map[auditv1.Outcome]int{}
	actorCounts := map[auditv1.ActorID]int{}
	count := 0
	for rows.Next() {
		var operationKind, targetID string
		var document []byte
		if err := rows.Scan(&operationKind, &targetID, &document); err != nil {
			t.Fatal(err)
		}
		var event auditv1.Event
		if err := json.Unmarshal(document, &event); err != nil {
			t.Fatalf("decode PipelineRun terminal Audit fact: %v", err)
		}
		if err := auditv1.ValidateEventForSource(auditv1.SourceDevOps, event); err != nil ||
			operationKind != "PIPELINE_RUN_TERMINAL" || event.Action != auditv1.ActionDevOpsPipelineRunCompleted ||
			event.Target.ID != targetID ||
			(event.Actor.ID != "system-devops-run-worker" && event.Actor.ID != "system-devops-run-control") ||
			event.IAMDecisionID != "" {
			t.Fatalf("PipelineRun terminal Audit fact=%#v operation=%s target=%s err=%v", event, operationKind, targetID, err)
		}
		counts[event.Outcome]++
		actorCounts[event.Actor.ID]++
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 7 || counts[auditv1.OutcomeSucceeded] != 1 ||
		counts[auditv1.OutcomeCancelled] != 5 || counts[auditv1.OutcomeManualIntervention] != 1 ||
		counts[auditv1.OutcomeFailed] != 0 || actorCounts["system-devops-run-worker"] != 5 ||
		actorCounts["system-devops-run-control"] != 2 {
		t.Fatalf("PipelineRun terminal Audit outcome counts=%#v actors=%#v total=%d", counts, actorCounts, count)
	}
}

func assertCancellationAuditFacts(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT operation.target_id, mutation.document, outbox.document
		FROM delivery.audit_operations AS operation
		JOIN delivery.mutations AS mutation
		  ON mutation.tenant_id = operation.tenant_id AND mutation.id = operation.id
		JOIN delivery.audit_outbox AS outbox
		  ON outbox.tenant_id = operation.tenant_id AND outbox.operation_id = operation.id
		WHERE operation.operation_kind = 'PIPELINE_RUN_CANCELLATION'
		ORDER BY operation.id`)
	if err != nil {
		t.Fatalf("read PipelineRun cancellation facts: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var targetID string
		var operationDocument, eventDocument []byte
		if err := rows.Scan(&targetID, &operationDocument, &eventDocument); err != nil {
			t.Fatal(err)
		}
		var operation runcontrol.CancellationOperation
		var event auditv1.Event
		if err := json.Unmarshal(operationDocument, &operation); err != nil {
			t.Fatalf("decode PipelineRun cancellation Operation: %v", err)
		}
		if err := json.Unmarshal(eventDocument, &event); err != nil {
			t.Fatalf("decode PipelineRun cancellation Audit fact: %v", err)
		}
		if err := runcontrol.ValidateCancellationOperation(operation); err != nil ||
			auditv1.ValidateEventForSource(auditv1.SourceDevOps, event) != nil ||
			string(operation.RunID) != targetID || event.Target.ID != targetID ||
			event.Action != auditv1.ActionDevOpsPipelineRunCancellationRequested ||
			event.Result != auditv1.ResultAccepted || event.Outcome != "" || event.Reason != "" ||
			event.Actor.ID != auditv1.ActorID(operation.RequestedBy.ID) ||
			string(event.IAMDecisionID) != operation.IAMDecisionID {
			t.Fatalf("PipelineRun cancellation operation=%#v event=%#v target=%s err=%v",
				operation, event, targetID, err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("PipelineRun cancellation fact count=%d", count)
	}
}

func assertReplayAuditFacts(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT operation.target_id, mutation.command_target_id,
		mutation.document, mutation.result_document, outbox.document
		FROM delivery.audit_operations AS operation
		JOIN delivery.mutations AS mutation
		  ON mutation.tenant_id = operation.tenant_id AND mutation.id = operation.id
		JOIN delivery.audit_outbox AS outbox
		  ON outbox.tenant_id = operation.tenant_id AND outbox.operation_id = operation.id
		WHERE operation.operation_kind = 'PIPELINE_RUN_REPLAY'
		ORDER BY operation.id`)
	if err != nil {
		t.Fatalf("read PipelineRun replay facts: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var targetID, sourceRunID string
		var operationDocument, resultDocument, eventDocument []byte
		if err := rows.Scan(
			&targetID, &sourceRunID, &operationDocument, &resultDocument, &eventDocument,
		); err != nil {
			t.Fatal(err)
		}
		var operation runcontrol.ReplayOperation
		var result devopsv1.PipelineRun
		var event auditv1.Event
		if err := json.Unmarshal(operationDocument, &operation); err != nil {
			t.Fatalf("decode PipelineRun replay Operation: %v", err)
		}
		if err := json.Unmarshal(resultDocument, &result); err != nil {
			t.Fatalf("decode PipelineRun replay result: %v", err)
		}
		if err := json.Unmarshal(eventDocument, &event); err != nil {
			t.Fatalf("decode PipelineRun replay Audit fact: %v", err)
		}
		if err := runcontrol.ValidateStoredReplay(runcontrol.StoredReplay{
			Operation: operation, Result: result,
		}); err != nil || auditv1.ValidateEventForSource(auditv1.SourceDevOps, event) != nil ||
			string(operation.SourceRunID) != sourceRunID || string(result.ID) != targetID ||
			result.Replay == nil || string(result.Replay.CommandID) != operation.ID ||
			event.Action != auditv1.ActionDevOpsPipelineRunReplayed ||
			event.Target.ID != targetID || event.Result != auditv1.ResultAccepted ||
			event.Actor.ID != auditv1.ActorID(operation.RequestedBy.ID) ||
			string(event.IAMDecisionID) != operation.IAMDecisionID {
			t.Fatalf("PipelineRun replay operation=%#v result=%#v event=%#v source=%s target=%s err=%v",
				operation, result, event, sourceRunID, targetID, err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("PipelineRun replay fact count=%d", count)
	}
}

func assertRunLifecyclePersistenceAndFencing(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	workerPool *pgxpool.Pool,
	runController *runcontrol.Service,
) {
	t.Helper()
	repository, err := devopspostgres.NewRunTaskRepository(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := runlifecycle.NewQueue(repository, runlifecycle.Config{LeaseDuration: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	first, found, err := queue.ClaimNext(ctx, "run-worker-first")
	if err != nil || !found || first.Mode != runlifecycle.ClaimExecute ||
		first.Run.Status.State != devopsv1.PipelineRunFetching ||
		first.Intent.Stage != devopsv1.PipelineRunStageFetch || first.FencingToken != 1 {
		t.Fatalf("first PipelineRun task claim=%#v found=%t err=%v", first, found, err)
	}
	renewedFirst, err := queue.Renew(ctx, first)
	if err != nil || renewedFirst.LeaseExpiresAt.Before(first.LeaseExpiresAt) {
		t.Fatalf("renew first PipelineRun task=%#v err=%v", renewedFirst, err)
	}
	makeRunTaskDue(t, ctx, admin, first.Intent.CommandID)
	recovered, found, err := queue.ClaimNext(ctx, "run-worker-recovered")
	if err != nil || !found || recovered.Mode != runlifecycle.ClaimObserve ||
		recovered.Run.ID != first.Run.ID || recovered.Intent != first.Intent ||
		recovered.FencingToken != first.FencingToken+1 {
		t.Fatalf("recovered PipelineRun task claim=%#v found=%t err=%v", recovered, found, err)
	}
	if _, err := queue.Renew(ctx, first); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("stale PipelineRun task renewal error=%v", err)
	}
	_, err = queue.Advance(ctx, runlifecycle.Transition{
		Lease: first, State: devopsv1.PipelineRunVerifying,
	})
	if !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("stale PipelineRun task fence error=%v", err)
	}
	if _, err := queue.Advance(ctx, runlifecycle.Transition{
		Lease: recovered, State: devopsv1.PipelineRunVerifying,
	}); err != nil {
		t.Fatalf("complete recovered fetch task: %v", err)
	}
	verify := claimExpectedRunStage(
		t, ctx, queue, recovered.Run.ID, devopsv1.PipelineRunVerifying,
		devopsv1.PipelineRunStageVerify,
	)
	if _, err := queue.Advance(ctx, runlifecycle.Transition{
		Lease: verify, State: devopsv1.PipelineRunReporting,
	}); err != nil {
		t.Fatalf("complete verify task: %v", err)
	}
	report := claimExpectedRunStage(
		t, ctx, queue, recovered.Run.ID, devopsv1.PipelineRunReporting,
		devopsv1.PipelineRunStageReport,
	)
	succeeded, err := queue.Advance(ctx, runlifecycle.Transition{
		Lease:  report,
		State:  devopsv1.PipelineRunSucceeded,
		Reason: devopsv1.PipelineRunReasonCompleted,
	})
	if err != nil || succeeded.Status.CompletedAt == nil {
		t.Fatalf("complete successful PipelineRun=%#v err=%v", succeeded, err)
	}

	fetch := claimExpectedRunStage(
		t, ctx, queue, "", devopsv1.PipelineRunFetching,
		devopsv1.PipelineRunStageFetch,
	)
	if _, err := queue.Advance(ctx, runlifecycle.Transition{
		Lease: fetch, State: devopsv1.PipelineRunVerifying,
	}); err != nil {
		t.Fatalf("advance reconciliation run to verify: %v", err)
	}
	verify = claimExpectedRunStage(
		t, ctx, queue, fetch.Run.ID, devopsv1.PipelineRunVerifying,
		devopsv1.PipelineRunStageVerify,
	)
	if _, err := queue.Advance(ctx, runlifecycle.Transition{
		Lease: verify, State: devopsv1.PipelineRunReporting,
	}); err != nil {
		t.Fatalf("advance reconciliation run to report: %v", err)
	}
	report = claimExpectedRunStage(
		t, ctx, queue, fetch.Run.ID, devopsv1.PipelineRunReporting,
		devopsv1.PipelineRunStageReport,
	)
	reconciling, err := queue.MarkReportUncertain(ctx, runlifecycle.Reconciliation{
		Lease: report, NextAttemptAt: databaseFuture(),
	})
	if err != nil || reconciling.Status.State != devopsv1.PipelineRunReconciling {
		t.Fatalf("mark report uncertain=%#v err=%v", reconciling, err)
	}
	makeRunTaskDue(t, ctx, admin, report.Intent.CommandID)
	observed := claimExpectedRunStage(
		t, ctx, queue, fetch.Run.ID, devopsv1.PipelineRunReconciling,
		devopsv1.PipelineRunStageReport,
	)
	if observed.Mode != runlifecycle.ClaimObserve || observed.Intent.CommandID != report.Intent.CommandID {
		t.Fatalf("reconciliation replaced report intent: %#v", observed)
	}
	for expected := uint64(1); expected <= runlifecycle.MaximumReconciliationAttempts; expected++ {
		attempts, err := queue.DeferReconciliation(ctx, runlifecycle.Reconciliation{
			Lease: observed, NextAttemptAt: databaseFuture(),
		})
		if err != nil || attempts != expected {
			t.Fatalf("defer reconciliation %d returned %d: %v", expected, attempts, err)
		}
		makeRunTaskDue(t, ctx, admin, report.Intent.CommandID)
		observed = claimExpectedRunStage(
			t, ctx, queue, fetch.Run.ID, devopsv1.PipelineRunReconciling,
			devopsv1.PipelineRunStageReport,
		)
		if observed.ReconciliationAttempts != expected {
			t.Fatalf("reconciliation attempts=%d want=%d", observed.ReconciliationAttempts, expected)
		}
	}
	if _, err := queue.DeferReconciliation(ctx, runlifecycle.Reconciliation{
		Lease: observed, NextAttemptAt: databaseFuture(),
	}); !errors.Is(err, runlifecycle.ErrReconciliationExhausted) {
		t.Fatalf("exhausted reconciliation deferral error=%v", err)
	}
	manual, err := queue.Advance(ctx, runlifecycle.Transition{
		Lease:  observed,
		State:  devopsv1.PipelineRunManualIntervention,
		Reason: devopsv1.PipelineRunReasonReconciliationExhausted,
	})
	if err != nil || manual.Status.CompletedAt == nil {
		t.Fatalf("complete manual-intervention PipelineRun=%#v err=%v", manual, err)
	}

	cancelledTask := claimExpectedRunStage(
		t, ctx, queue, "", devopsv1.PipelineRunFetching,
		devopsv1.PipelineRunStageFetch,
	)
	pending, err := runController.Cancel(ctx, runcontrol.CancelCommand{
		Authorization: auth(
			iamv1.ActionDevOpsRunCancel, iamv1.ResourcePipelineRun, cancelledTask.Run.ID,
		),
		RunID: cancelledTask.Run.ID, ExpectedResourceVersion: cancelledTask.Run.Status.ResourceVersion,
		IdempotencyKey: "cancel-active-integration",
	})
	if err != nil || pending.Value.Status.CompletedAt != nil ||
		pending.Value.Status.CancellationRequestedAt == nil ||
		pending.Value.Status.State != devopsv1.PipelineRunFetching {
		t.Fatalf("request active PipelineRun cancellation=%#v err=%v", pending, err)
	}
	if _, err := queue.Renew(ctx, cancelledTask); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("cancelled PipelineRun retained its old lease: %v", err)
	}
	staleCancellation := cancelledTask
	staleCancellation.Run = pending.Value
	if _, err := queue.Advance(ctx, runlifecycle.Transition{
		Lease: staleCancellation, State: devopsv1.PipelineRunCancelled,
		Reason: devopsv1.PipelineRunReasonCancelled,
	}); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("cancelled PipelineRun accepted its old fence: %v", err)
	}
	recoveredCancellation := claimExpectedRunStage(
		t, ctx, queue, cancelledTask.Run.ID, devopsv1.PipelineRunFetching,
		devopsv1.PipelineRunStageFetch,
	)
	if recoveredCancellation.Mode != runlifecycle.ClaimObserve ||
		recoveredCancellation.Intent != cancelledTask.Intent ||
		recoveredCancellation.Run.Status.CancellationRequestedAt == nil {
		t.Fatalf("cancelled PipelineRun did not recover its exact intent: %#v", recoveredCancellation)
	}
	cancelled, err := queue.Advance(ctx, runlifecycle.Transition{
		Lease: recoveredCancellation, State: devopsv1.PipelineRunCancelled,
		Reason: devopsv1.PipelineRunReasonCancelled,
	})
	if err != nil || cancelled.Status.CompletedAt == nil ||
		cancelled.Status.Stage != devopsv1.PipelineRunStageFetch ||
		cancelled.Status.CancellationRequestedAt == nil ||
		!cancelled.Status.CancellationRequestedAt.Equal(*pending.Value.Status.CancellationRequestedAt) {
		t.Fatalf("complete active PipelineRun cancellation=%#v err=%v", cancelled, err)
	}

	type claimResult struct {
		lease runlifecycle.Lease
		found bool
		err   error
	}
	startClaims := make(chan struct{})
	claimResults := make(chan claimResult, 3)
	for index := 0; index < 3; index++ {
		index := index
		go func() {
			<-startClaims
			lease, found, err := queue.ClaimNext(ctx, fmt.Sprintf("run-worker-quota-%d", index))
			claimResults <- claimResult{lease: lease, found: found, err: err}
		}()
	}
	close(startClaims)
	activeRuns := make([]runlifecycle.Lease, 0, runlifecycle.MaximumActiveRuns)
	for range 3 {
		result := <-claimResults
		if result.err != nil {
			t.Fatalf("concurrent active-run claim: %v", result.err)
		}
		if result.found {
			activeRuns = append(activeRuns, result.lease)
		}
	}
	if uint64(len(activeRuns)) != runlifecycle.MaximumActiveRuns ||
		activeRuns[0].Run.ID == activeRuns[1].Run.ID {
		t.Fatalf("concurrent active-run quota claims=%#v", activeRuns)
	}
	for _, active := range activeRuns {
		pending, err := runController.Cancel(ctx, runcontrol.CancelCommand{
			Authorization: auth(
				iamv1.ActionDevOpsRunCancel, iamv1.ResourcePipelineRun, active.Run.ID,
			),
			RunID: active.Run.ID, ExpectedResourceVersion: active.Run.Status.ResourceVersion,
			IdempotencyKey: "cancel-quota-" + string(active.Run.ID),
		})
		if err != nil || pending.Value.Status.CancellationRequestedAt == nil ||
			pending.Value.Status.CompletedAt != nil {
			t.Fatalf("request quota PipelineRun cancellation=%#v err=%v", pending, err)
		}
		if _, err := queue.Renew(ctx, active); !errors.Is(err, runlifecycle.ErrStaleLease) {
			t.Fatalf("quota PipelineRun retained its old lease: %v", err)
		}
		recovered = claimExpectedRunStage(
			t, ctx, queue, active.Run.ID, devopsv1.PipelineRunFetching,
			devopsv1.PipelineRunStageFetch,
		)
		if _, err := queue.Advance(ctx, runlifecycle.Transition{
			Lease:  recovered,
			State:  devopsv1.PipelineRunCancelled,
			Reason: devopsv1.PipelineRunReasonCancelled,
		}); err != nil {
			t.Fatalf("cancel quota test PipelineRun: %v", err)
		}
	}
}

func claimExpectedRunStage(
	t *testing.T,
	ctx context.Context,
	queue *runlifecycle.Queue,
	expectedRunID devopsv1.ResourceID,
	expectedState devopsv1.PipelineRunState,
	expectedStage devopsv1.PipelineRunStage,
) runlifecycle.Lease {
	t.Helper()
	lease, found, err := queue.ClaimNext(ctx, "run-worker-current")
	if err != nil || !found ||
		(expectedRunID != "" && lease.Run.ID != expectedRunID) ||
		lease.Run.Status.State != expectedState || lease.Intent.Stage != expectedStage {
		t.Fatalf(
			"claim %s/%s run=%s returned %#v found=%t err=%v",
			expectedState, expectedStage, expectedRunID, lease, found, err,
		)
	}
	return lease
}

func makeRunTaskDue(t *testing.T, ctx context.Context, admin *pgx.Conn, commandID string) {
	t.Helper()
	result, err := admin.Exec(
		ctx,
		`UPDATE delivery.pipeline_run_tasks
		    SET available_at = transaction_timestamp(),
		        lease_expires_at = CASE
		            WHEN lease_owner IS NULL THEN NULL
		            ELSE transaction_timestamp() - interval '1 microsecond'
		        END
		  WHERE command_id = $1 AND status = 'INTENT'`,
		commandID,
	)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("make PipelineRun task due rows=%d err=%v", result.RowsAffected(), err)
	}
}

func databaseFuture() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
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

func sourceAdmissionCommand(
	connectionID devopsv1.ResourceID,
	externalRepositoryID devopsv1.ResourceID,
	deliveryID string,
) runadmission.Command {
	return runadmission.Command{
		Change: domain.NormalizedChange{
			Scope:                           devopsv1.ResourceScope{TenantID: "tenant-one"},
			SourceConnectionID:              connectionID,
			VerifiedSourceConnectionVersion: 2,
			ExternalRepositoryID:            externalRepositoryID,
			TrustedBaseBranch:               "release",
			DeliveryID:                      deliveryID,
			CanonicalPayloadDigest:          "sha256:" + strings.Repeat("a", 64),
			Change: devopsv1.ChangeIdentity{
				Number: 42, Action: devopsv1.ChangeUpdated,
				HeadCommit:        strings.Repeat("1", 40),
				TrustedBaseCommit: strings.Repeat("2", 40),
			},
		},
		RequestID: "request-admission-integration", CorrelationID: "correlation-admission-integration",
		TraceParent: "00-5bf92f3577b34da6a3ce929d0e0e4736-10f067aa0ba902b7-01",
	}
}

func signedGiteaIngressCommand(secret []byte, changed bool) sourceingress.Command {
	extra := ""
	if changed {
		extra = `,"sender":{"id":99,"login":"ignored-provider-user"}`
	}
	body := []byte(fmt.Sprintf(`{
  "action":"synchronized",
  "number":42,
  "repository":{
    "id":42,
    "full_name":"matrix/service",
    "url":"https://gitea.example.com/api/v1/repos/matrix/service",
    "html_url":"https://gitea.example.com/matrix/service",
    "clone_url":"https://gitea.example.com/matrix/service.git",
    "object_format_name":"sha1"
  },
  "pull_request":{
    "number":42,
    "base":{
      "ref":"release",
      "sha":"%s",
      "repo_id":42,
      "repo":{
        "id":42,
        "full_name":"matrix/service",
        "url":"https://gitea.example.com/api/v1/repos/matrix/service",
        "html_url":"https://gitea.example.com/matrix/service",
        "clone_url":"https://gitea.example.com/matrix/service.git",
        "object_format_name":"sha1"
      }
    },
    "head":{"ref":"feature/change","sha":"%s","repo_id":77}
  }%s
}`, strings.Repeat("2", 40), strings.Repeat("1", 40), extra))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return sourceingress.Command{
		Scope:              devopsv1.ResourceScope{TenantID: "tenant-one"},
		SourceConnectionID: "connection-integration", ProviderEvent: "pull_request",
		DeliveryID: "123e4567-e89b-42d3-a456-426614174001",
		Signature:  hex.EncodeToString(mac.Sum(nil)), Body: body,
		RequestID: "request-admission-integration", CorrelationID: "correlation-admission-integration",
		TraceParent: "00-5bf92f3577b34da6a3ce929d0e0e4736-10f067aa0ba902b7-01",
	}
}

func assertDenied(t *testing.T, action func() error) {
	t.Helper()
	err := action()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "42501" {
		t.Fatalf("database action error=%v, want permission denied", err)
	}
}

func assertPostgresCode(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("database action error=%v, want PostgreSQL code %s", err, code)
	}
}
