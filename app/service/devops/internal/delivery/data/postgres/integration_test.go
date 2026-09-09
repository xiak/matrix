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

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/gitea"
	devopspostgres "github.com/xiak/matrix/app/service/devops/internal/delivery/data/postgres"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/sourcecredentialfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/auditdispatch"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/buildexecution"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/checkreporting"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceobservation"
	devopsmigration "github.com/xiak/matrix/app/service/devops/migration"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
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
		SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN (
			'matrix_devops_api_login', 'matrix_devops_check_reporter_login',
			'matrix_devops_worker_login',
			'matrix_devops_source_fetcher_login',
			'matrix_devops_source_observer_login'
		)
	)`).Scan(&clean); err != nil || !clean {
		t.Fatal("DevOps integration database is not clean")
	}

	apiDSN := runtimeDSN(t, adminDSN, "matrix_devops_api_login", "mxp1.devops-api-000000000000000000000000000000")
	checkReporterDSN := runtimeDSN(t, adminDSN, "matrix_devops_check_reporter_login", "mxp1.devops-check-reporter-000000000000000000000")
	workerDSN := runtimeDSN(t, adminDSN, "matrix_devops_worker_login", "mxp1.devops-worker-0000000000000000000000000000")
	sourceFetcherDSN := runtimeDSN(t, adminDSN, "matrix_devops_source_fetcher_login", "mxp1.devops-source-fetcher-000000000000000000000")
	sourceObserverDSN := runtimeDSN(t, adminDSN, "matrix_devops_source_observer_login", "mxp1.devops-source-observer-0000000000000000000")
	for attempt := 1; attempt <= 2; attempt++ {
		if err := devopsmigration.Apply(ctx, adminDSN, apiDSN, checkReporterDSN, sourceFetcherDSN, sourceObserverDSN, workerDSN); err != nil {
			t.Fatalf("apply DevOps migration attempt %d: %v", attempt, err)
		}
	}
	if err := devopsmigration.VerifyInstalled(ctx, adminDSN, apiDSN, checkReporterDSN, sourceFetcherDSN, sourceObserverDSN, workerDSN); err != nil {
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
	sourceFetcherPool, err := pgxpool.New(ctx, sourceFetcherDSN)
	if err != nil {
		t.Fatal("connect DevOps source fetcher pool")
	}
	defer sourceFetcherPool.Close()
	sourceFetcher, err := devopspostgres.NewSourceAcquisitionRepository(sourceFetcherPool)
	if err != nil {
		t.Fatal(err)
	}
	workerPool, err := pgxpool.New(ctx, workerDSN)
	if err != nil {
		t.Fatal("connect DevOps worker pool")
	}
	defer workerPool.Close()
	checkReporterPool, err := pgxpool.New(ctx, checkReporterDSN)
	if err != nil {
		t.Fatal("connect DevOps check reporter pool")
	}
	defer checkReporterPool.Close()
	checkRepository, err := devopspostgres.NewCheckReportingRepository(checkReporterPool)
	if err != nil {
		t.Fatal(err)
	}
	assertCheckReporterAuthorityAndHeartbeat(t, ctx, checkReporterPool, checkRepository)
	assertSourceFetcherAuthorityAndHeartbeat(
		t, ctx, sourceFetcherPool, sourceFetcher, repository,
	)
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
		AdapterID: "source-adapter-gitea-v1", EndpointOrigin: "https://gitea.example.com",
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

	observedConnectionVersion := assertSourceObservationPersistenceAndFencing(
		t, ctx, admin, sourceObserverDSN, pool, repository, usecase,
		connectionID, []devopsv1.ResourceID{bindingOne.ID, bindingTwo.ID}, connectionSpec,
	)
	ingressConnection, found, err := repository.ReadSourceConnection(
		ctx, devopsv1.ResourceScope{TenantID: "tenant-one"}, connectionID,
	)
	if err != nil || !found ||
		ingressConnection.Metadata.ResourceVersion != observedConnectionVersion ||
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
	secretDirectory, err := sourcecredential.DirectoryName(
		sourcecredential.PurposeWebhook,
		devopsv1.ResourceScope{TenantID: "tenant-one"}, rotated.WebhookSecretRef,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(secretRoot, secretDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	webhookSecret := []byte("integration-webhook-secret-000000001")
	material, err := sourcecredential.NewMaterial(
		sourcecredential.PurposeWebhook, webhookSecret, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	materialBytes, err := sourcecredential.Encode(sourcecredential.PurposeWebhook, material)
	material.Clear()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(materialBytes)
	if err := os.WriteFile(
		filepath.Join(secretRoot, secretDirectory, sourcecredential.MaterialFilename),
		materialBytes, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	secretResolver, err := sourcecredentialfile.NewResolver(
		sourcecredential.PurposeWebhook, secretRoot,
	)
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
			observedConnectionVersion,
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
				observedConnectionVersion,
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
		SET document = jsonb_set(
			jsonb_set(document, '{status,health}', '"PENDING"'),
			'{status,reason}', '"CONFIGURATION_CHANGED"'
		)
		WHERE tenant_id = 'tenant-one' AND id = $1`, connectionID); err != nil {
		t.Fatalf("make current source connection unavailable: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE delivery.repository_bindings
		SET document = jsonb_set(
			jsonb_set(document, '{status,health}', '"PENDING"'),
			'{status,reason}', '"CONFIGURATION_CHANGED"'
		)
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
	buildRepository, err := devopspostgres.NewBuildExecutionRepository(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	assertBuildWorkerAuthorityAndHeartbeat(t, ctx, workerPool, buildRepository)
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
	assertRunLifecyclePersistenceAndFencing(
		t, ctx, admin, pool, workerPool, checkReporterPool, sourceFetcher, buildRepository,
		checkRepository, runController,
	)
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
	if err != nil || snapshot.Pending != 88 || snapshot.Delivered != 0 {
		t.Fatalf("initial Audit outbox snapshot=%#v err=%v", snapshot, err)
	}
	for index := 0; index < 88; index++ {
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
	if err != nil || snapshot.Delivered != 88 || snapshot.Pending != 0 || snapshot.Leased != 0 ||
		snapshot.Retry != 0 || snapshot.DeadLetter != 0 || snapshot.ExpiredLease != 0 {
		t.Fatalf("delivered Audit outbox snapshot=%#v err=%v", snapshot, err)
	}
	legacySourceStatements := []struct {
		query string
		args  []any
	}{
		{query: `UPDATE delivery.source_connections
		   SET document = jsonb_set(
				document #- '{spec,endpointOrigin}' #- '{status,reason}',
				'{spec,allowedEndpointOrigins}',
				jsonb_build_array(document#>'{spec,endpointOrigin}'),
				true
		   )
		 WHERE tenant_id = 'tenant-one' AND id = $1`, args: []any{connectionID}},
		{query: `UPDATE delivery.repository_bindings
		   SET document = document #- '{status,reason}'
		 WHERE tenant_id = 'tenant-one' AND id = $1`, args: []any{bindingOne.ID}},
		{query: `UPDATE delivery.repository_binding_revisions
		   SET document = document #- '{status,reason}'
		 WHERE tenant_id = 'tenant-one' AND binding_id = $1`, args: []any{bindingOne.ID}},
		{query: `UPDATE delivery.mutations
		   SET result_document = jsonb_set(
				result_document #- '{sourceConnection,spec,endpointOrigin}' #- '{sourceConnection,status,reason}',
				'{sourceConnection,spec,allowedEndpointOrigins}',
				jsonb_build_array(result_document#>'{sourceConnection,spec,endpointOrigin}'),
				true
		   )
		 WHERE tenant_id = 'tenant-one'
		   AND mutation_kind = 'CREATE_SOURCE_CONNECTION'`},
		{query: `UPDATE delivery.mutations
		   SET result_document = result_document #- '{repositoryBinding,status,reason}'
		 WHERE tenant_id = 'tenant-one'
		   AND mutation_kind = 'CREATE_REPOSITORY_BINDING'`},
	}
	for index, statement := range legacySourceStatements {
		if _, err := admin.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("stage legacy source contract fixture %d: %v", index, err)
		}
	}
	if err := devopsmigration.Apply(ctx, adminDSN, apiDSN, checkReporterDSN, sourceFetcherDSN, sourceObserverDSN, workerDSN); err != nil {
		t.Fatalf("reapply DevOps migration with durable admission data: %v", err)
	}
	if err := devopsmigration.VerifyInstalled(ctx, adminDSN, apiDSN, checkReporterDSN, sourceFetcherDSN, sourceObserverDSN, workerDSN); err != nil {
		t.Fatalf("verify reapplied DevOps migration with durable admission data: %v", err)
	}
	var migratedOrigin, connectionReason, bindingReason, revisionReason string
	var mutationOrigin, mutationConnectionReason, mutationBindingReason string
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT document#>>'{spec,endpointOrigin}'
		   FROM delivery.source_connections
		  WHERE tenant_id = 'tenant-one' AND id = $1),
		(SELECT document#>>'{status,reason}'
		   FROM delivery.source_connections
		  WHERE tenant_id = 'tenant-one' AND id = $1),
		(SELECT document#>>'{status,reason}'
		   FROM delivery.repository_bindings
		  WHERE tenant_id = 'tenant-one' AND id = $2),
		(SELECT document#>>'{status,reason}'
		   FROM delivery.repository_binding_revisions
		  WHERE tenant_id = 'tenant-one' AND binding_id = $2
		  ORDER BY resource_version LIMIT 1),
		(SELECT result_document#>>'{sourceConnection,spec,endpointOrigin}'
		   FROM delivery.mutations
		  WHERE tenant_id = 'tenant-one' AND mutation_kind = 'CREATE_SOURCE_CONNECTION'),
		(SELECT result_document#>>'{sourceConnection,status,reason}'
		   FROM delivery.mutations
		  WHERE tenant_id = 'tenant-one' AND mutation_kind = 'CREATE_SOURCE_CONNECTION'),
		(SELECT result_document#>>'{repositoryBinding,status,reason}'
		   FROM delivery.mutations
		  WHERE tenant_id = 'tenant-one' AND mutation_kind = 'CREATE_REPOSITORY_BINDING'
		  ORDER BY created_at LIMIT 1)
	`, connectionID, bindingOne.ID).Scan(
		&migratedOrigin, &connectionReason, &bindingReason, &revisionReason,
		&mutationOrigin, &mutationConnectionReason, &mutationBindingReason,
	); err != nil {
		t.Fatalf("read migrated source contract: %v", err)
	}
	if migratedOrigin != connectionSpec.EndpointOrigin || mutationOrigin != connectionSpec.EndpointOrigin ||
		connectionReason != string(devopsv1.SourceConnectionReasonConfigurationChanged) ||
		bindingReason != string(devopsv1.RepositoryBindingReasonConfigurationChanged) ||
		revisionReason != string(devopsv1.RepositoryBindingReasonConfigurationChanged) ||
		mutationConnectionReason != string(devopsv1.SourceConnectionReasonConfigurationChanged) ||
		mutationBindingReason != string(devopsv1.RepositoryBindingReasonConfigurationChanged) {
		t.Fatalf(
			"migrated source contract origin=%q/%q reason=%q/%q/%q/%q/%q",
			migratedOrigin, mutationOrigin, connectionReason, bindingReason,
			revisionReason, mutationConnectionReason, mutationBindingReason,
		)
	}

	var mutationCount, sourceEventCount, runCount, runTaskCount, operationCount int
	var buildReceiptCount int
	var auditCount, bindingRevisionCount, pipelineRevisionCount int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM delivery.mutations),
		(SELECT count(*) FROM delivery.source_events),
		(SELECT count(*) FROM delivery.pipeline_runs),
		(SELECT count(*) FROM delivery.pipeline_run_tasks),
		(SELECT count(*) FROM delivery.audit_operations),
		(SELECT count(*) FROM delivery.audit_outbox),
		(SELECT count(*) FROM delivery.build_receipts),
		(SELECT count(*) FROM delivery.repository_binding_revisions WHERE binding_id = 'binding-integration-one'),
		(SELECT count(*) FROM delivery.pipeline_revisions WHERE pipeline_id = 'pipeline-integration')`).Scan(
		&mutationCount, &sourceEventCount, &runCount, &runTaskCount, &operationCount,
		&auditCount, &buildReceiptCount, &bindingRevisionCount, &pipelineRevisionCount,
	); err != nil {
		t.Fatalf("read delivery evidence: %v", err)
	}
	if mutationCount != 23 || sourceEventCount != 16 || runCount != 34 || runTaskCount != 10 ||
		operationCount != 88 || auditCount != 88 || buildReceiptCount != 2 ||
		bindingRevisionCount != 2 || pipelineRevisionCount != 3 {
		t.Fatalf(
			"evidence counts mutation=%d event=%d run=%d task=%d operation=%d audit=%d build=%d binding=%d pipeline=%d",
			mutationCount, sourceEventCount, runCount, runTaskCount, operationCount,
			auditCount, buildReceiptCount, bindingRevisionCount, pipelineRevisionCount,
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
	if _, err := admin.Exec(ctx, `UPDATE delivery.source_connections
		SET document = jsonb_set(
			document #- '{spec,endpointOrigin}',
			'{spec,allowedEndpointOrigins}',
			jsonb_build_array('"https://gitea.example.com"'::jsonb, '"https://mirror.example.com"'::jsonb),
			true
		)
		WHERE tenant_id = 'tenant-one' AND id = $1`, connectionID); err != nil {
		t.Fatalf("stage ambiguous legacy source contract: %v", err)
	}
	if err := devopsmigration.Apply(ctx, adminDSN, apiDSN, checkReporterDSN, sourceFetcherDSN, sourceObserverDSN, workerDSN); err == nil {
		t.Fatal("ambiguous legacy source endpoint migration succeeded")
	}
	if _, err := admin.Exec(ctx, `UPDATE delivery.source_connections
		SET document = jsonb_set(
			document #- '{spec,allowedEndpointOrigins}',
			'{spec,endpointOrigin}',
			'"https://gitea.example.com"'::jsonb,
			true
		)
		WHERE tenant_id = 'tenant-one' AND id = $1`, connectionID); err != nil {
		t.Fatalf("restore exact source endpoint after negative gate: %v", err)
	}
}

func assertSourceFetcherAuthorityAndHeartbeat(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	sourceFetcher *devopspostgres.SourceAcquisitionRepository,
	controlPlane *devopspostgres.ControlPlaneRepository,
) {
	t.Helper()
	readiness, err := sourceFetcher.Readiness(ctx)
	if err != nil || readiness.State != devopsv1.ReadinessNotReady {
		t.Fatalf("source fetcher admitted a missing heartbeat=%#v err=%v", readiness, err)
	}
	apiReadiness, err := controlPlane.Readiness(ctx)
	if err != nil || apiReadiness.State != devopsv1.ReadinessNotReady {
		t.Fatalf("DevOps API admitted a missing source fetcher=%#v err=%v", apiReadiness, err)
	}
	for _, table := range []string{
		"pipeline_runs", "pipeline_run_tasks", "source_archives",
		"source_fetcher_heartbeat", "source_connections",
	} {
		table := table
		assertDenied(t, func() error {
			_, deniedErr := pool.Exec(ctx, `SELECT count(*) FROM delivery.`+table)
			return deniedErr
		})
	}
	assertDenied(t, func() error {
		_, deniedErr := pool.Exec(
			ctx, `SELECT * FROM delivery.claim_check_report_task('forged-fetcher', 30)`,
		)
		return deniedErr
	})
	var callableFunctions int
	if err := pool.QueryRow(ctx, `SELECT count(*)
		  FROM pg_catalog.pg_proc AS procedure
		  JOIN pg_catalog.pg_namespace AS namespace
		    ON namespace.oid = procedure.pronamespace
		 WHERE namespace.nspname = 'delivery'
		   AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')`).Scan(
		&callableFunctions,
	); err != nil || callableFunctions != 5 {
		t.Fatalf("source fetcher callable function count=%d err=%v", callableFunctions, err)
	}
	if _, err := sourceFetcher.Heartbeat(ctx, "source-fetcher-integration"); err != nil {
		t.Fatalf("record source fetcher heartbeat: %v", err)
	}
	readiness, err = sourceFetcher.Readiness(ctx)
	if err != nil || readiness.State != devopsv1.ReadinessReady {
		t.Fatalf("source fetcher readiness=%#v err=%v", readiness, err)
	}
	apiReadiness, err = controlPlane.Readiness(ctx)
	if err != nil || apiReadiness.State != devopsv1.ReadinessReady {
		t.Fatalf("DevOps API source-fetcher readiness=%#v err=%v", apiReadiness, err)
	}
}

func assertCheckReporterAuthorityAndHeartbeat(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	repository *devopspostgres.CheckReportingRepository,
) {
	t.Helper()
	readiness, err := repository.Readiness(ctx)
	if err != nil || readiness.State != devopsv1.ReadinessNotReady {
		t.Fatalf("check reporter admitted a missing heartbeat=%#v err=%v", readiness, err)
	}
	for _, table := range []string{
		"source_connections", "repository_binding_revisions", "pipeline_revisions",
		"pipeline_runs", "pipeline_run_tasks", "build_receipts", "check_receipts",
		"check_reporter_heartbeat", "audit_operations", "audit_outbox",
	} {
		table := table
		assertDenied(t, func() error {
			_, deniedErr := pool.Exec(ctx, `SELECT count(*) FROM delivery.`+table)
			return deniedErr
		})
	}
	assertDenied(t, func() error {
		_, deniedErr := pool.Exec(ctx, `SELECT delivery.advance_pipeline_run_task(
			'tenant-one', 'pipeline-run-000000000000000000000000000000000000000000000000',
			'pipeline-run-000000000000000000000000000000000000000000000000:report:1',
			'check-reporter-forged', 1, 'SUCCEEDED', 'COMPLETED', '{}'::jsonb, '{}'::jsonb
		)`)
		return deniedErr
	})
	_, err = pool.Exec(ctx, `SELECT * FROM delivery.claim_pipeline_run_task(
		'generic-report-worker', 30
	)`)
	assertPostgresCode(t, err, "42883")
	for _, query := range []string{
		`SELECT * FROM delivery.claim_source_fetch_task('forged-reporter', 30)`,
		`SELECT * FROM delivery.claim_build_task('forged-reporter', 30)`,
		`SELECT * FROM delivery.claim_audit_event('forged-reporter', 30)`,
		`SELECT * FROM delivery.worker_readiness()`,
	} {
		query := query
		assertDenied(t, func() error {
			_, deniedErr := pool.Exec(ctx, query)
			return deniedErr
		})
	}
	var callableFunctions int
	if err := pool.QueryRow(ctx, `SELECT count(*)
		  FROM pg_catalog.pg_proc AS procedure
		  JOIN pg_catalog.pg_namespace AS namespace
		    ON namespace.oid = procedure.pronamespace
		 WHERE namespace.nspname = 'delivery'
		   AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')`).Scan(
		&callableFunctions,
	); err != nil || callableFunctions != 6 {
		t.Fatalf("check reporter callable function count=%d err=%v", callableFunctions, err)
	}
	if _, err := repository.Heartbeat(ctx, "check-reporter-integration"); err != nil {
		t.Fatalf("record check reporter heartbeat: %v", err)
	}
	readiness, err = repository.Readiness(ctx)
	if err != nil || readiness.State != devopsv1.ReadinessReady {
		t.Fatalf("check reporter readiness=%#v err=%v", readiness, err)
	}
}

func assertBuildWorkerAuthorityAndHeartbeat(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	repository *devopspostgres.BuildExecutionRepository,
) {
	t.Helper()
	readiness, err := repository.Readiness(ctx)
	if err != nil || readiness.State != devopsv1.ReadinessNotReady {
		t.Fatalf("build worker admitted a missing heartbeat=%#v err=%v", readiness, err)
	}
	for _, table := range []string{
		"pipeline_runs", "pipeline_run_tasks", "source_archives",
		"build_receipts", "build_worker_heartbeat", "pipeline_revisions",
	} {
		table := table
		assertDenied(t, func() error {
			_, deniedErr := pool.Exec(ctx, `SELECT count(*) FROM delivery.`+table)
			return deniedErr
		})
	}
	assertDenied(t, func() error {
		_, deniedErr := pool.Exec(
			ctx, `SELECT * FROM delivery.claim_source_fetch_task('forged-build-worker', 30)`,
		)
		return deniedErr
	})
	if _, err := repository.Heartbeat(ctx, "build-worker-integration"); err != nil {
		t.Fatalf("record build worker heartbeat: %v", err)
	}
	readiness, err = repository.Readiness(ctx)
	if err != nil || readiness.State != devopsv1.ReadinessReady {
		t.Fatalf("build worker readiness=%#v err=%v", readiness, err)
	}
}

func assertSourceObservationPersistenceAndFencing(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	sourceObserverDSN string,
	apiPool *pgxpool.Pool,
	apiRepository *devopspostgres.ControlPlaneRepository,
	configuration *pipelineconfiguration.Usecase,
	connectionID devopsv1.ResourceID,
	bindingIDs []devopsv1.ResourceID,
	connectionSpec devopsv1.SourceConnectionSpec,
) uint64 {
	t.Helper()
	apiReadiness, err := apiRepository.Readiness(ctx)
	if err != nil || apiReadiness.State != devopsv1.ReadinessNotReady {
		t.Fatalf("DevOps API admitted a missing source observer=%#v err=%v", apiReadiness, err)
	}
	sourcePool, err := pgxpool.New(ctx, sourceObserverDSN)
	if err != nil {
		t.Fatal("connect DevOps source observer pool")
	}
	defer sourcePool.Close()
	repository, err := devopspostgres.NewSourceObservationRepository(sourcePool)
	if err != nil {
		t.Fatal(err)
	}
	sourceReadiness, err := repository.Readiness(ctx)
	if err != nil || sourceReadiness.State != devopsv1.ReadinessNotReady {
		t.Fatalf("source observer admitted a missing heartbeat=%#v err=%v", sourceReadiness, err)
	}
	assertDenied(t, func() error {
		_, deniedErr := sourcePool.Exec(ctx, `SELECT count(*) FROM delivery.source_observation_tasks`)
		return deniedErr
	})
	assertDenied(t, func() error {
		_, deniedErr := sourcePool.Exec(ctx, `SELECT * FROM delivery.readiness()`)
		return deniedErr
	})
	assertDenied(t, func() error {
		_, deniedErr := apiPool.Exec(
			ctx, `SELECT delivery.record_source_observer_heartbeat('forged-api')`,
		)
		return deniedErr
	})
	if _, err := repository.Heartbeat(ctx, "source-observer-integration"); err != nil {
		t.Fatalf("record source observer heartbeat: %v", err)
	}
	sourceReadiness, err = repository.Readiness(ctx)
	if err != nil || sourceReadiness.State != devopsv1.ReadinessReady {
		t.Fatalf("source observer readiness=%#v err=%v", sourceReadiness, err)
	}
	apiReadiness, err = apiRepository.Readiness(ctx)
	if err != nil || apiReadiness.State != devopsv1.ReadinessReady {
		t.Fatalf("DevOps API source readiness=%#v err=%v", apiReadiness, err)
	}

	connectionLease, found, err := repository.Claim(
		ctx, "source-observer-integration", sourceobservation.LeaseDuration,
	)
	if err != nil || !found || connectionLease.Kind != sourceobservation.WorkSourceConnection ||
		connectionLease.ResourceID != connectionID {
		t.Fatalf("claim source connection=%#v found=%t err=%v", connectionLease, found, err)
	}
	observedConnection, err := repository.CompleteSourceConnection(
		ctx,
		connectionLease,
		domain.SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionReady,
			Reason: devopsv1.SourceConnectionReasonObserved,
		},
	)
	if err != nil || observedConnection.Status.Health != devopsv1.SourceConnectionReady {
		t.Fatalf("complete source connection=%#v err=%v", observedConnection, err)
	}

	pendingBindings := make(map[devopsv1.ResourceID]bool, len(bindingIDs))
	for _, bindingID := range bindingIDs {
		pendingBindings[bindingID] = true
	}
	for range bindingIDs {
		lease, found, err := repository.Claim(
			ctx, "source-observer-integration", sourceobservation.LeaseDuration,
		)
		if err != nil || !found || lease.Kind != sourceobservation.WorkRepositoryBinding ||
			!pendingBindings[lease.ResourceID] {
			t.Fatalf("claim repository binding=%#v found=%t err=%v", lease, found, err)
		}
		observedBinding, err := repository.CompleteRepositoryBinding(
			ctx,
			lease,
			domain.RepositoryBindingHealthObservation{
				Health: devopsv1.RepositoryBindingReady,
				Reason: devopsv1.RepositoryBindingReasonObserved,
			},
		)
		if err != nil || observedBinding.Status.Health != devopsv1.RepositoryBindingReady {
			t.Fatalf("complete repository binding=%#v err=%v", observedBinding, err)
		}
		delete(pendingBindings, lease.ResourceID)
	}
	if len(pendingBindings) != 0 {
		t.Fatalf("unobserved repository bindings=%v", pendingBindings)
	}

	fairProjectID := devopsv1.ResourceID("project-source-fairness")
	if _, err := configuration.CreateProject(ctx, pipelineconfiguration.CreateProjectCommand{
		Authorization: authForTenant(
			"tenant-two", iamv1.ActionDevOpsProjectCreate,
			iamv1.ResourceDevOpsProject, fairProjectID,
		),
		Request: devopsv1.CreateDevOpsProjectRequest{
			ID: fairProjectID, Name: "project-source-fairness",
		},
		IdempotencyKey: "create-project-source-fairness",
	}); err != nil {
		t.Fatalf("create source fairness project: %v", err)
	}
	fairConnectionID := devopsv1.ResourceID("connection-source-fairness")
	if _, err := configuration.CreateSourceConnection(
		ctx,
		pipelineconfiguration.CreateSourceConnectionCommand{
			Authorization: authForTenant(
				"tenant-two", iamv1.ActionDevOpsSourceConnectionCreate,
				iamv1.ResourceSourceConnection, fairConnectionID,
			),
			Request: devopsv1.CreateSourceConnectionRequest{
				ID: fairConnectionID, Name: "connection-source-fairness",
				Spec: connectionSpec,
			},
			IdempotencyKey: "create-connection-source-fairness",
		},
	); err != nil {
		t.Fatalf("create source fairness connection: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE delivery.source_observation_tasks
		SET available_at = created_at
		WHERE tenant_id = 'tenant-one'
		  AND resource_kind = 'SOURCE_CONNECTION' AND resource_id = $1`, connectionID); err != nil {
		t.Fatalf("make older tenant source task due: %v", err)
	}
	fairLease, found, err := repository.Claim(
		ctx, "source-observer-integration", sourceobservation.LeaseDuration,
	)
	if err != nil || !found || fairLease.TenantID != "tenant-two" ||
		fairLease.ResourceID != fairConnectionID {
		t.Fatalf("tenant-fair source claim=%#v found=%t err=%v", fairLease, found, err)
	}
	if _, err := repository.CompleteSourceConnection(
		ctx,
		fairLease,
		domain.SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionUnavailable,
			Reason: devopsv1.SourceConnectionReasonSecretUnavailable,
		},
	); err != nil {
		t.Fatalf("complete fair-tenant source observation: %v", err)
	}

	staleLease, found, err := repository.Claim(
		ctx, "source-observer-integration", sourceobservation.LeaseDuration,
	)
	if err != nil || !found || staleLease.TenantID != "tenant-one" ||
		staleLease.ResourceID != connectionID {
		t.Fatalf("claim source fencing fixture=%#v found=%t err=%v", staleLease, found, err)
	}
	result, err := admin.Exec(ctx, `UPDATE delivery.source_observation_tasks
		SET lease_owner = NULL, lease_expires_at = NULL
		WHERE tenant_id = $1 AND resource_kind = $2 AND resource_id = $3
		  AND fencing_token = $4`,
		staleLease.TenantID, staleLease.Kind, staleLease.ResourceID, staleLease.FencingToken,
	)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("release source fencing fixture rows=%d err=%v", result.RowsAffected(), err)
	}
	currentLease, found, err := repository.Claim(
		ctx, "source-observer-integration", sourceobservation.LeaseDuration,
	)
	if err != nil || !found || currentLease.ResourceID != connectionID ||
		currentLease.FencingToken <= staleLease.FencingToken {
		t.Fatalf("reclaim source fencing fixture=%#v found=%t err=%v", currentLease, found, err)
	}
	equalObservation := domain.SourceConnectionHealthObservation{
		Health: devopsv1.SourceConnectionReady,
		Reason: devopsv1.SourceConnectionReasonObserved,
	}
	if _, err := repository.CompleteSourceConnection(
		ctx, staleLease, equalObservation,
	); !errors.Is(err, sourceobservation.ErrStaleLease) {
		t.Fatalf("stale source fencing completion error=%v", err)
	}
	refreshedConnection, err := repository.CompleteSourceConnection(
		ctx, currentLease, equalObservation,
	)
	if err != nil || refreshedConnection.Status.Health != devopsv1.SourceConnectionReady ||
		refreshedConnection.Metadata.ResourceVersion != observedConnection.Metadata.ResourceVersion+1 {
		t.Fatalf("equal source health refresh=%#v err=%v", refreshedConnection, err)
	}

	if _, err := admin.Exec(ctx, `UPDATE delivery.source_observation_tasks
		SET available_at = created_at
		WHERE tenant_id = 'tenant-two'
		  AND resource_kind = 'SOURCE_CONNECTION' AND resource_id = $1`, fairConnectionID); err != nil {
		t.Fatalf("make stale-version source fixture due: %v", err)
	}
	staleVersionLease, found, err := repository.Claim(
		ctx, "source-observer-integration", sourceobservation.LeaseDuration,
	)
	if err != nil || !found || staleVersionLease.TenantID != "tenant-two" ||
		staleVersionLease.ResourceID != fairConnectionID {
		t.Fatalf("claim stale-version source fixture=%#v found=%t err=%v", staleVersionLease, found, err)
	}
	updatedFairSpec := connectionSpec
	updatedFairSpec.FetchCredentialRef = "secret-fetch-fairness-v2"
	if _, err := configuration.UpdateSourceConnection(
		ctx,
		pipelineconfiguration.UpdateSourceConnectionCommand{
			Authorization: authForTenant(
				"tenant-two", iamv1.ActionDevOpsSourceConnectionUpdate,
				iamv1.ResourceSourceConnection, fairConnectionID,
			),
			SourceConnectionID:      fairConnectionID,
			ExpectedResourceVersion: staleVersionLease.ResourceVersion,
			Request: devopsv1.UpdateSourceConnectionRequest{
				Spec: updatedFairSpec,
			},
			IdempotencyKey: "update-connection-source-fairness",
		},
	); err != nil {
		t.Fatalf("update stale-version source fixture: %v", err)
	}
	if _, err := repository.CompleteSourceConnection(
		ctx,
		staleVersionLease,
		domain.SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionUnavailable,
			Reason: devopsv1.SourceConnectionReasonSecretUnavailable,
		},
	); !errors.Is(err, sourceobservation.ErrStaleLease) {
		t.Fatalf("stale source resource-version completion error=%v", err)
	}
	currentVersionLease, found, err := repository.Claim(
		ctx, "source-observer-integration", sourceobservation.LeaseDuration,
	)
	if err != nil || !found || currentVersionLease.TenantID != "tenant-two" ||
		currentVersionLease.ResourceID != fairConnectionID ||
		currentVersionLease.ResourceVersion != staleVersionLease.ResourceVersion+1 {
		t.Fatalf("claim current source version=%#v found=%t err=%v", currentVersionLease, found, err)
	}
	if _, err := repository.CompleteSourceConnection(
		ctx,
		currentVersionLease,
		domain.SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionUnavailable,
			Reason: devopsv1.SourceConnectionReasonSecretUnavailable,
		},
	); err != nil {
		t.Fatalf("complete current source version: %v", err)
	}

	var healthOperations, healthEvents, connectionEvents, bindingEvents, sanitizedEvents int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM delivery.audit_operations
		  WHERE operation_kind = 'SOURCE_HEALTH_OBSERVATION'),
		count(*),
		count(*) FILTER (
			WHERE document->>'action' = 'devops.source-connection.health-transitioned'
		),
		count(*) FILTER (
			WHERE document->>'action' = 'devops.repository-binding.health-transitioned'
		),
		count(*) FILTER (
			WHERE document#>>'{actor,id}' = 'system-devops-source-observer'
			  AND document::text NOT LIKE '%gitea.example.com%'
			  AND document::text NOT LIKE '%secret-%'
		)
		FROM delivery.audit_outbox
		WHERE operation_id LIKE 'source-observation-%'`).Scan(
		&healthOperations, &healthEvents, &connectionEvents, &bindingEvents,
		&sanitizedEvents,
	); err != nil || healthOperations != 5 || healthEvents != 5 ||
		connectionEvents != 3 || bindingEvents != 2 || sanitizedEvents != 5 {
		t.Fatalf(
			"source health Audit operations=%d events=%d connection=%d binding=%d sanitized=%d err=%v",
			healthOperations, healthEvents, connectionEvents, bindingEvents,
			sanitizedEvents, err,
		)
	}
	return refreshedConnection.Metadata.ResourceVersion
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
	if count != 8 || counts[auditv1.OutcomeSucceeded] != 1 ||
		counts[auditv1.OutcomeCancelled] != 5 || counts[auditv1.OutcomeManualIntervention] != 1 ||
		counts[auditv1.OutcomeFailed] != 1 || actorCounts["system-devops-run-worker"] != 6 ||
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
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	checkReporterPool *pgxpool.Pool,
	sourceFetcher *devopspostgres.SourceAcquisitionRepository,
	buildRepository *devopspostgres.BuildExecutionRepository,
	checkRepository *devopspostgres.CheckReportingRepository,
	runController *runcontrol.Service,
) {
	t.Helper()
	if command, found, err := checkRepository.Claim(
		ctx, "check-reporter-no-fetch", checkreporting.LeaseDuration,
	); err != nil || found {
		t.Fatalf("check reporter claimed FETCH=%#v found=%t err=%v", command, found, err)
	}
	firstCommand, found, err := sourceFetcher.Claim(
		ctx, "source-fetcher-first", sourceacquisition.LeaseDuration,
	)
	first := firstCommand.Lease
	if err != nil || !found || first.Mode != runlifecycle.ClaimExecute ||
		first.Run.Status.State != devopsv1.PipelineRunFetching ||
		first.Intent.Stage != devopsv1.PipelineRunStageFetch || first.FencingToken != 1 {
		t.Fatalf("first PipelineRun task claim=%#v found=%t err=%v", first, found, err)
	}
	_, err = admin.Exec(
		ctx,
		`SELECT delivery.advance_pipeline_run_task(
		    $1, $2, $3, $4, $5, 'VERIFYING', NULL, '{}'::jsonb, NULL
		)`,
		first.TenantID,
		first.Run.ID,
		first.Intent.CommandID,
		first.WorkerID,
		int64(first.FencingToken),
	)
	assertPostgresCode(t, err, "55000")
	renewedFirst, err := sourceFetcher.Renew(
		ctx, first.Guard(), sourceacquisition.LeaseDuration,
	)
	if err != nil || renewedFirst.Before(first.LeaseExpiresAt) {
		t.Fatalf("renew first PipelineRun task=%s err=%v", renewedFirst, err)
	}
	makeRunTaskDue(t, ctx, admin, first.Intent.CommandID)
	recoveredCommand, found, err := sourceFetcher.Claim(
		ctx, "source-fetcher-recovered", sourceacquisition.LeaseDuration,
	)
	recovered := recoveredCommand.Lease
	if err != nil || !found || recovered.Mode != runlifecycle.ClaimObserve ||
		recovered.Run.ID != first.Run.ID || recovered.Intent != first.Intent ||
		recovered.FencingToken != first.FencingToken+1 {
		t.Fatalf("recovered PipelineRun task claim=%#v found=%t err=%v", recovered, found, err)
	}
	if _, err := sourceFetcher.Renew(
		ctx, first.Guard(), sourceacquisition.LeaseDuration,
	); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("stale PipelineRun task renewal error=%v", err)
	}
	if _, err := sourceFetcher.Complete(ctx, sourceacquisition.Completion{
		Command: recoveredCommand,
		State:   devopsv1.PipelineRunVerifying,
		Receipt: sourceArchiveReceipt(recoveredCommand),
	}); err != nil {
		t.Fatalf("complete recovered fetch task: %v", err)
	}
	if command, found, err := checkRepository.Claim(
		ctx, "check-reporter-no-verify", checkreporting.LeaseDuration,
	); err != nil || found {
		t.Fatalf("check reporter claimed VERIFY=%#v found=%t err=%v", command, found, err)
	}
	firstBuild := claimExpectedBuild(
		t, ctx, buildRepository, recovered.Run.ID, runlifecycle.ClaimExecute,
	)
	assertBuildReceiptTamperRejected(t, ctx, admin, workerPool, firstBuild)
	assertDenied(t, func() error {
		_, deniedErr := workerPool.Exec(ctx, `SELECT delivery.advance_pipeline_run_task(
			$1, $2, $3, $4, $5, 'REPORTING', NULL::text, '{}'::jsonb, NULL::jsonb
		)`, firstBuild.Lease.TenantID, firstBuild.Lease.Run.ID,
			firstBuild.Lease.Intent.CommandID, firstBuild.Lease.WorkerID,
			int64(firstBuild.Lease.FencingToken))
		return deniedErr
	})
	makeRunTaskDue(t, ctx, admin, firstBuild.Lease.Intent.CommandID)
	recoveredBuild := claimExpectedBuild(
		t, ctx, buildRepository, recovered.Run.ID, runlifecycle.ClaimObserve,
	)
	if !recoveredBuild.StartedAt.Equal(firstBuild.StartedAt) ||
		!recoveredBuild.DeadlineAt.Equal(firstBuild.DeadlineAt) {
		t.Fatalf(
			"build takeover changed execution window first=%s/%s recovered=%s/%s",
			firstBuild.StartedAt,
			firstBuild.DeadlineAt,
			recoveredBuild.StartedAt,
			recoveredBuild.DeadlineAt,
		)
	}
	if _, err := buildRepository.Renew(
		ctx, firstBuild.Lease.Guard(), buildexecution.LeaseDuration,
	); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("stale build task renewal error=%v", err)
	}
	renewedBuildLease, err := buildRepository.Renew(
		ctx, recoveredBuild.Lease.Guard(), buildexecution.LeaseDuration,
	)
	if err != nil || !renewedBuildLease.After(recoveredBuild.Lease.LeaseExpiresAt) {
		t.Fatalf(
			"renew current build task old=%s new=%s err=%v",
			recoveredBuild.Lease.LeaseExpiresAt,
			renewedBuildLease,
			err,
		)
	}
	firstBuildLog := assertBuildLogPersistence(
		t, ctx, admin, workerPool, buildRepository, firstBuild, recoveredBuild,
	)
	assertPublicBuildLogRead(
		t, ctx, admin, apiPool, runController, recoveredBuild.Lease.Run.ID,
	)
	if _, err := buildRepository.Complete(ctx, buildexecution.Completion{
		Command: firstBuild, State: devopsv1.PipelineRunReporting,
		Receipt: buildReceipt(firstBuild, devopsbuildv1.ConclusionPassed),
	}); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("stale build task completion error=%v", err)
	}
	if _, err := buildRepository.Complete(ctx, buildexecution.Completion{
		Command: recoveredBuild, State: devopsv1.PipelineRunReporting,
		Receipt: buildReceipt(recoveredBuild, devopsbuildv1.ConclusionPassed),
	}); err != nil {
		t.Fatalf("complete recovered build task: %v", err)
	}
	if err := buildRepository.AppendLogs(
		ctx, recoveredBuild, firstBuildLog,
	); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("completed build accepted a log replay: %v", err)
	}
	report := claimExpectedCheckReport(
		t, ctx, checkRepository, recovered.Run.ID, runlifecycle.ClaimExecute,
	)
	assertCheckReceiptTamperRejected(t, ctx, admin, checkReporterPool, report)
	reportReceipt, err := checkreporting.NewReceipt(report, 101)
	if err != nil {
		t.Fatalf("build check receipt: %v", err)
	}
	makeRunTaskDue(t, ctx, admin, report.Lease.Intent.CommandID)
	recoveredReport := claimExpectedCheckReport(
		t, ctx, checkRepository, recovered.Run.ID, runlifecycle.ClaimObserve,
	)
	if _, err := checkRepository.Complete(ctx, checkreporting.Completion{
		Command: report, State: devopsv1.PipelineRunSucceeded,
		Reason: devopsv1.PipelineRunReasonCompleted, Receipt: &reportReceipt,
	}); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("stale check report completion error=%v", err)
	}
	succeeded, err := checkRepository.Complete(ctx, checkreporting.Completion{
		Command: recoveredReport, State: devopsv1.PipelineRunSucceeded,
		Reason: devopsv1.PipelineRunReasonCompleted, Receipt: &reportReceipt,
	})
	if err != nil || succeeded.Status.CompletedAt == nil {
		t.Fatalf("complete successful PipelineRun=%#v err=%v", succeeded, err)
	}

	fetchCommand := claimExpectedSourceFetch(t, ctx, sourceFetcher, "")
	fetch := fetchCommand.Lease
	if _, err := sourceFetcher.Complete(ctx, sourceacquisition.Completion{
		Command: fetchCommand,
		State:   devopsv1.PipelineRunVerifying,
		Receipt: sourceArchiveReceipt(fetchCommand),
	}); err != nil {
		t.Fatalf("advance reconciliation run to verify: %v", err)
	}
	build := claimExpectedBuild(
		t, ctx, buildRepository, fetch.Run.ID, runlifecycle.ClaimExecute,
	)
	if _, err := buildRepository.Complete(ctx, buildexecution.Completion{
		Command: build, State: devopsv1.PipelineRunReporting,
		Receipt: buildReceipt(build, devopsbuildv1.ConclusionFailed),
	}); err != nil {
		t.Fatalf("advance reconciliation run to report: %v", err)
	}
	report = claimExpectedCheckReport(
		t, ctx, checkRepository, fetch.Run.ID, runlifecycle.ClaimExecute,
	)
	reconciling, err := checkRepository.MarkUncertain(ctx, runlifecycle.Reconciliation{
		Lease: report.Lease, NextAttemptAt: databaseFuture(),
	})
	if err != nil || reconciling.Status.State != devopsv1.PipelineRunReconciling {
		t.Fatalf("mark report uncertain=%#v err=%v", reconciling, err)
	}
	makeRunTaskDue(t, ctx, admin, report.Lease.Intent.CommandID)
	observed := claimExpectedCheckReport(
		t, ctx, checkRepository, fetch.Run.ID, runlifecycle.ClaimObserve,
	)
	if observed.Lease.Intent.CommandID != report.Lease.Intent.CommandID {
		t.Fatalf("reconciliation replaced report intent: %#v", observed)
	}
	for expected := uint64(1); expected <= runlifecycle.MaximumReconciliationAttempts; expected++ {
		attempts, err := checkRepository.Defer(ctx, runlifecycle.Reconciliation{
			Lease: observed.Lease, NextAttemptAt: databaseFuture(),
		})
		if err != nil || attempts != expected {
			t.Fatalf("defer reconciliation %d returned %d: %v", expected, attempts, err)
		}
		makeRunTaskDue(t, ctx, admin, report.Lease.Intent.CommandID)
		observed = claimExpectedCheckReport(
			t, ctx, checkRepository, fetch.Run.ID, runlifecycle.ClaimObserve,
		)
		if observed.Lease.ReconciliationAttempts != expected {
			t.Fatalf("reconciliation attempts=%d want=%d", observed.Lease.ReconciliationAttempts, expected)
		}
	}
	if _, err := checkRepository.Defer(ctx, runlifecycle.Reconciliation{
		Lease: observed.Lease, NextAttemptAt: databaseFuture(),
	}); !errors.Is(err, runlifecycle.ErrReconciliationExhausted) {
		t.Fatalf("exhausted reconciliation deferral error=%v", err)
	}
	manual, err := checkRepository.Complete(ctx, checkreporting.Completion{
		Command: observed, State: devopsv1.PipelineRunManualIntervention,
		Reason: devopsv1.PipelineRunReasonReconciliationExhausted,
	})
	if err != nil || manual.Status.CompletedAt == nil {
		t.Fatalf("complete manual-intervention PipelineRun=%#v err=%v", manual, err)
	}

	cancelledCommand := claimExpectedSourceFetch(t, ctx, sourceFetcher, "")
	cancelledTask := cancelledCommand.Lease
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
	if _, err := sourceFetcher.Renew(
		ctx, cancelledTask.Guard(), sourceacquisition.LeaseDuration,
	); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("cancelled PipelineRun retained its old lease: %v", err)
	}
	staleCancellation := cancelledCommand
	staleCancellation.Lease.Run = pending.Value
	if _, err := sourceFetcher.Complete(ctx, sourceacquisition.Completion{
		Command: staleCancellation,
		State:   devopsv1.PipelineRunCancelled,
		Reason:  devopsv1.PipelineRunReasonCancelled,
	}); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("cancelled PipelineRun accepted its old fence: %v", err)
	}
	recoveredCancellationCommand := claimExpectedSourceFetch(
		t, ctx, sourceFetcher, cancelledTask.Run.ID,
	)
	recoveredCancellation := recoveredCancellationCommand.Lease
	if recoveredCancellation.Mode != runlifecycle.ClaimObserve ||
		recoveredCancellation.Intent != cancelledTask.Intent ||
		recoveredCancellation.Run.Status.CancellationRequestedAt == nil {
		t.Fatalf("cancelled PipelineRun did not recover its exact intent: %#v", recoveredCancellation)
	}
	cancelled, err := sourceFetcher.Complete(ctx, sourceacquisition.Completion{
		Command: recoveredCancellationCommand,
		State:   devopsv1.PipelineRunCancelled,
		Reason:  devopsv1.PipelineRunReasonCancelled,
	})
	if err != nil || cancelled.Status.CompletedAt == nil ||
		cancelled.Status.Stage != devopsv1.PipelineRunStageFetch ||
		cancelled.Status.CancellationRequestedAt == nil ||
		!cancelled.Status.CancellationRequestedAt.Equal(*pending.Value.Status.CancellationRequestedAt) {
		t.Fatalf("complete active PipelineRun cancellation=%#v err=%v", cancelled, err)
	}

	failureCommand := claimExpectedSourceFetch(t, ctx, sourceFetcher, "")
	failed, err := sourceFetcher.Complete(ctx, sourceacquisition.Completion{
		Command: failureCommand,
		State:   devopsv1.PipelineRunFailed,
		Reason:  devopsv1.PipelineRunReasonSourceUnavailable,
	})
	if err != nil || failed.Status.State != devopsv1.PipelineRunFailed ||
		failed.Status.Reason != devopsv1.PipelineRunReasonSourceUnavailable {
		t.Fatalf("complete failed source fetch=%#v err=%v", failed, err)
	}
	var failedReceiptCount int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*) FROM delivery.source_archives WHERE run_id = $1`,
		failureCommand.Lease.Run.ID,
	).Scan(&failedReceiptCount); err != nil || failedReceiptCount != 0 {
		t.Fatalf("failed source fetch receipt count=%d err=%v", failedReceiptCount, err)
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
			command, found, err := sourceFetcher.Claim(
				ctx,
				fmt.Sprintf("source-fetcher-quota-%d", index),
				sourceacquisition.LeaseDuration,
			)
			claimResults <- claimResult{lease: command.Lease, found: found, err: err}
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
		if _, err := sourceFetcher.Renew(
			ctx, active.Guard(), sourceacquisition.LeaseDuration,
		); !errors.Is(err, runlifecycle.ErrStaleLease) {
			t.Fatalf("quota PipelineRun retained its old lease: %v", err)
		}
		recoveredCommand = claimExpectedSourceFetch(t, ctx, sourceFetcher, active.Run.ID)
		recovered = recoveredCommand.Lease
		if _, err := sourceFetcher.Complete(ctx, sourceacquisition.Completion{
			Command: recoveredCommand,
			State:   devopsv1.PipelineRunCancelled,
			Reason:  devopsv1.PipelineRunReasonCancelled,
		}); err != nil {
			t.Fatalf("cancel quota test PipelineRun: %v", err)
		}
	}
	var archiveCount, invalidArchiveCount int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM delivery.source_archives),
		(SELECT count(*)
		   FROM delivery.source_archives AS archive
		   JOIN delivery.pipeline_run_tasks AS task
		     ON task.tenant_id = archive.tenant_id
		    AND task.run_id = archive.run_id
		    AND task.command_id = archive.command_id
		  WHERE task.stage <> 'FETCH' OR task.status <> 'COMPLETED')`).Scan(
		&archiveCount, &invalidArchiveCount,
	); err != nil || archiveCount != 2 || invalidArchiveCount != 0 {
		t.Fatalf(
			"source archive receipts=%d invalid=%d err=%v",
			archiveCount, invalidArchiveCount, err,
		)
	}
	var checkReceiptCount, invalidCheckReceiptCount int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM delivery.check_receipts),
		(SELECT count(*)
		   FROM delivery.check_receipts AS receipt
		   JOIN delivery.pipeline_runs AS run
		     ON run.tenant_id = receipt.tenant_id
		    AND run.id = receipt.run_id
		   JOIN delivery.pipeline_run_tasks AS task
		     ON task.tenant_id = receipt.tenant_id
		    AND task.run_id = receipt.run_id
		    AND task.command_id = receipt.command_id
		  WHERE task.stage <> 'REPORT' OR task.status <> 'COMPLETED'
		     OR run.state NOT IN ('SUCCEEDED', 'FAILED'))`).Scan(
		&checkReceiptCount, &invalidCheckReceiptCount,
	); err != nil || checkReceiptCount != 1 || invalidCheckReceiptCount != 0 {
		t.Fatalf(
			"check receipts=%d invalid=%d err=%v",
			checkReceiptCount, invalidCheckReceiptCount, err,
		)
	}
	reporterReadiness, err := checkRepository.Readiness(ctx)
	if err != nil || reporterReadiness.State != devopsv1.ReadinessReady {
		t.Fatalf("check reporter post-journey readiness=%#v err=%v", reporterReadiness, err)
	}
}

func claimExpectedCheckReport(
	t *testing.T,
	ctx context.Context,
	repository *devopspostgres.CheckReportingRepository,
	expectedRunID devopsv1.ResourceID,
	expectedMode runlifecycle.ClaimMode,
) checkreporting.Command {
	t.Helper()
	command, found, err := repository.Claim(
		ctx, "check-reporter-current", checkreporting.LeaseDuration,
	)
	if err != nil || !found || command.Lease.Run.ID != expectedRunID ||
		(command.Lease.Run.Status.State != devopsv1.PipelineRunReporting &&
			command.Lease.Run.Status.State != devopsv1.PipelineRunReconciling) ||
		command.Lease.Intent.Stage != devopsv1.PipelineRunStageReport ||
		command.Lease.Mode != expectedMode ||
		command.Connection.Metadata.ID != command.BindingRevision.Spec.SourceConnectionID ||
		command.BindingRevision.Metadata.ID != command.Lease.Run.Input.RepositoryBindingID ||
		command.BindingRevision.ContentDigest != command.Lease.Run.Input.RepositoryBindingDigest ||
		command.Revision.ID != command.Lease.Run.Input.PipelineRevisionID ||
		command.Revision.ContentDigest != command.Lease.Run.Input.PipelineRevisionDigest ||
		command.BuildReceipt.RunID != command.Lease.Run.ID ||
		command.BuildReceipt.InputDigest != command.Lease.Run.InputDigest {
		t.Fatalf(
			"claim REPORT run=%s returned %#v found=%t err=%v",
			expectedRunID, command, found, err,
		)
	}
	return command
}

func claimExpectedBuild(
	t *testing.T,
	ctx context.Context,
	repository *devopspostgres.BuildExecutionRepository,
	expectedRunID devopsv1.ResourceID,
	expectedMode runlifecycle.ClaimMode,
) buildexecution.Command {
	t.Helper()
	command, found, err := repository.Claim(
		ctx, "build-worker-current", buildexecution.LeaseDuration,
	)
	if err != nil || !found || command.Lease.Run.ID != expectedRunID ||
		command.Lease.Run.Status.State != devopsv1.PipelineRunVerifying ||
		command.Lease.Intent.Stage != devopsv1.PipelineRunStageVerify ||
		command.Lease.Mode != expectedMode ||
		command.DeadlineAt.Sub(command.StartedAt) != buildexecution.ExecutionDeadline ||
		command.Archive.RunID != expectedRunID ||
		command.Revision.ID != command.Lease.Run.Input.PipelineRevisionID {
		t.Fatalf(
			"claim VERIFY run=%s returned %#v found=%t err=%v",
			expectedRunID,
			command,
			found,
			err,
		)
	}
	return command
}

func assertBuildReceiptTamperRejected(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	workerPool *pgxpool.Pool,
	command buildexecution.Command,
) {
	t.Helper()
	validDocument, err := json.Marshal(buildReceipt(command, devopsbuildv1.ConclusionPassed))
	if err != nil {
		t.Fatalf("encode build receipt fixture: %v", err)
	}
	tests := []struct {
		name        string
		wantMessage string
		mutate      func(map[string]any)
	}{
		{
			name:        "unknown field",
			wantMessage: "build receipt shape is invalid",
			mutate: func(document map[string]any) {
				document["nativeOutput"] = "must-not-cross-boundary"
			},
		},
		{
			name:        "archive binding",
			wantMessage: "build receipt authority is invalid",
			mutate: func(document map[string]any) {
				document["sourceArchiveDigest"] = "sha256:" + strings.Repeat("0", 64)
			},
		},
		{
			name:        "content digest",
			wantMessage: "build receipt digest is invalid",
			mutate: func(document map[string]any) {
				document["contentDigest"] = "sha256:" + strings.Repeat("0", 64)
			},
		},
	}
	for _, test := range tests {
		t.Run("database rejects build receipt "+test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(validDocument, &document); err != nil {
				t.Fatalf("decode build receipt fixture: %v", err)
			}
			test.mutate(document)
			submitted, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("encode changed build receipt: %v", err)
			}
			_, err = workerPool.Exec(
				ctx,
				`SELECT delivery.complete_build_task(
				    $1, $2, $3, $4, $5, 'REPORTING', NULL::text,
				    $6::jsonb, NULL::jsonb, NULL::jsonb
				)`,
				command.Lease.TenantID,
				command.Lease.Run.ID,
				command.Lease.Intent.CommandID,
				command.Lease.WorkerID,
				int64(command.Lease.FencingToken),
				submitted,
			)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "22023" ||
				postgresError.Message != test.wantMessage {
				t.Fatalf("changed build receipt error=%v", err)
			}
		})
	}
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*) FROM delivery.build_receipts WHERE run_id = $1`,
		command.Lease.Run.ID,
	).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected build receipts persisted count=%d err=%v", count, err)
	}
}

func assertCheckReceiptTamperRejected(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	checkReporterPool *pgxpool.Pool,
	command checkreporting.Command,
) {
	t.Helper()
	receipt, err := checkreporting.NewReceipt(command, 101)
	if err != nil {
		t.Fatalf("build check receipt fixture: %v", err)
	}
	validDocument, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("encode check receipt fixture: %v", err)
	}
	tests := []struct {
		name        string
		wantMessage string
		mutate      func(map[string]any)
	}{
		{
			name:        "unknown field",
			wantMessage: "check receipt shape is invalid",
			mutate: func(document map[string]any) {
				document["providerResponse"] = "must-not-cross-boundary"
			},
		},
		{
			name:        "binding",
			wantMessage: "check receipt authority is invalid",
			mutate: func(document map[string]any) {
				document["repositoryBindingDigest"] = "sha256:" + strings.Repeat("0", 64)
			},
		},
		{
			name:        "request digest",
			wantMessage: "check request digest is invalid",
			mutate: func(document map[string]any) {
				document["requestDigest"] = "sha256:" + strings.Repeat("0", 64)
			},
		},
		{
			name:        "content digest",
			wantMessage: "check receipt digest is invalid",
			mutate: func(document map[string]any) {
				document["contentDigest"] = "sha256:" + strings.Repeat("0", 64)
			},
		},
	}
	for _, test := range tests {
		t.Run("database rejects check receipt "+test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(validDocument, &document); err != nil {
				t.Fatalf("decode check receipt fixture: %v", err)
			}
			test.mutate(document)
			submitted, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("encode changed check receipt: %v", err)
			}
			_, err = checkReporterPool.Exec(
				ctx,
				`SELECT delivery.complete_check_report_task(
				    $1, $2, $3, $4, $5, 'SUCCEEDED', 'COMPLETED',
				    $6::jsonb, NULL::jsonb, NULL::jsonb
				)`,
				command.Lease.TenantID,
				command.Lease.Run.ID,
				command.Lease.Intent.CommandID,
				command.Lease.WorkerID,
				int64(command.Lease.FencingToken),
				submitted,
			)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "22023" ||
				postgresError.Message != test.wantMessage {
				t.Fatalf("changed check receipt error=%v", err)
			}
		})
	}
	_, err = checkReporterPool.Exec(
		ctx,
		`SELECT delivery.complete_check_report_task(
		    $1, $2, $3, $4, $5, 'SUCCEEDED', 'COMPLETED',
		    NULL::jsonb, NULL::jsonb, NULL::jsonb
		)`,
		command.Lease.TenantID,
		command.Lease.Run.ID,
		command.Lease.Intent.CommandID,
		command.Lease.WorkerID,
		int64(command.Lease.FencingToken),
	)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "22023" ||
		postgresError.Message != "check report completion receipt is invalid" {
		t.Fatalf("receipt-free successful check completion error=%v", err)
	}
	var count int
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*) FROM delivery.check_receipts WHERE run_id = $1`,
		command.Lease.Run.ID,
	).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected check receipts persisted count=%d err=%v", count, err)
	}
}

func buildReceipt(
	command buildexecution.Command,
	conclusion devopsbuildv1.Conclusion,
) *devopsbuildv1.Receipt {
	first := devopsbuildv1.StepConclusionPassed
	second := devopsbuildv1.StepConclusionPassed
	if conclusion == devopsbuildv1.ConclusionFailed {
		second = devopsbuildv1.StepConclusionFailed
	}
	receipt := devopsbuildv1.Receipt{
		TenantID:               command.Lease.TenantID,
		RunID:                  command.Lease.Run.ID,
		CommandID:              command.Lease.Intent.CommandID,
		InputDigest:            command.Lease.Run.InputDigest,
		SourceArchiveDigest:    command.Archive.ArchiveDigest,
		PipelineRevisionID:     command.Revision.ID,
		PipelineRevisionDigest: command.Revision.ContentDigest,
		ExecutorID:             "executor-integration",
		ExecutorProfile:        command.Revision.Spec.ExecutorProfile,
		ToolchainImageDigest:   command.Revision.Spec.ToolchainImageDigest,
		Conclusion:             conclusion,
		Steps: [2]devopsbuildv1.StepReceipt{
			{
				Ordinal: command.Revision.Spec.Steps[0].Ordinal,
				Kind:    command.Revision.Spec.Steps[0].Kind, Conclusion: first,
			},
			{
				Ordinal: command.Revision.Spec.Steps[1].Ordinal,
				Kind:    command.Revision.Spec.Steps[1].Kind, Conclusion: second,
			},
		},
	}
	receipt.ContentDigest = devopsbuildv1.DigestReceipt(receipt)
	return &receipt
}

func assertBuildLogPersistence(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	workerPool *pgxpool.Pool,
	repository *devopspostgres.BuildExecutionRepository,
	stale buildexecution.Command,
	current buildexecution.Command,
) devopsbuildv1.LogBatch {
	t.Helper()
	request := buildRequest(t, current)
	first := postgresBuildLogBatch(
		t, request, request.Steps[0], devopsbuildv1.LogProgress{},
		[]string{
			"[stdout] test ok\n", "[stdout] coverage ok\n",
			"[stderr] race scan ok\n", "[stdout] package scan ok\n",
		},
	)
	second := postgresBuildLogBatch(
		t, request, request.Steps[1], first.Next,
		[]string{"[stdout] vet ok\n", "[stdout] analyzer ok\n"},
	)
	if err := repository.AppendLogs(
		ctx, stale, first,
	); !errors.Is(err, runlifecycle.ErrStaleLease) {
		t.Fatalf("stale build log fence error=%v", err)
	}
	assertBuildLogTamperRejected(t, ctx, workerPool, current, first)
	if err := repository.AppendLogs(ctx, current, first); err != nil {
		t.Fatalf("append first build logs: %v", err)
	}
	if err := repository.AppendLogs(ctx, current, first); err != nil {
		t.Fatalf("replay equal first build logs: %v", err)
	}
	changed := first
	changed.Chunks = append([]devopsbuildv1.LogChunk(nil), first.Chunks...)
	changed.Chunks[0].Content = "[stdout] best ok\n"
	changed.Chunks[0].ContentDigest = devopsbuildv1.DigestLogChunk(
		changed.ExecutionID, changed.Step, changed.Chunks[0],
	)
	changed.ContentDigest = devopsbuildv1.DigestLogBatch(changed)
	if err := repository.AppendLogs(ctx, current, changed); err == nil {
		t.Fatal("changed build log sequence replay succeeded")
	} else {
		assertPostgresCode(t, err, "MX409")
	}
	if err := repository.AppendLogs(ctx, current, second); err != nil {
		t.Fatalf("append second build logs: %v", err)
	}

	var (
		count           int
		minimumSequence int64
		maximumSequence int64
		maximumBytes    int64
		expiredExactly  bool
	)
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*), min(last_sequence), max(last_sequence),
		        max(next_normalized_bytes),
		        bool_and(expires_at = created_at + interval '14 days')
		   FROM delivery.pipeline_run_logs
		  WHERE tenant_id = $1 AND run_id = $2 AND command_id = $3`,
		current.Lease.TenantID,
		current.Lease.Run.ID,
		current.Lease.Intent.CommandID,
	).Scan(
		&count, &minimumSequence, &maximumSequence, &maximumBytes, &expiredExactly,
	); err != nil || count != 2 || minimumSequence != int64(first.Next.LastSequence) ||
		maximumSequence != int64(second.Next.LastSequence) ||
		maximumBytes != second.Next.NormalizedBytes || !expiredExactly {
		t.Fatalf(
			"stored build logs count=%d sequence=%d..%d bytes=%d retention=%t err=%v",
			count, minimumSequence, maximumSequence, maximumBytes, expiredExactly, err,
		)
	}
	return first
}

func assertPublicBuildLogRead(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	runController *runcontrol.Service,
	runID devopsv1.ResourceID,
) {
	t.Helper()
	read := func(after uint64) devopsv1.PipelineRunLogPage {
		page, err := runController.Logs(ctx, runcontrol.LogQuery{
			Authorization: auth(
				iamv1.ActionDevOpsLogRead, iamv1.ResourcePipelineRun, runID,
			),
			RunID: runID, AfterSequence: after,
		})
		if err != nil {
			t.Fatalf("read PipelineRun logs after %d: %v", after, err)
		}
		if err := devopsv1.ValidatePipelineRunLogPage(page); err != nil {
			t.Fatalf("validate PipelineRun logs after %d: %v", after, err)
		}
		return page
	}
	first := read(0)
	if len(first.Chunks) != devopsv1.FixedLogPageChunkCount || !first.HasMore ||
		first.Truncated || first.NextSequence != 4 {
		t.Fatalf("first public PipelineRun log page=%#v", first)
	}
	for _, chunk := range first.Chunks {
		if chunk.Step != (devopsv1.VerificationStep{
			Ordinal: 1, Kind: devopsv1.VerificationStepGoTest,
		}) || !chunk.ExpiresAt.After(first.ReadAt) {
			t.Fatalf("first public PipelineRun log chunk=%#v", chunk)
		}
	}
	second := read(first.NextSequence)
	if len(second.Chunks) != 2 || second.HasMore || second.Truncated ||
		second.NextSequence != 6 {
		t.Fatalf("second public PipelineRun log page=%#v", second)
	}
	for _, chunk := range second.Chunks {
		if chunk.Step != (devopsv1.VerificationStep{
			Ordinal: 2, Kind: devopsv1.VerificationStepGoVet,
		}) {
			t.Fatalf("second public PipelineRun log chunk=%#v", chunk)
		}
	}
	empty := read(second.NextSequence)
	if len(empty.Chunks) != 0 || empty.HasMore || empty.Truncated ||
		empty.NextSequence != second.NextSequence {
		t.Fatalf("empty public PipelineRun log page=%#v", empty)
	}
	otherTenant := authForTenant(
		"tenant-two", iamv1.ActionDevOpsLogRead, iamv1.ResourcePipelineRun, runID,
	)
	if _, err := runController.Logs(ctx, runcontrol.LogQuery{
		Authorization: otherTenant, RunID: runID,
	}); !errors.Is(err, runcontrol.ErrNotFound) {
		t.Fatalf("cross-tenant PipelineRun log read error=%v", err)
	}
	if _, err := admin.Exec(
		ctx,
		`UPDATE delivery.pipeline_run_logs
		    SET created_at = transaction_timestamp() - interval '15 days',
		        expires_at = transaction_timestamp() - interval '1 day'
		  WHERE tenant_id = 'tenant-one' AND run_id = $1 AND step_ordinal = 1`,
		runID,
	); err != nil {
		t.Fatalf("expire first PipelineRun log batch: %v", err)
	}
	truncatedAuthorization := auth(
		iamv1.ActionDevOpsLogRead, iamv1.ResourcePipelineRun, runID,
	)
	truncatedAuthorization.RequestID = "request-log-retention-truncated"
	truncated, err := runController.Logs(ctx, runcontrol.LogQuery{
		Authorization: truncatedAuthorization, RunID: runID,
	})
	if err != nil || !truncated.Truncated || truncated.HasMore ||
		len(truncated.Chunks) != 2 || truncated.Chunks[0].Sequence != 5 ||
		truncated.NextSequence != 6 {
		t.Fatalf("retention-truncated PipelineRun logs=%#v err=%v", truncated, err)
	}

	var count, digestCount int
	var sanitized bool
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*),
		        count(DISTINCT outbox.document->>'requestDigest'),
		        bool_and(
		            outbox.document->>'action' = 'devops.pipeline-run.logs-read'
		            AND outbox.document#>>'{target,kind}' = 'PIPELINE_RUN'
		            AND outbox.document#>>'{target,id}' = $1
		            AND outbox.document->>'result' = 'SUCCEEDED'
		            AND outbox.document->>'iamDecisionId' = $2
		            AND outbox.document::text NOT LIKE '%test ok%'
		            AND outbox.document::text NOT LIKE '%executionId%'
		            AND outbox.document::text NOT LIKE '%contentDigest%'
		        )
		   FROM delivery.audit_operations AS operation
		   JOIN delivery.audit_outbox AS outbox
		     ON outbox.tenant_id = operation.tenant_id
		    AND outbox.operation_id = operation.id
		  WHERE operation.tenant_id = 'tenant-one'
		    AND operation.operation_kind = 'PIPELINE_RUN_LOG_READ'
		    AND operation.target_kind = 'PIPELINE_RUN'
		    AND operation.target_id = $1`,
		runID, "decision-"+string(runID),
	).Scan(&count, &digestCount, &sanitized); err != nil ||
		count != 4 || digestCount != 3 || !sanitized {
		t.Fatalf("PipelineRun log Audit count=%d digests=%d sanitized=%t err=%v",
			count, digestCount, sanitized, err)
	}
	assertPipelineRunLogReadTamperRejected(t, ctx, admin, apiPool, runID)
}

func assertPipelineRunLogReadTamperRejected(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	runID devopsv1.ResourceID,
) {
	t.Helper()
	var eventDocument []byte
	if err := admin.QueryRow(
		ctx,
		`SELECT outbox.document
		   FROM delivery.audit_operations AS operation
		   JOIN delivery.audit_outbox AS outbox
		     ON outbox.tenant_id = operation.tenant_id
		    AND outbox.operation_id = operation.id
		  WHERE operation.tenant_id = 'tenant-one'
		    AND operation.operation_kind = 'PIPELINE_RUN_LOG_READ'
		    AND operation.target_id = $1
		    AND outbox.document->>'requestId' = 'request-integration'
		  ORDER BY operation.created_at, operation.id
		  LIMIT 1`,
		runID,
	).Scan(&eventDocument); err != nil {
		t.Fatalf("load PipelineRun log Audit fixture: %v", err)
	}
	var event auditv1.Event
	if err := json.Unmarshal(eventDocument, &event); err != nil {
		t.Fatalf("decode PipelineRun log Audit fixture: %v", err)
	}
	operation := runcontrol.LogReadOperation{
		SchemaVersion: "v1", ID: string(event.OperationID), TenantID: "tenant-one",
		Kind: "READ_PIPELINE_RUN_LOGS", RunID: runID,
		RequestedBy: devopsv1.SubjectRef{
			Kind: devopsv1.SubjectKind(event.Actor.Type), ID: string(event.Actor.ID),
		},
		IAMDecisionID: string(event.IAMDecisionID), IAMAction: iamv1.ActionDevOpsLogRead,
		IAMResource:   iamv1.ResourceReference{Kind: iamv1.ResourcePipelineRun, ID: string(runID)},
		RequestDigest: event.RequestDigest,
		Target:        event.Target,
		RequestID:     event.RequestID, CorrelationID: event.CorrelationID,
		TraceParent: event.TraceParent, CreatedAt: event.OccurredAt,
	}
	matched := false
	for _, cursor := range []uint64{0, 4, 6} {
		operation.AfterSequence = cursor
		if runcontrol.ValidateLogReadOperation(operation) == nil {
			matched = true
			break
		}
	}
	if !matched || runcontrol.ValidateLogReadSubmission(runcontrol.LogReadSubmission{
		Operation: operation, AuditEvent: event,
	}) != nil {
		t.Fatal("stored PipelineRun log Audit fixture does not reconstruct its Operation")
	}

	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{
			name: "independent log resource",
			mutate: func(operation, _ map[string]any) {
				operation["iamResource"].(map[string]any)["kind"] = "PIPELINE_LOG"
			},
		},
		{
			name: "changed Audit action",
			mutate: func(_ map[string]any, audit map[string]any) {
				audit["action"] = string(auditv1.ActionDevOpsPipelineRunCompleted)
			},
		},
		{
			name: "log content in Audit",
			mutate: func(_ map[string]any, audit map[string]any) {
				audit["content"] = "[stdout] forbidden"
			},
		},
	}
	for _, test := range tests {
		t.Run("database rejects PipelineRun log read "+test.name, func(t *testing.T) {
			tx, err := apiPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
				t.Fatal(err)
			}
			var tenant string
			if err := tx.QueryRow(
				ctx, "SELECT set_config('matrix.devops_tenant_id', 'tenant-one', true)",
			).Scan(&tenant); err != nil || tenant != "tenant-one" {
				t.Fatalf("set PipelineRun log tenant=%q err=%v", tenant, err)
			}
			var now time.Time
			if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
				t.Fatal(err)
			}
			currentOperation := operation
			currentOperation.CreatedAt = now.UTC()
			currentEvent := event
			currentEvent.OccurredAt = now.UTC()
			var operationMap, eventMap map[string]any
			operationBytes, _ := json.Marshal(currentOperation)
			eventBytes, _ := json.Marshal(currentEvent)
			if json.Unmarshal(operationBytes, &operationMap) != nil ||
				json.Unmarshal(eventBytes, &eventMap) != nil {
				t.Fatal("decode PipelineRun log tamper fixture")
			}
			test.mutate(operationMap, eventMap)
			operationBytes, _ = json.Marshal(operationMap)
			eventBytes, _ = json.Marshal(eventMap)
			var page []byte
			err = tx.QueryRow(
				ctx,
				`SELECT page_document FROM delivery.read_pipeline_run_logs(
				    $1, $2, $3::jsonb, $4::jsonb
				)`,
				runID, int64(operation.AfterSequence), operationBytes, eventBytes,
			).Scan(&page)
			assertPostgresCode(t, err, "22023")
		})
	}
}

func assertBuildLogTamperRejected(
	t *testing.T,
	ctx context.Context,
	workerPool *pgxpool.Pool,
	command buildexecution.Command,
	batch devopsbuildv1.LogBatch,
) {
	t.Helper()
	valid, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		wantMessage string
		mutate      func(map[string]any)
	}{
		{
			name: "unknown field", wantMessage: "build log batch is invalid",
			mutate: func(value map[string]any) { value["native"] = "forbidden" },
		},
		{
			name: "execution identity", wantMessage: "build log execution identity is invalid",
			mutate: func(value map[string]any) {
				value["executionId"] = "sha256:" + strings.Repeat("f", 64)
			},
		},
		{
			name: "chunk digest", wantMessage: "build log chunk digest is invalid",
			mutate: func(value map[string]any) {
				value["chunks"].([]any)[0].(map[string]any)["contentDigest"] =
					"sha256:" + strings.Repeat("f", 64)
			},
		},
		{
			name: "batch digest", wantMessage: "build log batch digest is invalid",
			mutate: func(value map[string]any) {
				value["contentDigest"] = "sha256:" + strings.Repeat("f", 64)
			},
		},
		{
			name: "control content", wantMessage: "build log chunk content is invalid",
			mutate: func(value map[string]any) {
				value["chunks"].([]any)[0].(map[string]any)["content"] =
					"[stdout] unsafe\x1b[31m"
			},
		},
	}
	for _, test := range tests {
		t.Run("database rejects build log "+test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(valid, &document); err != nil {
				t.Fatal(err)
			}
			test.mutate(document)
			submitted, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, err = workerPool.Exec(
				ctx,
				`SELECT delivery.append_build_logs($1, $2, $3, $4, $5, $6)`,
				command.Lease.TenantID,
				command.Lease.Run.ID,
				command.Lease.Intent.CommandID,
				command.Lease.WorkerID,
				int64(command.Lease.FencingToken),
				submitted,
			)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "22023" ||
				postgresError.Message != test.wantMessage {
				t.Fatalf("changed build logs error=%v", err)
			}
		})
	}
}

func buildRequest(
	t *testing.T,
	command buildexecution.Command,
) devopsbuildv1.Request {
	t.Helper()
	steps := command.Revision.Spec.Steps
	request := devopsbuildv1.Request{
		TenantID:               command.Lease.TenantID,
		RunID:                  command.Lease.Run.ID,
		CommandID:              command.Lease.Intent.CommandID,
		InputDigest:            command.Lease.Run.InputDigest,
		SourceArchiveDigest:    command.Archive.ArchiveDigest,
		SourceArchiveBytes:     command.Archive.ArchiveBytes,
		SourceExpandedBytes:    command.Archive.ExpandedBytes,
		SourcePathCount:        command.Archive.PathCount,
		PipelineRevisionID:     command.Revision.ID,
		PipelineRevisionDigest: command.Revision.ContentDigest,
		VerificationProfile:    command.Revision.Spec.VerificationProfile,
		ExecutorProfile:        command.Revision.Spec.ExecutorProfile,
		ToolchainImageDigest:   command.Revision.Spec.ToolchainImageDigest,
		DependencyEgress:       command.Revision.Spec.DependencyEgress,
		Steps:                  [2]devopsv1.VerificationStep{steps[0], steps[1]},
		Limits:                 command.Revision.Spec.Limits,
		StartedAt:              command.StartedAt,
		DeadlineAt:             command.DeadlineAt,
	}
	if err := devopsbuildv1.ValidateRequest(request); err != nil {
		t.Fatal(err)
	}
	return request
}

func postgresBuildLogBatch(
	t *testing.T,
	request devopsbuildv1.Request,
	step devopsv1.VerificationStep,
	previous devopsbuildv1.LogProgress,
	contents []string,
) devopsbuildv1.LogBatch {
	t.Helper()
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	batch := devopsbuildv1.LogBatch{
		ExecutionID: executionID,
		Step:        step,
		Previous:    previous,
		Next:        previous,
		Chunks:      make([]devopsbuildv1.LogChunk, len(contents)),
	}
	for index, content := range contents {
		batch.Chunks[index] = devopsbuildv1.LogChunk{
			Sequence: previous.LastSequence + uint64(index) + 1,
			Content:  content,
		}
		batch.Chunks[index].ContentDigest = devopsbuildv1.DigestLogChunk(
			batch.ExecutionID, batch.Step, batch.Chunks[index],
		)
		batch.Next.NativeBytes += int64(len(content))
		batch.Next.NormalizedBytes += int64(len(content))
	}
	batch.Next.LastSequence += uint64(len(contents))
	batch.ContentDigest = devopsbuildv1.DigestLogBatch(batch)
	if err := devopsbuildv1.ValidateLogBatch(request, batch); err != nil {
		t.Fatal(err)
	}
	return batch
}

func claimExpectedSourceFetch(
	t *testing.T,
	ctx context.Context,
	repository *devopspostgres.SourceAcquisitionRepository,
	expectedRunID devopsv1.ResourceID,
) sourceacquisition.Command {
	t.Helper()
	command, found, err := repository.Claim(
		ctx, "source-fetcher-current", sourceacquisition.LeaseDuration,
	)
	if err != nil || !found ||
		(expectedRunID != "" && command.Lease.Run.ID != expectedRunID) ||
		command.Lease.Run.Status.State != devopsv1.PipelineRunFetching ||
		command.Lease.Intent.Stage != devopsv1.PipelineRunStageFetch {
		t.Fatalf(
			"claim FETCH run=%s returned %#v found=%t err=%v",
			expectedRunID, command, found, err,
		)
	}
	return command
}

func sourceArchiveReceipt(
	command sourceacquisition.Command,
) *sourcearchive.Receipt {
	return &sourcearchive.Receipt{
		TenantID:          command.Lease.TenantID,
		RunID:             command.Lease.Run.ID,
		CommandID:         command.Lease.Intent.CommandID,
		InputDigest:       command.Lease.Run.InputDigest,
		HeadCommit:        command.Lease.Run.Input.Change.HeadCommit,
		TrustedBaseCommit: command.Lease.Run.Input.Change.TrustedBaseCommit,
		MediaType:         sourceacquisition.ArchiveMediaType,
		ArchiveDigest:     "sha256:" + strings.Repeat("a", 64),
		ArchiveBytes:      1024,
		ExpandedBytes:     4096,
		PathCount:         2,
	}
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
	return authForTenant("tenant-one", action, kind, id)
}

func authForTenant(
	tenantID devopsv1.TenantID,
	action iamv1.Action,
	kind iamv1.ResourceKind,
	id devopsv1.ResourceID,
) port.Authorization {
	return port.Authorization{
		TenantID: tenantID, Subject: devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-one"},
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
	connectionVersion uint64,
	externalRepositoryID devopsv1.ResourceID,
	deliveryID string,
) runadmission.Command {
	return runadmission.Command{
		Change: domain.NormalizedChange{
			Scope:                           devopsv1.ResourceScope{TenantID: "tenant-one"},
			SourceConnectionID:              connectionID,
			VerifiedSourceConnectionVersion: connectionVersion,
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
