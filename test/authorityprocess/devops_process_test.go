package authorityprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

const (
	devopsProjectID              = devopsv1.ResourceID("project-process")
	devopsSourceConnectionID     = devopsv1.ResourceID("source-connection-process")
	devopsRepositoryBindingID    = devopsv1.ResourceID("repository-binding-process")
	devopsPipelineID             = devopsv1.ResourceID("pipeline-process")
	devopsDeniedViewerProjectID  = devopsv1.ResourceID("project-viewer-denied")
	devopsChangedReplayProjectID = "changed-process-project"
)

func enrollDevOpsService(
	t *testing.T,
	ctx context.Context,
	adminDSN string,
	installationID string,
) {
	t.Helper()
	apiDSN := migrationLoginDSN(
		t,
		adminDSN,
		"matrix_iam_api_login",
		"matrix-authority-process-default-iam-api",
	)
	workerDSN := migrationLoginDSN(
		t,
		adminDSN,
		"matrix_iam_worker_login",
		"matrix-authority-process-default-iam-worker",
	)
	bindings := []iammigration.ReleaseServiceBinding{
		{Purpose: iamv1.ServicePlatform, Credential: processSecret(t, platformServiceCredential)},
		{Purpose: iamv1.ServiceDevOps, Credential: processSecret(t, devopsServiceCredential)},
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := iammigration.ApplyForInstallation(
			ctx, adminDSN, apiDSN, workerDSN, installationID, bindings,
		); err != nil {
			t.Fatalf("enroll release-selected DevOps service attempt %d: %v", attempt, err)
		}
	}
	if err := iammigration.VerifyInstalledForInstallation(
		ctx, adminDSN, apiDSN, workerDSN, installationID, bindings,
	); err != nil {
		t.Fatalf("verify release-selected DevOps service: %v", err)
	}
}

func migrationLoginDSN(t *testing.T, adminDSN string, login string, password string) string {
	t.Helper()
	value, err := url.Parse(adminDSN)
	if err != nil || value.Host == "" || value.Path == "" ||
		value.Scheme != "postgres" && value.Scheme != "postgresql" {
		t.Fatal("parse authority migration administrator DSN")
	}
	value.User = url.UserPassword(login, password)
	return value.String()
}

func exerciseDevOpsConfigurationJourney(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	endpoint string,
	bearer string,
) {
	t.Helper()
	projectRequest := devopsv1.CreateDevOpsProjectRequest{
		ID: devopsProjectID, Name: "process-project",
	}
	projectResponse := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/projects",
		bearer,
		"create-devops-project-process",
		projectRequest,
	)
	project := decodeDevOpsResponse(
		t, projectResponse, http.StatusCreated, devopsv1.ValidateDevOpsProject,
	)
	assertDevOpsMutationHeaders(
		t, projectResponse, `"1"`, "/v1/projects/"+string(devopsProjectID),
	)
	if project.Metadata.ID != devopsProjectID ||
		project.Metadata.Scope.TenantID != "organization-process" {
		t.Fatalf("DevOps project authority=%#v", project.Metadata)
	}

	replayResponse := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/projects",
		bearer,
		"create-devops-project-process",
		projectRequest,
	)
	replayedProject := decodeDevOpsResponse(
		t, replayResponse, http.StatusCreated, devopsv1.ValidateDevOpsProject,
	)
	if !reflect.DeepEqual(replayedProject, project) {
		t.Fatalf("DevOps equal replay changed result: %#v", replayedProject)
	}

	changedReplay := projectRequest
	changedReplay.Name = devopsChangedReplayProjectID
	assertDevOpsProblem(
		t,
		performJSONWithIdempotency(
			t,
			http.MethodPost,
			endpoint+"/v1/projects",
			bearer,
			"create-devops-project-process",
			changedReplay,
		),
		http.StatusConflict,
		devopsv1.ErrorConflict,
		devopsChangedReplayProjectID,
	)

	connectionRequest := devopsv1.CreateSourceConnectionRequest{
		ID: devopsSourceConnectionID, Name: "gitea-process",
		Spec: devopsv1.SourceConnectionSpec{
			AdapterID:           "source-adapter-gitea-v1",
			EndpointOrigin:      "https://gitea.process.example",
			WebhookSecretRef:    "secret-webhook-process",
			FetchCredentialRef:  "secret-fetch-process",
			ReportCredentialRef: "secret-report-process",
		},
	}
	connectionResponse := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/source-connections",
		bearer,
		"create-devops-source-connection-process",
		connectionRequest,
	)
	connection := decodeDevOpsResponse(
		t, connectionResponse, http.StatusCreated, devopsv1.ValidateSourceConnection,
	)
	assertDevOpsMutationHeaders(
		t,
		connectionResponse,
		`"1"`,
		"/v1/source-connections/"+string(devopsSourceConnectionID),
	)
	if connection.Status.Health != devopsv1.SourceConnectionPending {
		t.Fatalf("DevOps source connection health=%s", connection.Status.Health)
	}

	bindingRequest := devopsv1.CreateRepositoryBindingRequest{
		ID: devopsRepositoryBindingID, Name: "matrix-process",
		ProjectID: devopsProjectID,
		Spec: devopsv1.RepositoryBindingSpec{
			SourceConnectionID:   devopsSourceConnectionID,
			ExternalRepositoryID: "repository-process-42",
			RepositoryPath:       "matrix/process",
			TrustedDefaultBranch: "main",
		},
	}
	bindingResponse := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/repository-bindings",
		bearer,
		"create-devops-repository-binding-process",
		bindingRequest,
	)
	binding := decodeDevOpsResponse(
		t, bindingResponse, http.StatusCreated, devopsv1.ValidateRepositoryBinding,
	)
	assertDevOpsMutationHeaders(
		t,
		bindingResponse,
		`"1"`,
		"/v1/repository-bindings/"+string(devopsRepositoryBindingID),
	)
	if binding.ProjectID != devopsProjectID ||
		binding.Status.Health != devopsv1.RepositoryBindingPending {
		t.Fatalf("DevOps repository binding=%#v", binding)
	}

	pipelineRequest := devopsv1.CreatePipelineRequest{
		ID: devopsPipelineID, Name: "verify-process", ProjectID: devopsProjectID,
		Draft: devopsv1.PipelineDraftSpec{
			RepositoryBindingID: devopsRepositoryBindingID,
			TriggerPolicy:       devopsv1.TriggerChange,
			VerificationProfile: devopsv1.VerificationGo126OfflineV1,
			DependencyEgress:    devopsv1.DependencyEgressNone,
			ReporterPolicy:      devopsv1.ReporterChangeCheckV1,
		},
	}
	pipelineResponse := performJSONWithIdempotency(
		t,
		http.MethodPost,
		endpoint+"/v1/pipelines",
		bearer,
		"create-devops-pipeline-process",
		pipelineRequest,
	)
	pipeline := decodeDevOpsResponse(
		t, pipelineResponse, http.StatusCreated, devopsv1.ValidatePipeline,
	)
	assertDevOpsMutationHeaders(
		t, pipelineResponse, `"1"`, "/v1/pipelines/"+string(devopsPipelineID),
	)
	if pipeline.ActiveRevision != nil {
		t.Fatalf("new DevOps Pipeline has active revision: %#v", pipeline.ActiveRevision)
	}

	activationResponse := performJSONWithPreconditions(
		t,
		http.MethodPost,
		endpoint+"/v1/pipelines/"+string(devopsPipelineID)+"/activate",
		bearer,
		"activate-devops-pipeline-process",
		`"1"`,
		nil,
	)
	activation := decodeDevOpsResponse(
		t, activationResponse, http.StatusCreated, devopsv1.ValidatePipelineActivation,
	)
	assertDevOpsMutationHeaders(
		t,
		activationResponse,
		`"2"`,
		"/v1/pipelines/"+string(devopsPipelineID)+"/revisions/"+string(activation.Revision.ID),
	)
	if activation.Revision.ActivatedBy != (devopsv1.SubjectRef{
		Kind: devopsv1.SubjectUser, ID: "principal-admin",
	}) {
		t.Fatalf("DevOps activation actor=%#v", activation.Revision.ActivatedBy)
	}

	readPipelineResponse := performJSON(
		t,
		http.MethodGet,
		endpoint+"/v1/pipelines/"+string(devopsPipelineID),
		bearer,
		nil,
	)
	readPipeline := decodeDevOpsResponse(
		t, readPipelineResponse, http.StatusOK, devopsv1.ValidatePipeline,
	)
	if !reflect.DeepEqual(readPipeline, activation.Pipeline) ||
		readPipelineResponse.Header.Get("ETag") != `"2"` {
		t.Fatalf("DevOps Pipeline read=%#v headers=%v", readPipeline, readPipelineResponse.Header)
	}

	revisionEndpoint := endpoint + "/v1/pipelines/" + string(devopsPipelineID) +
		"/revisions/" + string(activation.Revision.ID)
	readRevisionResponse := performJSON(t, http.MethodGet, revisionEndpoint, bearer, nil)
	readRevision := decodeDevOpsResponse(
		t, readRevisionResponse, http.StatusOK, devopsv1.ValidatePipelineRevision,
	)
	if !reflect.DeepEqual(readRevision, activation.Revision) ||
		readRevisionResponse.Header.Get("ETag") != `"`+activation.Revision.ContentDigest+`"` {
		t.Fatalf("DevOps PipelineRevision read=%#v headers=%v", readRevision, readRevisionResponse.Header)
	}

	assertDevOpsProblem(
		t,
		performJSON(
			t,
			http.MethodGet,
			endpoint+"/v1/pipelines/pipeline-other/revisions/"+string(activation.Revision.ID),
			bearer,
			nil,
		),
		http.StatusNotFound,
		devopsv1.ErrorNotFound,
		string(activation.Revision.ID),
	)
	assertDevOpsProblem(
		t,
		performJSON(
			t,
			http.MethodGet,
			endpoint+"/v1/projects/"+string(devopsProjectID),
			"",
			nil,
		),
		http.StatusUnauthorized,
		devopsv1.ErrorUnauthenticated,
		string(devopsProjectID),
	)

	var mutationCount int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM delivery.mutations WHERE tenant_id = 'organization-process'",
	).Scan(&mutationCount); err != nil {
		t.Fatalf("inspect DevOps process mutations: %v", err)
	}
	if mutationCount != 5 {
		t.Fatalf("DevOps process mutation count=%d want=5", mutationCount)
	}
}

func assertDevOpsViewerAccess(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	endpoint string,
	bearer string,
) {
	t.Helper()
	response := performJSON(
		t,
		http.MethodGet,
		endpoint+"/v1/pipelines/"+string(devopsPipelineID),
		bearer,
		nil,
	)
	decodeDevOpsResponse(t, response, http.StatusOK, devopsv1.ValidatePipeline)
	assertDevOpsProblem(
		t,
		performJSONWithIdempotency(
			t,
			http.MethodPost,
			endpoint+"/v1/projects",
			bearer,
			"create-devops-project-viewer-denied",
			devopsv1.CreateDevOpsProjectRequest{
				ID: devopsDeniedViewerProjectID, Name: "viewer-denied",
			},
		),
		http.StatusForbidden,
		devopsv1.ErrorForbidden,
		string(devopsDeniedViewerProjectID),
	)
	var count int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM delivery.projects WHERE id = $1",
		devopsDeniedViewerProjectID,
	).Scan(&count); err != nil {
		t.Fatalf("inspect denied DevOps project: %v", err)
	}
	if count != 0 {
		t.Fatalf("denied DevOps project count=%d", count)
	}
}

func waitAllDevOpsOutboxDelivered(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	waitDatabase(t, ctx, "DevOps Audit outbox delivery", func() (bool, error) {
		var outstanding int
		err := admin.QueryRow(
			ctx,
			"SELECT count(*) FROM delivery.audit_outbox WHERE status <> 'DELIVERED'",
		).Scan(&outstanding)
		return outstanding == 0, err
	})
	assertDevOpsConfigurationAudit(t, ctx, admin)
}

func assertDevOpsConfigurationAudit(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var revisionID string
	if err := admin.QueryRow(
		ctx,
		`SELECT id FROM delivery.pipeline_revisions
		  WHERE tenant_id = 'organization-process' AND pipeline_id = $1`,
		devopsPipelineID,
	).Scan(&revisionID); err != nil {
		t.Fatalf("read DevOps process revision identity: %v", err)
	}
	want := []struct {
		action auditv1.Action
		target string
	}{
		{auditv1.ActionDevOpsProjectCreated, string(devopsProjectID)},
		{auditv1.ActionDevOpsSourceConnectionCreated, string(devopsSourceConnectionID)},
		{auditv1.ActionDevOpsRepositoryBindingCreated, string(devopsRepositoryBindingID)},
		{auditv1.ActionDevOpsPipelineCreated, string(devopsPipelineID)},
		{auditv1.ActionDevOpsPipelineRevisionActivated, revisionID},
	}
	for _, expected := range want {
		var count int
		if err := admin.QueryRow(
			ctx,
			`SELECT count(*)
			   FROM delivery.audit_outbox AS outbox
			   JOIN iam.authorization_decisions AS decision
			     ON decision.tenant_id = outbox.tenant_id
			    AND decision.id = outbox.document->>'iamDecisionId'
			   JOIN audit.records AS record
			     ON record.source = 'DEVOPS'
			    AND record.event_id = outbox.event_id
			  WHERE outbox.document->>'action' = $1
			    AND outbox.document#>>'{target,id}' = $2
			    AND outbox.document#>>'{actor,id}' = 'principal-admin'
			    AND decision.allowed
			    AND decision.principal_id = 'principal-admin'
			    AND record.event_document = outbox.document`,
			string(expected.action),
			expected.target,
		).Scan(&count); err != nil {
			t.Fatalf("inspect DevOps Audit fact %s: %v", expected.action, err)
		}
		if count != 1 {
			t.Fatalf(
				"DevOps Audit fact action=%s target=%s count=%d",
				expected.action,
				expected.target,
				count,
			)
		}
	}
	healthWant := []struct {
		action auditv1.Action
		target string
	}{
		{auditv1.ActionDevOpsSourceConnectionHealthTransitioned, string(devopsSourceConnectionID)},
		{auditv1.ActionDevOpsRepositoryBindingHealthTransitioned, string(devopsRepositoryBindingID)},
	}
	for _, expected := range healthWant {
		var count int
		if err := admin.QueryRow(
			ctx,
			`SELECT count(*)
			   FROM delivery.audit_outbox AS outbox
			   JOIN audit.records AS record
			     ON record.source = 'DEVOPS'
			    AND record.event_id = outbox.event_id
			  WHERE outbox.document->>'action' = $1
			    AND outbox.document#>>'{target,id}' = $2
			    AND outbox.document#>>'{actor,type}' = 'SYSTEM'
			    AND outbox.document#>>'{actor,id}' = 'system-devops-source-observer'
			    AND NOT outbox.document ? 'iamDecisionId'
			    AND record.event_document = outbox.document`,
			string(expected.action),
			expected.target,
		).Scan(&count); err != nil {
			t.Fatalf("inspect DevOps source health Audit fact %s: %v", expected.action, err)
		}
		if count != 1 {
			t.Fatalf(
				"DevOps source health Audit fact action=%s target=%s count=%d",
				expected.action,
				expected.target,
				count,
			)
		}
	}
	var outboxCount, recordCount int
	if err := admin.QueryRow(
		ctx,
		`SELECT
			(SELECT count(*) FROM delivery.audit_outbox),
			(SELECT count(*) FROM audit.records WHERE source = 'DEVOPS')`,
	).Scan(&outboxCount, &recordCount); err != nil {
		t.Fatalf("count DevOps Audit process evidence: %v", err)
	}
	wantCount := len(want) + len(healthWant)
	if outboxCount != wantCount || recordCount != wantCount {
		t.Fatalf(
			"DevOps Audit process evidence outbox=%d records=%d want=%d",
			outboxCount,
			recordCount,
			wantCount,
		)
	}
}

func decodeDevOpsResponse[T any](
	t *testing.T,
	response processResponse,
	wantStatus int,
	validate func(T) error,
) T {
	t.Helper()
	var value T
	if response.Status != wantStatus {
		t.Fatalf("DevOps response status=%d want=%d body=%s", response.Status, wantStatus, response.Body)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("DevOps response Content-Type=%q", contentType)
	}
	if err := json.Unmarshal(response.Body, &value); err != nil {
		t.Fatalf("decode DevOps response: %v", err)
	}
	if err := validate(value); err != nil {
		t.Fatalf("validate DevOps response: %v", err)
	}
	return value
}

func assertDevOpsMutationHeaders(
	t *testing.T,
	response processResponse,
	etag string,
	location string,
) {
	t.Helper()
	if response.Header.Get("ETag") != etag || response.Header.Get("Location") != location {
		t.Fatalf(
			"DevOps mutation ETag=%q Location=%q want ETag=%q Location=%q",
			response.Header.Get("ETag"),
			response.Header.Get("Location"),
			etag,
			location,
		)
	}
}

func assertDevOpsProblem(
	t *testing.T,
	response processResponse,
	wantStatus int,
	wantCode devopsv1.ErrorCode,
	forbiddenText string,
) {
	t.Helper()
	if response.Status != wantStatus {
		t.Fatalf("DevOps problem status=%d want=%d body=%s", response.Status, wantStatus, response.Body)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "application/problem+json" {
		t.Fatalf("DevOps problem Content-Type=%q", contentType)
	}
	var problem devopsv1.Problem
	if err := json.Unmarshal(response.Body, &problem); err != nil ||
		devopsv1.ValidateProblem(problem) != nil || problem.Code != wantCode {
		t.Fatalf("decode DevOps problem: value=%#v err=%v", problem, err)
	}
	if forbiddenText != "" && bytes.Contains(response.Body, []byte(forbiddenText)) {
		t.Fatalf("DevOps problem leaked authority text %q", forbiddenText)
	}
}
