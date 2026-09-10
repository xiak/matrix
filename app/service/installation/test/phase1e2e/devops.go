package phase1e2e

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const (
	devOpsProjectID           devopsv1.ResourceID  = "phase1-project"
	devOpsSourceConnectionID  devopsv1.ResourceID  = "phase1-source"
	devOpsRepositoryBindingID devopsv1.ResourceID  = "phase1-repository"
	devOpsPipelineID          devopsv1.ResourceID  = "phase1-pipeline"
	devOpsTenant              devopsv1.TenantID    = "organization-default"
	devOpsForeignOrganization iamv1.OrganizationID = "organization-phase1-foreign"
	devOpsForeignPrincipal    iamv1.PrincipalID    = "principal-phase1-foreign"
	devOpsForeignLogin                             = "phase1-foreign-viewer"
	devOpsViewerLogin                              = "phase1-devops-viewer"
	devOpsSourceEndpoint                           = "https://gitea.phase1.invalid"
	devOpsWebhookSecretRef    devopsv1.ResourceID  = "phase1-webhook"
	devOpsFetchCredentialRef  devopsv1.ResourceID  = "phase1-fetch"
	devOpsReportCredentialRef devopsv1.ResourceID  = "phase1-report"
)

const seedForeignTenantSQL = `BEGIN;
INSERT INTO iam.organizations (
    id, display_name, status, resource_version, created_at, updated_at
) VALUES (
    'organization-phase1-foreign', 'Phase 1 Foreign Organization',
    'ACTIVE', 1, transaction_timestamp(), transaction_timestamp()
);
INSERT INTO iam.principals (
    tenant_id, id, principal_type, login_name, display_name, status,
    must_change_password, resource_version, created_at, updated_at
) VALUES (
    'organization-phase1-foreign', 'principal-phase1-foreign', 'USER',
    'phase1-foreign-viewer', 'Phase 1 Foreign Viewer', 'ACTIVE', false, 1,
    transaction_timestamp(), transaction_timestamp()
);
INSERT INTO iam.user_credentials (tenant_id, principal_id, password_hash, changed_at)
SELECT 'organization-phase1-foreign', 'principal-phase1-foreign',
       credential.password_hash, transaction_timestamp()
  FROM iam.user_credentials AS credential
 WHERE credential.tenant_id = 'organization-default'
   AND credential.principal_id = 'principal-admin';
INSERT INTO iam.login_index (login_name, tenant_id, principal_id)
VALUES (
    'phase1-foreign-viewer', 'organization-phase1-foreign',
    'principal-phase1-foreign'
);
INSERT INTO iam.role_bindings (
    tenant_id, id, principal_id, role_name, resource_version,
    created_at, updated_at
) VALUES (
    'organization-phase1-foreign', 'phase1-foreign-devops-viewer',
    'principal-phase1-foreign', 'DEVOPS_VIEWER', 1,
    transaction_timestamp(), transaction_timestamp()
);
COMMIT;
SELECT CASE WHEN
    (SELECT count(*) FROM iam.organizations
      WHERE id = 'organization-phase1-foreign') = 1
    AND (SELECT count(*) FROM iam.principals
      WHERE tenant_id = 'organization-phase1-foreign'
        AND id = 'principal-phase1-foreign') = 1
    AND (SELECT count(*) FROM iam.user_credentials
      WHERE tenant_id = 'organization-phase1-foreign'
        AND principal_id = 'principal-phase1-foreign') = 1
    AND (SELECT count(*) FROM iam.role_bindings
      WHERE tenant_id = 'organization-phase1-foreign'
        AND principal_id = 'principal-phase1-foreign'
        AND role_name = 'DEVOPS_VIEWER' AND revoked_at IS NULL) = 1
THEN 'READY' ELSE 'INVALID' END;`

const removeForeignTenantSQL = `BEGIN;
DELETE FROM iam.sessions WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.authorization_decisions WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.audit_outbox WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.role_bindings WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.user_credentials WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.login_index WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.principals WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.organizations WHERE id = 'organization-phase1-foreign';
COMMIT;
SELECT CASE WHEN
    NOT EXISTS (SELECT 1 FROM iam.organizations
      WHERE id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.principals
      WHERE tenant_id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.audit_outbox
      WHERE tenant_id = 'organization-phase1-foreign')
THEN 'REMOVED' ELSE 'PRESENT' END;`

const observeDevOpsConfigurationSQL = `SELECT CASE WHEN EXISTS (
    SELECT 1
      FROM delivery.projects AS project
      JOIN delivery.source_connections AS connection
        ON connection.tenant_id = project.tenant_id
       AND connection.id = 'phase1-source'
      JOIN delivery.repository_bindings AS binding
        ON binding.tenant_id = project.tenant_id
       AND binding.id = 'phase1-repository'
       AND binding.project_id = project.id
       AND binding.source_connection_id = connection.id
      JOIN delivery.pipelines AS pipeline
        ON pipeline.tenant_id = project.tenant_id
       AND pipeline.id = 'phase1-pipeline'
       AND pipeline.project_id = project.id
       AND pipeline.repository_binding_id = binding.id
      JOIN delivery.pipeline_revisions AS revision
        ON revision.tenant_id = pipeline.tenant_id
       AND revision.id = pipeline.active_revision_id
       AND revision.pipeline_id = pipeline.id
       AND revision.project_id = project.id
       AND revision.repository_binding_id = binding.id
       AND revision.revision = pipeline.active_revision
       AND revision.content_digest = pipeline.active_revision_digest
     WHERE project.tenant_id = 'organization-default'
       AND project.id = 'phase1-project'
) AND NOT EXISTS (
    SELECT 1 FROM delivery.projects
     WHERE id = 'phase1-project' AND tenant_id <> 'organization-default'
) THEN 'READY' ELSE 'INVALID' END;`

func (value *gate) exerciseDevOpsAccess(
	ctx context.Context,
	administrator, administratorPassword []byte,
	installationID string,
) error {
	if err := value.createDevOpsConfiguration(ctx, administrator); err != nil {
		return fail("devops-admin-control-plane")
	}
	if err := value.assertDevOpsConfiguration(ctx, administrator); err != nil {
		return fail("devops-admin-readback")
	}
	if err := value.assertDevOpsViewerBoundary(ctx, administrator); err != nil {
		return fail("devops-viewer-boundary")
	}
	if err := value.assertForeignTenantBoundary(
		ctx, administratorPassword, installationID,
	); err != nil {
		return fail("devops-foreign-tenant-boundary")
	}
	return nil
}

func (value *gate) assertDevOpsDatabaseState(
	ctx context.Context,
	installationID string,
) error {
	observed, err := value.postgresScalar(
		ctx, installationID, observeDevOpsConfigurationSQL,
	)
	if err != nil || observed != "READY" {
		return errors.New("DevOps database state observation failed")
	}
	return nil
}

func (value *gate) createDevOpsConfiguration(
	ctx context.Context,
	bearer []byte,
) error {
	project, err := createDevOpsResource(
		ctx, value.edge, "/api/devops/v1/projects", "phase1-create-devops-project",
		"/v1/projects/"+string(devOpsProjectID), bearer,
		devopsv1.CreateDevOpsProjectRequest{ID: devOpsProjectID, Name: "phase1-project"},
		devopsv1.ValidateDevOpsProject,
		func(resource devopsv1.DevOpsProject) uint64 { return resource.Metadata.ResourceVersion },
	)
	if err != nil || project.Metadata.ID != devOpsProjectID ||
		project.Metadata.Scope.TenantID != devOpsTenant {
		return errors.New("DevOps project creation failed")
	}

	connection, err := createDevOpsResource(
		ctx, value.edge, "/api/devops/v1/source-connections", "phase1-create-devops-source",
		"/v1/source-connections/"+string(devOpsSourceConnectionID), bearer,
		devopsv1.CreateSourceConnectionRequest{
			ID: devOpsSourceConnectionID, Name: "phase1-source",
			Spec: devopsv1.SourceConnectionSpec{
				AdapterID: "source-adapter-gitea-v1", EndpointOrigin: devOpsSourceEndpoint,
				WebhookSecretRef: devOpsWebhookSecretRef, FetchCredentialRef: devOpsFetchCredentialRef,
				ReportCredentialRef: devOpsReportCredentialRef,
			},
		},
		devopsv1.ValidateSourceConnection,
		func(resource devopsv1.SourceConnection) uint64 { return resource.Metadata.ResourceVersion },
	)
	if err != nil || connection.Metadata.ID != devOpsSourceConnectionID ||
		connection.Metadata.Scope.TenantID != devOpsTenant ||
		connection.Status.Health != devopsv1.SourceConnectionPending ||
		connection.Status.Reason != devopsv1.SourceConnectionReasonConfigurationChanged {
		return errors.New("DevOps source connection creation failed")
	}
	if _, err := scheduleDevOpsRecheck(
		ctx, value.edge, "/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID),
		"phase1-recheck-devops-source", bearer, devopsv1.ValidateSourceConnection,
		func(resource devopsv1.SourceConnection) uint64 { return resource.Metadata.ResourceVersion },
	); err != nil {
		return err
	}

	binding, err := createDevOpsResource(
		ctx, value.edge, "/api/devops/v1/repository-bindings", "phase1-create-devops-repository",
		"/v1/repository-bindings/"+string(devOpsRepositoryBindingID), bearer,
		devopsv1.CreateRepositoryBindingRequest{
			ID: devOpsRepositoryBindingID, Name: "phase1-repository", ProjectID: devOpsProjectID,
			Spec: devopsv1.RepositoryBindingSpec{
				SourceConnectionID:   devOpsSourceConnectionID,
				ExternalRepositoryID: "repository-phase1", RepositoryPath: "matrix/service",
				TrustedDefaultBranch: "main",
			},
		},
		devopsv1.ValidateRepositoryBinding,
		func(resource devopsv1.RepositoryBinding) uint64 { return resource.Metadata.ResourceVersion },
	)
	if err != nil || binding.Metadata.ID != devOpsRepositoryBindingID ||
		binding.Metadata.Scope.TenantID != devOpsTenant || binding.ProjectID != devOpsProjectID ||
		binding.Status.Health != devopsv1.RepositoryBindingPending ||
		binding.Status.Reason != devopsv1.RepositoryBindingReasonConfigurationChanged {
		return errors.New("DevOps repository binding creation failed")
	}
	if _, err := scheduleDevOpsRecheck(
		ctx, value.edge, "/api/devops/v1/repository-bindings/"+string(devOpsRepositoryBindingID),
		"phase1-recheck-devops-repository", bearer, devopsv1.ValidateRepositoryBinding,
		func(resource devopsv1.RepositoryBinding) uint64 { return resource.Metadata.ResourceVersion },
	); err != nil {
		return err
	}

	pipeline, err := createDevOpsResource(
		ctx, value.edge, "/api/devops/v1/pipelines", "phase1-create-devops-pipeline",
		"/v1/pipelines/"+string(devOpsPipelineID), bearer,
		devopsv1.CreatePipelineRequest{
			ID: devOpsPipelineID, Name: "phase1-pipeline", ProjectID: devOpsProjectID,
			Draft: devopsv1.PipelineDraftSpec{
				RepositoryBindingID: devOpsRepositoryBindingID,
				TriggerPolicy:       devopsv1.TriggerChange,
				VerificationProfile: devopsv1.VerificationGo126OfflineV1,
				DependencyEgress:    devopsv1.DependencyEgressNone,
				ReporterPolicy:      devopsv1.ReporterChangeCheckV1,
			},
		},
		devopsv1.ValidatePipeline,
		func(resource devopsv1.Pipeline) uint64 { return resource.Metadata.ResourceVersion },
	)
	if err != nil || pipeline.Metadata.ID != devOpsPipelineID ||
		pipeline.Metadata.Scope.TenantID != devOpsTenant || pipeline.ProjectID != devOpsProjectID ||
		pipeline.ActiveRevision != nil {
		return errors.New("DevOps Pipeline creation failed")
	}

	response, err := value.edge.json(
		ctx, http.MethodPost,
		"/api/devops/v1/pipelines/"+string(devOpsPipelineID)+"/activate", bearer, nil,
		map[string]string{
			"Idempotency-Key": "phase1-activate-devops-pipeline",
			"If-Match":        formatResourceVersion(pipeline.Metadata.ResourceVersion),
		},
		http.StatusCreated,
	)
	if err != nil {
		return err
	}
	defer clear(response.body)
	var activation devopsv1.PipelineActivation
	if decodeOne(response.body, &activation) != nil ||
		devopsv1.ValidatePipelineActivation(activation) != nil ||
		activation.Pipeline.Metadata.ID != devOpsPipelineID ||
		activation.Pipeline.Metadata.Scope.TenantID != devOpsTenant ||
		activation.Revision.PipelineID != devOpsPipelineID ||
		activation.Revision.Scope.TenantID != devOpsTenant ||
		activation.Pipeline.ActiveRevision == nil ||
		activation.Pipeline.ActiveRevision.ID != activation.Revision.ID ||
		!isQuotedResourceVersion(response.header, activation.Pipeline.Metadata.ResourceVersion) ||
		response.header.Get("Location") != "/v1/pipelines/"+string(devOpsPipelineID)+
			"/revisions/"+string(activation.Revision.ID) {
		return errors.New("DevOps Pipeline activation failed")
	}
	return nil
}

func (value *gate) assertDevOpsConfiguration(ctx context.Context, bearer []byte) error {
	var project devopsv1.DevOpsProject
	projectHeader, err := value.edge.get(
		ctx, "/api/devops/v1/projects/"+string(devOpsProjectID), bearer, &project,
	)
	if err != nil || devopsv1.ValidateDevOpsProject(project) != nil ||
		project.Metadata.ID != devOpsProjectID || project.Metadata.Scope.TenantID != devOpsTenant ||
		!isQuotedResourceVersion(projectHeader, project.Metadata.ResourceVersion) {
		return errors.New("DevOps project readback failed")
	}

	var connection devopsv1.SourceConnection
	connectionHeader, err := value.edge.get(
		ctx, "/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID), bearer, &connection,
	)
	if err != nil || devopsv1.ValidateSourceConnection(connection) != nil ||
		connection.Metadata.ID != devOpsSourceConnectionID ||
		connection.Metadata.Scope.TenantID != devOpsTenant ||
		!isQuotedResourceVersion(connectionHeader, connection.Metadata.ResourceVersion) {
		return errors.New("DevOps source connection readback failed")
	}

	var binding devopsv1.RepositoryBinding
	bindingHeader, err := value.edge.get(
		ctx, "/api/devops/v1/repository-bindings/"+string(devOpsRepositoryBindingID), bearer, &binding,
	)
	if err != nil || devopsv1.ValidateRepositoryBinding(binding) != nil ||
		binding.Metadata.ID != devOpsRepositoryBindingID ||
		binding.Metadata.Scope.TenantID != devOpsTenant || binding.ProjectID != devOpsProjectID ||
		!isQuotedResourceVersion(bindingHeader, binding.Metadata.ResourceVersion) {
		return errors.New("DevOps repository binding readback failed")
	}

	var pipeline devopsv1.Pipeline
	pipelineHeader, err := value.edge.get(
		ctx, "/api/devops/v1/pipelines/"+string(devOpsPipelineID), bearer, &pipeline,
	)
	if err != nil || devopsv1.ValidatePipeline(pipeline) != nil ||
		pipeline.Metadata.ID != devOpsPipelineID || pipeline.Metadata.Scope.TenantID != devOpsTenant ||
		pipeline.ProjectID != devOpsProjectID || pipeline.ActiveRevision == nil ||
		!isQuotedResourceVersion(pipelineHeader, pipeline.Metadata.ResourceVersion) {
		return errors.New("DevOps Pipeline readback failed")
	}

	var revision devopsv1.PipelineRevision
	revisionHeader, err := value.edge.get(
		ctx,
		"/api/devops/v1/pipelines/"+string(devOpsPipelineID)+"/revisions/"+
			string(pipeline.ActiveRevision.ID),
		bearer, &revision,
	)
	if err != nil || devopsv1.ValidatePipelineRevision(revision) != nil ||
		revision.ID != pipeline.ActiveRevision.ID || revision.PipelineID != devOpsPipelineID ||
		revision.Scope.TenantID != devOpsTenant || revision.ContentDigest != pipeline.ActiveRevision.ContentDigest ||
		revisionHeader.Get("ETag") != `"`+revision.ContentDigest+`"` {
		return errors.New("DevOps Pipeline revision readback failed")
	}
	return nil
}

func (value *gate) assertDevOpsViewerBoundary(
	ctx context.Context,
	administrator []byte,
) error {
	initialPassword, err := randomPassword(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(initialPassword)
	currentPassword, err := randomPassword(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(currentPassword)
	value.edge.addForbidden(initialPassword, currentPassword)

	principal, err := value.edge.createUser(
		ctx, administrator, devOpsViewerLogin, "Phase 1 DevOps Viewer",
		initialPassword, "phase1-create-devops-viewer",
	)
	if err != nil {
		return err
	}
	if _, err := value.edge.putRoleBinding(
		ctx, administrator, principal.ID, iamv1.RoleDevOpsViewer,
		"phase1-bind-devops-viewer",
	); err != nil {
		return err
	}
	initialSession, err := value.edge.loginAs(
		ctx, devOpsViewerLogin, initialPassword, "phase1-login-devops-viewer-initial",
		principal.ID, "organization-default",
	)
	if err != nil {
		return err
	}
	defer clear(initialSession)
	value.edge.addForbidden(initialSession)
	if err := value.edge.changePasswordAs(
		ctx, initialSession, initialPassword, currentPassword,
		"phase1-change-devops-viewer-password",
	); err != nil {
		return err
	}
	if err := value.edge.logout(ctx, initialSession); err != nil {
		return err
	}
	viewer, err := value.edge.loginAs(
		ctx, devOpsViewerLogin, currentPassword, "phase1-login-devops-viewer-current",
		principal.ID, "organization-default",
	)
	if err != nil {
		return err
	}
	defer clear(viewer)
	value.edge.addForbidden(viewer)
	if err := value.assertDevOpsConfiguration(ctx, viewer); err != nil {
		return err
	}
	if err := expectDevOpsProblem(
		ctx, value.edge, http.MethodPost, "/api/devops/v1/projects", viewer,
		devopsv1.CreateDevOpsProjectRequest{ID: "phase1-viewer-denied", Name: "phase1-viewer-denied"},
		map[string]string{"Idempotency-Key": "phase1-viewer-create-denied"},
		http.StatusForbidden, devopsv1.ErrorForbidden,
	); err != nil {
		return err
	}
	var connection devopsv1.SourceConnection
	header, err := value.edge.get(
		ctx, "/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID),
		viewer, &connection,
	)
	if err != nil || devopsv1.ValidateSourceConnection(connection) != nil || header.Get("ETag") == "" {
		return errors.New("DevOps Viewer source read failed")
	}
	if err := expectDevOpsProblem(
		ctx, value.edge, http.MethodPost,
		"/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID)+"/recheck",
		viewer, nil,
		map[string]string{
			"Idempotency-Key": "phase1-viewer-recheck-denied",
			"If-Match":        header.Get("ETag"),
		},
		http.StatusForbidden, devopsv1.ErrorForbidden,
	); err != nil {
		return err
	}
	return value.edge.logout(ctx, viewer)
}

func (value *gate) assertForeignTenantBoundary(
	ctx context.Context,
	password []byte,
	installationID string,
) (returnErr error) {
	seeded, err := value.postgresScalar(ctx, installationID, seedForeignTenantSQL)
	if err != nil || seeded != "READY" {
		return errors.New("foreign tenant fixture creation failed")
	}
	defer func() {
		if cleanupErr := value.removeForeignTenantFixture(ctx, installationID); cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()

	bearer, err := value.edge.loginAs(
		ctx, devOpsForeignLogin, password, "phase1-login-foreign-viewer",
		devOpsForeignPrincipal, devOpsForeignOrganization,
	)
	if err != nil {
		return err
	}
	defer clear(bearer)
	value.edge.addForbidden(bearer)
	return expectDevOpsProblem(
		ctx, value.edge, http.MethodGet,
		"/api/devops/v1/projects/"+string(devOpsProjectID), bearer, nil, nil,
		http.StatusNotFound, devopsv1.ErrorNotFound,
	)
}

func (value *gate) removeForeignTenantFixture(
	ctx context.Context,
	installationID string,
) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		removed, err := value.postgresScalar(
			cleanupContext, installationID, removeForeignTenantSQL,
		)
		if err == nil && removed == "REMOVED" {
			return nil
		}
		if !waitPoll(cleanupContext, 100*time.Millisecond) {
			break
		}
	}
	return errors.New("foreign tenant fixture removal failed")
}

func createDevOpsResource[T any](
	ctx context.Context,
	client *edgeClient,
	path, idempotencyKey, location string,
	bearer []byte,
	body any,
	validate func(T) error,
	resourceVersion func(T) uint64,
) (T, error) {
	var zero T
	response, err := client.json(
		ctx, http.MethodPost, path, bearer, body,
		map[string]string{"Idempotency-Key": idempotencyKey}, http.StatusCreated,
	)
	if err != nil {
		return zero, err
	}
	defer clear(response.body)
	var resource T
	if decodeOne(response.body, &resource) != nil || validate(resource) != nil ||
		!isQuotedResourceVersion(response.header, resourceVersion(resource)) ||
		response.header.Get("Location") != location {
		return zero, errors.New("DevOps resource creation response failed")
	}
	return resource, nil
}

func scheduleDevOpsRecheck[T any](
	ctx context.Context,
	client *edgeClient,
	resourcePath, idempotencyKey string,
	bearer []byte,
	validate func(T) error,
	resourceVersion func(T) uint64,
) (T, error) {
	var zero T
	for attempt := 0; attempt < 8; attempt++ {
		var current T
		header, err := client.get(ctx, resourcePath, bearer, &current)
		if err != nil || validate(current) != nil ||
			!isQuotedResourceVersion(header, resourceVersion(current)) {
			return zero, errors.New("DevOps recheck read failed")
		}
		response, err := client.json(
			ctx, http.MethodPost, resourcePath+"/recheck", bearer, nil,
			map[string]string{
				"Idempotency-Key": idempotencyKey,
				"If-Match":        header.Get("ETag"),
			},
			http.StatusAccepted, http.StatusPreconditionFailed,
		)
		if err != nil {
			return zero, err
		}
		if response.status == http.StatusPreconditionFailed {
			problemErr := validateDevOpsProblem(
				response, http.StatusPreconditionFailed, devopsv1.ErrorPreconditionFailed,
			)
			clear(response.body)
			if problemErr != nil {
				return zero, problemErr
			}
			if !waitPoll(ctx, 25*time.Millisecond) {
				return zero, errors.New("DevOps recheck was interrupted")
			}
			continue
		}
		var resource T
		if decodeOne(response.body, &resource) != nil || validate(resource) != nil ||
			!isQuotedResourceVersion(response.header, resourceVersion(resource)) ||
			response.header.Get("Location") != resourcePath[len("/api/devops"):] {
			clear(response.body)
			return zero, errors.New("DevOps recheck response failed")
		}
		clear(response.body)
		return resource, nil
	}
	return zero, errors.New("DevOps recheck exceeded conflict retry bound")
}

func expectDevOpsProblem(
	ctx context.Context,
	client *edgeClient,
	method, path string,
	bearer []byte,
	body any,
	headers map[string]string,
	status int,
	code devopsv1.ErrorCode,
) error {
	response, err := client.json(ctx, method, path, bearer, body, headers, status)
	if err != nil {
		return err
	}
	defer clear(response.body)
	return validateDevOpsProblem(response, status, code)
}

func validateDevOpsProblem(
	response httpResult,
	status int,
	code devopsv1.ErrorCode,
) error {
	var problem devopsv1.Problem
	if decodeOne(response.body, &problem) != nil || devopsv1.ValidateProblem(problem) != nil ||
		problem.Status != status || problem.Code != code || response.header.Get("ETag") != "" ||
		response.header.Get("Location") != "" {
		return errors.New("DevOps problem response failed")
	}
	return nil
}
