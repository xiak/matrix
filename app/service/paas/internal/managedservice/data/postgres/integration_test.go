package postgres_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/postgresmigration"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
	auditpostgres "github.com/xiak/matrix/app/service/paas/internal/audit/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/audit/usecase/auditdispatch"
	managedservicepostgres "github.com/xiak/matrix/app/service/paas/internal/managedservice/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase/reconcileinstallation"
	paasmigration "github.com/xiak/matrix/app/service/paas/migration"
)

const (
	managedServiceIntegrationDSN = "MATRIX_MANAGEDSERVICE_POSTGRES_TEST_DSN"
	managedServiceDependencyDSN  = "MATRIX_MANAGEDSERVICE_DEPENDENCY_POSTGRES_TEST_DSN"
	managedServicePredecessorDSN = "MATRIX_MANAGEDSERVICE_PREDECESSOR_POSTGRES_TEST_DSN"
	managedServicePredecessor    = "ba2ea256528349f1300092ba0fd44641d758accb"
	managedServiceAPIPassword    = "mxp1.managed-api-00000000000000000000000000000"
	managedServiceWorkerPassword = "mxp1.managed-worker-0000000000000000000000000"
)

func fixedPaaSPredecessorSource(t *testing.T) postgresmigration.Source {
	t.Helper()
	read := func(path string) string {
		command := exec.Command("git", "show", managedServicePredecessor+":"+path)
		content, err := command.Output()
		if err != nil || len(content) == 0 {
			t.Fatalf("read fixed predecessor PaaS source %s", path)
		}
		return string(content)
	}
	return postgresmigration.Source{
		Context: "paas",
		UpSQL: read("app/service/paas/internal/apphosting/data/postgres/migrations/000001_placement_core/up.sql") + "\n" +
			read("app/service/paas/internal/managedservice/data/postgres/migrations/000001_service_authority/up.sql"),
		VerifySQL: read("app/service/paas/internal/apphosting/data/postgres/migrations/000001_placement_core/verify.sql") + "\n" +
			read("app/service/paas/internal/managedservice/data/postgres/migrations/000001_service_authority/verify.sql"),
	}
}

func managedServiceRepository(t *testing.T, pool *pgxpool.Pool) *managedservicepostgres.Repository {
	t.Helper()
	repository, err := managedservicepostgres.NewRepository(pool)
	if err != nil {
		t.Fatal("create managed-service repository")
	}
	return repository
}

func integrationRegion() managedservicev1.Region {
	inspectedAt := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	return managedservicev1.Region{
		ID: "local-primary", DisplayName: "本机主区域",
		Profile: managedservicev1.RegionLocalMachine,
		State:   managedservicev1.RegionReady, InspectedAt: &inspectedAt,
		Capacity: managedservicev1.RegionCapacity{
			CPUMillicores: 4000, MemoryMiB: 8192, StorageGiB: 100,
		},
	}
}

func TestManagedServiceDirectPredecessorUpgradeAndTermination(t *testing.T) {
	adminDSN := os.Getenv(managedServicePredecessorDSN)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", managedServicePredecessorDSN)
	}
	parsed, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(parsed.ConnConfig.Database, "matrix_managedservice_predecessor_") {
		database := ""
		if parsed != nil {
			database = parsed.ConnConfig.Database
		}
		t.Fatalf("managed-service predecessor DSN database=%q err=%v", database, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	apiDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_api_login", managedServiceAPIPassword)
	workerDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_worker_login", managedServiceWorkerPassword)
	logins := []postgresmigration.Login{
		{Name: "matrix_paas_api_login", Group: "matrix_paas_api", DSN: apiDSN},
		{Name: "matrix_paas_worker_login", Group: "matrix_paas_worker", DSN: workerDSN},
	}
	if err := postgresmigration.Apply(ctx, adminDSN, fixedPaaSPredecessorSource(t), logins); err != nil {
		t.Fatalf("apply fixed predecessor PaaS schema: %v", err)
	}

	predecessorPool, err := pgxpool.New(ctx, apiDSN)
	if err != nil {
		t.Fatal("open predecessor managed-service API pool")
	}
	const (
		predecessorTenant       = "organization-predecessor"
		predecessorQuota        = "quota-predecessor-mysql"
		predecessorInstallation = "predecessor-mysql"
		predecessorOperation    = "operation-predecessor-provision"
	)
	predecessorService, found := domain.DefaultCatalog().ResolveService(managedservicev1.MySQLServiceID)
	if !found {
		predecessorPool.Close()
		t.Fatal("fixed predecessor MySQL service definition is absent")
	}
	// The fixed predecessor's own repository had already proved the create
	// workflow at ba2ea25. This fixture persists its observable READY state
	// using only that predecessor's released tables and worker functions; the
	// assertions below exercise the current schema and use cases exclusively.
	tx, err := predecessorPool.Begin(ctx)
	if err != nil {
		predecessorPool.Close()
		t.Fatal("begin predecessor fixture")
	}
	if _, err = tx.Exec(ctx, "SELECT pg_catalog.set_config('matrix.tenant_id', $1, true)", predecessorTenant); err == nil {
		_, err = tx.Exec(ctx, `
INSERT INTO managedservice.service_activations (
    tenant_id, service_id, service_revision, service_digest, idempotency_key,
    request_digest, activated_by_type, activated_by_id, iam_decision_id, request_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2, $3, 'predecessor-activation-request',
    $4, 'USER', 'principal-predecessor', 'decision-predecessor-activation', 'request-predecessor-activation'
)`, predecessorService.ID, predecessorService.Revision, predecessorService.ContentDigest,
			"sha256:"+strings.Repeat("c", 64))
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
INSERT INTO managedservice.quota_entitlements (
    tenant_id, id, offering_id, quota_shape_id, purchased_count, reserved_count,
    idempotency_key, request_digest, activated_by_type, activated_by_id,
    iam_decision_id, request_id
) VALUES (
    managedservice.current_tenant_id(), $1, 'mysql-8.4', 'mysql-small', 1, 1,
    'predecessor-quota-request', $2, 'USER', 'principal-predecessor',
    'decision-predecessor', 'request-predecessor'
)`, predecessorQuota, "sha256:"+strings.Repeat("a", 64))
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
INSERT INTO managedservice.service_installations (
    tenant_id, id, name, offering_id, engine_version, quota_entitlement_id, region_id,
    current_operation_id
) VALUES (
    managedservice.current_tenant_id(), $1, 'Predecessor MySQL',
    'mysql-8.4', '8.4', $2, 'local-primary', $3
)`, predecessorInstallation, predecessorQuota, predecessorOperation)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
INSERT INTO managedservice.operations (
    tenant_id, id, installation_id, kind, quota_release, idempotency_key, request_digest,
    requested_by_type, requested_by_id, iam_decision_id, request_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2, 'PROVISION', 'NONE',
    'predecessor-installation-request', $3, 'USER', 'principal-predecessor',
    'decision-predecessor', 'request-predecessor'
)`, predecessorOperation, predecessorInstallation, "sha256:"+strings.Repeat("b", 64))
	}
	if err == nil {
		err = tx.Commit(ctx)
	} else {
		_ = tx.Rollback(context.Background())
	}
	if err != nil {
		predecessorPool.Close()
		t.Fatalf("persist fixed predecessor READY fixture: %v", err)
	}
	predecessorWorker, err := pgxpool.New(ctx, workerDSN)
	if err != nil {
		predecessorPool.Close()
		t.Fatal("open predecessor worker pool")
	}
	var claimedOperation string
	var fencingToken int64
	if err := predecessorWorker.QueryRow(ctx, `
SELECT operation_id, fencing_token
  FROM managedservice.claim_operation('predecessor-worker', 30)`).Scan(&claimedOperation, &fencingToken); err != nil ||
		claimedOperation != predecessorOperation || fencingToken != 1 {
		predecessorWorker.Close()
		predecessorPool.Close()
		t.Fatalf("claim predecessor operation=%q fence=%d err=%v", claimedOperation, fencingToken, err)
	}
	if _, err := predecessorWorker.Exec(ctx, `
SELECT managedservice.complete_operation($1, $2, 'predecessor-worker', $3, $4, $5)`,
		predecessorTenant, predecessorOperation, fencingToken,
		"127.0.0.1:23306", "credential-predecessor-mysql"); err != nil {
		predecessorWorker.Close()
		predecessorPool.Close()
		t.Fatalf("complete predecessor operation: %v", err)
	}
	predecessorWorker.Close()
	predecessorPool.Close()

	for attempt := 1; attempt <= 2; attempt++ {
		if err := paasmigration.Apply(ctx, adminDSN, apiDSN, workerDSN); err != nil {
			t.Fatalf("apply current PaaS schema attempt %d: %v", attempt, err)
		}
	}
	currentPool, err := pgxpool.New(ctx, apiDSN)
	if err != nil {
		t.Fatal("open current managed-service API pool")
	}
	defer currentPool.Close()
	currentService, err := usecase.NewService(managedServiceRepository(t, currentPool), usecase.Config{
		Catalog: domain.DefaultCatalog(), WorkloadRoleAuthority: integrationWorkloadRoleBinder{},
		WorkloadRoleRuntime: integrationWorkloadRoleBinder{}, Region: integrationRegion(),
		NewQuotaID:     func() (string, error) { return "quota-unused", nil },
		NewOperationID: func() (string, error) { return "operation-predecessor-termination", nil },
	})
	if err != nil {
		t.Fatal("create current managed-service use case")
	}
	authorization := integrationAuthorization(predecessorTenant)
	retainedActivation, err := currentService.GetServiceActivation(ctx, authorization, predecessorService.ID)
	if err != nil || retainedActivation.Service != (managedservicev1.ServiceDefinitionReference{
		ID: predecessorService.ID, Revision: predecessorService.Revision, ContentDigest: predecessorService.ContentDigest,
	}) {
		t.Fatalf("current schema did not retain predecessor service activation=%#v err=%v", retainedActivation, err)
	}
	retainedQuota, err := currentService.GetQuotaEntitlement(ctx, authorization, predecessorQuota)
	if err != nil || retainedQuota.PurchasedCount != 1 || retainedQuota.ReservedCount != 0 || retainedQuota.ConsumedCount != 1 {
		t.Fatalf("current schema did not retain predecessor quota=%#v err=%v", retainedQuota, err)
	}
	retainedInstallation, err := currentService.GetServiceInstallation(ctx, authorization, predecessorInstallation)
	if err != nil || retainedInstallation.Phase != managedservicev1.InstallationReady ||
		retainedInstallation.Operation.ID != predecessorOperation ||
		retainedInstallation.Operation.Kind != managedservicev1.InstallationOperationProvision ||
		retainedInstallation.Endpoint == nil || retainedInstallation.CredentialReference == nil {
		t.Fatalf("current schema did not retain predecessor installation=%#v err=%v", retainedInstallation, err)
	}
	terminating, replayed, err := currentService.TerminateInstallation(ctx, usecase.TerminateInstallationCommand{
		Authorization: authorization, InstallationID: predecessorInstallation,
		IdempotencyKey: "predecessor-termination-request",
	})
	if err != nil || replayed || terminating.Phase != managedservicev1.InstallationTerminationPending {
		t.Fatalf("terminate retained predecessor installation=%#v replayed=%v err=%v", terminating, replayed, err)
	}
	currentWorker, err := pgxpool.New(ctx, workerDSN)
	if err != nil {
		t.Fatal("open current worker pool")
	}
	defer currentWorker.Close()
	workerRepository := managedServiceRepository(t, currentWorker)
	work, found, err := workerRepository.Claim(ctx, "current-predecessor-worker", 30*time.Second)
	if err != nil || !found || work.Kind != managedservicev1.InstallationOperationTerminate {
		t.Fatalf("claim retained termination=%#v found=%v err=%v", work, found, err)
	}
	if err := workerRepository.CompleteTermination(ctx, work); err != nil {
		t.Fatalf("complete retained termination: %v", err)
	}
	terminated, err := currentService.GetServiceInstallation(ctx, authorization, predecessorInstallation)
	if err != nil || terminated.Phase != managedservicev1.InstallationTerminated ||
		terminated.Endpoint != nil || terminated.CredentialReference != nil {
		t.Fatalf("retained termination result=%#v err=%v", terminated, err)
	}
	retainedQuota, err = currentService.GetQuotaEntitlement(ctx, authorization, predecessorQuota)
	if err != nil || retainedQuota.ReservedCount != 0 || retainedQuota.ConsumedCount != 0 {
		t.Fatalf("retained termination quota=%#v err=%v", retainedQuota, err)
	}
	roleAuthorization := authorization
	roleAuthorization.Subject = paasv1.SubjectRef{Type: paasv1.SubjectRole, ID: "predecessor-activation-role", RoleSession: &paasv1.RoleSessionReference{
		SessionID: "predecessor-activation-session", SourceUserID: "predecessor-activation-user",
	}}
	postgresService, found := domain.DefaultCatalog().ResolveService(managedservicev1.PostgreSQLServiceID)
	if !found {
		t.Fatal("current PostgreSQL service definition is absent")
	}
	roleActivation, replayed, err := currentService.ActivateService(ctx, usecase.ActivateServiceCommand{
		Authorization: roleAuthorization, IdempotencyKey: "predecessor-role-activation-request",
		Request: managedservicev1.ActivateServiceRequest{Service: managedservicev1.ServiceDefinitionReference{
			ID: postgresService.ID, Revision: postgresService.Revision, ContentDigest: postgresService.ContentDigest,
		}},
	})
	if err != nil || replayed || roleActivation.Service.ID != postgresService.ID {
		t.Fatalf("upgraded predecessor rejected current ROLE activation=%#v replayed=%v err=%v", roleActivation, replayed, err)
	}
	var schemaVersion uint64
	if err := currentPool.QueryRow(ctx, `SELECT schema_version FROM paas.readiness()`).Scan(&schemaVersion); err != nil || schemaVersion != 9 {
		t.Fatalf("current PaaS readiness schema=%d err=%v", schemaVersion, err)
	}
}

func TestManagedServicePostgresJourneyAndTenantIsolation(t *testing.T) {
	adminDSN := os.Getenv(managedServiceIntegrationDSN)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", managedServiceIntegrationDSN)
	}
	parsed, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(parsed.ConnConfig.Database, "matrix_managedservice_") {
		database := ""
		if parsed != nil {
			database = parsed.ConnConfig.Database
		}
		t.Fatalf("managed-service integration DSN database=%q err=%v", database, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	apiDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_api_login", managedServiceAPIPassword)
	workerDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_worker_login", managedServiceWorkerPassword)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := paasmigration.Apply(ctx, adminDSN, apiDSN, workerDSN); err != nil {
			t.Fatalf("apply PaaS migration attempt %d: %v", attempt, err)
		}
	}
	pool, err := pgxpool.New(ctx, apiDSN)
	if err != nil {
		t.Fatal("open managed-service API pool")
	}
	defer pool.Close()
	assertCompiledCatalogConstraints(t, ctx, pool)
	repository, err := managedservicepostgres.NewRepository(pool)
	if err != nil {
		t.Fatal("create managed-service repository")
	}
	inspectedAt := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	var quotaSequence, operationSequence atomic.Uint32
	service, err := usecase.NewService(repository, usecase.Config{
		Catalog:               domain.DefaultCatalog(),
		WorkloadRoleAuthority: integrationWorkloadRoleBinder{},
		WorkloadRoleRuntime:   integrationWorkloadRoleBinder{},
		Region: managedservicev1.Region{
			ID: "local-primary", DisplayName: "本机主区域",
			Profile: managedservicev1.RegionLocalMachine,
			State:   managedservicev1.RegionReady, InspectedAt: &inspectedAt,
			Capacity: managedservicev1.RegionCapacity{
				CPUMillicores: 4000, MemoryMiB: 8192, StorageGiB: 100,
			},
		},
		NewQuotaID: func() (string, error) {
			return "quota-integration-" + sequenceSuffix(quotaSequence.Add(1)), nil
		},
		NewOperationID: func() (string, error) {
			return "operation-integration-" + sequenceSuffix(operationSequence.Add(1)), nil
		},
	})
	if err != nil {
		t.Fatal("create managed-service use case")
	}
	authorizationA := integrationAuthorization("organization-a")
	postgresService, err := service.GetService(ctx, authorizationA, managedservicev1.PostgreSQLServiceID)
	if err != nil {
		t.Fatalf("resolve PostgreSQL service definition: %v", err)
	}
	activationAuthorization := authorizationA
	activationAuthorization.Subject = paasv1.SubjectRef{Type: paasv1.SubjectRole, ID: "activation-role", RoleSession: &paasv1.RoleSessionReference{
		SessionID: "activation-session", SourceUserID: "activation-user",
	}}
	activationCommand := usecase.ActivateServiceCommand{
		Authorization: activationAuthorization, IdempotencyKey: "service-activation-integration-request",
		Request: managedservicev1.ActivateServiceRequest{Service: managedservicev1.ServiceDefinitionReference{
			ID: postgresService.ID, Revision: postgresService.Revision, ContentDigest: postgresService.ContentDigest,
		}},
	}
	quotaCommand := usecase.ActivateQuotaCommand{
		Authorization: authorizationA, IdempotencyKey: "quota-integration-request",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	}
	if _, _, err := service.ActivateQuota(ctx, quotaCommand); !errors.Is(err, usecase.ErrServiceNotActivated) {
		t.Fatalf("quota before service activation error=%v", err)
	}
	activation, replayed, err := service.ActivateService(ctx, activationCommand)
	if err != nil || replayed || activation.Service != activationCommand.Request.Service {
		t.Fatalf("activate service=%#v replayed=%v err=%v", activation, replayed, err)
	}
	replayedActivation, replayed, err := service.ActivateService(ctx, activationCommand)
	if err != nil || !replayed || replayedActivation != activation {
		t.Fatalf("replay service activation=%#v replayed=%v err=%v", replayedActivation, replayed, err)
	}
	changedActivation := activationCommand
	changedActivation.Request.Service.Revision++
	if _, _, err := service.ActivateService(ctx, changedActivation); !errors.Is(err, usecase.ErrServiceDefinitionConflict) {
		t.Fatalf("changed service activation error=%v", err)
	}
	quota, replayed, err := service.ActivateQuota(ctx, quotaCommand)
	if err != nil || replayed {
		t.Fatalf("activate quota=%#v replayed=%v err=%v", quota, replayed, err)
	}
	replayedQuota, replayed, err := service.ActivateQuota(ctx, quotaCommand)
	if err != nil || !replayed || replayedQuota.ID != quota.ID {
		t.Fatalf("replay quota=%#v replayed=%v err=%v", replayedQuota, replayed, err)
	}
	quotaCommand.Request.InstanceCount = 2
	if _, _, err := service.ActivateQuota(ctx, quotaCommand); !errors.Is(err, usecase.ErrIdempotencyConflict) {
		t.Fatalf("changed quota replay error=%v", err)
	}
	installationCommand := usecase.CreateInstallationCommand{
		Authorization: authorizationA, IdempotencyKey: "installation-integration-request",
		Request: managedservicev1.CreateInstallationRequest{
			ID: "postgres-integration", Name: "Postgres integration",
			OfferingID:         domain.PostgreSQLOfferingID,
			QuotaEntitlementID: quota.ID, RegionID: "local-primary",
		},
	}
	installation, replayed, err := service.CreateInstallation(ctx, installationCommand)
	if err != nil || replayed || installation.Phase != managedservicev1.InstallationPending {
		t.Fatalf("create installation=%#v replayed=%v err=%v", installation, replayed, err)
	}
	replayedInstallation, replayed, err := service.CreateInstallation(ctx, installationCommand)
	if err != nil || !replayed || replayedInstallation.ID != installation.ID {
		t.Fatalf("replay installation=%#v replayed=%v err=%v", replayedInstallation, replayed, err)
	}
	quotaResults, err := service.ListCommandResults(ctx, usecase.ListCommandResultsQuery{
		Authorization: authorizationA, CommandType: managedservicev1.CommandQuotaActivate,
	})
	if err != nil || len(quotaResults.Items) != 1 || quotaResults.Items[0].IdempotencyKey != quotaCommand.IdempotencyKey ||
		quotaResults.Items[0].Target.ID != quota.ID || quotaResults.Items[0].State != managedservicev1.CommandSucceeded {
		t.Fatalf("quota command results=%#v err=%v", quotaResults, err)
	}
	createResults, err := service.ListCommandResults(ctx, usecase.ListCommandResultsQuery{
		Authorization: authorizationA, CommandType: managedservicev1.CommandInstallationCreate,
	})
	if err != nil || len(createResults.Items) != 1 || createResults.Items[0].IdempotencyKey != installationCommand.IdempotencyKey ||
		createResults.Items[0].Target.ID != installation.ID || createResults.Items[0].State != managedservicev1.CommandInProgress ||
		createResults.Items[0].CompletedAt != nil || createResults.Items[0].Operation == nil ||
		createResults.Items[0].Operation.ID != installation.Operation.ID {
		t.Fatalf("pending installation command results=%#v err=%v", createResults, err)
	}
	otherPrincipal := authorizationA
	otherPrincipal.Subject.ID = "principal-other"
	otherPrincipalResults, err := service.ListCommandResults(ctx, usecase.ListCommandResultsQuery{
		Authorization: otherPrincipal, CommandType: managedservicev1.CommandInstallationCreate,
	})
	if err != nil || len(otherPrincipalResults.Items) != 0 {
		t.Fatalf("other principal observed command results=%#v err=%v", otherPrincipalResults, err)
	}
	workerPool, err := pgxpool.New(ctx, workerDSN)
	if err != nil {
		t.Fatal("open managed-service worker pool")
	}
	defer workerPool.Close()
	workerRepository, err := managedservicepostgres.NewRepository(workerPool)
	if err != nil {
		t.Fatal("create managed-service worker repository")
	}
	work, found, err := workerRepository.Claim(ctx, "managed-worker-integration", 30*time.Second)
	if err != nil || !found || work.Installation.ID != installation.ID || work.Attempt != 1 {
		t.Fatalf("claim installation=%#v found=%v err=%v", work, found, err)
	}
	if err := workerRepository.CompleteProvision(ctx, work, managedserviceadapterv1.ProvisionResult{
		Endpoint: "127.0.0.1:25432", CredentialReference: "credential-postgres-integration",
	}); err != nil {
		t.Fatalf("complete installation: %v", err)
	}
	if err := workerRepository.CompleteProvision(ctx, work, managedserviceadapterv1.ProvisionResult{
		Endpoint: "127.0.0.1:25432", CredentialReference: "credential-postgres-integration",
	}); !errors.Is(err, reconcileinstallation.ErrQueueUnavailable) {
		t.Fatalf("stale completion error=%v", err)
	}
	createResults, err = service.ListCommandResults(ctx, usecase.ListCommandResultsQuery{
		Authorization: authorizationA, CommandType: managedservicev1.CommandInstallationCreate,
	})
	if err != nil || len(createResults.Items) != 1 || createResults.Items[0].State != managedservicev1.CommandSucceeded ||
		createResults.Items[0].CompletedAt == nil || createResults.Items[0].Operation == nil ||
		createResults.Items[0].Operation.Phase != managedservicev1.InstallationReady {
		t.Fatalf("completed installation command results=%#v err=%v", createResults, err)
	}
	auditRepository, err := auditpostgres.NewAuditOutboxRepository(workerPool)
	if err != nil {
		t.Fatal("create managed-service Audit outbox repository")
	}
	ingestor := &managedServiceAuditIngestor{}
	dispatcher, err := auditdispatch.NewUsecase(auditRepository, ingestor, auditdispatch.Config{
		WorkerID: "managed-audit-integration", LeaseDuration: 30 * time.Second,
		DeliveryTimeout: 5 * time.Second, InitialBackoff: time.Second,
		MaxBackoff: time.Minute, MaxAttempts: 5,
		Now: func() time.Time { return time.Date(2026, 8, 26, 12, 1, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal("create managed-service Audit dispatcher")
	}
	for expected := 1; expected <= 4; expected++ {
		result, dispatchErr := dispatcher.DispatchOnce(ctx)
		if dispatchErr != nil || !result.Claimed || !result.Delivered {
			t.Fatalf("dispatch managed-service Audit event %d: result=%#v err=%v", expected, result, dispatchErr)
		}
	}
	if result, dispatchErr := dispatcher.DispatchOnce(ctx); dispatchErr != nil || result.Claimed {
		t.Fatalf("unexpected fifth managed-service Audit event: result=%#v err=%v", result, dispatchErr)
	}
	actions := map[string]int{}
	roleActivationActor := false
	for _, event := range ingestor.events {
		actions[event.Action]++
		if event.Action == audit.ServiceActivationActivated && event.Actor.Equal(activationAuthorization.Subject) {
			roleActivationActor = true
		}
	}
	if actions[audit.ServiceActivationActivated] != 1 ||
		actions[audit.QuotaEntitlementActivated] != 1 ||
		actions[audit.ServiceInstallationCreated] != 1 ||
		actions[audit.ServiceInstallationReady] != 1 || !roleActivationActor {
		t.Fatalf("managed-service Audit actions = %#v", actions)
	}
	snapshot, err := dispatcher.Snapshot(ctx)
	if err != nil || snapshot.Delivered != 4 || snapshot.Pending != 0 || snapshot.DeadLetter != 0 {
		t.Fatalf("combined PaaS Audit snapshot = %#v err=%v", snapshot, err)
	}
	quotas, err := service.ListQuotaEntitlements(ctx, authorizationA)
	if err != nil || len(quotas.Items) != 1 || quotas.Items[0].ReservedCount != 0 ||
		quotas.Items[0].ConsumedCount != 1 {
		t.Fatalf("tenant A quotas=%#v err=%v", quotas, err)
	}
	activations, err := service.ListServiceActivations(ctx, authorizationA)
	if err != nil || len(activations.Items) != 1 || activations.Items[0] != activation {
		t.Fatalf("tenant A service activations=%#v err=%v", activations, err)
	}
	currentActivation, err := service.GetServiceActivation(ctx, authorizationA, activation.Service.ID)
	if err != nil || currentActivation != activation {
		t.Fatalf("tenant A service activation=%#v err=%v", currentActivation, err)
	}
	installations, err := service.ListServiceInstallations(ctx, authorizationA)
	if err != nil || len(installations.Items) != 1 || installations.Items[0].ID != installation.ID ||
		installations.Items[0].Phase != managedservicev1.InstallationReady {
		t.Fatalf("tenant A installations=%#v err=%v", installations, err)
	}
	currentQuota, err := service.GetQuotaEntitlement(ctx, authorizationA, quota.ID)
	if err != nil || currentQuota.ConsumedCount != 1 || currentQuota.ReservedCount != 0 {
		t.Fatalf("tenant A quota resource=%#v err=%v", currentQuota, err)
	}
	currentInstallation, err := service.GetServiceInstallation(ctx, authorizationA, installation.ID)
	if err != nil || currentInstallation.Phase != managedservicev1.InstallationReady {
		t.Fatalf("tenant A installation resource=%#v err=%v", currentInstallation, err)
	}
	currentOperation, err := service.GetInstallationOperation(ctx, authorizationA, installation.ID)
	if err != nil || currentOperation.ID != installation.Operation.ID ||
		currentOperation.Phase != managedservicev1.InstallationReady {
		t.Fatalf("tenant A operation resource=%#v err=%v", currentOperation, err)
	}
	authorizationB := integrationAuthorization("organization-b")
	otherActivations, activationErr := service.ListServiceActivations(ctx, authorizationB)
	if activationErr != nil || len(otherActivations.Items) != 0 {
		t.Fatalf("tenant B observed tenant A activation=%#v err=%v", otherActivations, activationErr)
	}
	if _, err := service.GetServiceActivation(ctx, authorizationB, activation.Service.ID); !errors.Is(err, usecase.ErrNotFound) {
		t.Fatalf("tenant B service activation error=%v", err)
	}
	terminationCommand := usecase.TerminateInstallationCommand{
		Authorization: authorizationB, InstallationID: installation.ID,
		IdempotencyKey: "termination-cross-tenant",
	}
	if _, _, err := service.TerminateInstallation(ctx, terminationCommand); !errors.Is(err, usecase.ErrNotFound) {
		t.Fatalf("tenant B termination error=%v", err)
	}
	terminationCommand.Authorization = authorizationA
	terminationCommand.IdempotencyKey = "termination-integration-request"
	terminating, replayed, err := service.TerminateInstallation(ctx, terminationCommand)
	if err != nil || replayed || terminating.Phase != managedservicev1.InstallationTerminationPending ||
		terminating.Operation.Kind != managedservicev1.InstallationOperationTerminate ||
		terminating.Endpoint == nil || terminating.CredentialReference == nil {
		t.Fatalf("start termination=%#v replayed=%v err=%v", terminating, replayed, err)
	}
	replayedTermination, replayed, err := service.TerminateInstallation(ctx, terminationCommand)
	if err != nil || !replayed || !reflect.DeepEqual(replayedTermination, terminating) {
		t.Fatalf("termination replay=%#v replayed=%v err=%v", replayedTermination, replayed, err)
	}
	terminationWork, found, err := workerRepository.Claim(ctx, "managed-worker-integration", 30*time.Second)
	if err != nil || !found || terminationWork.Kind != managedservicev1.InstallationOperationTerminate ||
		terminationWork.Installation.Phase != managedservicev1.InstallationTerminating ||
		terminationWork.Installation.ID != installation.ID {
		t.Fatalf("claim termination=%#v found=%v err=%v", terminationWork, found, err)
	}
	if err := workerRepository.CompleteTermination(ctx, terminationWork); err != nil {
		t.Fatalf("complete termination: %v", err)
	}
	if err := workerRepository.CompleteTermination(ctx, terminationWork); !errors.Is(err, reconcileinstallation.ErrQueueUnavailable) {
		t.Fatalf("stale termination completion error=%v", err)
	}
	for expected := 5; expected <= 6; expected++ {
		result, dispatchErr := dispatcher.DispatchOnce(ctx)
		if dispatchErr != nil || !result.Claimed || !result.Delivered {
			t.Fatalf("dispatch managed-service Audit event %d: result=%#v err=%v", expected, result, dispatchErr)
		}
	}
	if result, dispatchErr := dispatcher.DispatchOnce(ctx); dispatchErr != nil || result.Claimed {
		t.Fatalf("unexpected seventh managed-service Audit event: result=%#v err=%v", result, dispatchErr)
	}
	actions = map[string]int{}
	for _, event := range ingestor.events {
		actions[event.Action]++
	}
	if actions[audit.ServiceInstallationTerminationRequested] != 1 ||
		actions[audit.ServiceInstallationTerminated] != 1 {
		t.Fatalf("managed-service termination Audit actions=%#v", actions)
	}
	snapshot, err = dispatcher.Snapshot(ctx)
	if err != nil || snapshot.Delivered != 6 || snapshot.Pending != 0 || snapshot.DeadLetter != 0 {
		t.Fatalf("terminated PaaS Audit snapshot=%#v err=%v", snapshot, err)
	}
	currentQuota, err = service.GetQuotaEntitlement(ctx, authorizationA, quota.ID)
	if err != nil || currentQuota.ConsumedCount != 0 || currentQuota.ReservedCount != 0 {
		t.Fatalf("terminated quota resource=%#v err=%v", currentQuota, err)
	}
	currentInstallation, err = service.GetServiceInstallation(ctx, authorizationA, installation.ID)
	if err != nil || currentInstallation.Phase != managedservicev1.InstallationTerminated ||
		currentInstallation.Endpoint != nil || currentInstallation.CredentialReference != nil ||
		currentInstallation.Operation.Kind != managedservicev1.InstallationOperationTerminate ||
		currentInstallation.Operation.Phase != managedservicev1.InstallationReady {
		t.Fatalf("terminated installation resource=%#v err=%v", currentInstallation, err)
	}
	terminationResults, err := service.ListCommandResults(ctx, usecase.ListCommandResultsQuery{
		Authorization: authorizationA, CommandType: managedservicev1.CommandInstallationTerminate,
	})
	if err != nil || len(terminationResults.Items) != 1 ||
		terminationResults.Items[0].IdempotencyKey != terminationCommand.IdempotencyKey ||
		terminationResults.Items[0].Target.ID != installation.ID ||
		terminationResults.Items[0].State != managedservicev1.CommandSucceeded ||
		terminationResults.Items[0].CompletedAt == nil || terminationResults.Items[0].Operation == nil ||
		terminationResults.Items[0].Operation.ID != terminating.Operation.ID {
		t.Fatalf("termination command results=%#v err=%v", terminationResults, err)
	}
	createResults, err = service.ListCommandResults(ctx, usecase.ListCommandResultsQuery{
		Authorization: authorizationA, CommandType: managedservicev1.CommandInstallationCreate,
	})
	if err != nil || len(createResults.Items) != 1 || createResults.Items[0].State != managedservicev1.CommandSucceeded ||
		createResults.Items[0].Operation == nil || createResults.Items[0].Operation.ID != installation.Operation.ID {
		t.Fatalf("retained create command result=%#v err=%v", createResults, err)
	}
	otherQuotas, quotaErr := service.ListQuotaEntitlements(ctx, authorizationB)
	otherInstallations, installationErr := service.ListServiceInstallations(ctx, authorizationB)
	if quotaErr != nil || installationErr != nil || len(otherQuotas.Items) != 0 || len(otherInstallations.Items) != 0 {
		t.Fatalf("tenant B observed tenant A state: quotas=%#v installations=%#v errors=%v/%v",
			otherQuotas, otherInstallations, quotaErr, installationErr)
	}
	otherCommandResults, commandErr := service.ListCommandResults(ctx, usecase.ListCommandResultsQuery{
		Authorization: authorizationB, CommandType: managedservicev1.CommandInstallationTerminate,
	})
	if commandErr != nil || len(otherCommandResults.Items) != 0 {
		t.Fatalf("tenant B observed tenant A command results=%#v err=%v", otherCommandResults, commandErr)
	}
	if _, err := service.GetQuotaEntitlement(ctx, authorizationB, quota.ID); !errors.Is(err, usecase.ErrNotFound) {
		t.Fatalf("tenant B quota resource error=%v", err)
	}
	if _, err := service.GetServiceInstallation(ctx, authorizationB, installation.ID); !errors.Is(err, usecase.ErrNotFound) {
		t.Fatalf("tenant B installation resource error=%v", err)
	}
	installationCommand.Authorization = authorizationB
	installationCommand.Request.ID = "postgres-cross-tenant"
	installationCommand.IdempotencyKey = "installation-cross-tenant"
	if _, _, err := service.CreateInstallation(ctx, installationCommand); !errors.Is(err, usecase.ErrNotFound) {
		t.Fatalf("cross-tenant entitlement error=%v", err)
	}

	concurrentAuthorization := integrationAuthorization("organization-concurrent")
	concurrentActivationCommand := activationCommand
	concurrentActivationCommand.Authorization = concurrentAuthorization
	concurrentActivationCommand.IdempotencyKey = "service-activation-concurrent-request"
	if createdActivation, replayed, err := service.ActivateService(ctx, concurrentActivationCommand); err != nil || replayed ||
		createdActivation.Service != concurrentActivationCommand.Request.Service {
		t.Fatalf("activate concurrent service=%#v replayed=%v err=%v", createdActivation, replayed, err)
	}
	concurrentQuota, replayed, err := service.ActivateQuota(ctx, usecase.ActivateQuotaCommand{
		Authorization: concurrentAuthorization, IdempotencyKey: "quota-concurrent-request",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	})
	if err != nil || replayed {
		t.Fatalf("activate concurrent quota=%#v replayed=%v err=%v", concurrentQuota, replayed, err)
	}
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	concurrentService, err := usecase.NewService(&quotaBarrierRepository{
		Repository: repository, quotaID: concurrentQuota.ID, arrived: arrived, release: release,
	}, usecase.Config{
		Catalog: domain.DefaultCatalog(), WorkloadRoleAuthority: integrationWorkloadRoleBinder{},
		WorkloadRoleRuntime: integrationWorkloadRoleBinder{}, Region: integrationRegion(),
		NewQuotaID: func() (string, error) { return "quota-concurrent-unused", nil },
		NewOperationID: func() (string, error) {
			return "operation-concurrent-" + sequenceSuffix(operationSequence.Add(1)), nil
		},
	})
	if err != nil {
		t.Fatal("create concurrent managed-service use case")
	}
	type concurrentResult struct {
		installation managedservicev1.ServiceInstallation
		err          error
	}
	results := make(chan concurrentResult, 2)
	for _, id := range []string{"postgres-concurrent-one", "postgres-concurrent-two"} {
		go func(id string) {
			created, _, createErr := concurrentService.CreateInstallation(ctx, usecase.CreateInstallationCommand{
				Authorization: concurrentAuthorization, IdempotencyKey: "installation-" + id,
				Request: managedservicev1.CreateInstallationRequest{
					ID: id, Name: id, OfferingID: domain.PostgreSQLOfferingID,
					QuotaEntitlementID: concurrentQuota.ID, RegionID: integrationRegion().ID,
				},
			})
			results <- concurrentResult{installation: created, err: createErr}
		}(id)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		select {
		case <-arrived:
		case <-ctx.Done():
			t.Fatal("concurrent reservations did not reach the PostgreSQL transaction barrier")
		}
	}
	close(release)
	var created managedservicev1.ServiceInstallation
	var succeeded, exhausted int
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			created = result.installation
			succeeded++
		case errors.Is(result.err, usecase.ErrQuotaExhausted):
			exhausted++
		default:
			t.Fatalf("concurrent reservation error=%v", result.err)
		}
	}
	if succeeded != 1 || exhausted != 1 || managedservicev1.ValidateServiceInstallation(created) != nil {
		t.Fatalf("concurrent reservation succeeded=%d exhausted=%d created=%#v", succeeded, exhausted, created)
	}
	retainedConcurrentQuota, err := service.GetQuotaEntitlement(ctx, concurrentAuthorization, concurrentQuota.ID)
	if err != nil || retainedConcurrentQuota.PurchasedCount != 1 || retainedConcurrentQuota.ReservedCount != 1 ||
		retainedConcurrentQuota.ConsumedCount != 0 || retainedConcurrentQuota.ResourceVersion != concurrentQuota.ResourceVersion+1 {
		t.Fatalf("concurrent quota=%#v err=%v", retainedConcurrentQuota, err)
	}
	concurrentInstallations, err := service.ListServiceInstallations(ctx, concurrentAuthorization)
	if err != nil || len(concurrentInstallations.Items) != 1 || concurrentInstallations.Items[0].ID != created.ID ||
		concurrentInstallations.Items[0].Phase != managedservicev1.InstallationPending {
		t.Fatalf("concurrent installations=%#v err=%v", concurrentInstallations, err)
	}
	for expected := 7; expected <= 9; expected++ {
		result, dispatchErr := dispatcher.DispatchOnce(ctx)
		if dispatchErr != nil || !result.Claimed || !result.Delivered {
			t.Fatalf("dispatch concurrent managed-service Audit event %d: result=%#v err=%v", expected, result, dispatchErr)
		}
	}
	if result, dispatchErr := dispatcher.DispatchOnce(ctx); dispatchErr != nil || result.Claimed {
		t.Fatalf("unexpected concurrent loser Audit event: result=%#v err=%v", result, dispatchErr)
	}
	actions = map[string]int{}
	for _, event := range ingestor.events {
		actions[event.Action]++
	}
	if actions[audit.ServiceActivationActivated] != 2 || actions[audit.QuotaEntitlementActivated] != 2 ||
		actions[audit.ServiceInstallationCreated] != 2 ||
		actions[audit.ServiceInstallationReady] != 1 || actions[audit.ServiceInstallationTerminationRequested] != 1 ||
		actions[audit.ServiceInstallationTerminated] != 1 {
		t.Fatalf("concurrent managed-service Audit actions=%#v", actions)
	}
	snapshot, err = dispatcher.Snapshot(ctx)
	if err != nil || snapshot.Delivered != 9 || snapshot.Pending != 0 || snapshot.DeadLetter != 0 {
		t.Fatalf("concurrent managed-service Audit snapshot=%#v err=%v", snapshot, err)
	}
}

type quotaBarrierRepository struct {
	usecase.Repository
	quotaID string
	arrived chan<- struct{}
	release <-chan struct{}
}

func (value *quotaBarrierRepository) Begin(
	ctx context.Context,
	tenantID string,
	mode usecase.TransactionMode,
) (usecase.Transaction, error) {
	transaction, err := value.Repository.Begin(ctx, tenantID, mode)
	if err != nil {
		return nil, err
	}
	return &quotaBarrierTransaction{
		Transaction: transaction, quotaID: value.quotaID, arrived: value.arrived, release: value.release,
	}, nil
}

type quotaBarrierTransaction struct {
	usecase.Transaction
	quotaID string
	arrived chan<- struct{}
	release <-chan struct{}
}

func (value *quotaBarrierTransaction) GetQuotaEntitlementForUpdate(
	ctx context.Context,
	id string,
) (managedservicev1.QuotaEntitlement, error) {
	if id == value.quotaID {
		select {
		case value.arrived <- struct{}{}:
		default:
		}
		select {
		case <-value.release:
		case <-ctx.Done():
			return managedservicev1.QuotaEntitlement{}, ctx.Err()
		}
	}
	return value.Transaction.GetQuotaEntitlementForUpdate(ctx, id)
}

type integrationWorkloadRoleBinder struct{}

func (integrationWorkloadRoleBinder) BindWorkloadRole(
	context.Context,
	iamv1.ServiceRoleTemplateReference,
	string,
	port.AuthorizationRequest,
) (iamv1.ServiceLinkedRoleAccess, error) {
	return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
}

func (integrationWorkloadRoleBinder) RevokeWorkloadRole(
	context.Context,
	iamv1.WorkloadRoleBindingID,
	uint64,
	string,
	port.AuthorizationRequest,
) (iamv1.WorkloadRoleBinding, error) {
	return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
}

func (integrationWorkloadRoleBinder) ListWorkloadRoleCommandResults(
	context.Context,
	iamv1.WorkloadRoleCommandType,
	string,
) (iamv1.WorkloadRoleCommandResultList, error) {
	return iamv1.WorkloadRoleCommandResultList{
		APIVersion: iamv1.APIVersion, Kind: "WorkloadRoleCommandResultList",
		Items: []iamv1.WorkloadRoleCommandResult{},
	}, nil
}

func (integrationWorkloadRoleBinder) AssumeWorkloadRole(
	context.Context,
	iamv1.WorkloadRoleBindingID,
	string,
	port.WorkloadRoleAuthorizationRequest,
) (port.WorkloadRoleLease, error) {
	return nil, port.ErrAuthorizationUnavailable
}

func integrationRuntimeDSN(t *testing.T, adminDSN, role, password string) string {
	t.Helper()
	value, err := url.Parse(adminDSN)
	if err != nil || value.Scheme != "postgresql" {
		t.Fatal("parse managed-service integration DSN")
	}
	value.User = url.UserPassword(role, password)
	return value.String()
}

func integrationAuthorization(tenantID string) port.Authorization {
	return port.Authorization{
		TenantID: tenantID, Subject: paasv1.SubjectRef{Type: port.SubjectUser, ID: "principal-integration"},
		DecisionID: "decision-integration", RequestID: "request-integration",
	}
}

func sequenceSuffix(value uint32) string {
	if value == 1 {
		return "one"
	}
	if value == 2 {
		return "two"
	}
	return "many"
}

type managedServiceAuditIngestor struct {
	events []audit.Event
}

func (ingestor *managedServiceAuditIngestor) Ingest(_ context.Context, event audit.Event) error {
	ingestor.events = append(ingestor.events, event)
	return nil
}

// Prove the generated database contract with real writes through the restricted
// API login. Each probe rolls back, so it cannot become reconciliation work.
func TestManagedServiceElasticsearchDependencyCustodyAndRaces(t *testing.T) {
	adminDSN := os.Getenv(managedServiceDependencyDSN)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", managedServiceDependencyDSN)
	}
	parsed, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(parsed.ConnConfig.Database, "matrix_managedservice_dependency_") {
		t.Fatal("dependency test requires a dedicated database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	apiDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_api_login", managedServiceAPIPassword)
	workerDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_worker_login", managedServiceWorkerPassword)
	for range 2 {
		if err := paasmigration.Apply(ctx, adminDSN, apiDSN, workerDSN); err != nil {
			t.Fatal("apply dependency schema", err)
		}
	}
	pool, err := pgxpool.New(ctx, apiDSN)
	if err != nil {
		t.Fatal("open dependency API pool")
	}
	defer pool.Close()
	workerPool, err := pgxpool.New(ctx, workerDSN)
	if err != nil {
		t.Fatal("open dependency worker pool")
	}
	defer workerPool.Close()
	repository, queue := managedServiceRepository(t, pool), managedServiceRepository(t, workerPool)
	var sequence atomic.Uint32
	newID := func() (string, error) { return "dependency-" + strconv.FormatUint(uint64(sequence.Add(1)), 10), nil }
	config := usecase.Config{Catalog: domain.DefaultCatalog(), Region: integrationRegion(),
		Authorizer: integrationDependencyAuthorizer{}, WorkloadRoleAuthority: integrationWorkloadRoleBinder{},
		WorkloadRoleRuntime: integrationWorkloadRoleBinder{}, NewQuotaID: newID, NewOperationID: newID}
	service, err := usecase.NewService(repository, config)
	if err != nil {
		t.Fatal(err)
	}
	authorization := integrationAuthorization("dependency-account")
	other := integrationAuthorization("dependency-other")
	quota := func(actor port.Authorization, serviceID, offeringID, shapeID string) managedservicev1.QuotaEntitlement {
		t.Helper()
		definition, err := service.GetService(ctx, actor, serviceID)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := newID()
		if _, _, err := service.ActivateService(ctx, usecase.ActivateServiceCommand{Authorization: actor, IdempotencyKey: key,
			Request: managedservicev1.ActivateServiceRequest{Service: managedservicev1.ServiceDefinitionReference{
				ID: definition.ID, Revision: definition.Revision, ContentDigest: definition.ContentDigest}}}); err != nil {
			t.Fatal(err)
		}
		key, _ = newID()
		value, _, err := service.ActivateQuota(ctx, usecase.ActivateQuotaCommand{Authorization: actor, IdempotencyKey: key,
			Request: managedservicev1.ActivateQuotaRequest{OfferingID: offeringID, QuotaShapeID: shapeID, InstanceCount: 8}})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	eQuota := quota(authorization, managedservicev1.ElasticsearchServiceID, managedservicev1.ElasticsearchOfferingID, "elasticsearch-small")
	kQuota := quota(authorization, managedservicev1.KibanaServiceID, managedservicev1.KibanaOfferingID, "kibana-small")
	otherQuota := quota(other, managedservicev1.ElasticsearchServiceID, managedservicev1.ElasticsearchOfferingID, "elasticsearch-small")
	claim := func(id string, kind managedservicev1.InstallationOperationKind) reconcileinstallation.WorkItem {
		t.Helper()
		work, found, err := queue.Claim(ctx, "dependency-worker", time.Minute)
		if err != nil || !found || work.Installation.ID != id || work.Kind != kind {
			t.Fatalf("claim exact dependency operation %s: %v", id, err)
		}
		return work
	}
	createSearch := func(actor port.Authorization, entitlement managedservicev1.QuotaEntitlement, id string) managedservicev1.ServiceInstallation {
		t.Helper()
		if _, _, err := service.CreateInstallation(ctx, usecase.CreateInstallationCommand{Authorization: actor, IdempotencyKey: "create-" + id,
			Request: managedservicev1.CreateInstallationRequest{ID: id, Name: id, OfferingID: entitlement.OfferingID, QuotaEntitlementID: entitlement.ID, RegionID: "local-primary"}}); err != nil {
			t.Fatal(err)
		}
		work := claim(id, managedservicev1.InstallationOperationProvision)
		if err := queue.CompleteProvision(ctx, work, managedserviceadapterv1.ProvisionResult{Endpoint: "http://127.0.0.1:27123", CredentialReference: "credential-" + id}); err != nil {
			t.Fatal(err)
		}
		value, err := service.GetServiceInstallation(ctx, actor, id)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	search := createSearch(authorization, eQuota, "dependency-search")
	foreign := createSearch(other, otherQuota, "foreign-search")
	create := func(id string, dependency managedservicev1.ServiceInstallation) usecase.CreateInstallationCommand {
		return usecase.CreateInstallationCommand{Authorization: authorization, Credential: authorization.TenantID, IdempotencyKey: "create-" + id,
			Request: managedservicev1.CreateInstallationRequest{ID: id, Name: id, OfferingID: kQuota.OfferingID, QuotaEntitlementID: kQuota.ID, RegionID: "local-primary",
				Elasticsearch: &managedservicev1.ElasticsearchReference{InstallationID: dependency.ID, ResourceVersion: dependency.ResourceVersion}}}
	}
	terminate := func(actor port.Authorization, id, key string) usecase.TerminateInstallationCommand {
		return usecase.TerminateInstallationCommand{Authorization: actor, InstallationID: id, IdempotencyKey: key}
	}
	snapshot := func() (managedservicev1.QuotaEntitlement, int64, int64) {
		t.Helper()
		q, err := service.GetQuotaEntitlement(ctx, authorization, kQuota.ID)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, "SELECT pg_catalog.set_config('matrix.tenant_id', $1, true)", authorization.TenantID); err != nil {
			t.Fatal(err)
		}
		var operations, events int64
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM managedservice.operations").Scan(&operations); err != nil {
			t.Fatal(err)
		}
		// Audit remains behind its bounded security-definer observer.
		if err := workerPool.QueryRow(ctx, "SELECT pending_count + leased_count + retry_count + delivered_count + dead_letter_count FROM managedservice.audit_outbox_snapshot()").Scan(&events); err != nil {
			t.Fatal(err)
		}
		return q, operations, events
	}
	beforeQuota, beforeOperations, beforeEvents := snapshot()
	for _, name := range []string{"missing", "foreign", "stale"} {
		command := create("rejected-kibana", search)
		switch name {
		case "missing":
			command.Request.Elasticsearch.InstallationID = "absent-search"
		case "foreign":
			command.Request.Elasticsearch.InstallationID = foreign.ID
		case "stale":
			command.Request.Elasticsearch.ResourceVersion++
		}
		if _, _, err := service.CreateInstallation(ctx, command); !errors.Is(err, usecase.ErrDependencyUnavailable) {
			t.Fatalf("%s dependency error=%v", name, err)
		}
	}
	// Bypass the application check to prove the restricted SQL boundary itself.
	for _, name := range []string{"foreign", "stale", "engine", "region"} {
		tx, err := repository.Begin(ctx, authorization.TenantID, usecase.ReadWrite)
		if err != nil {
			t.Fatal(err)
		}
		draft := usecase.InstallationDraft{ID: "sql-rejected-kibana", Name: "SQL dependency probe", OfferingID: kQuota.OfferingID, EngineVersion: search.EngineVersion,
			QuotaEntitlementID: kQuota.ID, RegionID: search.RegionID, OperationID: "sql-rejected-operation", IdempotencyKey: "sql-rejected-command",
			RequestDigest: "sha256:" + strings.Repeat("a", 64), ActorType: port.SubjectUser, ActorID: authorization.Subject.ID, IAMDecisionID: authorization.DecisionID, RequestID: authorization.RequestID,
			Elasticsearch: &managedservicev1.ElasticsearchReference{InstallationID: search.ID, ResourceVersion: search.ResourceVersion}}
		switch name {
		case "foreign":
			draft.Elasticsearch.InstallationID = foreign.ID
		case "stale":
			draft.Elasticsearch.ResourceVersion++
		case "engine":
			draft.EngineVersion = "8.20.0"
		case "region":
			draft.RegionID = "other-region"
		}
		_, reserveErr := tx.ReserveInstallation(ctx, draft, beforeQuota.ResourceVersion)
		_ = tx.Rollback(ctx)
		if !errors.Is(reserveErr, usecase.ErrDependencyUnavailable) {
			t.Fatalf("SQL %s dependency error=%v", name, reserveErr)
		}
	}
	afterQuota, afterOperations, afterEvents := snapshot()
	if beforeQuota != afterQuota || beforeOperations != afterOperations || beforeEvents != afterEvents {
		t.Fatal("dependency rejection changed quota, operations or Audit")
	}

	command := create("dependency-kibana", search)
	created, replayed, err := service.CreateInstallation(ctx, command)
	if err != nil || replayed || created.Elasticsearch == nil || *created.Elasticsearch != *command.Request.Elasticsearch {
		t.Fatal("persist typed dependency", err)
	}
	wrongProduct := create("rejected-dependent-kibana", created)
	if _, _, err := service.CreateInstallation(ctx, wrongProduct); !errors.Is(err, usecase.ErrDependencyUnavailable) {
		t.Fatal("Kibana accepted another Kibana as Elasticsearch", err)
	}
	retained, err := service.GetServiceInstallation(ctx, authorization, created.ID)
	if err != nil || !reflect.DeepEqual(retained, created) {
		t.Fatal("dependency read differs from reservation", err)
	}
	denyDelete := func() {
		t.Helper()
		beforeQuota, beforeOperations, beforeEvents := snapshot()
		if _, _, err := service.TerminateInstallation(ctx, terminate(authorization, search.ID, "delete-protected-search")); !errors.Is(err, usecase.ErrDependencyInUse) {
			t.Fatal("live dependency failed to prevent Elasticsearch termination", err)
		}
		afterQuota, afterOperations, afterEvents := snapshot()
		if beforeQuota != afterQuota || beforeOperations != afterOperations || beforeEvents != afterEvents {
			t.Fatal("denied termination left partial effects")
		}
	}
	denyDelete()
	work := claim(created.ID, managedservicev1.InstallationOperationProvision)
	if work.Installation.Elasticsearch == nil || *work.Installation.Elasticsearch != *command.Request.Elasticsearch {
		t.Fatal("worker claim lost dependency binding")
	}
	if err := queue.FailCleanup(ctx, work, "PROVIDER_CLEANUP_FAILED"); err != nil {
		t.Fatal(err)
	}
	denyDelete()
	if _, _, err := service.TerminateInstallation(ctx, terminate(authorization, created.ID, "retry-kibana-cleanup")); err != nil {
		t.Fatal("retry failed provisioning cleanup", err)
	}
	work = claim(created.ID, managedservicev1.InstallationOperationTerminate)
	if err := queue.Fail(ctx, work, "PROVIDER_TERMINATION_FAILED"); err != nil {
		t.Fatal(err)
	}
	denyDelete()
	if _, _, err := service.TerminateInstallation(ctx, terminate(authorization, created.ID, "retry-kibana-cleanup-again")); err != nil {
		t.Fatal("retry native credential revocation", err)
	}
	work = claim(created.ID, managedservicev1.InstallationOperationTerminate)
	if err := queue.CompleteTermination(ctx, work); err != nil {
		t.Fatal("release reserved quota after eventual cleanup", err)
	}
	retained, err = service.GetServiceInstallation(ctx, authorization, created.ID)
	if err != nil || retained.Phase != managedservicev1.InstallationTerminated || retained.Elasticsearch == nil || *retained.Elasticsearch != *command.Request.Elasticsearch {
		t.Fatal("terminal dependency history was lost", err)
	}
	cleanedQuota, _, _ := snapshot()
	if cleanedQuota.ReservedCount != 0 || cleanedQuota.ConsumedCount != 0 {
		t.Fatal("cleanup retried the wrong quota release")
	}
	finishSearch := func(actor port.Authorization, id string) {
		t.Helper()
		if _, _, err := service.TerminateInstallation(ctx, terminate(actor, id, "finish-"+id)); err != nil {
			t.Fatal(err)
		}
		if err := queue.CompleteTermination(ctx, claim(id, managedservicev1.InstallationOperationTerminate)); err != nil {
			t.Fatal(err)
		}
	}
	finishSearch(authorization, search.ID)
	finishSearch(other, foreign.ID)

	for _, winner := range []string{"create", "terminate"} {
		t.Run("dependency-race-"+winner, func(t *testing.T) {
			search := createSearch(authorization, eQuota, "race-search-"+winner)
			barrier := &dependencyBarrierRepository{Repository: repository, winner: winner, held: make(chan struct{}), entered: make(chan struct{}, 1), release: make(chan struct{})}
			racing, err := usecase.NewService(barrier, config)
			if err != nil {
				t.Fatal(err)
			}
			createResult, terminateResult := make(chan error, 1), make(chan error, 1)
			command := create("race-kibana-"+winner, search)
			createCall := func() { _, _, err := racing.CreateInstallation(ctx, command); createResult <- err }
			terminateCall := func() {
				_, _, err := racing.TerminateInstallation(ctx, terminate(authorization, search.ID, "race-delete-"+winner))
				terminateResult <- err
			}
			if winner == "create" {
				go createCall()
			} else {
				go terminateCall()
			}
			select {
			case <-barrier.held:
			case <-ctx.Done():
				t.Fatal("dependency winner did not acquire its row lock")
			}
			if winner == "create" {
				go terminateCall()
			} else {
				go createCall()
			}
			select {
			case <-barrier.entered:
			case <-ctx.Done():
				t.Fatal("dependency loser did not enter its conflicting transaction")
			}
			close(barrier.release)
			createErr, terminateErr := <-createResult, <-terminateResult
			if winner == "create" {
				if createErr != nil || !errors.Is(terminateErr, usecase.ErrDependencyInUse) {
					t.Fatalf("create winner create=%v terminate=%v", createErr, terminateErr)
				}
				if err := queue.Fail(ctx, claim(command.Request.ID, managedservicev1.InstallationOperationProvision), "CLEANED_FIXTURE"); err != nil {
					t.Fatal(err)
				}
				finishSearch(authorization, search.ID)
			} else {
				if terminateErr != nil || !errors.Is(createErr, usecase.ErrDependencyUnavailable) {
					t.Fatalf("terminate winner create=%v terminate=%v", createErr, terminateErr)
				}
				if _, err := service.GetServiceInstallation(ctx, authorization, command.Request.ID); !errors.Is(err, usecase.ErrNotFound) {
					t.Fatal("termination winner left dangling Kibana", err)
				}
				if err := queue.CompleteTermination(ctx, claim(search.ID, managedservicev1.InstallationOperationTerminate)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	adminPool, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal("open dependency schema verifier")
	}
	defer adminPool.Close()
	if _, err := adminPool.Exec(ctx, "ALTER TABLE managedservice.service_installations DISABLE TRIGGER protect_elasticsearch_dependency"); err != nil {
		t.Fatal(err)
	}
	verifyErr := paasmigration.VerifyInstalled(ctx, adminDSN, apiDSN, workerDSN)
	if _, err := adminPool.Exec(ctx, "ALTER TABLE managedservice.service_installations ENABLE TRIGGER protect_elasticsearch_dependency"); err != nil {
		t.Fatal(err)
	}
	if verifyErr == nil {
		t.Fatal("disabled dependency guard passed schema readiness")
	}
	if err := paasmigration.VerifyInstalled(ctx, adminDSN, apiDSN, workerDSN); err != nil {
		t.Fatal("restored dependency guard failed readiness", err)
	}
}

type integrationDependencyAuthorizer struct{ port.Authorizer }

func (integrationDependencyAuthorizer) Authorize(_ context.Context, request port.AuthorizationRequest) (port.Authorization, error) {
	if port.ValidateAuthorizationRequest(request) != nil || request.Action != port.AuthorizeInstallationUse || request.Credential != "dependency-account" {
		return port.Authorization{}, port.ErrPermissionDenied
	}
	result := integrationAuthorization(request.Credential)
	result.RequestID = request.RequestID
	return result, nil
}

type dependencyBarrierRepository struct {
	usecase.Repository
	winner  string
	held    chan struct{}
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *dependencyBarrierRepository) Begin(ctx context.Context, tenant string, mode usecase.TransactionMode) (usecase.Transaction, error) {
	tx, err := r.Repository.Begin(ctx, tenant, mode)
	if err != nil {
		return nil, err
	}
	return &dependencyBarrierTransaction{Transaction: tx, barrier: r}, nil
}

type dependencyBarrierTransaction struct {
	usecase.Transaction
	barrier *dependencyBarrierRepository
}

func (tx *dependencyBarrierTransaction) ReserveInstallation(ctx context.Context, draft usecase.InstallationDraft, version uint64) (managedservicev1.ServiceInstallation, error) {
	if tx.barrier.winner != "create" {
		select {
		case tx.barrier.entered <- struct{}{}:
		default:
		}
	}
	value, err := tx.Transaction.ReserveInstallation(ctx, draft, version)
	if err == nil && tx.barrier.winner == "create" {
		tx.barrier.once.Do(func() {
			close(tx.barrier.held)
			select {
			case <-tx.barrier.release:
			case <-ctx.Done():
			}
		})
	}
	return value, err
}

func (tx *dependencyBarrierTransaction) StartTermination(ctx context.Context, draft usecase.TerminationDraft) (managedservicev1.ServiceInstallation, error) {
	if tx.barrier.winner != "terminate" {
		select {
		case tx.barrier.entered <- struct{}{}:
		default:
		}
	}
	value, err := tx.Transaction.StartTermination(ctx, draft)
	if err == nil && tx.barrier.winner == "terminate" {
		tx.barrier.once.Do(func() {
			close(tx.barrier.held)
			select {
			case <-tx.barrier.release:
			case <-ctx.Done():
			}
		})
	}
	return value, err
}

func assertCompiledCatalogConstraints(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	probe := func(offeringID, shapeID, engineVersion, expectedConstraint string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, "SELECT pg_catalog.set_config('matrix.tenant_id', 'organization-catalog-contract', true)"); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO managedservice.quota_entitlements (
			tenant_id, id, offering_id, quota_shape_id, purchased_count, idempotency_key, request_digest,
			activated_by_type, activated_by_id, iam_decision_id, request_id
		) VALUES (managedservice.current_tenant_id(), 'catalog-quota', $1, $2, 1, 'catalog-request', $3,
			'USER', 'catalog-principal', 'catalog-decision', 'catalog-request')`,
			offeringID, shapeID, "sha256:"+strings.Repeat("a", 64))
		var dependencyID, dependencyVersion any
		if err == nil && offeringID == managedservicev1.KibanaOfferingID {
			search, _, found := domain.DefaultCatalog().Resolve(managedservicev1.ElasticsearchOfferingID, "elasticsearch-small")
			if !found {
				t.Fatal("catalog lacks Kibana's prerequisite")
			}
			_, err = tx.Exec(ctx, `INSERT INTO managedservice.quota_entitlements (
				tenant_id, id, offering_id, quota_shape_id, purchased_count, idempotency_key, request_digest,
				activated_by_type, activated_by_id, iam_decision_id, request_id
			) VALUES (managedservice.current_tenant_id(), 'catalog-search-quota', $1, 'elasticsearch-small', 1, 'catalog-search-request', $2,
				'USER', 'catalog-principal', 'catalog-decision', 'catalog-search-request')`, search.ID, "sha256:"+strings.Repeat("a", 64))
			if err != nil {
				t.Fatal("seed catalog prerequisite quota", err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO managedservice.service_installations (
				tenant_id, id, name, offering_id, engine_version, quota_entitlement_id, region_id, current_operation_id,
				phase, endpoint, credential_reference
			) VALUES (managedservice.current_tenant_id(), 'catalog-search', 'Catalog search', $1, $2,
				'catalog-search-quota', 'local-primary', 'catalog-search-operation', 'READY', 'http://127.0.0.1:27123', 'credential-catalog-search')`, search.ID, search.EngineVersion)
			if err != nil {
				t.Fatal("seed catalog prerequisite installation", err)
			}
			dependencyID, dependencyVersion = "catalog-search", uint64(1)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO managedservice.service_installations (
				tenant_id, id, name, offering_id, engine_version, quota_entitlement_id, region_id, current_operation_id,
				elasticsearch_installation_id, elasticsearch_resource_version
			) VALUES (managedservice.current_tenant_id(), 'catalog-installation', 'Catalog constraint probe',
				$1, $2, 'catalog-quota', 'local-primary', 'catalog-operation', $3, $4)`, offeringID, engineVersion, dependencyID, dependencyVersion)
		}
		if expectedConstraint == "" {
			if err != nil {
				t.Fatalf("released catalog pair %s/%s cannot persist: %v", offeringID, shapeID, err)
			}
			return
		}
		var failure *pgconn.PgError
		if offeringID == managedservicev1.KibanaOfferingID && expectedConstraint == "service_installations_ids_valid" {
			if !errors.As(err, &failure) || failure.Code != "MX424" {
				t.Fatal("mismatched Kibana engine passed dependency binding", err)
			}
			return
		}
		if !errors.As(err, &failure) || failure.Code != "23514" || failure.ConstraintName != expectedConstraint {
			t.Fatalf("catalog mismatch did not fail its owning constraint %s", expectedConstraint)
		}
	}
	offerings := domain.DefaultCatalog().List()
	for index, offering := range offerings {
		for _, shape := range offering.QuotaShapes {
			probe(offering.ID, shape.ID, offering.EngineVersion, "")
		}
		foreignShape := offerings[(index+1)%len(offerings)].QuotaShapes[0].ID
		probe(offering.ID, foreignShape, offering.EngineVersion, "quota_entitlements_catalog_valid")
		probe(offering.ID, offering.QuotaShapes[0].ID, "0.0.0", "service_installations_ids_valid")
	}
	probe("unreleased-1", offerings[0].QuotaShapes[0].ID, "1", "quota_entitlements_catalog_valid")
}
