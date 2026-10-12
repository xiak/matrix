package postgres_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
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
	managedServicePredecessorDSN = "MATRIX_MANAGEDSERVICE_PREDECESSOR_POSTGRES_TEST_DSN"
	managedServicePredecessor    = "dc5f63a3c6dea5fa2943bb78628cd753582cb2bc"
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
	// The fixed predecessor's own repository had already proved the create
	// workflow at dc5f63a. This fixture persists its observable READY state
	// using only that predecessor's released tables and worker functions; the
	// assertions below exercise the current schema and use cases exclusively.
	tx, err := predecessorPool.Begin(ctx)
	if err != nil {
		predecessorPool.Close()
		t.Fatal("begin predecessor fixture")
	}
	if _, err = tx.Exec(ctx, "SELECT pg_catalog.set_config('matrix.tenant_id', $1, true)", predecessorTenant); err == nil {
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
    tenant_id, id, name, offering_id, engine_version, quota_entitlement_id, region_id
) VALUES (
    managedservice.current_tenant_id(), $1, 'Predecessor MySQL',
    'mysql-8.4', '8.4', $2, 'local-primary'
)`, predecessorInstallation, predecessorQuota)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
INSERT INTO managedservice.operations (
    tenant_id, id, installation_id, idempotency_key, request_digest,
    requested_by_type, requested_by_id, iam_decision_id, request_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2,
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
	var schemaVersion uint64
	if err := currentPool.QueryRow(ctx, `SELECT schema_version FROM paas.readiness()`).Scan(&schemaVersion); err != nil || schemaVersion != 5 {
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
	quotaCommand := usecase.ActivateQuotaCommand{
		Authorization: authorizationA, IdempotencyKey: "quota-integration-request",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
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
	for expected := 1; expected <= 3; expected++ {
		result, dispatchErr := dispatcher.DispatchOnce(ctx)
		if dispatchErr != nil || !result.Claimed || !result.Delivered {
			t.Fatalf("dispatch managed-service Audit event %d: result=%#v err=%v", expected, result, dispatchErr)
		}
	}
	if result, dispatchErr := dispatcher.DispatchOnce(ctx); dispatchErr != nil || result.Claimed {
		t.Fatalf("unexpected fourth managed-service Audit event: result=%#v err=%v", result, dispatchErr)
	}
	actions := map[string]int{}
	for _, event := range ingestor.events {
		actions[event.Action]++
	}
	if actions[audit.QuotaEntitlementActivated] != 1 ||
		actions[audit.ServiceInstallationCreated] != 1 ||
		actions[audit.ServiceInstallationReady] != 1 {
		t.Fatalf("managed-service Audit actions = %#v", actions)
	}
	snapshot, err := dispatcher.Snapshot(ctx)
	if err != nil || snapshot.Delivered != 3 || snapshot.Pending != 0 || snapshot.DeadLetter != 0 {
		t.Fatalf("combined PaaS Audit snapshot = %#v err=%v", snapshot, err)
	}
	quotas, err := service.ListQuotaEntitlements(ctx, authorizationA)
	if err != nil || len(quotas.Items) != 1 || quotas.Items[0].ReservedCount != 0 ||
		quotas.Items[0].ConsumedCount != 1 {
		t.Fatalf("tenant A quotas=%#v err=%v", quotas, err)
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
	for expected := 4; expected <= 5; expected++ {
		result, dispatchErr := dispatcher.DispatchOnce(ctx)
		if dispatchErr != nil || !result.Claimed || !result.Delivered {
			t.Fatalf("dispatch managed-service Audit event %d: result=%#v err=%v", expected, result, dispatchErr)
		}
	}
	if result, dispatchErr := dispatcher.DispatchOnce(ctx); dispatchErr != nil || result.Claimed {
		t.Fatalf("unexpected sixth managed-service Audit event: result=%#v err=%v", result, dispatchErr)
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
	if err != nil || snapshot.Delivered != 5 || snapshot.Pending != 0 || snapshot.DeadLetter != 0 {
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
	otherQuotas, quotaErr := service.ListQuotaEntitlements(ctx, authorizationB)
	otherInstallations, installationErr := service.ListServiceInstallations(ctx, authorizationB)
	if quotaErr != nil || installationErr != nil || len(otherQuotas.Items) != 0 || len(otherInstallations.Items) != 0 {
		t.Fatalf("tenant B observed tenant A state: quotas=%#v installations=%#v errors=%v/%v",
			otherQuotas, otherInstallations, quotaErr, installationErr)
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
	for expected := 6; expected <= 7; expected++ {
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
	if actions[audit.QuotaEntitlementActivated] != 2 || actions[audit.ServiceInstallationCreated] != 2 ||
		actions[audit.ServiceInstallationReady] != 1 || actions[audit.ServiceInstallationTerminationRequested] != 1 ||
		actions[audit.ServiceInstallationTerminated] != 1 {
		t.Fatalf("concurrent managed-service Audit actions=%#v", actions)
	}
	snapshot, err = dispatcher.Snapshot(ctx)
	if err != nil || snapshot.Delivered != 7 || snapshot.Pending != 0 || snapshot.DeadLetter != 0 {
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
	port.AuthorizationRequest,
) (iamv1.ServiceLinkedRoleAccess, error) {
	return iamv1.ServiceLinkedRoleAccess{}, port.ErrAuthorizationUnavailable
}

func (integrationWorkloadRoleBinder) RevokeWorkloadRole(
	context.Context,
	iamv1.WorkloadRoleBindingID,
	uint64,
	port.AuthorizationRequest,
) (iamv1.WorkloadRoleBinding, error) {
	return iamv1.WorkloadRoleBinding{}, port.ErrAuthorizationUnavailable
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
		TenantID: tenantID, SubjectType: port.SubjectUser,
		SubjectID:  "principal-integration",
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
