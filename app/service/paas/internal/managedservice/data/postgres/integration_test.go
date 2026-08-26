package postgres_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
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

const managedServiceIntegrationDSN = "MATRIX_MANAGEDSERVICE_POSTGRES_TEST_DSN"

func TestManagedServicePostgresJourneyAndTenantIsolation(t *testing.T) {
	adminDSN := os.Getenv(managedServiceIntegrationDSN)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", managedServiceIntegrationDSN)
	}
	parsed, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(parsed.ConnConfig.Database, "matrix_managedservice_") {
		t.Fatal("managed-service integration DSN must select a safely named disposable database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	apiDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_api_login", "mxp1.managed-api-00000000000000000000000000000")
	workerDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_worker_login", "mxp1.managed-worker-0000000000000000000000000")
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
		Catalog: domain.DefaultCatalog(),
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
	if err := workerRepository.Complete(ctx, work, managedserviceadapterv1.ProvisionResult{
		Endpoint: "127.0.0.1:25432", CredentialReference: "credential-postgres-integration",
	}); err != nil {
		t.Fatalf("complete installation: %v", err)
	}
	if err := workerRepository.Complete(ctx, work, managedserviceadapterv1.ProvisionResult{
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
