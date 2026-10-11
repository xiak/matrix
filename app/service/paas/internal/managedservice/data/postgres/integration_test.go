package postgres_test

import (
	"context"
	"errors"
	"fmt"
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
	managedServicePredecessor    = "01146e7c465bbf28116d541f17ecbe28f917a4fe"
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

func TestManagedServicePredecessorCatalogUpgrade(t *testing.T) {
	adminDSN := os.Getenv(managedServicePredecessorDSN)
	if adminDSN == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", managedServicePredecessorDSN)
	}
	parsed, err := pgxpool.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(parsed.ConnConfig.Database, "matrix_managedservice_predecessor_") {
		t.Fatal("managed-service predecessor DSN must select a safely named disposable database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	apiDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_api_login", "mxp1.predecessor-api-000000000000000000000000")
	workerDSN := integrationRuntimeDSN(t, adminDSN, "matrix_paas_worker_login", "mxp1.predecessor-worker-0000000000000000000")
	logins := []postgresmigration.Login{
		{Name: "matrix_paas_api_login", Group: "matrix_paas_api", DSN: apiDSN},
		{Name: "matrix_paas_worker_login", Group: "matrix_paas_worker", DSN: workerDSN},
	}
	if err := postgresmigration.Apply(ctx, adminDSN, fixedPaaSPredecessorSource(t), logins); err != nil {
		t.Fatalf("apply fixed predecessor PaaS schema: %v", err)
	}

	var quotaSequence, operationSequence atomic.Uint32
	newService := func(pool *pgxpool.Pool) *usecase.Service {
		service, err := usecase.NewService(managedServiceRepository(t, pool), usecase.Config{
			Catalog: domain.DefaultCatalog(), WorkloadRoleAuthority: integrationWorkloadRoleBinder{},
			WorkloadRoleRuntime: integrationWorkloadRoleBinder{}, Region: integrationRegion(),
			NewQuotaID: func() (string, error) {
				return fmt.Sprintf("quota-predecessor-%d", quotaSequence.Add(1)), nil
			},
			NewOperationID: func() (string, error) {
				return fmt.Sprintf("operation-predecessor-%d", operationSequence.Add(1)), nil
			},
		})
		if err != nil {
			t.Fatal("create predecessor managed-service use case")
		}
		return service
	}
	authorization := integrationAuthorization("organization-predecessor")
	predecessorPool, err := pgxpool.New(ctx, apiDSN)
	if err != nil {
		t.Fatal("open predecessor managed-service API pool")
	}
	predecessorService := newService(predecessorPool)
	postgresQuota, _, err := predecessorService.ActivateQuota(ctx, usecase.ActivateQuotaCommand{
		Authorization: authorization, IdempotencyKey: "predecessor-postgres-quota",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	})
	if err != nil {
		predecessorPool.Close()
		t.Fatalf("create predecessor PostgreSQL quota: %v", err)
	}
	postgresInstallation, _, err := predecessorService.CreateInstallation(ctx, usecase.CreateInstallationCommand{
		Authorization: authorization, IdempotencyKey: "predecessor-postgres-installation",
		Request: managedservicev1.CreateInstallationRequest{
			ID: "predecessor-postgres", Name: "Predecessor PostgreSQL",
			OfferingID: domain.PostgreSQLOfferingID, QuotaEntitlementID: postgresQuota.ID, RegionID: "local-primary",
		},
	})
	if err != nil || postgresInstallation.Phase != managedservicev1.InstallationPending {
		predecessorPool.Close()
		t.Fatalf("create predecessor PostgreSQL installation=%#v err=%v", postgresInstallation, err)
	}
	postgresQuota, err = predecessorService.GetQuotaEntitlement(ctx, authorization, postgresQuota.ID)
	if err != nil || postgresQuota.ReservedCount != 1 || postgresQuota.ConsumedCount != 0 {
		predecessorPool.Close()
		t.Fatalf("read predecessor PostgreSQL reservation=%#v err=%v", postgresQuota, err)
	}
	if _, _, err := predecessorService.ActivateQuota(ctx, usecase.ActivateQuotaCommand{
		Authorization: authorization, IdempotencyKey: "predecessor-mysql-must-fail",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.MySQLOfferingID, QuotaShapeID: "mysql-small", InstanceCount: 1,
		},
	}); err == nil {
		predecessorPool.Close()
		t.Fatal("PostgreSQL-only predecessor accepted a MySQL entitlement")
	}
	quotas, err := predecessorService.ListQuotaEntitlements(ctx, authorization)
	if err != nil || len(quotas.Items) != 1 || quotas.Items[0].ID != postgresQuota.ID {
		predecessorPool.Close()
		t.Fatalf("failed predecessor MySQL attempt changed quotas=%#v err=%v", quotas, err)
	}
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
	currentService := newService(currentPool)
	retainedQuota, err := currentService.GetQuotaEntitlement(ctx, authorization, postgresQuota.ID)
	if err != nil || retainedQuota != postgresQuota {
		t.Fatalf("current schema did not retain predecessor quota=%#v err=%v", retainedQuota, err)
	}
	retainedInstallation, err := currentService.GetServiceInstallation(ctx, authorization, postgresInstallation.ID)
	if err != nil || !reflect.DeepEqual(retainedInstallation, postgresInstallation) {
		t.Fatalf("current schema did not retain predecessor installation=%#v err=%v", retainedInstallation, err)
	}
	mysqlQuota, _, err := currentService.ActivateQuota(ctx, usecase.ActivateQuotaCommand{
		Authorization: authorization, IdempotencyKey: "current-mysql-quota",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.MySQLOfferingID, QuotaShapeID: "mysql-small", InstanceCount: 1,
		},
	})
	if err != nil {
		t.Fatalf("activate current MySQL quota: %v", err)
	}
	mysqlInstallation, _, err := currentService.CreateInstallation(ctx, usecase.CreateInstallationCommand{
		Authorization: authorization, IdempotencyKey: "current-mysql-installation",
		Request: managedservicev1.CreateInstallationRequest{
			ID: "current-mysql", Name: "Current MySQL", OfferingID: domain.MySQLOfferingID,
			QuotaEntitlementID: mysqlQuota.ID, RegionID: "local-primary",
		},
	})
	if err != nil || mysqlInstallation.EngineVersion != "8.4" || mysqlInstallation.Phase != managedservicev1.InstallationPending {
		t.Fatalf("create current MySQL installation=%#v err=%v", mysqlInstallation, err)
	}
	var schemaVersion uint64
	if err := currentPool.QueryRow(ctx, `SELECT schema_version FROM paas.readiness()`).Scan(&schemaVersion); err != nil || schemaVersion != 4 {
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
