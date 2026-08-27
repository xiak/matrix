package postgres

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	auditpostgres "github.com/xiak/matrix/app/service/paas/internal/audit/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/audit/usecase/auditdispatch"
)

func TestInstallationPartitionUpgradePreservesTenantWork(t *testing.T) {
	const variable = "MATRIX_PAAS_UPGRADE_POSTGRES_TEST_DSN"
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", variable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(config.Database, "matrix_paas_upgrade_") {
		t.Fatal("upgrade fixture requires a dedicated matrix_paas_upgrade_ database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	var clean, postgres18 bool
	if err := admin.QueryRow(ctx, `SELECT to_regnamespace('paas') IS NULL
		AND to_regnamespace('managedservice') IS NULL,
		current_setting('server_version_num')::integer BETWEEN 180000 AND 189999`).Scan(&clean, &postgres18); err != nil || !clean || !postgres18 {
		t.Fatalf("upgrade requires clean PostgreSQL 18: clean=%v postgres18=%v err=%v", clean, postgres18, err)
	}

	// Git owns the superseded schema. Seed retained work through its actual
	// transaction functions; this is a migration gate, not an N-1 binary claim.
	for _, path := range []string{
		"app/service/paas/internal/apphosting/data/postgres/migrations/000001_placement_core/up.sql",
		"app/service/paas/internal/managedservice/data/postgres/migrations/000001_service_authority/up.sql",
	} {
		baseline, err := exec.CommandContext(ctx, "git", "show", "3916644ca85a938447e69e46ef69b014236a62bc:"+path).Output()
		if err != nil {
			t.Fatalf("read fixed pre-partition migration: %v", err)
		}
		if _, err := admin.Exec(ctx, string(baseline)); err != nil {
			t.Fatalf("apply fixed pre-partition migration: %v", err)
		}
	}
	ensureAPITestRole(t, ctx, admin)
	ensureWorkerTestRole(t, ctx, admin)
	apiPool := openAPIPool(t, ctx, config)
	defer apiPool.Close()
	workerPool := openWorkerPool(t, ctx, config)
	defer workerPool.Close()
	tenantRepository, err := NewApplicationRepository(apiPool)
	if err != nil {
		t.Fatal(err)
	}
	workerRepository, err := NewOperationQueueRepository(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tenantRepository.Readiness(ctx); err == nil {
		t.Fatal("new PaaS API accepted schema 1 as ready")
	}
	if _, err := workerRepository.Readiness(ctx); err == nil {
		t.Fatal("new PaaS worker accepted schema 1 as ready")
	}
	fixture := seedIntegrationFixture(t, ctx, admin, "upgrade-retained")
	retained := assertApplicationLifecycle(t, ctx, admin, apiPool, fixture, "upgrade-retained")
	var retainedEventID string
	var retainedFence int64
	if err := workerPool.QueryRow(ctx, `SELECT event_id, fencing_token
		FROM paas.claim_audit_event('worker-upgrade', 120)`).Scan(&retainedEventID, &retainedFence); err != nil {
		t.Fatalf("lease retained Audit through schema 1: %v", err)
	}

	// Compare immutable content and in-flight leases, not the physical table
	// layout: adding an authority partition must not rewrite either contract.
	retainedState := func() string {
		var state string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
			'operations', (SELECT jsonb_agg(jsonb_build_object('document', document,
				'leaseOwner', lease_owner, 'leaseExpiresAt', lease_expires_at, 'fence', fencing_token)
				ORDER BY id) FROM paas.operations WHERE tenant_id=$1),
			'generations', (SELECT jsonb_agg(jsonb_build_object('document', document,
				'contentDigest', content_digest) ORDER BY deployment_id, generation)
				FROM paas.deployment_generations WHERE tenant_id=$1),
			'outbox', (SELECT jsonb_agg(jsonb_build_object('document', document,
				'status', status, 'attempts', attempts, 'leaseOwner', lease_owner,
				'leaseExpiresAt', lease_expires_at, 'fence', fencing_token) ORDER BY event_id)
				FROM paas.audit_outbox WHERE tenant_id=$1),
			'pool', (SELECT document FROM paas.execution_pools WHERE id=$2),
			'target', (SELECT document FROM paas.execution_targets WHERE id=$3)
		)::text`, fixture.tenantA, fixture.poolID, fixture.targetID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := retainedState()
	applyMigrationTwiceAndVerify(t, ctx, admin)
	if retainedState() != before {
		t.Fatal("installation partition upgrade rewrote tenant work or an in-flight lease")
	}
	if ready, err := tenantRepository.Readiness(ctx); err != nil || ready.State != paasv1.ReadinessReady || ready.SchemaVersion != 2 {
		t.Fatalf("upgraded PaaS API readiness=%#v err=%v", ready, err)
	}
	tenantWorkflow, err := applicationlifecycle.NewUsecase(tenantRepository, applicationlifecycle.Config{MaxTransactionAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	tenantAuthorization := integrationAuthorization(fixture.tenantA, retained.Operation.RequestedBy, "retained-read")
	if operation, err := tenantWorkflow.GetOperation(ctx, tenantAuthorization, retained.Operation.ID); err != nil || operation.ID != retained.Operation.ID || operation.State != paasv1.OperationAccepted {
		t.Fatalf("retained Operation no longer readable: %v", err)
	}
	auditRepository, err := auditpostgres.NewAuditOutboxRepository(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditRepository.Complete(ctx, auditdispatch.Completion{
		TenantID: fixture.tenantA, EventID: retainedEventID, WorkerID: "worker-upgrade",
		FencingToken: retainedFence, Stream: auditdispatch.StreamAppHosting, Outcome: auditdispatch.OutcomeDelivered,
	}); err != nil {
		t.Fatalf("schema 2 could not complete retained schema 1 Audit lease: %v", err)
	}

	repository, err := NewExecutionAdmissionRepository(apiPool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := executionadmission.New(repository, executionadmission.Config{
		InstallationID: string(fixture.tenantA), ObservationTimeout: time.Second,
		MaximumObservationAge: 15 * time.Second, MaxTransactionAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := port.Authorization{InstallationID: string(fixture.tenantA), Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"}, DecisionID: "decision-upgrade", RequestID: "request-upgrade"}
	_, platformOperation, _, err := service.CreatePool(ctx, executionadmission.CreatePoolCommand{
		Authorization: authorization, IdempotencyKey: "create-upgrade-pool",
		Request: paasv1.CreateExecutionPoolRequest{ID: "pool-after-upgrade", Name: "upgraded-pool", Spec: paasv1.ExecutionPoolSpec{AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}}},
	})
	if err != nil {
		t.Fatalf("admit platform pool after retained-data upgrade: %v", err)
	}
	if _, err := service.GetOperation(ctx, authorization, retained.Operation.ID); !errors.Is(err, executionadmission.ErrNotFound) {
		t.Fatalf("installation read equal-ID tenant partition: %v", err)
	}
	if _, err := tenantWorkflow.GetOperation(ctx, tenantAuthorization, platformOperation.ID); !errors.Is(err, applicationlifecycle.ErrNotFound) {
		t.Fatalf("tenant read equal-ID installation partition: %v", err)
	}
	if _, err := service.GetPool(ctx, authorization, fixture.poolID); !errors.Is(err, executionadmission.ErrNotFound) {
		t.Fatalf("upgrade silently enrolled a legacy execution pool: %v", err)
	}
	claim, found, err := auditRepository.Claim(ctx, "worker-after-upgrade", 30*time.Second)
	if err != nil || !found || claim.InstallationID != string(fixture.tenantA) || claim.TenantID != "" || claim.Event.OperationID != platformOperation.ID {
		t.Fatalf("new installation outbox partition after upgrade: found=%v err=%v", found, err)
	}
	// Accepted tenant work remains executable with its original generation;
	// the same queue's fencing and terminal transition gates still apply.
	assertOperationQueue(t, ctx, admin, workerPool, retained)
}
