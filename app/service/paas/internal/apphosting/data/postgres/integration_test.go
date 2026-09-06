package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/data/enrollmentissuer"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/nodeenrollment"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/refreshexecutionprofile"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/transitionreservation"
	auditpostgres "github.com/xiak/matrix/app/service/paas/internal/audit/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/audit/usecase/auditdispatch"
	paasmigration "github.com/xiak/matrix/app/service/paas/migration"
)

const (
	postgresIntegrationDSN = "MATRIX_PAAS_POSTGRES_TEST_DSN"
	apiTestRole            = "matrix_paas_test_api"
	apiTestPassword        = "matrix-api-test-only"
	workerTestRole         = "matrix_paas_test_worker"
	workerTestPassword     = "matrix-test-only"
)

func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv(postgresIntegrationDSN)
	if dsn == "" {
		t.Skipf("set %s to a disposable PostgreSQL 18 database", postgresIntegrationDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL integration DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_paas_") {
		t.Fatalf(
			"refusing to mutate database %q; integration database name must start with matrix_paas_",
			adminConfig.Database,
		)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect PostgreSQL integration database: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	applyMigrationTwiceAndVerify(t, ctx, admin)
	ensureAPITestRole(t, ctx, admin)
	ensureWorkerTestRole(t, ctx, admin)
	apiPool := openAPIPool(t, ctx, adminConfig)
	defer apiPool.Close()
	workerPool := openWorkerPool(t, ctx, adminConfig)
	defer workerPool.Close()

	prefix := fmt.Sprintf("integration-%x", time.Now().UnixNano())
	assertExecutionProfileRefresh(t, ctx, admin, apiPool, workerPool, prefix)
	fixture := seedIntegrationFixture(t, ctx, admin, prefix)
	applicationResult := assertApplicationLifecycle(t, ctx, admin, apiPool, fixture, prefix)
	assertAuditPersistenceAndFencing(t, ctx, admin, apiPool, workerPool, applicationResult)
	assertOperationQueue(t, ctx, admin, workerPool, applicationResult)
	planner, err := placement.NewV1Planner(5 * time.Minute)
	if err != nil {
		t.Fatalf("create placement planner: %v", err)
	}
	placementRepository, err := NewPlacementRepository(workerPool)
	if err != nil {
		t.Fatalf("create placement repository: %v", err)
	}
	placementUsecase, err := createplacement.NewUsecase(
		planner,
		placementRepository,
		createplacement.Config{
			PendingReservationTTL:  10 * time.Minute,
			MaxTransactionAttempts: 5,
		},
	)
	if err != nil {
		t.Fatalf("create placement use case: %v", err)
	}

	commands := []createplacement.Command{
		fixture.placementCommand(fixture.deploymentIDs[0], prefix+"-operation-a", prefix+"-decision-a", "request-a"),
		fixture.placementCommand(fixture.deploymentIDs[1], prefix+"-operation-b", prefix+"-decision-b", "request-b"),
	}
	results, scheduledIndex := runConcurrentPlacements(
		t,
		ctx,
		placementUsecase,
		commands,
	)
	assertCapacityDidNotOvercommit(t, ctx, admin, fixture, results)
	assertExactReplayAndConflict(t, ctx, placementUsecase, commands, results)

	scheduledDecision := results[scheduledIndex].Decision
	reservationID, claimID := reservationIdentity(
		t,
		ctx,
		admin,
		fixture.tenantA,
		scheduledDecision.Metadata.ID,
	)
	assertWorkerRLS(t, ctx, workerPool, fixture, scheduledDecision.Metadata.ID, reservationID, claimID)

	reservationRepository, err := NewCapacityReservationRepository(workerPool)
	if err != nil {
		t.Fatalf("create capacity reservation repository: %v", err)
	}
	reservationUsecase, err := transitionreservation.NewUsecase(reservationRepository)
	if err != nil {
		t.Fatalf("create capacity reservation transition use case: %v", err)
	}
	assertReservationTransitions(
		t,
		ctx,
		admin,
		reservationUsecase,
		fixture,
		integrationPlacementGuard(commands[scheduledIndex]),
		reservationID,
		claimID,
	)

	assertAtomicRollbackAfterWrites(
		t,
		ctx,
		admin,
		planner,
		placementRepository,
		fixture,
		prefix,
	)
	assertPendingExpiry(
		t,
		ctx,
		admin,
		planner,
		placementRepository,
		reservationUsecase,
		fixture,
		prefix,
	)
	if os.Getenv("MATRIX_COMPOSE_E2E") == "1" {
		assertRealComposeWorkerWorkflow(
			t, ctx, admin, apiPool, workerPool, placementUsecase, fixture, prefix,
		)
	}
	assertInPlaceReplacementWorkflow(
		t,
		ctx,
		admin,
		apiPool,
		workerPool,
		placementUsecase,
		fixture,
		prefix,
	)
	assertDeploymentWorkerWorkflow(
		t,
		ctx,
		admin,
		apiPool,
		workerPool,
		placementUsecase,
		fixture,
		prefix,
	)
	assertNorthboundIAMAudit(t, ctx, admin, apiPool, workerPool, fixture, prefix)
	assertExecutionAdmission(t, ctx, admin, apiPool, workerPool, prefix)
	assertTerminalSessionPersistence(t, ctx, admin, apiPool, workerPool, fixture, prefix)
	assertExecutionTargetRemovalFencesCurrentWork(t, ctx, admin, apiPool, workerPool, prefix)
}

type integrationFixture struct {
	tenantA                  paasv1.TenantID
	tenantB                  paasv1.TenantID
	applicationID            paasv1.ResourceID
	configurationID          paasv1.ResourceID
	configurationRevisionIDs []paasv1.ResourceID
	revisionID               paasv1.ResourceID
	policyID                 paasv1.ResourceID
	poolID                   paasv1.ResourceID
	targetID                 paasv1.ResourceID
	deploymentIDs            []paasv1.ResourceID
	observedAt               time.Time
}

func (fixture integrationFixture) placementCommand(
	deploymentID paasv1.ResourceID,
	operationID string,
	decisionID string,
	requestSeed string,
) createplacement.Command {
	return createplacement.Command{
		TenantID:      fixture.tenantA,
		OperationID:   paasv1.OperationID(operationID),
		DecisionID:    paasv1.ResourceID(decisionID),
		DeploymentID:  deploymentID,
		RequestDigest: integrationDigest(requestSeed),
		TraceID:       "trace-" + requestSeed,
	}
}

func integrationPlacementGuard(command createplacement.Command) operationqueue.LeaseGuard {
	return operationqueue.LeaseGuard{
		TenantID: command.TenantID, OperationID: command.OperationID,
		WorkerID: "worker-placement", FencingToken: 1,
	}
}

func integrationAuthorization(
	tenantID paasv1.TenantID,
	subject paasv1.SubjectRef,
	requestSeed string,
) port.Authorization {
	return port.Authorization{
		TenantID:   tenantID,
		Subject:    subject,
		DecisionID: "decision-" + requestSeed,
		RequestID:  "request-" + requestSeed,
		AuditID:    "audit-" + requestSeed,
	}
}

func applyMigrationTwiceAndVerify(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	for attempt := 1; attempt <= 2; attempt++ {
		if err := paasmigration.Up(ctx, admin); err != nil {
			t.Fatalf("apply placement migration attempt %d: %v", attempt, err)
		}
	}
	if err := paasmigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify placement migration: %v", err)
	}
}

func ensureAPITestRole(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)",
		apiTestRole,
	).Scan(&exists); err != nil {
		t.Fatalf("inspect API test role: %v", err)
	}
	if !exists {
		if _, err := admin.Exec(
			ctx,
			`CREATE ROLE matrix_paas_test_api
			 LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
			 PASSWORD 'matrix-api-test-only'`,
		); err != nil {
			t.Fatalf("create API test role: %v", err)
		}
	} else if _, err := admin.Exec(
		ctx,
		`ALTER ROLE matrix_paas_test_api
		 LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
		 PASSWORD 'matrix-api-test-only'`,
	); err != nil {
		t.Fatalf("reset API test role: %v", err)
	}
	if _, err := admin.Exec(ctx, "GRANT matrix_paas_api TO matrix_paas_test_api"); err != nil {
		t.Fatalf("grant API test membership: %v", err)
	}
}

func ensureWorkerTestRole(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)",
		workerTestRole,
	).Scan(&exists); err != nil {
		t.Fatalf("inspect worker test role: %v", err)
	}
	if !exists {
		if _, err := admin.Exec(
			ctx,
			`CREATE ROLE matrix_paas_test_worker
			 LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
			 PASSWORD 'matrix-test-only'`,
		); err != nil {
			t.Fatalf("create worker test role: %v", err)
		}
	} else if _, err := admin.Exec(
		ctx,
		`ALTER ROLE matrix_paas_test_worker
		 LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
		 PASSWORD 'matrix-test-only'`,
	); err != nil {
		t.Fatalf("reset worker test role: %v", err)
	}
	if _, err := admin.Exec(
		ctx,
		"GRANT matrix_paas_worker TO matrix_paas_test_worker",
	); err != nil {
		t.Fatalf("grant worker test membership: %v", err)
	}
}

func openAPIPool(
	t *testing.T,
	ctx context.Context,
	adminConfig *pgx.ConnConfig,
) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(adminConfig.ConnString())
	if err != nil {
		t.Fatalf("parse API pool DSN: %v", err)
	}
	config.ConnConfig.User = apiTestRole
	config.ConnConfig.Password = apiTestPassword
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("create API PostgreSQL pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping API PostgreSQL pool: %v", err)
	}
	return pool
}

func openWorkerPool(
	t *testing.T,
	ctx context.Context,
	adminConfig *pgx.ConnConfig,
) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(adminConfig.ConnString())
	if err != nil {
		t.Fatalf("parse worker pool DSN: %v", err)
	}
	config.ConnConfig.User = workerTestRole
	config.ConnConfig.Password = workerTestPassword
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("create worker PostgreSQL pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping worker PostgreSQL pool: %v", err)
	}
	return pool
}

type integrationExecutionTargetAdapter struct {
	observation paasv1.ExecutionTargetObservation
}

func (adapter *integrationExecutionTargetAdapter) Capabilities(
	context.Context,
) (paasv1.AdapterCapabilitiesContract, error) {
	return paasv1.AdapterCapabilitiesContract{}, nil
}

func (adapter *integrationExecutionTargetAdapter) InspectExecutionTarget(
	context.Context,
	paasv1.InspectExecutionTargetRequest,
) (paasv1.ExecutionTargetObservation, error) {
	return paasv1.ExecutionTargetObservation{}, errors.New("unexpected target inspection")
}

func (adapter *integrationExecutionTargetAdapter) ObserveExecutionTarget(
	_ context.Context,
	request paasv1.ObserveExecutionTargetRequest,
) (paasv1.ExecutionTargetObservation, error) {
	if paasv1.ValidateObserveExecutionTargetRequest(request) != nil ||
		request.Command.ExecutionTargetID != adapter.observation.ExecutionTargetID {
		return paasv1.ExecutionTargetObservation{}, errors.New("invalid target observation request")
	}
	return adapter.observation, nil
}

func assertExecutionProfileRefresh(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	prefix string,
) {
	t.Helper()
	installationID := prefix + "-profile-installation"
	tenantID := paasv1.TenantID(prefix + "-profile-tenant")
	ids := refreshexecutionprofile.IDs{
		PoolID:   "execution-pool-local",
		TargetID: "execution-target-local",
		PolicyID: "placement-policy-local",
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	adapter := &integrationExecutionTargetAdapter{observation: paasv1.ExecutionTargetObservation{
		ExecutionTargetID:   ids.TargetID,
		IdentityFingerprint: integrationDigest(prefix + "-machine"),
		Labels:              map[string]string{"matrix-os": "linux", "matrix-arch": "amd64"},
		Capacity: paasv1.Capacity{
			CPUMillis: 4000, MemoryBytes: 8 * 1024 * 1024 * 1024,
			StorageBytes: 100 * 1024 * 1024 * 1024, WorkloadSlots: 4,
		},
		Allocatable: paasv1.Capacity{
			CPUMillis: 4000, MemoryBytes: 4 * 1024 * 1024 * 1024,
			StorageBytes: 50 * 1024 * 1024 * 1024, WorkloadSlots: 4,
		},
		Health: paasv1.ExecutionTargetHealthReady,
		SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{
			paasv1.IsolationWorkload,
		},
		ObservedAt: now,
	}}
	repository, err := NewExecutionProfileRepository(workerPool)
	if err != nil {
		t.Fatalf("create execution profile repository: %v", err)
	}
	service, err := refreshexecutionprofile.New(
		adapter,
		repository,
		refreshexecutionprofile.Config{
			InstallationID: installationID,
			TenantID:       tenantID, IDs: ids, MachineBindingRef: "local-machine-v1",
			ObservationTimeout: 5 * time.Second, MaximumObservationAge: 5 * time.Minute,
			MaxTransactionAttempts: 5,
		},
	)
	if err != nil {
		t.Fatalf("create execution profile service: %v", err)
	}
	if err := service.Refresh(ctx); err != nil {
		t.Fatalf("create execution profile through worker boundary: %v", err)
	}
	if err := service.Ready(ctx); err != nil {
		t.Fatalf("created execution profile readiness: %v", err)
	}
	if _, err := admin.Exec(ctx,
		"UPDATE paas.execution_targets SET installation_id = NULL WHERE id = $1",
		ids.TargetID,
	); err != nil {
		t.Fatalf("stage retained local target: %v", err)
	}
	if _, err := admin.Exec(ctx,
		"UPDATE paas.execution_pools SET installation_id = NULL WHERE id = $1",
		ids.PoolID,
	); err != nil {
		t.Fatalf("stage retained local pool: %v", err)
	}
	adapter.observation.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	if err := service.Refresh(ctx); err != nil {
		t.Fatalf("refresh execution profile through worker boundary: %v", err)
	}
	var poolInstallation, targetInstallation string
	var poolVersion, targetVersion, policyVersion uint64
	if err := admin.QueryRow(
		ctx,
		`SELECT pool.installation_id,
		        target.installation_id,
		        pool.resource_version,
		        target.resource_version,
		        policy.resource_version
		   FROM paas.execution_pools AS pool
		   JOIN paas.execution_targets AS target
		     ON target.execution_pool_id = pool.id
		   JOIN paas.placement_policies AS policy
		     ON policy.tenant_id = $1
		    AND policy.id = $2
		  WHERE pool.id = $3
		    AND target.id = $4`,
		tenantID,
		ids.PolicyID,
		ids.PoolID,
		ids.TargetID,
	).Scan(&poolInstallation, &targetInstallation, &poolVersion, &targetVersion, &policyVersion); err != nil {
		t.Fatalf("read reconciled execution profile: %v", err)
	}
	if poolVersion != 2 || targetVersion != 2 || policyVersion != 1 {
		t.Fatalf(
			"execution profile versions pool=%d target=%d policy=%d",
			poolVersion,
			targetVersion,
			policyVersion,
		)
	}
	if poolInstallation != installationID || targetInstallation != installationID {
		t.Fatalf("retained local profile was not scoped: pool=%q target=%q", poolInstallation, targetInstallation)
	}
	assertNodeEnrollmentPersistence(t, ctx, admin, apiPool, installationID, ids.PoolID, prefix)

	managedTargetID := paasv1.ResourceID(prefix + "-profile-node")
	managedAdapter := &admissionAdapter{
		targetID:    managedTargetID,
		fingerprint: integrationDigest(prefix + "-profile-node"),
	}
	admissionRepository, err := NewExecutionAdmissionRepository(apiPool)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := executionadmission.New(admissionRepository, executionadmission.Config{
		InstallationID: installationID,
		Bindings: []executionadmission.Binding{{
			Ref: "node-binding", TargetID: managedTargetID,
			IdentityFingerprint: managedAdapter.fingerprint, Adapter: managedAdapter,
		}},
		ObservationTimeout: time.Second, MaximumObservationAge: 15 * time.Second,
		MaxTransactionAttempts: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := port.Authorization{
		InstallationID: installationID,
		Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "profile-platform-user"},
		DecisionID:     "profile-platform-decision", RequestID: "profile-platform-request",
	}
	registered, _, replayed, err := admission.RegisterTarget(ctx, executionadmission.RegisterTargetCommand{
		Authorization: authorization, IdempotencyKey: "register-profile-node",
		Request: paasv1.RegisterExecutionTargetRequest{
			ID: managedTargetID, Name: "profile-node", ExecutionPoolID: ids.PoolID,
			BindingRef: "node-binding",
			Labels:     map[string]string{"matrix-profile": "local-compose"},
		},
	})
	if err != nil || replayed || registered.Metadata.ID != managedTargetID {
		t.Fatalf("register node in built-in pool: replay=%v target=%#v err=%v", replayed, registered, err)
	}
	pool, err := admission.GetPool(ctx, authorization, ids.PoolID)
	if err != nil || pool.Status.ExecutionTargetCount != 2 || pool.Status.ReadyExecutionTargetCount != 2 {
		t.Fatalf("built-in pool did not retain both targets: %#v err=%v", pool, err)
	}
	pools, err := admission.ListPools(ctx, authorization)
	if err != nil || paasv1.ValidateExecutionPoolList(pools) != nil || len(pools.Items) != 1 ||
		pools.Items[0].Metadata.ID != ids.PoolID || pools.Items[0].Status.ExecutionTargetCount != 2 ||
		pools.Items[0].Status.ReadyExecutionTargetCount != 2 {
		t.Fatalf("list installation execution pools: %#v err=%v", pools, err)
	}
	localTarget, err := admission.GetTarget(ctx, authorization, ids.TargetID)
	if err != nil || localTarget.Spec.InfrastructureAdapter.Name != "localmachine" {
		t.Fatalf("installation cannot read built-in target: %#v err=%v", localTarget, err)
	}
	managedCalls := managedAdapter.calls.Load()
	inventory, err := admission.ListTargets(ctx, authorization)
	if err != nil || paasv1.ValidateExecutionTargetList(inventory) != nil || len(inventory.Items) != 2 ||
		string(inventory.Items[0].Metadata.ID) >= string(inventory.Items[1].Metadata.ID) ||
		managedAdapter.calls.Load() != managedCalls {
		t.Fatalf("list built-in and managed targets: inventory=%#v calls=%d err=%v", inventory, managedAdapter.calls.Load(), err)
	}
	listed := map[paasv1.ResourceID]paasv1.ExecutionTarget{}
	for _, item := range inventory.Items {
		listed[item.Metadata.ID] = item
	}
	if listed[ids.TargetID].Status.ObservedAt != localTarget.Status.ObservedAt ||
		listed[managedTargetID].Status.Usage == nil || registered.Status.Usage == nil ||
		listed[managedTargetID].Status.Usage.ObservedAt != registered.Status.Usage.ObservedAt {
		t.Fatal("inventory replaced persisted source timestamps")
	}
	encodedInventory, err := json.Marshal(inventory)
	if err != nil || strings.Contains(string(encodedInventory), "node-binding") ||
		strings.Contains(string(encodedInventory), "bindingRef") ||
		strings.Contains(string(encodedInventory), "identityFingerprint") {
		t.Fatalf("inventory leaked protected binding material: %s err=%v", encodedInventory, err)
	}
	adapter.observation.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	if err := service.Refresh(ctx); err != nil {
		t.Fatalf("local refresh overwrote managed pool membership: %v", err)
	}
	pool, err = admission.GetPool(ctx, authorization, ids.PoolID)
	if err != nil || pool.Status.ExecutionTargetCount != 2 || pool.Status.ReadyExecutionTargetCount != 2 {
		t.Fatalf("local refresh changed managed pool membership: %#v err=%v", pool, err)
	}
	outbox, err := auditpostgres.NewAuditOutboxRepository(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	claim, found, err := outbox.Claim(ctx, "profile-audit-worker", 30*time.Second)
	if err != nil || !found || claim.InstallationID != installationID {
		t.Fatalf("claim built-in pool admission fact: found=%v claim=%#v err=%v", found, claim, err)
	}
	if err := outbox.Complete(ctx, auditdispatch.Completion{
		InstallationID: claim.InstallationID, EventID: claim.EventID, Stream: claim.Stream,
		WorkerID: "profile-audit-worker", FencingToken: claim.FencingToken,
		Outcome: auditdispatch.OutcomeDelivered,
	}); err != nil {
		t.Fatalf("complete built-in pool admission fact: %v", err)
	}
	if _, err := workerPool.Exec(
		ctx,
		"UPDATE paas.execution_targets SET resource_version = resource_version WHERE id = $1",
		ids.TargetID,
	); err == nil {
		t.Fatal("worker login bypassed the execution profile function")
	}
	adapter.observation.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	adapter.observation.Health = paasv1.ExecutionTargetHealthDegraded
	adapter.observation.SupportedIsolationGuarantees = nil
	if err := service.Refresh(ctx); err != nil {
		t.Fatalf("persist degraded execution profile through worker boundary: %v", err)
	}
	if err := service.Ready(ctx); err == nil {
		t.Fatal("persisted degraded execution profile reported ready")
	}
	adapter.observation.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	adapter.observation.IdentityFingerprint = integrationDigest(prefix + "-other-machine")
	if err := service.Refresh(ctx); !errors.Is(err, refreshexecutionprofile.ErrConflict) {
		t.Fatalf("execution target identity change error = %v", err)
	}
}

func assertNodeEnrollmentPersistence(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	installationID string,
	poolID paasv1.ResourceID,
	prefix string,
) {
	t.Helper()
	issuer, issuerPrivateKey := newIntegrationEnrollmentIssuer(t, installationID)
	repository, err := NewNodeEnrollmentRepository(apiPool)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentConfig := nodeenrollment.Config{
		InstallationID: installationID, Lifetime: 5 * time.Minute,
		CertificateLifetime:            30 * 24 * time.Hour,
		SupportedRuntimeContractDigest: integrationDigest("node-runtime-contract"),
		ControllerID:                   "paas-controller-v1", ManagementPort: 16443, CollectorPort: 19100,
		MaxTransactionAttempts: 5,
	}
	service, err := nodeenrollment.New(repository, issuer, enrollmentConfig)
	if err != nil {
		t.Fatal(err)
	}
	wrappingPrivateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	wrappingPublicKey, err := x509.MarshalPKIXPublicKey(&wrappingPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	authorization := port.Authorization{
		InstallationID: installationID,
		Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "enrollment-platform-user"},
		DecisionID:     "enrollment-platform-decision",
		RequestID:      "enrollment-platform-request",
		AuditID:        "enrollment-platform-audit",
	}
	command := nodeenrollment.CreateCommand{
		Authorization:       authorization,
		IdempotencyKey:      prefix + "-enroll-node",
		ControlPlaneBaseURL: "https://matrix.invalid/api/paas/v1",
		Request: paasv1.CreateNodeEnrollmentRequest{
			Name:              "enrollment-host",
			ExecutionPoolID:   poolID,
			Labels:            map[string]string{"matrix-zone": "integration"},
			WrappingPublicKey: base64.RawURLEncoding.EncodeToString(wrappingPublicKey),
		},
	}
	created, err := service.Create(ctx, command)
	if err != nil || created.Replayed || paasv1.ValidateCreateNodeEnrollmentResponse(created.Response) != nil ||
		created.Operation.State != paasv1.OperationAccepted {
		t.Fatalf("create persisted node enrollment: result=%#v err=%v", created, err)
	}
	replayed, err := service.Create(ctx, command)
	if err != nil || !replayed.Replayed || !reflect.DeepEqual(replayed.Response, created.Response) ||
		!reflect.DeepEqual(replayed.Operation, created.Operation) {
		t.Fatalf("replay persisted node enrollment: result=%#v err=%v", replayed, err)
	}

	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(created.Response.WrappedCredential.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	label := []byte("matrix-node-enrollment-v1\x00" + installationID + "\x00" + string(created.Response.Enrollment.Metadata.ID))
	credential, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrappingPrivateKey, ciphertext, label)
	if err != nil {
		t.Fatalf("decrypt one-time join credential: %v", err)
	}
	defer clear(credential)
	credentialDigest := sha256.Sum256(credential)
	if created.Response.Join.CredentialDigest != "sha256:"+hex.EncodeToString(credentialDigest[:]) {
		t.Fatal("wrapped join credential does not match its signed digest")
	}
	var (
		credentialSalt     []byte
		credentialVerifier string
		enrollmentState    string
		operationState     string
		operationAction    string
		storedCount        int
	)
	if err := admin.QueryRow(ctx, `SELECT enrollment.credential_salt,
			enrollment.credential_verifier, enrollment.state,
			operation.state, operation.action,
			count(*) OVER ()
		FROM paas.node_enrollments AS enrollment
		JOIN paas.operations AS operation
		  ON operation.authority_key = enrollment.authority_key
		 AND operation.id = enrollment.operation_id
		WHERE enrollment.installation_id = $1 AND enrollment.id = $2`,
		installationID, created.Response.Enrollment.Metadata.ID,
	).Scan(
		&credentialSalt, &credentialVerifier, &enrollmentState,
		&operationState, &operationAction, &storedCount,
	); err != nil {
		t.Fatalf("inspect persisted node enrollment: %v", err)
	}
	verifierInput := make([]byte, 0, len(credentialSalt)+len(credential))
	verifierInput = append(verifierInput, credentialSalt...)
	verifierInput = append(verifierInput, credential...)
	verifierDigest := sha256.Sum256(verifierInput)
	clear(verifierInput)
	if len(credentialSalt) != 32 || credentialVerifier != "sha256:"+hex.EncodeToString(verifierDigest[:]) ||
		credentialVerifier == created.Response.Join.CredentialDigest || enrollmentState != "WAITING_INSTALL" ||
		operationState != "ACCEPTED" || operationAction != "REGISTER_EXECUTION_TARGET" || storedCount != 1 {
		t.Fatal("node enrollment authority or salted credential verifier was not persisted exactly once")
	}
	_, err = admin.Exec(ctx, `UPDATE paas.node_enrollments SET credential_salt = NULL
		WHERE installation_id = $1 AND id = $2`,
		installationID, created.Response.Enrollment.Metadata.ID,
	)
	assertPostgresCode(t, err, "23514")
	retainingCredential := created.Response.Enrollment
	consumedAt := retainingCredential.Metadata.CreatedAt.Add(time.Microsecond)
	retainingCredential.State = paasv1.NodeEnrollmentVerifying
	retainingCredential.CredentialConsumedAt = &consumedAt
	retainingCredential.Metadata.ResourceVersion++
	retainingCredential.Metadata.UpdatedAt = consumedAt
	if paasv1.ValidateNodeEnrollment(retainingCredential) != nil {
		t.Fatal("invalid credential-retention attack fixture")
	}
	_, err = admin.Exec(ctx, `UPDATE paas.node_enrollments
		SET state = 'VERIFYING', resource_version = $3, document = $4::jsonb
		WHERE installation_id = $1 AND id = $2`,
		installationID, created.Response.Enrollment.Metadata.ID,
		retainingCredential.Metadata.ResourceVersion, integrationJSON(t, retainingCredential),
	)
	assertPostgresCode(t, err, "23514")

	read, err := service.Get(ctx, authorization, created.Response.Enrollment.Metadata.ID)
	listed, listErr := service.List(ctx, authorization)
	if err != nil || listErr != nil || !reflect.DeepEqual(read, created.Response.Enrollment) || len(listed.Items) != 1 ||
		!reflect.DeepEqual(listed.Items[0], created.Response.Enrollment) {
		t.Fatalf("read persisted node enrollment: get=%#v list=%#v errors=%v/%v", read, listed, err, listErr)
	}
	ordinaryJSON := strings.ToLower(string(integrationJSON(t, listed)))
	for _, forbidden := range []string{"wrappedcredential", "ciphertext", "credentialsalt", "credentialverifier"} {
		if strings.Contains(ordinaryJSON, forbidden) {
			t.Fatalf("ordinary node enrollment read exposed %s", forbidden)
		}
	}
	var visibleAcrossInstallations bool
	err = repository.WithinInstallation(ctx, installationID+"-other", func(
		transactionContext context.Context,
		transaction nodeenrollment.Transaction,
	) error {
		_, visibleAcrossInstallations, err = transaction.LoadEnrollment(
			transactionContext, created.Response.Enrollment.Metadata.ID,
		)
		return err
	})
	if err != nil || visibleAcrossInstallations {
		t.Fatalf("node enrollment crossed installation RLS boundary: visible=%t err=%v", visibleAcrossInstallations, err)
	}
	if _, err := apiPool.Exec(ctx, `UPDATE paas.node_enrollments
		SET resource_version = resource_version WHERE installation_id = $1 AND id = $2`,
		installationID, created.Response.Enrollment.Metadata.ID,
	); err == nil {
		t.Fatal("API login bypassed the node enrollment transition functions")
	}

	exchangeCreateCommand := command
	exchangeCreateCommand.IdempotencyKey = prefix + "-exchange-node"
	exchangeCreateCommand.Request.Name = "enrollment-exchange"
	exchangeCreated, err := service.Create(ctx, exchangeCreateCommand)
	if err != nil {
		t.Fatalf("create exchangeable node enrollment: %v", err)
	}
	exchangeCredential := integrationEnrollmentCredential(
		t, exchangeCreated.Response, wrappingPrivateKey, installationID,
	)
	defer clear(exchangeCredential)
	_, nodePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, collectorPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exchangeRequest := integrationEnrollmentExchangeRequest(
		t, exchangeCreated.Response, exchangeCredential, prefix+"-exchange",
		nodePrivateKey, collectorPrivateKey,
	)
	exchanged, err := service.Exchange(ctx, nodeenrollment.ExchangeCommand{
		EnrollmentID:        exchangeCreated.Response.Enrollment.Metadata.ID,
		ObservedPeerAddress: "192.168.50.10", Request: exchangeRequest,
	})
	if err != nil || exchanged.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		exchanged.Enrollment.Metadata.ResourceVersion != 2 ||
		paasv1.ValidateNodeEnrollmentExchangeResponseForRequest(exchanged.Response, exchangeRequest) != nil {
		t.Fatalf("exchange persisted node enrollment: result=%#v err=%v", exchanged, err)
	}
	if _, err := service.Exchange(ctx, nodeenrollment.ExchangeCommand{
		EnrollmentID:        exchangeCreated.Response.Enrollment.Metadata.ID,
		ObservedPeerAddress: "192.168.50.10", Request: exchangeRequest,
	}); !errors.Is(err, nodeenrollment.ErrCredentialConsumed) {
		t.Fatalf("replayed consumed credential error = %v", err)
	}

	var persistedExchange nodeenrollment.StoredEnrollment
	err = repository.WithinInstallation(ctx, installationID, func(
		transactionContext context.Context,
		transaction nodeenrollment.Transaction,
	) error {
		var found bool
		var loadErr error
		persistedExchange, found, loadErr = transaction.LoadEnrollment(
			transactionContext, exchangeCreated.Response.Enrollment.Metadata.ID,
		)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return errors.New("exchanged enrollment is absent")
		}
		return nil
	})
	if err != nil || persistedExchange.Exchange == nil || persistedExchange.SealedExchangeResult == nil ||
		len(persistedExchange.CredentialSalt) != 0 || persistedExchange.CredentialVerifier != "" ||
		persistedExchange.WrappedCredential.Ciphertext != "" {
		t.Fatalf("load persisted exchange: stored=%#v err=%v", persistedExchange, err)
	}
	defer persistedExchange.Clear()
	recovered, err := issuer.OpenExchangeResult(
		ctx, *persistedExchange.Exchange, *persistedExchange.SealedExchangeResult,
	)
	if err != nil || !reflect.DeepEqual(recovered, exchanged.Response) {
		t.Fatalf("recover sealed persisted exchange: response=%#v err=%v", recovered, err)
	}
	var exchangeDocument, sealedDocument string
	var exchangedCredentialCleared bool
	if err := admin.QueryRow(ctx, `SELECT
		credential_salt IS NULL AND credential_verifier IS NULL
			AND wrapped_credential_document IS NULL,
		exchange_document::text, sealed_exchange_result_document::text
		FROM paas.node_enrollments
		WHERE installation_id = $1 AND id = $2`,
		installationID, exchangeCreated.Response.Enrollment.Metadata.ID,
	).Scan(&exchangedCredentialCleared, &exchangeDocument, &sealedDocument); err != nil ||
		!exchangedCredentialCleared || len(exchangeDocument) > 16*1024 || len(sealedDocument) > 64*1024 {
		t.Fatalf("inspect exchanged credential storage: cleared=%t exchange=%d sealed=%d err=%v", exchangedCredentialCleared, len(exchangeDocument), len(sealedDocument), err)
	}
	for _, forbidden := range []string{
		base64.RawURLEncoding.EncodeToString(exchangeCredential),
		exchangeRequest.NodeCertificateRequest,
		exchangeRequest.CollectorCertificateRequest,
	} {
		if strings.Contains(exchangeDocument, forbidden) || strings.Contains(sealedDocument, forbidden) {
			t.Fatal("persisted node exchange retained raw credential or CSR material")
		}
	}
	_, err = admin.Exec(ctx, `UPDATE paas.node_enrollments
		SET exchange_document = jsonb_set(
			exchange_document, '{nodeListenAddress}', to_jsonb('8.8.8.8:16443'::text)
		)
		WHERE installation_id = $1 AND id = $2`,
		installationID, exchangeCreated.Response.Enrollment.Metadata.ID,
	)
	assertPostgresCode(t, err, "23514")

	concurrentCreateCommand := command
	concurrentCreateCommand.IdempotencyKey = prefix + "-concurrent-node"
	concurrentCreateCommand.Request.Name = "enrollment-concurrent"
	concurrentCreated, err := service.Create(ctx, concurrentCreateCommand)
	if err != nil {
		t.Fatalf("create concurrently exchangeable enrollment: %v", err)
	}
	concurrentCredential := integrationEnrollmentCredential(
		t, concurrentCreated.Response, wrappingPrivateKey, installationID,
	)
	defer clear(concurrentCredential)
	concurrentNodePrivateKey := integrationEd25519PrivateKey(t)
	concurrentCollectorPrivateKey := integrationEd25519PrivateKey(t)
	concurrentRequest := integrationEnrollmentExchangeRequest(
		t, concurrentCreated.Response, concurrentCredential, prefix+"-concurrent",
		concurrentNodePrivateKey, concurrentCollectorPrivateKey,
	)
	startExchange := make(chan struct{})
	exchangeErrors := make(chan error, 2)
	for range 2 {
		go func() {
			<-startExchange
			_, exchangeErr := service.Exchange(ctx, nodeenrollment.ExchangeCommand{
				EnrollmentID:        concurrentCreated.Response.Enrollment.Metadata.ID,
				ObservedPeerAddress: "192.168.50.11", Request: concurrentRequest,
			})
			exchangeErrors <- exchangeErr
		}()
	}
	close(startExchange)
	successes, consumed := 0, 0
	for range 2 {
		exchangeErr := <-exchangeErrors
		switch {
		case exchangeErr == nil:
			successes++
		case errors.Is(exchangeErr, nodeenrollment.ErrCredentialConsumed):
			consumed++
		default:
			t.Fatalf("concurrent node enrollment exchange error = %v", exchangeErr)
		}
	}
	if successes != 1 || consumed != 1 {
		t.Fatalf("concurrent node exchange outcomes success=%d consumed=%d", successes, consumed)
	}

	collisionCreateCommand := command
	collisionCreateCommand.IdempotencyKey = prefix + "-collision-node"
	collisionCreateCommand.Request.Name = "enrollment-collision"
	collisionCreated, err := service.Create(ctx, collisionCreateCommand)
	if err != nil {
		t.Fatalf("create public-key collision enrollment: %v", err)
	}
	collisionCredential := integrationEnrollmentCredential(
		t, collisionCreated.Response, wrappingPrivateKey, installationID,
	)
	defer clear(collisionCredential)
	collisionCollectorPrivateKey := integrationEd25519PrivateKey(t)
	collisionRequest := integrationEnrollmentExchangeRequest(
		t, collisionCreated.Response, collisionCredential, prefix+"-collision",
		collectorPrivateKey, collisionCollectorPrivateKey,
	)
	if _, err := service.Exchange(ctx, nodeenrollment.ExchangeCommand{
		EnrollmentID:        collisionCreated.Response.Enrollment.Metadata.ID,
		ObservedPeerAddress: "192.168.50.12", Request: collisionRequest,
	}); !errors.Is(err, nodeenrollment.ErrConflict) {
		t.Fatalf("cross-role public-key collision error = %v", err)
	}
	collisionEnrollment, err := service.Get(
		ctx, authorization, collisionCreated.Response.Enrollment.Metadata.ID,
	)
	if err != nil || collisionEnrollment.State != paasv1.NodeEnrollmentWaitingInstall ||
		collisionEnrollment.CredentialConsumedAt != nil {
		t.Fatalf("public-key collision changed enrollment: %#v / %v", collisionEnrollment, err)
	}
	identityCollisionScenarios := []struct {
		name   string
		mutate func(*paasv1.ExchangeNodeEnrollmentRequest)
	}{
		{name: "exchange-id", mutate: func(value *paasv1.ExchangeNodeEnrollmentRequest) {
			value.ExchangeID = exchangeRequest.ExchangeID
		}},
		{name: "machine", mutate: func(value *paasv1.ExchangeNodeEnrollmentRequest) {
			value.MachineFingerprint = exchangeRequest.MachineFingerprint
		}},
	}
	for _, scenario := range identityCollisionScenarios {
		identityCollisionCommand := command
		identityCollisionCommand.IdempotencyKey = prefix + "-" + scenario.name + "-collision-node"
		identityCollisionCommand.Request.Name = "enrollment-" + scenario.name + "-collision"
		identityCollisionCreated, createErr := service.Create(ctx, identityCollisionCommand)
		if createErr != nil {
			t.Fatalf("create %s collision enrollment: %v", scenario.name, createErr)
		}
		identityCollisionCredential := integrationEnrollmentCredential(
			t, identityCollisionCreated.Response, wrappingPrivateKey, installationID,
		)
		defer clear(identityCollisionCredential)
		identityCollisionRequest := integrationEnrollmentExchangeRequest(
			t, identityCollisionCreated.Response, identityCollisionCredential,
			prefix+"-"+scenario.name+"-collision",
			integrationEd25519PrivateKey(t), integrationEd25519PrivateKey(t),
		)
		scenario.mutate(&identityCollisionRequest)
		if paasv1.ValidateExchangeNodeEnrollmentRequest(identityCollisionRequest) != nil {
			t.Fatalf("invalid %s collision fixture", scenario.name)
		}
		if _, exchangeErr := service.Exchange(ctx, nodeenrollment.ExchangeCommand{
			EnrollmentID:        identityCollisionCreated.Response.Enrollment.Metadata.ID,
			ObservedPeerAddress: "192.168.50.15",
			Request:             identityCollisionRequest,
		}); !errors.Is(exchangeErr, nodeenrollment.ErrConflict) {
			t.Fatalf("%s collision error = %v", scenario.name, exchangeErr)
		}
		identityCollisionEnrollment, getErr := service.Get(
			ctx, authorization, identityCollisionCreated.Response.Enrollment.Metadata.ID,
		)
		if getErr != nil || identityCollisionEnrollment.State != paasv1.NodeEnrollmentWaitingInstall ||
			identityCollisionEnrollment.CredentialConsumedAt != nil {
			t.Fatalf(
				"%s collision changed enrollment: %#v / %v",
				scenario.name, identityCollisionEnrollment, getErr,
			)
		}
	}

	crossRoleCommands := [2]nodeenrollment.CreateCommand{command, command}
	crossRoleCommands[0].IdempotencyKey = prefix + "-cross-role-node-a"
	crossRoleCommands[0].Request.Name = "enrollment-cross-role-a"
	crossRoleCommands[1].IdempotencyKey = prefix + "-cross-role-node-b"
	crossRoleCommands[1].Request.Name = "enrollment-cross-role-b"
	var crossRoleCreated [2]nodeenrollment.CreateResult
	var crossRoleCredentials [2][]byte
	for index := range crossRoleCommands {
		crossRoleCreated[index], err = service.Create(ctx, crossRoleCommands[index])
		if err != nil {
			t.Fatalf("create concurrent cross-role collision enrollment %d: %v", index, err)
		}
		crossRoleCredentials[index] = integrationEnrollmentCredential(
			t, crossRoleCreated[index].Response, wrappingPrivateKey, installationID,
		)
		defer clear(crossRoleCredentials[index])
	}
	crossRoleKeyA := integrationEd25519PrivateKey(t)
	crossRoleKeyB := integrationEd25519PrivateKey(t)
	crossRoleRequests := [2]paasv1.ExchangeNodeEnrollmentRequest{
		integrationEnrollmentExchangeRequest(
			t, crossRoleCreated[0].Response, crossRoleCredentials[0], prefix+"-cross-role-a",
			crossRoleKeyA, crossRoleKeyB,
		),
		integrationEnrollmentExchangeRequest(
			t, crossRoleCreated[1].Response, crossRoleCredentials[1], prefix+"-cross-role-b",
			crossRoleKeyB, crossRoleKeyA,
		),
	}
	readCommittedService, err := nodeenrollment.New(
		&readCommittedNodeEnrollmentRepository{
			NodeEnrollmentRepository: repository,
			barrier:                  newConcurrentExchangeBarrier(),
		},
		issuer,
		enrollmentConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	type crossRoleOutcome struct {
		index int
		err   error
	}
	startCrossRoleExchange := make(chan struct{})
	crossRoleOutcomes := make(chan crossRoleOutcome, len(crossRoleRequests))
	for index := range crossRoleRequests {
		go func(index int) {
			<-startCrossRoleExchange
			_, exchangeErr := readCommittedService.Exchange(ctx, nodeenrollment.ExchangeCommand{
				EnrollmentID:        crossRoleCreated[index].Response.Enrollment.Metadata.ID,
				ObservedPeerAddress: fmt.Sprintf("192.168.50.%d", 13+index),
				Request:             crossRoleRequests[index],
			})
			crossRoleOutcomes <- crossRoleOutcome{index: index, err: exchangeErr}
		}(index)
	}
	close(startCrossRoleExchange)
	crossRoleSuccesses, crossRoleConflicts := 0, 0
	for range crossRoleRequests {
		outcome := <-crossRoleOutcomes
		switch {
		case outcome.err == nil:
			crossRoleSuccesses++
		case errors.Is(outcome.err, nodeenrollment.ErrConflict):
			crossRoleConflicts++
		default:
			t.Fatalf("concurrent cross-role collision exchange %d error = %v", outcome.index, outcome.err)
		}
	}
	if crossRoleSuccesses != 1 || crossRoleConflicts != 1 {
		t.Fatalf(
			"concurrent cross-role key outcomes success=%d conflict=%d",
			crossRoleSuccesses, crossRoleConflicts,
		)
	}
	waiting, verifying := 0, 0
	for index := range crossRoleCreated {
		value, getErr := service.Get(
			ctx, authorization, crossRoleCreated[index].Response.Enrollment.Metadata.ID,
		)
		if getErr != nil {
			t.Fatalf("read concurrent cross-role collision enrollment %d: %v", index, getErr)
		}
		switch value.State {
		case paasv1.NodeEnrollmentWaitingInstall:
			if value.CredentialConsumedAt != nil {
				t.Fatalf("rejected cross-role collision enrollment %d consumed its credential", index)
			}
			waiting++
		case paasv1.NodeEnrollmentVerifying:
			if value.CredentialConsumedAt == nil {
				t.Fatalf("accepted cross-role collision enrollment %d retained its credential", index)
			}
			verifying++
		default:
			t.Fatalf("concurrent cross-role collision enrollment %d state = %s", index, value.State)
		}
	}
	if waiting != 1 || verifying != 1 {
		t.Fatalf("concurrent cross-role persisted states waiting=%d verifying=%d", waiting, verifying)
	}

	revocableCommand := command
	revocableCommand.IdempotencyKey = prefix + "-revoke-node"
	revocableCommand.Request.Name = "enrollment-revoke"
	revocable, err := service.Create(ctx, revocableCommand)
	if err != nil {
		t.Fatalf("create revocable node enrollment: %v", err)
	}
	revokeCommand := nodeenrollment.RevokeCommand{
		Authorization:           authorization,
		EnrollmentID:            revocable.Response.Enrollment.Metadata.ID,
		ExpectedResourceVersion: revocable.Response.Enrollment.Metadata.ResourceVersion,
		IdempotencyKey:          prefix + "-revoke-enrollment",
	}
	revoked, err := service.Revoke(ctx, revokeCommand)
	if err != nil || revoked.Replayed || revoked.Enrollment.State != paasv1.NodeEnrollmentRevoked ||
		revoked.Enrollment.Metadata.ResourceVersion != 2 || revoked.Enrollment.ReplacedByID != "" {
		t.Fatalf("revoke persisted node enrollment: result=%#v err=%v", revoked, err)
	}
	revokedReplay, err := service.Revoke(ctx, revokeCommand)
	if err != nil || !revokedReplay.Replayed || !reflect.DeepEqual(revokedReplay.Enrollment, revoked.Enrollment) {
		t.Fatalf("replay persisted node enrollment revocation: result=%#v err=%v", revokedReplay, err)
	}
	var terminationFingerprint, terminationDigest, replacedByID string
	var revokedCredentialCleared bool
	if err := admin.QueryRow(ctx, `SELECT
			COALESCE(termination_idempotency_fingerprint, ''),
			COALESCE(termination_request_digest, ''),
			COALESCE(replaced_by_id, ''),
			credential_salt IS NULL AND credential_verifier IS NULL
				AND wrapped_credential_document IS NULL
		FROM paas.node_enrollments
		WHERE installation_id = $1 AND id = $2`,
		installationID, revoked.Enrollment.Metadata.ID,
	).Scan(&terminationFingerprint, &terminationDigest, &replacedByID, &revokedCredentialCleared); err != nil ||
		terminationFingerprint == "" || terminationDigest == "" || replacedByID != "" || !revokedCredentialCleared {
		t.Fatalf("inspect persisted node enrollment revocation: fingerprint=%q digest=%q replacement=%q err=%v", terminationFingerprint, terminationDigest, replacedByID, err)
	}

	regenerableCommand := command
	regenerableCommand.IdempotencyKey = prefix + "-regenerable-node"
	regenerableCommand.Request.Name = "enrollment-regenerate"
	regenerable, err := service.Create(ctx, regenerableCommand)
	if err != nil {
		t.Fatalf("create regenerable node enrollment: %v", err)
	}
	regenerateCommand := nodeenrollment.RegenerateCommand{
		Authorization:           authorization,
		EnrollmentID:            regenerable.Response.Enrollment.Metadata.ID,
		ExpectedResourceVersion: regenerable.Response.Enrollment.Metadata.ResourceVersion,
		IdempotencyKey:          prefix + "-regenerate-enrollment",
		Request: paasv1.RegenerateNodeEnrollmentRequest{
			WrappingPublicKey: base64.RawURLEncoding.EncodeToString(wrappingPublicKey),
		},
		ControlPlaneBaseURL: command.ControlPlaneBaseURL,
	}
	regenerated, err := service.Regenerate(ctx, regenerateCommand)
	if err != nil || regenerated.Replayed ||
		regenerated.Response.Enrollment.Metadata.ID == regenerable.Response.Enrollment.Metadata.ID ||
		regenerated.Response.Enrollment.ExecutionTargetID == regenerable.Response.Enrollment.ExecutionTargetID {
		t.Fatalf("regenerate persisted node enrollment: result=%#v err=%v", regenerated, err)
	}
	regeneratedReplay, err := service.Regenerate(ctx, regenerateCommand)
	if err != nil || !regeneratedReplay.Replayed ||
		!reflect.DeepEqual(regeneratedReplay.Response, regenerated.Response) ||
		!reflect.DeepEqual(regeneratedReplay.Operation, regenerated.Operation) {
		t.Fatalf("replay persisted node enrollment regeneration: result=%#v err=%v", regeneratedReplay, err)
	}
	var sourceState, sourceOperationState, replacementState string
	var sourceCredentialCleared, replacementCredentialPresent bool
	if err := admin.QueryRow(ctx, `SELECT source.state, source_operation.state,
			replacement.state, source.replaced_by_id,
			source.credential_salt IS NULL AND source.credential_verifier IS NULL
				AND source.wrapped_credential_document IS NULL,
			replacement.credential_salt IS NOT NULL AND replacement.credential_verifier IS NOT NULL
				AND replacement.wrapped_credential_document IS NOT NULL
		FROM paas.node_enrollments AS source
		JOIN paas.operations AS source_operation
		  ON source_operation.authority_key = source.authority_key
		 AND source_operation.id = source.operation_id
		JOIN paas.node_enrollments AS replacement
		  ON replacement.installation_id = source.installation_id
		 AND replacement.id = source.replaced_by_id
		WHERE source.installation_id = $1 AND source.id = $2`,
		installationID, regenerable.Response.Enrollment.Metadata.ID,
	).Scan(&sourceState, &sourceOperationState, &replacementState, &replacedByID,
		&sourceCredentialCleared, &replacementCredentialPresent); err != nil ||
		sourceState != "REVOKED" || sourceOperationState != "CANCELLED" ||
		replacementState != "WAITING_INSTALL" || replacedByID != string(regenerated.Response.Enrollment.Metadata.ID) ||
		!sourceCredentialCleared || !replacementCredentialPresent {
		t.Fatalf("inspect atomic enrollment replacement: source=%s operation=%s replacement=%s id=%s err=%v", sourceState, sourceOperationState, replacementState, replacedByID, err)
	}

	stagedEnrollment := created.Response.Enrollment
	stagedEnrollment.ExpiresAt = stagedEnrollment.Metadata.CreatedAt.Add(time.Microsecond)
	stagedJoin := created.Response.Join
	stagedJoin.ExpiresAt = stagedEnrollment.ExpiresAt
	stagedJoin.Signature = ""
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(stagedJoin)
	if err != nil {
		t.Fatal(err)
	}
	stagedJoin.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivateKey, commitment))
	if paasv1.ValidateNodeEnrollment(stagedEnrollment) != nil || paasv1.ValidateNodeEnrollmentJoin(stagedJoin) != nil {
		t.Fatal("invalid overdue node enrollment fixture")
	}
	if _, err := admin.Exec(ctx, `UPDATE paas.node_enrollments
		SET expires_at = $3, document = $4::jsonb, join_document = $5::jsonb
		WHERE installation_id = $1 AND id = $2`,
		installationID, stagedEnrollment.Metadata.ID, stagedEnrollment.ExpiresAt,
		integrationJSON(t, stagedEnrollment), integrationJSON(t, stagedJoin),
	); err != nil {
		t.Fatalf("stage overdue node enrollment: %v", err)
	}
	expired, err := service.Get(ctx, authorization, stagedEnrollment.Metadata.ID)
	if err != nil || expired.State != paasv1.NodeEnrollmentExpired ||
		expired.Metadata.ResourceVersion != 2 || expired.Diagnostic == nil ||
		expired.Diagnostic.Code != paasv1.NodeEnrollmentDiagnosticExpired {
		t.Fatalf("expire persisted node enrollment: enrollment=%#v err=%v", expired, err)
	}
	var terminalAt *time.Time
	var expiredCredentialCleared bool
	if err := admin.QueryRow(ctx, `SELECT operation.state, operation.terminal_at,
			enrollment.credential_salt IS NULL AND enrollment.credential_verifier IS NULL
				AND enrollment.wrapped_credential_document IS NULL
		FROM paas.operations AS operation
		JOIN paas.node_enrollments AS enrollment
		  ON enrollment.authority_key = operation.authority_key
		 AND enrollment.operation_id = operation.id
		WHERE enrollment.installation_id = $1 AND enrollment.id = $2`,
		installationID, stagedEnrollment.Metadata.ID,
	).Scan(&operationState, &terminalAt, &expiredCredentialCleared); err != nil ||
		operationState != "CANCELLED" || terminalAt == nil || !expiredCredentialCleared {
		t.Fatalf("expiration did not close registration Operation atomically: state=%s terminal=%v err=%v", operationState, terminalAt, err)
	}
}

type readCommittedNodeEnrollmentRepository struct {
	*NodeEnrollmentRepository
	barrier *concurrentExchangeBarrier
}

func (repository *readCommittedNodeEnrollmentRepository) WithinInstallation(
	ctx context.Context,
	installationID string,
	callback func(context.Context, nodeenrollment.Transaction) error,
) error {
	return repository.withinInstallation(
		ctx,
		installationID,
		pgx.ReadCommitted,
		func(transactionContext context.Context, transaction nodeenrollment.Transaction) error {
			return callback(transactionContext, concurrentExchangeTransaction{
				Transaction: transaction,
				barrier:     repository.barrier,
			})
		},
	)
}

type concurrentExchangeTransaction struct {
	nodeenrollment.Transaction
	barrier *concurrentExchangeBarrier
}

func (transaction concurrentExchangeTransaction) ExchangeEnrollment(
	ctx context.Context,
	before nodeenrollment.StoredEnrollment,
	after nodeenrollment.StoredEnrollment,
) error {
	if err := transaction.barrier.wait(ctx); err != nil {
		return err
	}
	return transaction.Transaction.ExchangeEnrollment(ctx, before, after)
}

type concurrentExchangeBarrier struct {
	mutex   sync.Mutex
	arrived int
	ready   chan struct{}
}

func newConcurrentExchangeBarrier() *concurrentExchangeBarrier {
	return &concurrentExchangeBarrier{ready: make(chan struct{})}
}

func (barrier *concurrentExchangeBarrier) wait(ctx context.Context) error {
	barrier.mutex.Lock()
	barrier.arrived++
	if barrier.arrived == 2 {
		close(barrier.ready)
	}
	ready := barrier.ready
	barrier.mutex.Unlock()
	select {
	case <-ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newIntegrationEnrollmentIssuer(
	t *testing.T,
	installationID string,
) (*enrollmentissuer.Issuer, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certificateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "matrix-integration-enrollment-issuer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil {
		t.Fatal(err)
	}
	certificateTemplate.URIs = append(certificateTemplate.URIs, issuerURI)
	certificateDER, err := x509.CreateCertificate(
		rand.Reader, certificateTemplate, certificateTemplate, publicKey, privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := enrollmentissuer.New(
		installationID, certificateDER, privateKeyDER,
	)
	clear(privateKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, privateKey
}

func integrationEnrollmentCredential(
	t *testing.T,
	created paasv1.CreateNodeEnrollmentResponse,
	wrappingPrivateKey *rsa.PrivateKey,
	installationID string,
) []byte {
	t.Helper()
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(created.WrappedCredential.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	label := []byte(
		"matrix-node-enrollment-v1\x00" + installationID + "\x00" + string(created.Enrollment.Metadata.ID),
	)
	credential, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrappingPrivateKey, ciphertext, label)
	clear(ciphertext)
	if err != nil {
		t.Fatalf("decrypt integration enrollment credential: %v", err)
	}
	digest := sha256.Sum256(credential)
	if len(credential) != 32 || created.Join.CredentialDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		clear(credential)
		t.Fatal("integration enrollment credential differs from its signed commitment")
	}
	return credential
}

func integrationEd25519PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func integrationEnrollmentExchangeRequest(
	t *testing.T,
	created paasv1.CreateNodeEnrollmentResponse,
	credential []byte,
	identitySeed string,
	nodePrivateKey ed25519.PrivateKey,
	collectorPrivateKey ed25519.PrivateKey,
) paasv1.ExchangeNodeEnrollmentRequest {
	t.Helper()
	certificateRequest := func(privateKey ed25519.PrivateKey) string {
		encoded, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	identityDigest := sha256.Sum256([]byte(identitySeed))
	request := paasv1.ExchangeNodeEnrollmentRequest{
		APIVersion:   paasv1.NodeEnrollmentExchangeAPIVersion,
		Kind:         paasv1.NodeEnrollmentExchangeRequestKind,
		EnrollmentID: created.Enrollment.Metadata.ID, InstallationID: created.Join.InstallationID,
		ExecutionTargetID:           created.Enrollment.ExecutionTargetID,
		ExchangeID:                  "node-exchange-" + hex.EncodeToString(identityDigest[:16]),
		Credential:                  base64.RawURLEncoding.EncodeToString(credential),
		MachineFingerprint:          integrationDigest(identitySeed + "-machine"),
		RuntimeContractDigest:       integrationDigest("node-runtime-contract"),
		Listener:                    paasv1.NodeEnrollmentListenerClaim{ManagementPort: 16443, CollectorPort: 19100},
		NodeCertificateRequest:      certificateRequest(nodePrivateKey),
		CollectorCertificateRequest: certificateRequest(collectorPrivateKey),
	}
	if err := paasv1.ValidateExchangeNodeEnrollmentRequest(request); err != nil {
		t.Fatalf("build integration enrollment exchange request: %v", err)
	}
	return request
}

func seedIntegrationFixture(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	prefix string,
) integrationFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fixture := integrationFixture{
		tenantA:         paasv1.TenantID(prefix + "-tenant-a"),
		tenantB:         paasv1.TenantID(prefix + "-tenant-b"),
		applicationID:   paasv1.ResourceID(prefix + "-application"),
		configurationID: paasv1.ResourceID(prefix + "-configuration"),
		configurationRevisionIDs: []paasv1.ResourceID{
			paasv1.ResourceID(prefix + "-configuration-revision-a"),
			paasv1.ResourceID(prefix + "-configuration-revision-b"),
		},
		revisionID: paasv1.ResourceID(prefix + "-revision"),
		policyID:   paasv1.ResourceID(prefix + "-policy"),
		poolID:     paasv1.ResourceID(prefix + "-pool"),
		targetID:   paasv1.ResourceID(prefix + "-target"),
		deploymentIDs: []paasv1.ResourceID{
			paasv1.ResourceID(prefix + "-deployment-a"),
			paasv1.ResourceID(prefix + "-deployment-b"),
		},
		observedAt: now.Add(-time.Second),
	}
	application := paasv1.Application{
		APIVersion: paasv1.APIVersion,
		Kind:       "Application",
		Metadata: integrationMetadata(
			fixture.applicationID,
			"application",
			paasv1.AuthorityTenant,
			fixture.tenantA,
			1,
			now,
			false,
		),
	}
	configuration := paasv1.Configuration{
		APIVersion: paasv1.APIVersion,
		Kind:       "Configuration",
		Metadata: integrationMetadata(
			fixture.configurationID,
			"configuration",
			paasv1.AuthorityTenant,
			fixture.tenantA,
			1,
			now,
			false,
		),
		ApplicationID: fixture.applicationID,
	}
	configurationRevisions := make([]paasv1.ConfigurationRevision, 0, 2)
	for index, value := range []string{"one", "two"} {
		values := map[string]string{
			"MATRIX_SETTING":    value,
			"MATRIX_GENERATION": fmt.Sprintf("%d", index+1),
		}
		configurationRevisions = append(configurationRevisions, paasv1.ConfigurationRevision{
			APIVersion: paasv1.APIVersion,
			Kind:       "ConfigurationRevision",
			Metadata: integrationMetadata(
				fixture.configurationRevisionIDs[index],
				fmt.Sprintf("config-%c", 'a'+rune(index)),
				paasv1.AuthorityTenant,
				fixture.tenantA,
				1,
				now,
				true,
			),
			Spec: paasv1.ConfigurationRevisionSpec{
				ConfigurationID: fixture.configurationID,
				Values:          values,
				ContentDigest:   paasv1.ConfigurationValuesDigest(values),
			},
		})
	}
	revision := paasv1.ApplicationRevision{
		APIVersion: paasv1.APIVersion,
		Kind:       "ApplicationRevision",
		Metadata: integrationMetadata(
			fixture.revisionID,
			"revision",
			paasv1.AuthorityTenant,
			fixture.tenantA,
			1,
			now,
			true,
		),
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: fixture.applicationID,
			Revision:      "v1",
			ContentDigest: integrationDigest(prefix + "-revision-content"),
			Components: []paasv1.ApplicationRevisionComponent{{
				Name: "web",
				Artifact: paasv1.ArtifactRef{
					Kind:    paasv1.ArtifactOCIImage,
					Locator: "registry.invalid/matrix/integration-web",
					Digest:  integrationDigest(prefix + "-artifact"),
				},
				Resources: paasv1.ResourceRequirements{
					CPUMillis:   100,
					MemoryBytes: 32 * 1024 * 1024,
				},
				Endpoints: []paasv1.ApplicationEndpoint{{
					Name: "ready", Port: 8080, Protocol: paasv1.EndpointHTTP,
					Visibility: paasv1.EndpointPrivate,
				}},
				Inputs: []paasv1.ComponentInput{
					{
						Name: "settings", Kind: paasv1.InputConfiguration,
						Injection: paasv1.InjectionEnvironment,
					},
					{
						Name: "credential", Kind: paasv1.InputSecret,
						Injection: paasv1.InjectionFile,
					},
				},
			}},
		},
	}
	policy := paasv1.PlacementPolicy{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementPolicy",
		Metadata: integrationMetadata(
			fixture.policyID,
			"policy",
			paasv1.AuthorityTenant,
			fixture.tenantA,
			1,
			now,
			false,
		),
		Spec: paasv1.PlacementPolicySpec{
			RequiredIsolationGuarantee: paasv1.IsolationWorkload,
			EligibleExecutionPoolIDs:   []paasv1.ResourceID{fixture.poolID},
			Strategy:                   paasv1.PlacementFirstFit,
		},
	}
	pool := paasv1.ExecutionPool{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionPool",
		Metadata: integrationMetadata(
			fixture.poolID,
			"pool",
			paasv1.AuthorityPlatform,
			"",
			1,
			now,
			false,
		),
		Spec: paasv1.ExecutionPoolSpec{
			AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{
				paasv1.IsolationWorkload,
			},
		},
		Status: paasv1.ExecutionPoolStatus{
			Phase:                     paasv1.ExecutionPoolReady,
			ExecutionTargetCount:      1,
			ReadyExecutionTargetCount: 1,
			ObservedAt:                fixture.observedAt,
		},
	}
	capacity := paasv1.Capacity{
		CPUMillis:     100,
		MemoryBytes:   32 * 1024 * 1024,
		WorkloadSlots: 1,
	}
	target := paasv1.ExecutionTarget{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionTarget",
		Metadata: integrationMetadata(
			fixture.targetID,
			"target",
			paasv1.AuthorityPlatform,
			"",
			1,
			now,
			false,
		),
		Spec: paasv1.ExecutionTargetSpec{
			ExecutionPoolID: fixture.poolID,
			InfrastructureAdapter: paasv1.AdapterRef{
				Kind:            paasv1.AdapterInfrastructure,
				Name:            "localmachine",
				ContractVersion: "v1",
			},
			DeploymentExecutor: paasv1.AdapterRef{
				Kind:            paasv1.AdapterDeploymentExecutor,
				Name:            "compose",
				ContractVersion: "v1",
			},
			DesiredState: paasv1.ExecutionTargetActive,
		},
		Status: paasv1.ExecutionTargetStatus{
			Health:                       paasv1.ExecutionTargetHealthReady,
			Capacity:                     capacity,
			Allocatable:                  capacity,
			SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
			ObservedAt:                   fixture.observedAt,
		},
	}
	assertContractValid(t, application, revision, policy, pool, target)
	if err := paasv1.ValidateConfiguration(configuration); err != nil {
		t.Fatalf("invalid Configuration fixture: %v", err)
	}
	for _, configurationRevision := range configurationRevisions {
		if err := paasv1.ValidateConfigurationRevision(configurationRevision); err != nil {
			t.Fatalf("invalid ConfigurationRevision fixture: %v", err)
		}
	}

	execDocument(t, ctx, admin,
		`INSERT INTO paas.applications (tenant_id, id, resource_version, document)
		 VALUES ($1, $2, $3, $4::jsonb)`,
		fixture.tenantA, fixture.applicationID, 1, integrationJSON(t, application),
	)
	execDocument(t, ctx, admin,
		`INSERT INTO paas.configurations
		 (tenant_id, id, application_id, resource_version, document)
		 VALUES ($1, $2, $3, $4, $5::jsonb)`,
		fixture.tenantA,
		fixture.configurationID,
		fixture.applicationID,
		1,
		integrationJSON(t, configuration),
	)
	for _, configurationRevision := range configurationRevisions {
		execDocument(t, ctx, admin,
			`INSERT INTO paas.configuration_revisions
			 (tenant_id, id, configuration_id, content_digest, resource_version, document)
			 VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
			fixture.tenantA,
			configurationRevision.Metadata.ID,
			configurationRevision.Spec.ConfigurationID,
			configurationRevision.Spec.ContentDigest,
			1,
			integrationJSON(t, configurationRevision),
		)
	}
	execDocument(t, ctx, admin,
		`INSERT INTO paas.application_revisions
		 (tenant_id, id, application_id, content_digest, resource_version, document)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		fixture.tenantA,
		fixture.revisionID,
		fixture.applicationID,
		revision.Spec.ContentDigest,
		1,
		integrationJSON(t, revision),
	)
	execDocument(t, ctx, admin,
		`INSERT INTO paas.placement_policies (tenant_id, id, resource_version, document)
		 VALUES ($1, $2, $3, $4::jsonb)`,
		fixture.tenantA, fixture.policyID, 1, integrationJSON(t, policy),
	)
	execDocument(t, ctx, admin,
		`INSERT INTO paas.execution_pools (id, resource_version, document)
		 VALUES ($1, $2, $3::jsonb)`,
		fixture.poolID, 1, integrationJSON(t, pool),
	)
	execDocument(t, ctx, admin,
		`INSERT INTO paas.execution_targets
		 (id, execution_pool_id, resource_version, document)
		 VALUES ($1, $2, $3, $4::jsonb)`,
		fixture.targetID, fixture.poolID, 1, integrationJSON(t, target),
	)
	if _, err := admin.Exec(
		ctx,
		`INSERT INTO paas.execution_target_allocations (execution_target_id)
		 VALUES ($1)`,
		fixture.targetID,
	); err != nil {
		t.Fatalf("insert execution target allocation: %v", err)
	}
	for index, deploymentID := range fixture.deploymentIDs {
		suffix := string(rune('a' + index))
		seedDeployment(
			t, ctx, admin, fixture, deploymentID,
			paasv1.OperationID(prefix+"-operation-"+suffix), now,
		)
	}
	return fixture
}

func seedDeployment(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	fixture integrationFixture,
	deploymentID paasv1.ResourceID,
	creationOperationID paasv1.OperationID,
	now time.Time,
) {
	t.Helper()
	operation := paasv1.Operation{
		APIVersion: paasv1.APIVersion,
		Kind:       "Operation",
		ID:         creationOperationID,
		Scope: paasv1.ResourceScope{
			Kind:     paasv1.AuthorityTenant,
			TenantID: fixture.tenantA,
		},
		Action: paasv1.OperationDeploy,
		Target: paasv1.ResourceRef{
			Kind: "Deployment",
			ID:   deploymentID,
		},
		RequestedBy: paasv1.SubjectRef{
			Type: paasv1.SubjectSystemUser,
			ID:   "system",
		},
		IdempotencyFingerprint: integrationDigest(string(deploymentID) + "-idempotency"),
		RequestDigest:          integrationDigest(string(deploymentID) + "-request"),
		State:                  paasv1.OperationPlanning,
		Attempt:                1,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		t.Fatalf("invalid creation Operation fixture: %v", err)
	}
	execDocument(t, ctx, admin,
		`INSERT INTO paas.operations (
		     tenant_id, id, action, target_kind, target_id,
		     idempotency_fingerprint, request_digest, state, attempt,
		     next_attempt_at, lease_owner, lease_expires_at, fencing_token,
		     created_at, updated_at, document
		 ) VALUES (
		     $1, $2, $3, $4, $5, $6, $7, $8, $9,
		     $10, 'worker-placement', $10::timestamptz + interval '10 minutes', 1,
		     $10, $10, $11::jsonb
		 )`,
		fixture.tenantA,
		operation.ID,
		operation.Action,
		operation.Target.Kind,
		operation.Target.ID,
		operation.IdempotencyFingerprint,
		operation.RequestDigest,
		operation.State,
		operation.Attempt,
		now,
		integrationJSON(t, operation),
	)
	deployment := paasv1.Deployment{
		APIVersion: paasv1.APIVersion,
		Kind:       "Deployment",
		Metadata: integrationMetadata(
			deploymentID,
			"deployment",
			paasv1.AuthorityTenant,
			fixture.tenantA,
			1,
			now,
			false,
		),
		Generation: 1,
		Spec: paasv1.DeploymentSpec{
			ApplicationRevisionID: fixture.revisionID,
			PlacementPolicyID:     fixture.policyID,
			DesiredState:          paasv1.DeploymentDesiredRunning,
			Components: []paasv1.DeploymentComponent{{
				Name:     "web",
				Replicas: 1,
			}},
		},
		Status: paasv1.DeploymentStatus{
			Phase:              paasv1.DeploymentPending,
			CurrentOperationID: creationOperationID,
			ObservedAt:         now.Add(-time.Second),
		},
	}
	if err := paasv1.ValidateDeployment(deployment); err != nil {
		t.Fatalf("invalid Deployment fixture: %v", err)
	}
	execDocument(t, ctx, admin,
		`INSERT INTO paas.deployments
		 (tenant_id, id, generation, application_revision_id, policy_id, resource_version, document)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
		fixture.tenantA,
		deploymentID,
		deployment.Generation,
		fixture.revisionID,
		fixture.policyID,
		1,
		integrationJSON(t, deployment),
	)
	generation := paasv1.DeploymentGeneration{
		APIVersion:           paasv1.APIVersion,
		Kind:                 "DeploymentGeneration",
		Scope:                deployment.Metadata.Scope,
		DeploymentID:         deployment.Metadata.ID,
		Generation:           deployment.Generation,
		Spec:                 deployment.Spec,
		CreatedByOperationID: creationOperationID,
		CreatedAt:            now,
	}
	generation.ContentDigest = paasv1.DeploymentSpecContentDigest(generation.Spec)
	if err := paasv1.ValidateDeploymentGeneration(generation); err != nil {
		t.Fatalf("invalid DeploymentGeneration fixture: %v", err)
	}
	execDocument(t, ctx, admin,
		`INSERT INTO paas.deployment_generations (
		     tenant_id, deployment_id, generation, application_revision_id,
		     policy_id, content_digest, created_by_operation_id, created_at, document
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
		fixture.tenantA,
		generation.DeploymentID,
		generation.Generation,
		generation.Spec.ApplicationRevisionID,
		generation.Spec.PlacementPolicyID,
		generation.ContentDigest,
		generation.CreatedByOperationID,
		generation.CreatedAt,
		integrationJSON(t, generation),
	)
}

func assertContractValid(
	t *testing.T,
	application paasv1.Application,
	revision paasv1.ApplicationRevision,
	policy paasv1.PlacementPolicy,
	pool paasv1.ExecutionPool,
	target paasv1.ExecutionTarget,
) {
	t.Helper()
	checks := []struct {
		name string
		err  error
	}{
		{"Application", paasv1.ValidateApplication(application)},
		{"ApplicationRevision", paasv1.ValidateApplicationRevision(revision)},
		{"PlacementPolicy", paasv1.ValidatePlacementPolicy(policy)},
		{"ExecutionPool", paasv1.ValidateExecutionPool(pool)},
		{"ExecutionTarget", paasv1.ValidateExecutionTarget(target)},
	}
	for _, check := range checks {
		if check.err != nil {
			t.Fatalf("invalid %s fixture: %v", check.name, check.err)
		}
	}
}

func integrationMetadata(
	id paasv1.ResourceID,
	name string,
	authority paasv1.AuthorityKind,
	tenantID paasv1.TenantID,
	resourceVersion uint64,
	now time.Time,
	immutable bool,
) paasv1.ResourceMetadata {
	createdAt := now.Add(-time.Hour)
	updatedAt := now.Add(-time.Minute)
	if immutable {
		updatedAt = createdAt
	}
	return paasv1.ResourceMetadata{
		ID:   id,
		Name: name,
		Scope: paasv1.ResourceScope{
			Kind:     authority,
			TenantID: tenantID,
		},
		Labels:          map[string]string{"gate": "postgres-integration"},
		ResourceVersion: resourceVersion,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}

var errInjectedAfterApplicationWrites = errors.New("injected failure after application writes")

type failAfterApplicationSubmitRepository struct {
	delegate applicationlifecycle.Repository
}

func (repository failAfterApplicationSubmitRepository) WithinTransaction(
	ctx context.Context,
	tenantID paasv1.TenantID,
	callback func(context.Context, applicationlifecycle.Transaction) error,
) error {
	return repository.delegate.WithinTransaction(
		ctx,
		tenantID,
		func(callbackContext context.Context, transaction applicationlifecycle.Transaction) error {
			return callback(
				callbackContext,
				failAfterApplicationSubmitTransaction{Transaction: transaction},
			)
		},
	)
}

type failAfterApplicationSubmitTransaction struct {
	applicationlifecycle.Transaction
}

func (transaction failAfterApplicationSubmitTransaction) SubmitDeployment(
	ctx context.Context,
	submission applicationlifecycle.Submission,
) error {
	if err := transaction.Transaction.SubmitDeployment(ctx, submission); err != nil {
		return err
	}
	return errInjectedAfterApplicationWrites
}

func assertApplicationLifecycle(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	fixture integrationFixture,
	prefix string,
) applicationlifecycle.Result {
	t.Helper()
	repository, err := NewApplicationRepository(apiPool)
	if err != nil {
		t.Fatalf("create application repository: %v", err)
	}
	usecase, err := applicationlifecycle.NewUsecase(
		repository,
		applicationlifecycle.Config{MaxTransactionAttempts: 5},
	)
	if err != nil {
		t.Fatalf("create application lifecycle use case: %v", err)
	}
	deploymentID := paasv1.ResourceID(prefix + "-submitted-deployment")
	command := applicationlifecycle.SubmitCommand{
		Authorization: integrationAuthorization(
			fixture.tenantA,
			paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "integration-user"},
			"submit-deployment",
		),
		DeploymentID:   deploymentID,
		Name:           "submitted",
		Spec:           applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[0]),
		IdempotencyKey: "submit-deployment",
	}
	created, err := usecase.Submit(ctx, command)
	if err != nil {
		t.Fatalf("submit application Deployment through API login: %v", err)
	}
	if created.Deployment.Generation != 1 || created.Operation.State != paasv1.OperationAccepted {
		t.Fatalf("created application result = %#v", created)
	}
	replay, err := usecase.Submit(ctx, command)
	if err != nil {
		t.Fatalf("replay application Deployment through API login: %v", err)
	}
	if !replay.Replayed || replay.Operation.ID != created.Operation.ID {
		t.Fatalf("application replay = %#v, want Operation %q", replay, created.Operation.ID)
	}
	changed := command
	changed.Spec = applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[0])
	changed.Spec.Components[0].Replicas = 2
	if _, err := usecase.Submit(ctx, changed); !errors.Is(
		err,
		applicationlifecycle.ErrIdempotencyConflict,
	) {
		t.Fatalf("changed application replay error = %v", err)
	}
	stale := command
	stale.IdempotencyKey = "stale-create"
	stale.Spec = applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[1])
	if _, err := usecase.Submit(ctx, stale); !errors.Is(
		err,
		applicationlifecycle.ErrResourceVersionConflict,
	) {
		t.Fatalf("stale application If-Match error = %v", err)
	}

	if err := repository.WithinTransaction(
		ctx,
		fixture.tenantB,
		func(transactionContext context.Context, transaction applicationlifecycle.Transaction) error {
			_, found, err := transaction.LoadDeployment(transactionContext, deploymentID)
			if err != nil {
				return err
			}
			if found {
				return errors.New("tenant B read tenant A Deployment")
			}
			return nil
		},
	); err != nil {
		t.Fatalf("API tenant RLS: %v", err)
	}
	permissionErr := withinTenantTransaction(
		ctx,
		apiPool,
		fixture.tenantA,
		pgx.TxOptions{AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			_, err := tx.Exec(
				ctx,
				`UPDATE paas.deployment_generations
				    SET content_digest = content_digest
				  WHERE tenant_id = $1 AND deployment_id = $2 AND generation = 1`,
				fixture.tenantA,
				deploymentID,
			)
			return err
		},
	)
	assertPostgresCode(t, permissionErr, "42501")

	faultDeploymentID := paasv1.ResourceID(prefix + "-application-fault")
	faultUsecase, err := applicationlifecycle.NewUsecase(
		failAfterApplicationSubmitRepository{delegate: repository},
		applicationlifecycle.Config{MaxTransactionAttempts: 1},
	)
	if err != nil {
		t.Fatalf("create fault-injected application use case: %v", err)
	}
	faultCommand := command
	faultCommand.DeploymentID = faultDeploymentID
	faultCommand.Name = "fault"
	faultCommand.IdempotencyKey = "fault-after-submit"
	if _, err := faultUsecase.Submit(ctx, faultCommand); !errors.Is(
		err,
		errInjectedAfterApplicationWrites,
	) {
		t.Fatalf("fault-injected application error = %v", err)
	}
	var deployments int
	var generations int
	var operations int
	var auditEvents int
	if err := admin.QueryRow(
		ctx,
		`SELECT
		    (SELECT count(*) FROM paas.deployments
		      WHERE tenant_id = $1 AND id = $2),
		    (SELECT count(*) FROM paas.deployment_generations
		      WHERE tenant_id = $1 AND deployment_id = $2),
		    (SELECT count(*) FROM paas.operations
		      WHERE tenant_id = $1 AND target_id = $2),
		    (SELECT count(*) FROM paas.audit_outbox
		      WHERE tenant_id = $1 AND document#>>'{target,id}' = $2)`,
		fixture.tenantA,
		faultDeploymentID,
	).Scan(&deployments, &generations, &operations, &auditEvents); err != nil {
		t.Fatalf("inspect rolled-back application submission: %v", err)
	}
	if deployments != 0 || generations != 0 || operations != 0 || auditEvents != 0 {
		t.Fatalf(
			"application transaction leaked rows: deployments=%d generations=%d operations=%d audit=%d",
			deployments,
			generations,
			operations,
			auditEvents,
		)
	}
	return created
}

func assertOperationQueue(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	workerPool *pgxpool.Pool,
	applicationResult applicationlifecycle.Result,
) {
	t.Helper()
	repository, err := NewOperationQueueRepository(workerPool)
	if err != nil {
		t.Fatalf("create Operation queue repository: %v", err)
	}
	readiness, err := repository.Readiness(ctx)
	if err != nil || readiness.State != paasv1.ReadinessReady ||
		paasv1.ValidateReadiness(readiness) != nil {
		t.Fatalf("read PaaS worker readiness: value=%#v err=%v", readiness, err)
	}
	queue, err := operationqueue.NewQueue(
		repository,
		operationqueue.Config{LeaseDuration: 30 * time.Second},
	)
	if err != nil {
		t.Fatalf("create Operation queue: %v", err)
	}
	first, found, err := queue.ClaimNext(ctx, "worker-a")
	if err != nil {
		t.Fatalf("claim application Operation: %v", err)
	}
	if !found || first.Operation.ID != applicationResult.Operation.ID ||
		first.FencingToken != 1 || first.Operation.Attempt != 1 {
		t.Fatalf("first Operation lease = %#v", first)
	}
	if _, found, err := queue.ClaimNext(ctx, "worker-b"); err != nil || found {
		t.Fatalf("concurrent Operation claim found/error = %v/%v", found, err)
	}
	planning, err := queue.Advance(ctx, operationqueue.Transition{
		Lease: first,
		State: paasv1.OperationPlanning,
	})
	if err != nil {
		t.Fatalf("advance Operation to planning: %v", err)
	}
	if _, err := admin.Exec(
		ctx,
		`UPDATE paas.operations
		    SET lease_expires_at = transaction_timestamp() - interval '1 second'
		  WHERE tenant_id = $1 AND id = $2`,
		planning.TenantID,
		planning.Operation.ID,
	); err != nil {
		t.Fatalf("expire first worker lease: %v", err)
	}
	second, found, err := queue.ClaimNext(ctx, "worker-b")
	if err != nil {
		t.Fatalf("reclaim expired Operation: %v", err)
	}
	if !found || second.FencingToken != 2 || second.Operation.Attempt != 2 ||
		second.Operation.State != paasv1.OperationPlanning {
		t.Fatalf("reclaimed Operation lease = %#v", second)
	}
	if _, err := queue.Advance(ctx, operationqueue.Transition{
		Lease: planning,
		State: paasv1.OperationQueued,
	}); !errors.Is(err, operationqueue.ErrStaleLease) {
		t.Fatalf("expired worker transition error = %v, want stale lease", err)
	}
	for _, state := range []paasv1.OperationState{
		paasv1.OperationQueued,
		paasv1.OperationExecuting,
		paasv1.OperationReconciling,
		paasv1.OperationExecuting,
		paasv1.OperationVerifying,
	} {
		second, err = queue.Advance(ctx, operationqueue.Transition{Lease: second, State: state})
		if err != nil {
			t.Fatalf("advance Operation to %s: %v", state, err)
		}
	}
	second, err = queue.Advance(ctx, operationqueue.Transition{
		Lease:        second,
		State:        paasv1.OperationSucceeded,
		ReleaseLease: true,
	})
	if err != nil {
		t.Fatalf("complete Operation: %v", err)
	}
	if second.Operation.State != paasv1.OperationSucceeded ||
		second.Operation.TerminalAt == nil || second.WorkerID != "" {
		t.Fatalf("completed Operation lease = %#v", second)
	}
	var attempt uint64
	var fencingToken uint64
	var leaseOwner *string
	if err := admin.QueryRow(
		ctx,
		`SELECT attempt, fencing_token, lease_owner
		   FROM paas.operations
		  WHERE tenant_id = $1 AND id = $2`,
		applicationResult.Operation.Scope.TenantID,
		applicationResult.Operation.ID,
	).Scan(&attempt, &fencingToken, &leaseOwner); err != nil {
		t.Fatalf("inspect completed Operation lease: %v", err)
	}
	if attempt != 2 || fencingToken != 2 || leaseOwner != nil {
		t.Fatalf(
			"completed Operation attempt/fencing/owner = %d/%d/%v",
			attempt,
			fencingToken,
			leaseOwner,
		)
	}
}

func applicationIntegrationSpec(
	fixture integrationFixture,
	configurationRevisionID paasv1.ResourceID,
) paasv1.DeploymentSpec {
	return paasv1.DeploymentSpec{
		ApplicationRevisionID: fixture.revisionID,
		PlacementPolicyID:     fixture.policyID,
		DesiredState:          paasv1.DeploymentDesiredRunning,
		Components: []paasv1.DeploymentComponent{{
			Name:     "web",
			Replicas: 1,
			Bindings: []paasv1.ComponentBinding{{
				Name:                    "settings",
				ConfigurationRevisionID: configurationRevisionID,
			}, {
				Name: "credential",
				SecretVersion: &paasv1.SecretVersionReference{
					SecretID: paasv1.ResourceID(string(fixture.applicationID) + "-credential"),
					Version:  "version-0001",
				},
			}},
		}},
	}
}

func runConcurrentPlacements(
	t *testing.T,
	ctx context.Context,
	usecase *createplacement.Usecase,
	commands []createplacement.Command,
) ([]createplacement.Result, int) {
	t.Helper()
	results := make([]createplacement.Result, len(commands))
	errs := make([]error, len(commands))
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(len(commands))
	for index := range commands {
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errs[index] = usecase.CreatePlacement(
				ctx, commands[index], integrationPlacementGuard(commands[index]),
			)
		}(index)
	}
	close(start)
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("concurrent placement %d: %v", index, err)
		}
	}
	scheduledIndex := -1
	unschedulable := 0
	for index, result := range results {
		switch result.Decision.Outcome {
		case paasv1.PlacementScheduled:
			if scheduledIndex != -1 {
				t.Fatalf("multiple concurrent placements scheduled: %#v", results)
			}
			scheduledIndex = index
		case paasv1.PlacementUnschedulable:
			unschedulable++
		default:
			t.Fatalf("unexpected placement outcome %q", result.Decision.Outcome)
		}
	}
	if scheduledIndex == -1 || unschedulable != len(results)-1 {
		t.Fatalf("placement outcomes = %#v", results)
	}
	return results, scheduledIndex
}

func assertCapacityDidNotOvercommit(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	fixture integrationFixture,
	results []createplacement.Result,
) {
	t.Helper()
	var consumingClaims int
	var cpuMillis int64
	var memoryBytes int64
	var workloadSlots int64
	if err := admin.QueryRow(
		ctx,
		`SELECT count(*),
		        COALESCE(sum(cpu_millis), 0),
		        COALESCE(sum(memory_bytes), 0),
		        COALESCE(sum(workload_slots), 0)
		   FROM paas.capacity_claims
		  WHERE execution_target_id = $1
		    AND (
		        state = 'ACTIVE'
		        OR (state = 'PENDING' AND lease_expires_at > transaction_timestamp())
		    )`,
		fixture.targetID,
	).Scan(&consumingClaims, &cpuMillis, &memoryBytes, &workloadSlots); err != nil {
		t.Fatalf("read consuming capacity claims: %v", err)
	}
	var targetDocument []byte
	if err := admin.QueryRow(
		ctx,
		"SELECT document FROM paas.execution_targets WHERE id = $1",
		fixture.targetID,
	).Scan(&targetDocument); err != nil {
		t.Fatalf("read execution target capacity: %v", err)
	}
	var target paasv1.ExecutionTarget
	if err := decodeDocument("ExecutionTarget", targetDocument, &target); err != nil {
		t.Fatalf("decode execution target capacity: %v", err)
	}
	if consumingClaims != 1 ||
		cpuMillis > target.Status.Capacity.CPUMillis ||
		memoryBytes > target.Status.Capacity.MemoryBytes ||
		workloadSlots > target.Status.Capacity.WorkloadSlots {
		t.Fatalf(
			"capacity overcommit: claims=%d cpu=%d memory=%d slots=%d",
			consumingClaims,
			cpuMillis,
			memoryBytes,
			workloadSlots,
		)
	}
	var decisions int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM paas.placement_decisions WHERE tenant_id = $1",
		fixture.tenantA,
	).Scan(&decisions); err != nil {
		t.Fatalf("count placement decisions: %v", err)
	}
	if decisions < len(results) {
		t.Fatalf("placement decisions = %d, want at least %d", decisions, len(results))
	}
}

func assertExactReplayAndConflict(
	t *testing.T,
	ctx context.Context,
	usecase *createplacement.Usecase,
	commands []createplacement.Command,
	results []createplacement.Result,
) {
	t.Helper()
	for index, command := range commands {
		replay, err := usecase.CreatePlacement(
			ctx, command, integrationPlacementGuard(command),
		)
		if err != nil {
			t.Fatalf("replay placement %d: %v", index, err)
		}
		if !replay.Replayed || !reflect.DeepEqual(replay.Decision, results[index].Decision) {
			t.Fatalf("replay %d = %#v, want identical %#v", index, replay, results[index])
		}
		conflict := command
		conflict.RequestDigest = integrationDigest(fmt.Sprintf("conflict-%d", index))
		if _, err := usecase.CreatePlacement(
			ctx, conflict, integrationPlacementGuard(conflict),
		); !errors.Is(
			err,
			createplacement.ErrIdempotencyConflict,
		) {
			t.Fatalf("changed replay %d error = %v, want idempotency conflict", index, err)
		}
	}
}

func reservationIdentity(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	decisionID paasv1.ResourceID,
) (paasv1.ResourceID, string) {
	t.Helper()
	var reservationID string
	var claimID string
	if err := admin.QueryRow(
		ctx,
		`SELECT id, capacity_claim_id::text
		   FROM paas.capacity_reservations
		  WHERE tenant_id = $1 AND decision_id = $2`,
		tenantID,
		decisionID,
	).Scan(&reservationID, &claimID); err != nil {
		t.Fatalf("read capacity reservation identity: %v", err)
	}
	return paasv1.ResourceID(reservationID), claimID
}

func assertWorkerRLS(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture integrationFixture,
	decisionID paasv1.ResourceID,
	reservationID paasv1.ResourceID,
	claimID string,
) {
	t.Helper()
	withWorkerTenant(t, ctx, pool, fixture.tenantB, func(tx pgx.Tx) {
		for _, query := range []struct {
			statement string
			identity  any
		}{
			{"SELECT count(*) FROM paas.deployments WHERE id = $1", fixture.deploymentIDs[0]},
			{"SELECT count(*) FROM paas.placement_decisions WHERE id = $1", decisionID},
			{"SELECT count(*) FROM paas.capacity_reservations WHERE id = $1", reservationID},
		} {
			var count int
			if err := tx.QueryRow(ctx, query.statement, query.identity).Scan(&count); err != nil {
				t.Fatalf("tenant B RLS read: %v", err)
			}
			if count != 0 {
				t.Fatalf("tenant B observed tenant A row through %q", query.statement)
			}
		}
	})

	withWorkerTenant(t, ctx, pool, fixture.tenantB, func(tx pgx.Tx) {
		_, err := tx.Exec(
			ctx,
			"DELETE FROM paas.placement_decisions WHERE id = $1",
			decisionID,
		)
		assertPostgresCode(t, err, "42501")
	})
	withWorkerTenant(t, ctx, pool, fixture.tenantA, func(tx pgx.Tx) {
		_, err := tx.Exec(
			ctx,
			"UPDATE paas.capacity_claims SET state = 'RELEASED' WHERE id = $1::uuid",
			claimID,
		)
		assertPostgresCode(t, err, "42501")
	})
}

func assertReservationTransitions(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	usecase *transitionreservation.Usecase,
	fixture integrationFixture,
	guard operationqueue.LeaseGuard,
	reservationID paasv1.ResourceID,
	claimID string,
) {
	t.Helper()
	tenantBGuard := guard
	tenantBGuard.TenantID = fixture.tenantB
	_, err := usecase.Transition(ctx, transitionreservation.Command{
		TenantID:                fixture.tenantB,
		ReservationID:           reservationID,
		Action:                  transitionreservation.ActionActivate,
		ExpectedResourceVersion: 1,
	}, tenantBGuard)
	if !errors.Is(err, transitionreservation.ErrStaleLease) {
		t.Fatalf("tenant B transition error = %v, want stale lease", err)
	}

	activate := transitionreservation.Command{
		TenantID:                fixture.tenantA,
		ReservationID:           reservationID,
		Action:                  transitionreservation.ActionActivate,
		ExpectedResourceVersion: 1,
	}
	result, err := usecase.Transition(ctx, activate, guard)
	if err != nil {
		t.Fatalf("activate capacity reservation: %v", err)
	}
	if result.State != placement.CapacityClaimActive || result.ResourceVersion != 2 || result.Replayed {
		t.Fatalf("activate result = %#v", result)
	}
	replay, err := usecase.Transition(ctx, activate, guard)
	if err != nil {
		t.Fatalf("replay activate capacity reservation: %v", err)
	}
	if replay.State != result.State || replay.ResourceVersion != result.ResourceVersion || !replay.Replayed {
		t.Fatalf("activate replay = %#v, want %#v as replay", replay, result)
	}

	release := transitionreservation.Command{
		TenantID:                fixture.tenantA,
		ReservationID:           reservationID,
		Action:                  transitionreservation.ActionRelease,
		ExpectedResourceVersion: 2,
	}
	result, err = usecase.Transition(ctx, release, guard)
	if err != nil {
		t.Fatalf("release capacity reservation: %v", err)
	}
	if result.State != placement.CapacityClaimReleased || result.ResourceVersion != 3 || result.Replayed {
		t.Fatalf("release result = %#v", result)
	}
	replay, err = usecase.Transition(ctx, release, guard)
	if err != nil {
		t.Fatalf("replay release capacity reservation: %v", err)
	}
	if replay.State != result.State || replay.ResourceVersion != result.ResourceVersion || !replay.Replayed {
		t.Fatalf("release replay = %#v, want %#v as replay", replay, result)
	}

	var claimState string
	var claimVersion uint64
	var claimLease *time.Time
	var reservationVersion uint64
	if err := admin.QueryRow(
		ctx,
		`SELECT claim.state,
		        claim.resource_version,
		        claim.lease_expires_at,
		        reservation.resource_version
		   FROM paas.capacity_claims AS claim
		   JOIN paas.capacity_reservations AS reservation
		     ON reservation.capacity_claim_id = claim.id
		  WHERE claim.id = $1::uuid`,
		claimID,
	).Scan(&claimState, &claimVersion, &claimLease, &reservationVersion); err != nil {
		t.Fatalf("verify released capacity reservation: %v", err)
	}
	if claimState != "RELEASED" || claimVersion != 3 || reservationVersion != 3 || claimLease != nil {
		t.Fatalf(
			"released rows state=%s claimVersion=%d reservationVersion=%d lease=%v",
			claimState,
			claimVersion,
			reservationVersion,
			claimLease,
		)
	}
}

var errInjectedAfterDecisionWrites = errors.New("injected failure after decision writes")

type failAfterCreateRepository struct {
	delegate createplacement.Repository
}

func (repository failAfterCreateRepository) WithinTransaction(
	ctx context.Context,
	tenantID paasv1.TenantID,
	guard operationqueue.LeaseGuard,
	callback func(context.Context, createplacement.Transaction) error,
) error {
	return repository.delegate.WithinTransaction(
		ctx,
		tenantID,
		guard,
		func(callbackContext context.Context, transaction createplacement.Transaction) error {
			return callback(callbackContext, failAfterCreateTransaction{Transaction: transaction})
		},
	)
}

type failAfterCreateTransaction struct {
	createplacement.Transaction
}

func (transaction failAfterCreateTransaction) CreateDecision(
	ctx context.Context,
	creation createplacement.DecisionCreation,
) error {
	if err := transaction.Transaction.CreateDecision(ctx, creation); err != nil {
		return err
	}
	return errInjectedAfterDecisionWrites
}

func assertAtomicRollbackAfterWrites(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	planner *placement.Planner,
	repository *PlacementRepository,
	fixture integrationFixture,
	prefix string,
) {
	t.Helper()
	deploymentID := paasv1.ResourceID(prefix + "-deployment-fault")
	seedDeployment(
		t, ctx, admin, fixture, deploymentID,
		paasv1.OperationID(prefix+"-operation-fault"),
		time.Now().UTC().Truncate(time.Microsecond),
	)
	var claimsBefore int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM paas.capacity_claims WHERE execution_target_id = $1",
		fixture.targetID,
	).Scan(&claimsBefore); err != nil {
		t.Fatalf("count claims before injected failure: %v", err)
	}
	usecase, err := createplacement.NewUsecase(
		planner,
		failAfterCreateRepository{delegate: repository},
		createplacement.Config{
			PendingReservationTTL:  10 * time.Minute,
			MaxTransactionAttempts: 1,
		},
	)
	if err != nil {
		t.Fatalf("create fault-injected placement use case: %v", err)
	}
	command := fixture.placementCommand(
		deploymentID,
		prefix+"-operation-fault",
		prefix+"-decision-fault",
		"request-fault",
	)
	if _, err := usecase.CreatePlacement(
		ctx, command, integrationPlacementGuard(command),
	); !errors.Is(
		err,
		errInjectedAfterDecisionWrites,
	) {
		t.Fatalf("fault-injected placement error = %v", err)
	}
	var decisions int
	var reservations int
	var claimsAfter int
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM paas.placement_decisions WHERE tenant_id = $1 AND id = $2",
		fixture.tenantA,
		command.DecisionID,
	).Scan(&decisions); err != nil {
		t.Fatalf("count rolled-back decision: %v", err)
	}
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM paas.capacity_reservations WHERE tenant_id = $1 AND decision_id = $2",
		fixture.tenantA,
		command.DecisionID,
	).Scan(&reservations); err != nil {
		t.Fatalf("count rolled-back reservation: %v", err)
	}
	if err := admin.QueryRow(
		ctx,
		"SELECT count(*) FROM paas.capacity_claims WHERE execution_target_id = $1",
		fixture.targetID,
	).Scan(&claimsAfter); err != nil {
		t.Fatalf("count claims after injected failure: %v", err)
	}
	if decisions != 0 || reservations != 0 || claimsAfter != claimsBefore {
		t.Fatalf(
			"atomic rollback failed: decisions=%d reservations=%d claims=%d before=%d",
			decisions,
			reservations,
			claimsAfter,
			claimsBefore,
		)
	}
}

func assertPendingExpiry(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	planner *placement.Planner,
	repository *PlacementRepository,
	transitionUsecase *transitionreservation.Usecase,
	fixture integrationFixture,
	prefix string,
) {
	t.Helper()
	deploymentID := paasv1.ResourceID(prefix + "-deployment-expiry")
	seedDeployment(
		t, ctx, admin, fixture, deploymentID,
		paasv1.OperationID(prefix+"-operation-expiry"),
		time.Now().UTC().Truncate(time.Microsecond),
	)
	usecase, err := createplacement.NewUsecase(
		planner,
		repository,
		createplacement.Config{
			PendingReservationTTL:  time.Microsecond,
			MaxTransactionAttempts: 3,
		},
	)
	if err != nil {
		t.Fatalf("create expiring placement use case: %v", err)
	}
	command := fixture.placementCommand(
		deploymentID,
		prefix+"-operation-expiry",
		prefix+"-decision-expiry",
		"request-expiry",
	)
	result, err := usecase.CreatePlacement(
		ctx, command, integrationPlacementGuard(command),
	)
	if err != nil {
		t.Fatalf("create expiring placement: %v", err)
	}
	if result.Decision.Outcome != paasv1.PlacementScheduled {
		t.Fatalf("expiring placement outcome = %q", result.Decision.Outcome)
	}
	reservationID, _ := reservationIdentity(
		t,
		ctx,
		admin,
		fixture.tenantA,
		result.Decision.Metadata.ID,
	)
	activate := transitionreservation.Command{
		TenantID:                fixture.tenantA,
		ReservationID:           reservationID,
		Action:                  transitionreservation.ActionActivate,
		ExpectedResourceVersion: 1,
	}
	guard := integrationPlacementGuard(command)
	if _, err := transitionUsecase.Transition(ctx, activate, guard); !errors.Is(
		err,
		transitionreservation.ErrInvalidTransition,
	) {
		t.Fatalf("activate expired reservation error = %v", err)
	}
	expire := activate
	expire.Action = transitionreservation.ActionExpire
	expired, err := transitionUsecase.Transition(ctx, expire, guard)
	if err != nil {
		t.Fatalf("expire pending reservation: %v", err)
	}
	if expired.State != placement.CapacityClaimReleased ||
		expired.ResourceVersion != 2 ||
		expired.Replayed {
		t.Fatalf("expire result = %#v", expired)
	}
	replay, err := transitionUsecase.Transition(ctx, expire, guard)
	if err != nil {
		t.Fatalf("replay pending expiry: %v", err)
	}
	if !replay.Replayed || replay.State != expired.State || replay.ResourceVersion != expired.ResourceVersion {
		t.Fatalf("expiry replay = %#v, want %#v as replay", replay, expired)
	}
}

func withWorkerTenant(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID paasv1.TenantID,
	callback func(pgx.Tx),
) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		t.Fatalf("begin direct worker transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('matrix.tenant_id', $1, true)",
		string(tenantID),
	); err != nil {
		t.Fatalf("set direct worker tenant: %v", err)
	}
	callback(tx)
}

func assertPostgresCode(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func execDocument(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	statement string,
	arguments ...any,
) {
	t.Helper()
	if _, err := admin.Exec(ctx, statement, arguments...); err != nil {
		t.Fatalf("seed PostgreSQL integration fixture: %v", err)
	}
}

func integrationJSON(t *testing.T, value any) string {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode integration fixture: %v", err)
	}
	return string(document)
}

func integrationDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
