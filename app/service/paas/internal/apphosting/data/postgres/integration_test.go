package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/transitionreservation"
)

const (
	postgresIntegrationDSN = "MATRIX_PAAS_POSTGRES_TEST_DSN"
	runtimeTestRole        = "matrix_paas_test_runtime"
	runtimeTestPassword    = "matrix-test-only"
)

func TestPostgresGateBIntegration(t *testing.T) {
	dsn := os.Getenv(postgresIntegrationDSN)
	if dsn == "" {
		t.Skipf("set %s to a disposable PostgreSQL 18 database", postgresIntegrationDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL integration DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_paas_gateb") {
		t.Fatalf(
			"refusing to mutate database %q; integration database name must start with matrix_paas_gateb",
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
	ensureRuntimeTestRole(t, ctx, admin)
	runtimePool := openRuntimePool(t, ctx, adminConfig)
	defer runtimePool.Close()

	prefix := fmt.Sprintf("gateb-%x", time.Now().UnixNano())
	fixture := seedGateBFixture(t, ctx, admin, prefix)
	planner, err := placement.NewV1Planner(5 * time.Minute)
	if err != nil {
		t.Fatalf("create placement planner: %v", err)
	}
	placementRepository, err := NewPlacementRepository(runtimePool)
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
	assertRuntimeRLS(t, ctx, runtimePool, fixture, scheduledDecision.Metadata.ID, reservationID, claimID)

	reservationRepository, err := NewCapacityReservationRepository(runtimePool)
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
}

type gateBFixture struct {
	tenantA       paasv1.TenantID
	tenantB       paasv1.TenantID
	applicationID paasv1.ResourceID
	revisionID    paasv1.ResourceID
	policyID      paasv1.ResourceID
	poolID        paasv1.ResourceID
	targetID      paasv1.ResourceID
	deploymentIDs []paasv1.ResourceID
	observedAt    time.Time
}

func (fixture gateBFixture) placementCommand(
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

func applyMigrationTwiceAndVerify(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate PostgreSQL integration test source")
	}
	migrationRoot := filepath.Join(
		filepath.Dir(currentFile),
		"migrations",
		"000001_placement_core",
	)
	up := readIntegrationFile(t, filepath.Join(migrationRoot, "up.sql"))
	verify := readIntegrationFile(t, filepath.Join(migrationRoot, "verify.sql"))
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := admin.Exec(ctx, up); err != nil {
			t.Fatalf("apply placement migration attempt %d: %v", attempt, err)
		}
	}
	if _, err := admin.Exec(ctx, verify); err != nil {
		t.Fatalf("verify placement migration: %v", err)
	}
}

func readIntegrationFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func ensureRuntimeTestRole(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)",
		runtimeTestRole,
	).Scan(&exists); err != nil {
		t.Fatalf("inspect runtime test role: %v", err)
	}
	if !exists {
		if _, err := admin.Exec(
			ctx,
			`CREATE ROLE matrix_paas_test_runtime
			 LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
			 PASSWORD 'matrix-test-only'`,
		); err != nil {
			t.Fatalf("create runtime test role: %v", err)
		}
	} else if _, err := admin.Exec(
		ctx,
		`ALTER ROLE matrix_paas_test_runtime
		 LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
		 PASSWORD 'matrix-test-only'`,
	); err != nil {
		t.Fatalf("reset runtime test role: %v", err)
	}
	if _, err := admin.Exec(
		ctx,
		"GRANT matrix_paas_runtime TO matrix_paas_test_runtime",
	); err != nil {
		t.Fatalf("grant runtime test membership: %v", err)
	}
}

func openRuntimePool(
	t *testing.T,
	ctx context.Context,
	adminConfig *pgx.ConnConfig,
) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(adminConfig.ConnString())
	if err != nil {
		t.Fatalf("parse runtime pool DSN: %v", err)
	}
	config.ConnConfig.User = runtimeTestRole
	config.ConnConfig.Password = runtimeTestPassword
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("create runtime PostgreSQL pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping runtime PostgreSQL pool: %v", err)
	}
	return pool
}

func seedGateBFixture(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	prefix string,
) gateBFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fixture := gateBFixture{
		tenantA:       paasv1.TenantID(prefix + "-tenant-a"),
		tenantB:       paasv1.TenantID(prefix + "-tenant-b"),
		applicationID: paasv1.ResourceID(prefix + "-application"),
		revisionID:    paasv1.ResourceID(prefix + "-revision"),
		policyID:      paasv1.ResourceID(prefix + "-policy"),
		poolID:        paasv1.ResourceID(prefix + "-pool"),
		targetID:      paasv1.ResourceID(prefix + "-target"),
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
					Locator: "registry.invalid/matrix/gateb-web",
					Digest:  integrationDigest(prefix + "-artifact"),
				},
				Resources: paasv1.ResourceRequirements{
					CPUMillis:   100,
					MemoryBytes: 1024 * 1024,
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
		MemoryBytes:   1024 * 1024,
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

	execDocument(t, ctx, admin,
		`INSERT INTO paas.applications (tenant_id, id, resource_version, document)
		 VALUES ($1, $2, $3, $4::jsonb)`,
		fixture.tenantA, fixture.applicationID, 1, integrationJSON(t, application),
	)
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
	for _, deploymentID := range fixture.deploymentIDs {
		seedDeployment(t, ctx, admin, fixture, deploymentID, now)
	}
	return fixture
}

func seedDeployment(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	fixture gateBFixture,
	deploymentID paasv1.ResourceID,
	now time.Time,
) {
	t.Helper()
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
			Phase:      paasv1.DeploymentPending,
			ObservedAt: now.Add(-time.Second),
		},
	}
	if err := paasv1.ValidateDeployment(deployment); err != nil {
		t.Fatalf("invalid Deployment fixture: %v", err)
	}
	execDocument(t, ctx, admin,
		`INSERT INTO paas.deployments
		 (tenant_id, id, application_revision_id, policy_id, resource_version, document)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		fixture.tenantA,
		deploymentID,
		fixture.revisionID,
		fixture.policyID,
		1,
		integrationJSON(t, deployment),
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
			results[index], errs[index] = usecase.CreatePlacement(ctx, commands[index])
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
	fixture gateBFixture,
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
	if consumingClaims != 1 || cpuMillis > 100 || memoryBytes > 1024*1024 || workloadSlots > 1 {
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
		replay, err := usecase.CreatePlacement(ctx, command)
		if err != nil {
			t.Fatalf("replay placement %d: %v", index, err)
		}
		if !replay.Replayed || !reflect.DeepEqual(replay.Decision, results[index].Decision) {
			t.Fatalf("replay %d = %#v, want identical %#v", index, replay, results[index])
		}
		conflict := command
		conflict.RequestDigest = integrationDigest(fmt.Sprintf("conflict-%d", index))
		if _, err := usecase.CreatePlacement(ctx, conflict); !errors.Is(
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

func assertRuntimeRLS(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture gateBFixture,
	decisionID paasv1.ResourceID,
	reservationID paasv1.ResourceID,
	claimID string,
) {
	t.Helper()
	withRuntimeTenant(t, ctx, pool, fixture.tenantB, func(tx pgx.Tx) {
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

	withRuntimeTenant(t, ctx, pool, fixture.tenantB, func(tx pgx.Tx) {
		_, err := tx.Exec(
			ctx,
			"DELETE FROM paas.placement_decisions WHERE id = $1",
			decisionID,
		)
		assertPostgresCode(t, err, "42501")
	})
	withRuntimeTenant(t, ctx, pool, fixture.tenantA, func(tx pgx.Tx) {
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
	fixture gateBFixture,
	reservationID paasv1.ResourceID,
	claimID string,
) {
	t.Helper()
	_, err := usecase.Transition(ctx, transitionreservation.Command{
		TenantID:                fixture.tenantB,
		ReservationID:           reservationID,
		Action:                  transitionreservation.ActionActivate,
		ExpectedResourceVersion: 1,
	})
	if !errors.Is(err, transitionreservation.ErrNotFound) {
		t.Fatalf("tenant B transition error = %v, want not found", err)
	}

	activate := transitionreservation.Command{
		TenantID:                fixture.tenantA,
		ReservationID:           reservationID,
		Action:                  transitionreservation.ActionActivate,
		ExpectedResourceVersion: 1,
	}
	result, err := usecase.Transition(ctx, activate)
	if err != nil {
		t.Fatalf("activate capacity reservation: %v", err)
	}
	if result.State != placement.CapacityClaimActive || result.ResourceVersion != 2 || result.Replayed {
		t.Fatalf("activate result = %#v", result)
	}
	replay, err := usecase.Transition(ctx, activate)
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
	result, err = usecase.Transition(ctx, release)
	if err != nil {
		t.Fatalf("release capacity reservation: %v", err)
	}
	if result.State != placement.CapacityClaimReleased || result.ResourceVersion != 3 || result.Replayed {
		t.Fatalf("release result = %#v", result)
	}
	replay, err = usecase.Transition(ctx, release)
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
	callback func(context.Context, createplacement.Transaction) error,
) error {
	return repository.delegate.WithinTransaction(
		ctx,
		tenantID,
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
	fixture gateBFixture,
	prefix string,
) {
	t.Helper()
	deploymentID := paasv1.ResourceID(prefix + "-deployment-fault")
	seedDeployment(t, ctx, admin, fixture, deploymentID, time.Now().UTC().Truncate(time.Microsecond))
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
	if _, err := usecase.CreatePlacement(ctx, command); !errors.Is(
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
	fixture gateBFixture,
	prefix string,
) {
	t.Helper()
	deploymentID := paasv1.ResourceID(prefix + "-deployment-expiry")
	seedDeployment(t, ctx, admin, fixture, deploymentID, time.Now().UTC().Truncate(time.Microsecond))
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
	result, err := usecase.CreatePlacement(ctx, command)
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
	if _, err := transitionUsecase.Transition(ctx, activate); !errors.Is(
		err,
		transitionreservation.ErrInvalidTransition,
	) {
		t.Fatalf("activate expired reservation error = %v", err)
	}
	expire := activate
	expire.Action = transitionreservation.ActionExpire
	expired, err := transitionUsecase.Transition(ctx, expire)
	if err != nil {
		t.Fatalf("expire pending reservation: %v", err)
	}
	if expired.State != placement.CapacityClaimReleased ||
		expired.ResourceVersion != 2 ||
		expired.Replayed {
		t.Fatalf("expire result = %#v", expired)
	}
	replay, err := transitionUsecase.Transition(ctx, expire)
	if err != nil {
		t.Fatalf("replay pending expiry: %v", err)
	}
	if !replay.Replayed || replay.State != expired.State || replay.ResourceVersion != expired.ResourceVersion {
		t.Fatalf("expiry replay = %#v, want %#v as replay", replay, expired)
	}
}

func withRuntimeTenant(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID paasv1.TenantID,
	callback func(pgx.Tx),
) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		t.Fatalf("begin direct runtime transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('matrix.tenant_id', $1, true)",
		string(tenantID),
	); err != nil {
		t.Fatalf("set direct runtime tenant: %v", err)
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
