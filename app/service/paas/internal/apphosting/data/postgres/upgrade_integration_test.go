package postgres

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	auditpostgres "github.com/xiak/matrix/app/service/paas/internal/audit/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/audit/usecase/auditdispatch"
	paasmigration "github.com/xiak/matrix/app/service/paas/migration"
)

const (
	deploymentRuntimeCompatibilityDSN = "MATRIX_PAAS_RUNTIME_COMPAT_POSTGRES_TEST_DSN"
	hostLifecyclePredecessor          = "5344b739b4284e2f6f42a12165105d9b0e349bdc"
	compatibilityAPILogin             = "matrix_paas_api_login"
	compatibilityWorkerLogin          = "matrix_paas_worker_login"
	compatibilityAPIPassword          = "mxp1.runtime-compat-api-000000000000000000000000"
	compatibilityWorkerPassword       = "mxp1.runtime-compat-worker-00000000000000000000"
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
	if ready, err := tenantRepository.Readiness(ctx); err != nil || ready.State != paasv1.ReadinessReady || ready.SchemaVersion != paasDatabaseSchemaVersion {
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

func TestHostLifecycleExactPredecessorUpgradeAndRollbackRejection(t *testing.T) {
	adminDSN := os.Getenv(deploymentRuntimeCompatibilityDSN)
	if adminDSN == "" {
		t.Skipf(
			"set %s to a clean disposable PostgreSQL 18 database",
			deploymentRuntimeCompatibilityDSN,
		)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	adminConfig, err := pgx.ParseConfig(adminDSN)
	if err != nil || !strings.HasPrefix(
		adminConfig.Database,
		"matrix_paas_runtime_compat_",
	) {
		t.Fatal("runtime compatibility gate requires a safely named PostgreSQL URL")
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("connect runtime compatibility database")
	}
	defer func() { _ = admin.Close(context.Background()) }()
	var clean, postgres18 bool
	if err := admin.QueryRow(
		ctx,
		`SELECT to_regnamespace('paas') IS NULL
		        AND to_regnamespace('managedservice') IS NULL,
		        current_setting('server_version_num')::integer BETWEEN 180000 AND 189999`,
	).Scan(&clean, &postgres18); err != nil || !clean || !postgres18 {
		t.Fatalf(
			"runtime compatibility gate requires clean PostgreSQL 18: clean=%v postgres18=%v err=%v",
			clean,
			postgres18,
			err,
		)
	}

	temporary := t.TempDir()
	repositoryRoot := compatibilityRepositoryRoot(t, ctx)
	predecessorSource := extractFixedPaaSSource(
		t,
		ctx,
		repositoryRoot,
		temporary,
		hostLifecyclePredecessor,
	)
	predecessor := buildFixedPaaSBinaries(t, ctx, predecessorSource, temporary)
	apiMigrationDSN := compatibilityRuntimeDSN(
		t,
		adminDSN,
		compatibilityAPILogin,
		compatibilityAPIPassword,
		false,
	)
	workerMigrationDSN := compatibilityRuntimeDSN(
		t,
		adminDSN,
		compatibilityWorkerLogin,
		compatibilityWorkerPassword,
		false,
	)
	apiProcessDSN := compatibilityRuntimeDSN(
		t,
		adminDSN,
		compatibilityAPILogin,
		compatibilityAPIPassword,
		true,
	)
	adminDSNPath := writeCompatibilityFile(t, temporary, "admin-dsn", adminDSN)
	apiMigrationDSNPath := writeCompatibilityFile(
		t,
		temporary,
		"api-migration-dsn",
		apiMigrationDSN,
	)
	workerMigrationDSNPath := writeCompatibilityFile(
		t,
		temporary,
		"worker-migration-dsn",
		workerMigrationDSN,
	)
	predecessorMigrationEnvironment := []string{
		"MATRIX_MIGRATION_DATABASE_DSN_FILE=" + adminDSNPath,
		"MATRIX_MIGRATION_PAAS_API_DSN_FILE=" + apiMigrationDSNPath,
		"MATRIX_MIGRATION_PAAS_WORKER_DSN_FILE=" + workerMigrationDSNPath,
	}
	runFixedPaaSMigration(
		t,
		ctx,
		predecessor.migration,
		"apply",
		predecessorMigrationEnvironment,
	)
	runFixedPaaSMigration(
		t,
		ctx,
		predecessor.migration,
		"verify",
		predecessorMigrationEnvironment,
	)
	if err := paasmigration.Verify(ctx, admin); err == nil {
		t.Fatal("schema-3 migration verification accepted the predecessor schema")
	}

	apiPool, err := pgxpool.New(ctx, apiProcessDSN)
	if err != nil {
		t.Fatal("open predecessor PaaS API pool")
	}
	defer apiPool.Close()
	workerProcessDSN := compatibilityRuntimeDSN(
		t,
		adminDSN,
		compatibilityWorkerLogin,
		compatibilityWorkerPassword,
		true,
	)
	workerPool, err := pgxpool.New(ctx, workerProcessDSN)
	if err != nil {
		t.Fatal("open predecessor PaaS worker pool")
	}
	defer workerPool.Close()
	fixture := seedIntegrationFixture(t, ctx, admin, "runtime-compat")
	retained := assertApplicationLifecycle(
		t,
		ctx,
		admin,
		apiPool,
		fixture,
		"runtime-compat",
	)
	retainedBefore := compatibilityRetainedState(t, ctx, admin, fixture)

	for attempt := 1; attempt <= 2; attempt++ {
		if err := paasmigration.Apply(
			ctx,
			adminDSN,
			apiMigrationDSN,
			workerMigrationDSN,
		); err != nil {
			t.Fatalf("apply host lifecycle schema expansion attempt %d: %v", attempt, err)
		}
	}
	if err := paasmigration.VerifyInstalled(
		ctx,
		adminDSN,
		apiMigrationDSN,
		workerMigrationDSN,
	); err != nil {
		t.Fatalf("verify host lifecycle schema expansion: %v", err)
	}
	if retainedAfter := compatibilityRetainedState(
		t,
		ctx,
		admin,
		fixture,
	); retainedAfter != retainedBefore {
		t.Fatal("host lifecycle schema expansion rewrote predecessor tenant work")
	}
	runtimeBefore := createCompatibilityRuntimeSnapshot(
		t,
		ctx,
		admin,
		apiPool,
		workerPool,
		fixture,
		retained,
	)
	rollbackStateBefore := compatibilityRetainedState(t, ctx, admin, fixture)

	// The predecessor's read-only migration verifier audits the still-supported
	// structural and privilege subset; it is not a release-profile permit. The
	// schema-2 API must nevertheless fail readiness before serving against
	// schema 3, which can persist REMOVED tombstones and lifecycle facts.
	// Rollback across this profile boundary requires an authenticated backup.
	runFixedPaaSMigration(
		t,
		ctx,
		predecessor.migration,
		"verify",
		predecessorMigrationEnvironment,
	)
	assertFixedPaaSNotReady(
		t,
		ctx,
		predecessor.api,
		temporary,
		apiProcessDSN,
	)
	if err := paasmigration.VerifyInstalled(
		ctx,
		adminDSN,
		apiMigrationDSN,
		workerMigrationDSN,
	); err != nil {
		t.Fatalf("successor verification after rejected predecessor: %v", err)
	}
	if rollbackStateAfter := compatibilityRetainedState(
		t,
		ctx,
		admin,
		fixture,
	); rollbackStateAfter != rollbackStateBefore {
		t.Fatal("rejected predecessor verifier or API rewrote retained PaaS work")
	}
	if runtimeAfter := compatibilityRuntimeState(
		t,
		ctx,
		admin,
		fixture.tenantA,
		retained.Deployment.Metadata.ID,
	); runtimeAfter != runtimeBefore {
		t.Fatal("rejected predecessor verifier or API rewrote the runtime snapshot")
	}
	assertCompatibilityRuntimeReadable(
		t,
		ctx,
		apiPool,
		fixture.tenantA,
		retained.Deployment.Metadata.ID,
	)
}

type fixedPaaSBinaries struct {
	migration string
	api       string
}

func compatibilityRepositoryRoot(t *testing.T, ctx context.Context) string {
	t.Helper()
	command := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil {
		t.Fatal("locate repository root for fixed predecessor")
	}
	root := filepath.Clean(strings.TrimSpace(string(output)))
	if !filepath.IsAbs(root) {
		t.Fatal("fixed predecessor repository root is not absolute")
	}
	return root
}

// The accepted predecessor is materialized from immutable Git objects into a
// test-only directory. It never becomes a source, build, or runtime dependency.
func extractFixedPaaSSource(
	t *testing.T,
	ctx context.Context,
	repositoryRoot string,
	temporary string,
	fixedCommit string,
) string {
	t.Helper()
	command := exec.CommandContext(
		ctx,
		"git",
		"archive",
		"--format=zip",
		fixedCommit,
		"go.mod",
		"go.sum",
		"api",
		"app/adapter",
		"app/service/installation/nodeconfig",
		"app/service/internal",
		"app/service/paas",
	)
	command.Dir = repositoryRoot
	archive, err := command.Output()
	if err != nil || len(archive) == 0 || len(archive) > 64<<20 {
		t.Fatal("cannot read bounded fixed PaaS source archive")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal("fixed PaaS source archive is invalid")
	}
	destination := filepath.Join(temporary, "paas-runtime-predecessor")
	var extracted uint64
	for _, entry := range reader.File {
		path := filepath.FromSlash(entry.Name)
		if !filepath.IsLocal(path) || entry.UncompressedSize64 > 8<<20 ||
			extracted+entry.UncompressedSize64 > 64<<20 {
			t.Fatal("fixed PaaS source archive contains an unsafe entry")
		}
		target := filepath.Join(destination, path)
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal("create fixed PaaS source directory")
			}
			continue
		}
		if !entry.FileInfo().Mode().IsRegular() {
			t.Fatal("fixed PaaS source archive contains a non-regular entry")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal("create fixed PaaS source parent")
		}
		source, err := entry.Open()
		if err != nil {
			t.Fatal("open fixed PaaS source entry")
		}
		content, readErr := io.ReadAll(io.LimitReader(source, (8<<20)+1))
		closeErr := source.Close()
		if readErr != nil || closeErr != nil ||
			uint64(len(content)) != entry.UncompressedSize64 {
			t.Fatal("extract fixed PaaS source entry")
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal("write fixed PaaS source entry")
		}
		extracted += entry.UncompressedSize64
	}
	return destination
}

func buildFixedPaaSBinaries(
	t *testing.T,
	ctx context.Context,
	source string,
	temporary string,
) fixedPaaSBinaries {
	t.Helper()
	extension := ""
	if runtime.GOOS == "windows" {
		extension = ".exe"
	}
	result := fixedPaaSBinaries{
		migration: filepath.Join(temporary, "matrix-paas-migrate-r7"+extension),
		api:       filepath.Join(temporary, "matrix-paas-r7"+extension),
	}
	for _, build := range []struct {
		output      string
		packagePath string
	}{
		{result.migration, "./app/service/paas/cmd/matrix-paas-migrate"},
		{result.api, "./app/service/paas/cmd/matrix-paas"},
	} {
		command := exec.CommandContext(
			ctx,
			"go",
			"build",
			"-p",
			"2",
			"-trimpath",
			"-o",
			build.output,
			build.packagePath,
		)
		command.Dir = source
		output, err := command.CombinedOutput()
		if err != nil || len(output) > 128<<10 {
			t.Fatalf("build fixed PaaS predecessor %s", build.packagePath)
		}
	}
	return result
}

func compatibilityRuntimeDSN(
	t *testing.T,
	adminDSN string,
	user string,
	password string,
	pooled bool,
) string {
	t.Helper()
	admin, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("parse compatibility administrator DSN")
	}
	value, err := url.Parse(adminDSN)
	if err != nil || (value.Scheme != "postgres" && value.Scheme != "postgresql") ||
		value.Host == "" {
		t.Fatal("runtime compatibility gate requires an explicit PostgreSQL URL")
	}
	value.User = url.UserPassword(user, password)
	query := value.Query()
	query.Del("user")
	query.Del("password")
	query.Del("pool_max_conns")
	query.Set("application_name", "matrix-paas-runtime-compat:"+user)
	if pooled {
		query.Set("pool_max_conns", "2")
	}
	value.RawQuery = query.Encode()
	result := value.String()
	if pooled {
		config, err := pgxpool.ParseConfig(result)
		if err != nil || config.MaxConns != 2 || config.ConnConfig.User != user ||
			config.ConnConfig.Password != password || config.ConnConfig.Host != admin.Host ||
			config.ConnConfig.Port != admin.Port || config.ConnConfig.Database != admin.Database {
			t.Fatal("pooled compatibility DSN changed its bounded database identity")
		}
	} else {
		config, err := pgx.ParseConfig(result)
		if err != nil || config.User != user || config.Password != password ||
			config.Host != admin.Host || config.Port != admin.Port ||
			config.Database != admin.Database ||
			config.RuntimeParams["pool_max_conns"] != "" {
			t.Fatal("migration compatibility DSN changed its bounded database identity")
		}
	}
	return result
}

func writeCompatibilityFile(
	t *testing.T,
	temporary string,
	name string,
	value string,
) string {
	t.Helper()
	path := filepath.Join(temporary, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write protected compatibility file %s", name)
	}
	return path
}

func runFixedPaaSMigration(
	t *testing.T,
	ctx context.Context,
	binary string,
	action string,
	environment []string,
) {
	t.Helper()
	command := exec.CommandContext(ctx, binary, action)
	command.Env = replaceCompatibilityEnvironment(environment)
	output, err := command.CombinedOutput()
	if err != nil || len(output) > 64<<10 {
		t.Fatalf("fixed PaaS migration %s failed", action)
	}
}

func replaceCompatibilityEnvironment(overrides []string) []string {
	names := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		name, _, _ := strings.Cut(override, "=")
		names[strings.ToUpper(name)] = struct{}{}
	}
	result := make([]string, 0, len(os.Environ())+len(overrides))
	for _, existing := range os.Environ() {
		name, _, _ := strings.Cut(existing, "=")
		if _, replaced := names[strings.ToUpper(name)]; !replaced {
			result = append(result, existing)
		}
	}
	return append(result, overrides...)
}

func compatibilityRetainedState(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	fixture integrationFixture,
) string {
	t.Helper()
	var state string
	if err := admin.QueryRow(
		ctx,
		`SELECT jsonb_build_object(
		    'applications', (SELECT jsonb_agg(document ORDER BY id)
		                       FROM paas.applications WHERE tenant_id=$1),
		    'configurations', (SELECT jsonb_agg(document ORDER BY id)
		                         FROM paas.configurations WHERE tenant_id=$1),
		    'configurationRevisions', (SELECT jsonb_agg(document ORDER BY id)
		                                 FROM paas.configuration_revisions WHERE tenant_id=$1),
		    'applicationRevisions', (SELECT jsonb_agg(document ORDER BY id)
		                               FROM paas.application_revisions WHERE tenant_id=$1),
		    'deployments', (SELECT jsonb_agg(document ORDER BY id)
		                      FROM paas.deployments WHERE tenant_id=$1),
		    'generations', (SELECT jsonb_agg(document ORDER BY deployment_id, generation)
		                      FROM paas.deployment_generations WHERE tenant_id=$1),
		    'operations', (SELECT jsonb_agg(document ORDER BY id)
		                     FROM paas.operations WHERE tenant_id=$1),
		    'outbox', (SELECT jsonb_agg(document ORDER BY event_id)
		                 FROM paas.audit_outbox WHERE tenant_id=$1),
		    'decisions', (SELECT jsonb_agg(document ORDER BY id)
		                    FROM paas.placement_decisions WHERE tenant_id=$1),
		    'claims', (SELECT jsonb_agg(jsonb_build_object(
		                    'id', claim.id, 'state', claim.state,
		                    'resourceVersion', claim.resource_version,
		                    'leaseExpiresAt', claim.lease_expires_at
		                ) ORDER BY claim.id)
		                FROM paas.capacity_claims AS claim
		                JOIN paas.capacity_reservations AS reservation
		                  ON reservation.capacity_claim_id=claim.id
		                WHERE reservation.tenant_id=$1),
		    'reservations', (SELECT jsonb_agg(jsonb_build_object(
		                    'id', id, 'decisionId', decision_id,
		                    'claimId', capacity_claim_id, 'resourceVersion', resource_version
		                ) ORDER BY id)
		                FROM paas.capacity_reservations WHERE tenant_id=$1),
		    'pool', (SELECT document FROM paas.execution_pools WHERE id=$2),
		    'target', (SELECT document FROM paas.execution_targets WHERE id=$3)
		)::text`,
		fixture.tenantA,
		fixture.poolID,
		fixture.targetID,
	).Scan(&state); err != nil {
		t.Fatal("read predecessor retained state")
	}
	return state
}

func createCompatibilityRuntimeSnapshot(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	fixture integrationFixture,
	retained applicationlifecycle.Result,
) string {
	t.Helper()
	planner, err := placement.NewV1Planner(5 * time.Minute)
	if err != nil {
		t.Fatal("create compatibility placement planner")
	}
	placementRepository, err := NewPlacementRepository(workerPool)
	if err != nil {
		t.Fatal("create compatibility placement repository")
	}
	placementUsecase, err := createplacement.NewUsecase(
		planner,
		placementRepository,
		createplacement.Config{
			PendingReservationTTL:  10 * time.Minute,
			MaxTransactionAttempts: 3,
		},
	)
	if err != nil {
		t.Fatal("create compatibility placement use case")
	}
	executor := &postgresWorkerExecutor{
		t: t, ctx: ctx, admin: admin, fixture: fixture,
		plans: make(map[paasv1.OperationID]*postgresWorkerPlan),
	}
	worker := newDeploymentWorkerFixture(
		t,
		apiPool,
		workerPool,
		placementUsecase,
		executor,
		fixture.targetID,
		"compose-local",
		10*time.Second,
	)
	executor.expect(retained.Operation.ID, postgresWorkerPlan{
		method: "apply", resultState: paasv1.AdapterResultSucceeded,
		observationPhase: paasv1.DeploymentReady, expectedConsuming: 1,
		expectedConfigurationRevisionID: fixture.configurationRevisionIDs[0],
	})
	processWorkerOperation(t, ctx, worker.worker)
	ready, operation := loadWorkerOutcome(
		t,
		ctx,
		admin,
		fixture.tenantA,
		retained.Deployment.Metadata.ID,
		retained.Operation.ID,
	)
	assertWorkerOutcome(
		t,
		ready,
		operation,
		1,
		1,
		paasv1.DeploymentReady,
		paasv1.OperationSucceeded,
	)
	runtimeRepository, err := NewDeploymentRuntimeRepository(workerPool)
	if err != nil {
		t.Fatal("create compatibility runtime repository")
	}
	candidate := findDeploymentRuntimeCandidate(
		t,
		ctx,
		runtimeRepository,
		fixture.tenantA,
		retained.Deployment.Metadata.ID,
	)
	var observedAt time.Time
	if err := admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&observedAt); err != nil {
		t.Fatal("read compatibility database time")
	}
	observedAt = databaseTime(observedAt)
	observation := paasv1.DeploymentRuntimeObservation{
		DeploymentID:          candidate.DeploymentID,
		Generation:            candidate.Generation,
		ApplicationRevisionID: candidate.ApplicationRevisionID,
		ExecutionTargetID:     candidate.ExecutionTargetID,
		Instances: []paasv1.DeploymentRuntimeInstance{{
			ID:            "instance-fedcba9876543210fedcba9876543210",
			ComponentName: "web",
			State:         paasv1.DeploymentInstanceRunning,
			Health:        paasv1.DeploymentInstanceHealthHealthy,
		}},
		ObservedAt: observedAt,
	}
	stored, err := runtimeRepository.Store(
		ctx,
		fixture.tenantA,
		candidate.PlacementDecisionID,
		deploymentTelemetrySnapshot(observation, observedAt.Add(15*time.Second)),
	)
	if err != nil || !stored {
		t.Fatalf("store compatibility runtime snapshot: stored=%v err=%v", stored, err)
	}
	assertCompatibilityRuntimeReadable(
		t,
		ctx,
		apiPool,
		fixture.tenantA,
		retained.Deployment.Metadata.ID,
	)
	return compatibilityRuntimeState(
		t,
		ctx,
		admin,
		fixture.tenantA,
		retained.Deployment.Metadata.ID,
	)
}

func compatibilityRuntimeState(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
) string {
	t.Helper()
	var state string
	if err := admin.QueryRow(
		ctx,
		`SELECT jsonb_build_object(
		    'runtime', (
		        SELECT jsonb_build_object(
		            'generation', deployment_generation,
		            'applicationRevisionId', application_revision_id,
		            'executionTargetId', execution_target_id,
		            'placementDecisionId', placement_decision_id,
		            'observedAt', observed_at,
		            'validUntil', valid_until,
		            'document', document
		        )
		        FROM paas.deployment_runtime_snapshots
		        WHERE tenant_id=$1 AND deployment_id=$2
		    ),
		    'resources', (
		        SELECT jsonb_build_object(
		            'generation', deployment_generation,
		            'applicationRevisionId', application_revision_id,
		            'executionTargetId', execution_target_id,
		            'placementDecisionId', placement_decision_id,
		            'observedAt', observed_at,
		            'validUntil', valid_until,
		            'document', document
		        )
		        FROM paas.deployment_resource_snapshots
		        WHERE tenant_id=$1 AND deployment_id=$2
		    )
		)::text
		`,
		tenantID,
		deploymentID,
	).Scan(&state); err != nil {
		t.Fatal("read compatibility runtime snapshot state")
	}
	return state
}

func assertCompatibilityRuntimeReadable(
	t *testing.T,
	ctx context.Context,
	apiPool *pgxpool.Pool,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
) {
	t.Helper()
	repository, err := NewApplicationRepository(apiPool)
	if err != nil {
		t.Fatal("create compatibility application repository")
	}
	workflow, err := applicationlifecycle.NewUsecase(
		repository,
		applicationlifecycle.Config{MaxTransactionAttempts: 3},
	)
	if err != nil {
		t.Fatal("create compatibility application workflow")
	}
	snapshot, err := workflow.GetDeploymentRuntime(
		ctx,
		integrationAuthorization(
			tenantID,
			paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "runtime-compat-reader"},
			"runtime-compat-read",
		),
		deploymentID,
	)
	if err != nil || snapshot.State != paasv1.MeasurementAvailable ||
		snapshot.Value == nil || len(snapshot.Value.Observation.Instances) != 1 ||
		snapshot.Value.Observation.Instances[0].ID !=
			"instance-fedcba9876543210fedcba9876543210" ||
		snapshot.Resources.State != paasv1.MeasurementAvailable ||
		snapshot.Resources.Value == nil ||
		len(snapshot.Resources.Value.Observation.Instances) != 1 ||
		snapshot.Resources.Value.Observation.Instances[0].ID !=
			"instance-fedcba9876543210fedcba9876543210" {
		t.Fatalf("read compatibility runtime snapshot=%#v err=%v", snapshot, err)
	}
}

func assertFixedPaaSNotReady(
	t *testing.T,
	ctx context.Context,
	binary string,
	temporary string,
	apiDSN string,
) {
	t.Helper()
	const serviceCredential = "mx1.RuntimeCompatibilityPaaSServiceCredential000000001"
	credentialPath := writeCompatibilityFile(
		t,
		temporary,
		"paas-service-credential",
		serviceCredential,
	)
	dsnPath := writeCompatibilityFile(t, temporary, "paas-process-dsn", apiDSN)
	identity := iamv1.ServiceIdentity{
		APIVersion:     iamv1.APIVersion,
		Kind:           "ServiceIdentity",
		InstallationID: "installation-runtime-compat",
		OrganizationID: "organization-runtime-compat",
		PrincipalID:    "principal-runtime-compat-paas",
		Purpose:        iamv1.ServicePaaS,
	}
	var calls atomic.Uint32
	var invalid atomic.Bool
	iamServer := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/service-identity" ||
			request.URL.RawQuery != "" || request.ContentLength > 0 ||
			len(request.TransferEncoding) != 0 ||
			request.Header.Get("Authorization") != "Bearer "+serviceCredential {
			invalid.Store(true)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		calls.Add(1)
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(identity)
	}))
	defer iamServer.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("reserve fixed predecessor PaaS address")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("release fixed predecessor PaaS address")
	}
	processContext, stop := context.WithCancel(ctx)
	command := exec.CommandContext(processContext, binary)
	command.Env = replaceCompatibilityEnvironment([]string{
		"MATRIX_PAAS_DATABASE_DSN_FILE=" + dsnPath,
		"MATRIX_PAAS_IAM_ENDPOINT=" + iamServer.URL,
		"MATRIX_PAAS_SERVICE_CREDENTIAL_FILE=" + credentialPath,
		"MATRIX_PAAS_LISTEN_ADDRESS=" + address,
		"MATRIX_PAAS_INSTALLATION_ID=installation-runtime-compat",
		"MATRIX_PAAS_RELEASE_ID=matrix-v0.3.0-runtime-7",
		"MATRIX_PAAS_VERIFICATION_ARTIFACT_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"MATRIX_PAAS_NODE_CONNECTIONS_FILE=",
	})
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		stop()
		t.Fatal("start fixed predecessor PaaS API")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: time.Second}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(20 * time.Second)
	refused := false
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			"http://"+address+"/ready",
			nil,
		)
		if err != nil {
			break
		}
		response, err := client.Do(request)
		if err == nil {
			var problem paasv1.Problem
			decodeErr := json.NewDecoder(response.Body).Decode(&problem)
			closeErr := response.Body.Close()
			if response.StatusCode == http.StatusServiceUnavailable && decodeErr == nil &&
				closeErr == nil && problem.Status == http.StatusServiceUnavailable &&
				problem.Code == paasv1.ErrorInternal && paasv1.ValidateProblem(problem) == nil {
				refused = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case <-wait:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-wait
	}
	if !refused || invalid.Load() || calls.Load() != 0 {
		t.Fatalf(
			"fixed predecessor PaaS did not reject expanded schema: refused=%v invalidIAM=%v iamCalls=%d",
			refused,
			invalid.Load(),
			calls.Load(),
		)
	}
}
