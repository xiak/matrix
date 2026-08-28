package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	auditauthority "github.com/xiak/matrix/app/service/audit/internal/authority"
	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
	iammigration "github.com/xiak/matrix/app/service/iam/migration"
)

const (
	authorityPostgresIntegrationDSN = "MATRIX_AUTHORITY_POSTGRES_TEST_DSN"

	iamMigratorTestRole      = "matrix_iam_test_migrator"
	iamAPITestRole           = "matrix_iam_test_api"
	iamWorkerTestRole        = "matrix_iam_test_worker"
	auditMigratorTestRole    = "matrix_audit_test_migrator"
	auditRuntimeTestRole     = "matrix_audit_test_runtime"
	authorityTestPassword    = "matrix-authority-gatea-test-only"
	authorityMaximumSequence = int64(9007199254740991)
)

var authorityGroupRoles = []string{
	"matrix_iam_owner",
	"matrix_iam_migrator",
	"matrix_iam_api",
	"matrix_iam_worker",
	"matrix_audit_owner",
	"matrix_audit_migrator",
	"matrix_audit_runtime",
}

func TestPostgresAuthorityIntegration(t *testing.T) {
	dsn := os.Getenv(authorityPostgresIntegrationDSN)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", authorityPostgresIntegrationDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse authority PostgreSQL DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_authority_") {
		t.Fatalf(
			"refusing to mutate database %q; integration database name must start with matrix_authority_",
			adminConfig.Database,
		)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect authority PostgreSQL database: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	assertPostgres18(t, ctx, admin)
	assertCleanAuthoritySchemas(t, ctx, admin)
	applyAuthorityBootstraps(t, ctx, admin)

	ensureAuthorityLoginRole(t, ctx, admin, iamMigratorTestRole, "matrix_iam_migrator")
	ensureAuthorityLoginRole(t, ctx, admin, iamAPITestRole, "matrix_iam_api")
	ensureAuthorityLoginRole(t, ctx, admin, iamWorkerTestRole, "matrix_iam_worker")
	ensureAuthorityLoginRole(t, ctx, admin, auditMigratorTestRole, "matrix_audit_migrator")
	ensureAuthorityLoginRole(t, ctx, admin, auditRuntimeTestRole, "matrix_audit_runtime")

	iamMigrator := openAuthorityConnection(t, ctx, adminConfig, iamMigratorTestRole)
	defer func() { _ = iamMigrator.Close(context.Background()) }()
	auditMigrator := openAuthorityConnection(t, ctx, adminConfig, auditMigratorTestRole)
	defer func() { _ = auditMigrator.Close(context.Background()) }()
	assertLeastPrivilegeLogin(t, ctx, iamMigrator, "matrix_iam_migrator")
	assertLeastPrivilegeLogin(t, ctx, auditMigrator, "matrix_audit_migrator")
	applyAuthorityMigrationsTwice(
		t, ctx, admin, iamMigrator, auditMigrator,
	)

	iamAPI := openAuthorityConnection(t, ctx, adminConfig, iamAPITestRole)
	defer func() { _ = iamAPI.Close(context.Background()) }()
	iamWorker := openAuthorityConnection(t, ctx, adminConfig, iamWorkerTestRole)
	defer func() { _ = iamWorker.Close(context.Background()) }()
	auditRuntime := openAuthorityConnection(t, ctx, adminConfig, auditRuntimeTestRole)
	defer func() { _ = auditRuntime.Close(context.Background()) }()
	assertLeastPrivilegeLogin(t, ctx, iamAPI, "matrix_iam_api")
	assertLeastPrivilegeLogin(t, ctx, iamWorker, "matrix_iam_worker")
	assertLeastPrivilegeLogin(t, ctx, auditRuntime, "matrix_audit_runtime")
	assertAuthorityDatabaseAttackSurface(t, ctx, iamAPI, iamWorker, auditRuntime)

	assertIAMUninitialized(t, ctx, iamAPI)
	fixture := applyIAMBootstrap(t, ctx, admin, iamAPI)
	assertIAMLookupBoundaries(t, ctx, iamAPI, fixture)

	firstClaim := claimIAMOutbox(t, ctx, iamWorker, "worker-a", 1)
	if firstClaim.Attempts != 1 || firstClaim.FencingToken != 1 ||
		firstClaim.LeaseExpiresAt.Sub(firstClaim.ClaimedAt) != time.Second {
		t.Fatalf("first IAM Audit lease = %#v", firstClaim)
	}
	if _, err := iamWorker.Exec(ctx, "SELECT pg_sleep(1.1)"); err != nil {
		t.Fatalf("wait for database lease expiry: %v", err)
	}
	secondClaim := claimIAMOutbox(t, ctx, iamWorker, "worker-b", 2)
	if secondClaim.EventID != firstClaim.EventID || secondClaim.Attempts != 2 ||
		secondClaim.FencingToken != 2 ||
		secondClaim.LeaseExpiresAt.Sub(secondClaim.ClaimedAt) != 2*time.Second {
		t.Fatalf("reclaimed IAM Audit lease = %#v, first = %#v", secondClaim, firstClaim)
	}
	_, err = iamWorker.Exec(
		ctx,
		"SELECT iam.complete_audit_event($1, $2, $3, 'DELIVERED', 0, NULL)",
		firstClaim.EventID,
		firstClaim.WorkerID,
		firstClaim.FencingToken,
	)
	assertAuthorityPostgresCode(t, err, "40001")

	bootstrapEvent := decodeAuthorityEvent(t, secondClaim.EventDocument)
	if firstClaim.InstallationID != fixture.InstallationID || secondClaim.InstallationID != fixture.InstallationID ||
		firstClaim.TenantID != string(bootstrapEvent.TenantID) || bootstrapEvent.InstallationID != "" {
		t.Fatal("tenant outbox claim replaced its physical owner with the sealed installation")
	}
	bootstrapRecord, bootstrapFact := appendAcceptedAuditRecord(
		t, ctx, auditRuntime, auditv1.SourceIAM, bootstrapEvent,
	)
	if bootstrapRecord.Sequence != 1 || bootstrapRecord.PreviousHash != auditauthority.GenesisHash {
		t.Fatalf("bootstrap Audit record = %#v", bootstrapRecord)
	}
	if _, err := iamWorker.Exec(
		ctx,
		"SELECT iam.complete_audit_event($1, $2, $3, 'DELIVERED', 0, NULL)",
		secondClaim.EventID,
		secondClaim.WorkerID,
		secondClaim.FencingToken,
	); err != nil {
		t.Fatalf("complete current IAM Audit lease: %v", err)
	}
	assertIAMOutboxDelivered(t, ctx, admin, secondClaim)

	assertEqualAndChangedAuditReplay(
		t, ctx, auditRuntime, bootstrapRecord, bootstrapFact,
	)
	tenantAEvent := authorityAuditEvent(
		"event-tenant-a-application",
		bootstrapEvent.TenantID,
		"application-a",
		auditv1.ActionPaaSApplicationCreated,
	)
	assertRejectedAuditAppend(
		t,
		ctx,
		auditRuntime,
		auditv1.SourcePaaS,
		tenantAEvent,
		func(submission *auditSubmission) {
			submission.Record.RecordHash = authorityDigest("forged-record-hash")
		},
		"22023",
	)
	assertRejectedAuditAppend(
		t,
		ctx,
		auditRuntime,
		auditv1.SourcePaaS,
		tenantAEvent,
		func(submission *auditSubmission) {
			var document map[string]any
			if err := json.Unmarshal([]byte(submission.EventDocument), &document); err != nil {
				t.Fatalf("decode Audit canonical mismatch document: %v", err)
			}
			document["requestId"] = "request-forged"
			submission.EventDocument = authorityJSON(t, document)
		},
		"22023",
	)
	assertRejectedAuditAppend(
		t,
		ctx,
		auditRuntime,
		auditv1.SourcePaaS,
		tenantAEvent,
		func(submission *auditSubmission) {
			var document map[string]any
			if err := json.Unmarshal([]byte(submission.EventDocument), &document); err != nil {
				t.Fatalf("decode Audit attack document: %v", err)
			}
			document["payload"] = "forbidden"
			submission.EventDocument = authorityJSON(t, document)
		},
		"22023",
	)
	assertRejectedAuditAppend(
		t,
		ctx,
		auditRuntime,
		auditv1.SourcePaaS,
		tenantAEvent,
		func(submission *auditSubmission) {
			submission.Source = auditv1.SourceIAM
		},
		"22023",
	)
	tenantARecord, _ := appendAcceptedAuditRecord(
		t, ctx, auditRuntime, auditv1.SourcePaaS, tenantAEvent,
	)
	if tenantARecord.Sequence != 2 || tenantARecord.PreviousHash != bootstrapRecord.RecordHash {
		t.Fatalf("second tenant A Audit record = %#v", tenantARecord)
	}

	tenantBEvent := authorityAuditEvent(
		"event-tenant-b-application",
		"organization-b",
		"application-b",
		auditv1.ActionPaaSApplicationCreated,
	)
	tenantBRecord, _ := appendAcceptedAuditRecord(
		t, ctx, auditRuntime, auditv1.SourcePaaS, tenantBEvent,
	)
	if tenantBRecord.Sequence != 1 || tenantBRecord.PreviousHash != auditauthority.GenesisHash {
		t.Fatalf("tenant B Audit record = %#v", tenantBRecord)
	}
	assertAuditContractCatalog(t, ctx, auditRuntime, auditMigrator)
	assertStoredAuditChains(t, ctx, auditRuntime, bootstrapEvent.TenantID)
	assertForcedTenantIsolation(
		t, ctx, iamMigrator, auditMigrator, bootstrapEvent.TenantID,
	)
	assertAuditImmutability(t, ctx, auditMigrator, bootstrapEvent.TenantID)
	assertIAMSessionDatabaseTime(t, ctx, admin, iamAPI, fixture)
	assertIAMAuthorizationCatalog(t, ctx, admin, iamAPI, fixture)
}

func assertAuditContractCatalog(
	t *testing.T,
	ctx context.Context,
	runtimeConnection *pgx.Conn,
	migrator *pgx.Conn,
) {
	t.Helper()
	for index, action := range auditv1.AllActions() {
		contract, known := auditv1.ContractForAction(action)
		if !known {
			t.Fatalf("Audit action %q has no contract", action)
		}
		event := authorityAuditEvent(
			fmt.Sprintf("event-catalog-%d", index),
			auditv1.TenantID(fmt.Sprintf("organization-catalog-%d", index)),
			fmt.Sprintf("target-catalog-%d", index),
			action,
		)
		record, _ := appendAcceptedAuditRecord(
			t, ctx, runtimeConnection, contract.Source, event,
		)
		if record.Sequence != 1 || record.PreviousHash != auditauthority.GenesisHash {
			t.Fatalf("Audit catalog action %q record = %#v", action, record)
		}
		var matched int
		if err := runtimeConnection.QueryRow(ctx,
			"SELECT count(*) FROM audit.read_records($1,$2,2,NULL,NULL,$3,NULL,NULL) WHERE event_id=$4",
			string(auditauthority.ChainFor(event.TenantID, event.InstallationID)), authorityMaximumSequence+1,
			string(action), string(event.EventID)).Scan(&matched); err != nil || matched != 1 {
			t.Fatalf("Audit catalog action %q cannot be queried: matches=%d error=%v", action, matched, err)
		}
		// Exercise the database's closed target shape independently of canonical
		// hash mismatch rejection. The authorized migration identity only calls
		// validation here; no invalid record is inserted or encoder duplicated.
		forgedTarget := event
		if action == auditv1.ActionIAMTenantAdministratorRecovered {
			forgedTarget.Target.TenantID = ""
		} else {
			forgedTarget.Target.TenantID = "organization-forged"
		}
		tx, err := migrator.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_audit_owner"); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, "SELECT audit.assert_event($1,$2,$3,$4::jsonb)", contract.Source, event.EventID, string(auditauthority.ChainFor(event.TenantID, event.InstallationID)), authorityJSON(t, forgedTarget))
		_ = tx.Rollback(ctx)
		assertAuthorityPostgresCode(t, err, "22023")
		if contract.PlatformOnly {
			for _, mutation := range []string{"both", "tenant", "actor", "installation"} {
				candidate := event
				candidate.EventID += auditv1.EventID("-" + mutation)
				candidate.OperationID = auditv1.OperationID("operation-" + string(candidate.EventID))
				if !contract.OperationRequired {
					candidate.OperationID = ""
				}
				assertRejectedAuditAppend(t, ctx, runtimeConnection, contract.Source, candidate, func(submission *auditSubmission) {
					forged := candidate
					switch mutation {
					case "both":
						forged.TenantID = auditv1.TenantID(forged.InstallationID)
					case "tenant":
						forged.TenantID, forged.InstallationID = auditv1.TenantID(forged.InstallationID), ""
					case "actor":
						forged.Actor.Type = auditv1.ActorSystem
					case "installation":
						forged.InstallationID = "other-installation"
					}
					submission.EventDocument = authorityJSON(t, forged)
				}, "22023")
			}
		}
	}
}

func TestAuditRetainedTenantPartitionUpgrade(t *testing.T) {
	const variable = "MATRIX_AUDIT_UPGRADE_POSTGRES_TEST_DSN"
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
	if !strings.HasPrefix(config.Database, "matrix_audit_upgrade_") {
		t.Fatal("upgrade fixture requires a dedicated matrix_audit_upgrade_ database")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertPostgres18(t, ctx, admin)
	assertCleanAuthoritySchemas(t, ctx, admin)
	if err := auditmigration.Bootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	ensureAuthorityLoginRole(t, ctx, admin, auditMigratorTestRole, "matrix_audit_migrator")
	ensureAuthorityLoginRole(t, ctx, admin, auditRuntimeTestRole, "matrix_audit_runtime")
	migrator := openAuthorityConnection(t, ctx, config, auditMigratorTestRole)
	defer func() { _ = migrator.Close(context.Background()) }()
	runtimeConnection := openAuthorityConnection(t, ctx, config, auditRuntimeTestRole)
	defer func() { _ = runtimeConnection.Close(context.Background()) }()

	// Git owns the superseded schema. This opt-in upgrade gate executes the
	// accepted fixed baseline, without keeping a second DDL implementation.
	baseline, err := exec.CommandContext(ctx, "git", "show",
		"9fd45b03ea398828fa3e74bf99961d2348c68299:app/service/audit/internal/data/postgres/migrations/000001_authority/up.sql").Output()
	if err != nil {
		t.Fatalf("read fixed pre-partition Audit migration: %v", err)
	}
	if _, err := migrator.Exec(ctx, string(baseline)); err != nil {
		t.Fatalf("apply fixed baseline: %v", err)
	}
	event := authorityAuditEvent("event-retained", "shared-authority", "application-retained", auditv1.ActionPaaSApplicationCreated)
	tx, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var sequence int64
	var previousHash string
	var ingestedAt time.Time
	if err := tx.QueryRow(ctx, "SELECT * FROM audit.lock_tenant_head($1)", string(event.TenantID)).Scan(&sequence, &previousHash, &ingestedAt); err != nil {
		t.Fatal(err)
	}
	retained, fact, err := auditauthority.AppendRecord(auditauthority.Checkpoint{
		ChainID: auditauthority.TenantChain(event.TenantID), Sequence: uint64(sequence), RecordHash: previousHash,
	}, uint64(sequence+1), auditv1.SourcePaaS, event, ingestedAt.UTC())
	if err != nil {
		t.Fatal(err)
	}
	var outcome, storedHash string
	var storedSequence int64
	if err := tx.QueryRow(ctx, `SELECT * FROM audit.append_record($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10)`,
		string(retained.Source), string(event.EventID), string(event.TenantID), int64(retained.Sequence),
		authorityJSON(t, event), fact.Document, fact.ContentDigest, retained.PreviousHash, retained.RecordHash, retained.IngestedAt,
	).Scan(&outcome, &storedSequence, &storedHash); err != nil || outcome != "ACCEPTED" || storedHash != retained.RecordHash {
		t.Fatalf("seed immutable retained record through old SQL API: outcome=%s err=%v", outcome, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var beforeDocument, beforeCanonical, beforeDigest, beforeHash string
	if err := admin.QueryRow(ctx, `SELECT event_document::text, canonical_document, content_digest, record_hash
		FROM audit.records WHERE tenant_id=$1 AND sequence=1`, string(event.TenantID)).Scan(
		&beforeDocument, &beforeCanonical, &beforeDigest, &beforeHash); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := auditmigration.Up(ctx, migrator); err != nil {
			t.Fatalf("upgrade attempt %d: %v", attempt+1, err)
		}
		if err := auditmigration.Verify(ctx, migrator); err != nil {
			t.Fatalf("verify upgrade: %v", err)
		}
	}
	var afterDocument, afterCanonical, afterDigest, afterHash string
	if err := admin.QueryRow(ctx, `SELECT event_document::text, canonical_document, content_digest, record_hash
		FROM audit.records WHERE tenant_id=$1 AND sequence=1`, string(event.TenantID)).Scan(
		&afterDocument, &afterCanonical, &afterDigest, &afterHash); err != nil {
		t.Fatal(err)
	}
	if beforeDocument != afterDocument || beforeCanonical != afterCanonical || beforeDigest != afterDigest || beforeHash != afterHash {
		t.Fatal("upgrade rewrote immutable Audit content or hashes")
	}
	retainedRows := readAuditRecords(t, ctx, runtimeConnection, event.TenantID)
	if len(retainedRows) != 1 || retainedRows[0] != retained {
		t.Fatal("upgraded tenant record differs")
	}
	genesis, _ := auditauthority.GenesisCheckpoint(auditauthority.TenantChain(event.TenantID))
	if _, err := auditauthority.VerifyChain(genesis, retainedRows); err != nil {
		t.Fatal(err)
	}
	assertEqualAndChangedAuditReplay(t, ctx, runtimeConnection, retained, fact)

	platformEvent := authorityAuditEvent("event-new-platform", event.TenantID, "execution-pool-upgrade", auditv1.ActionPaaSExecutionPoolCreated)
	platformEvent.OperationID = event.OperationID
	platformRecord, _ := appendAcceptedAuditRecord(t, ctx, runtimeConnection, auditv1.SourcePaaS, platformEvent)
	platformRows := readAuditChainRecords(t, ctx, runtimeConnection, auditauthority.InstallationChain(string(event.TenantID)))
	if len(platformRows) != 1 || platformRows[0] != platformRecord || platformRecord.Sequence != 1 ||
		platformRecord.Event.TenantID != "" || len(readAuditRecords(t, ctx, runtimeConnection, event.TenantID)) != 1 {
		t.Fatal("equal tenant/installation IDs or Operations shared a storage partition")
	}
	for _, chain := range []auditauthority.ChainID{auditauthority.TenantChain(event.TenantID), auditauthority.InstallationChain(string(event.TenantID))} {
		if count := ownerTenantCount(t, ctx, migrator, "matrix_audit_owner", "matrix.audit_chain_id", "audit.records", string(chain)); count != 1 {
			t.Fatalf("forced RLS for %s returned %d rows", chain, count)
		}
	}
	if count := ownerTenantCount(t, ctx, migrator, "matrix_audit_owner", "matrix.audit_chain_id", "audit.records", string(event.TenantID)); count != 0 {
		t.Fatal("unnamespaced authority bypassed RLS")
	}
	assertAuditImmutability(t, ctx, migrator, event.TenantID)
}

func assertPostgres18(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	var encoded string
	if err := connection.QueryRow(ctx, "SHOW server_version_num").Scan(&encoded); err != nil {
		t.Fatalf("read PostgreSQL version: %v", err)
	}
	version, err := strconv.Atoi(encoded)
	if err != nil || version < 180000 || version >= 190000 {
		t.Fatalf("PostgreSQL server_version_num = %q, want major 18", encoded)
	}
}

func assertCleanAuthoritySchemas(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var iamExists, auditExists bool
	if err := admin.QueryRow(
		ctx,
		"SELECT to_regnamespace('iam') IS NOT NULL, to_regnamespace('audit') IS NOT NULL",
	).Scan(&iamExists, &auditExists); err != nil {
		t.Fatalf("inspect authority schemas: %v", err)
	}
	if iamExists || auditExists {
		t.Fatalf("authority integration database is not clean: iam=%t audit=%t", iamExists, auditExists)
	}
}

func applyAuthorityBootstraps(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
) {
	t.Helper()
	for attempt := 1; attempt <= 2; attempt++ {
		if err := iammigration.Bootstrap(ctx, admin); err != nil {
			t.Fatalf("apply IAM PostgreSQL bootstrap attempt %d: %v", attempt, err)
		}
		if err := auditmigration.Bootstrap(ctx, admin); err != nil {
			t.Fatalf("apply Audit PostgreSQL bootstrap attempt %d: %v", attempt, err)
		}
	}
}

func applyAuthorityMigrationsTwice(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	iamMigrator *pgx.Conn,
	auditMigrator *pgx.Conn,
) {
	t.Helper()
	for attempt := 1; attempt <= 2; attempt++ {
		if err := iammigration.Up(ctx, iamMigrator); err != nil {
			t.Fatalf("apply IAM authority migration as non-superuser attempt %d: %v", attempt, err)
		}
		if err := auditmigration.Up(ctx, auditMigrator); err != nil {
			t.Fatalf("apply Audit authority migration as non-superuser attempt %d: %v", attempt, err)
		}
	}
	if err := iammigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify IAM authority migration: %v", err)
	}
	if err := auditmigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify Audit authority migration: %v", err)
	}
}

func ensureAuthorityLoginRole(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	roleName string,
	groupName string,
) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)",
		roleName,
	).Scan(&exists); err != nil {
		t.Fatalf("inspect authority test role %s: %v", roleName, err)
	}
	roleIdentifier := pgx.Identifier{roleName}.Sanitize()
	passwordLiteral := postgresLiteral(authorityTestPassword)
	verb := "CREATE ROLE"
	if exists {
		verb = "ALTER ROLE"
	}
	statement := fmt.Sprintf(
		"%s %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "+
			"NOREPLICATION NOBYPASSRLS PASSWORD %s",
		verb,
		roleIdentifier,
		passwordLiteral,
	)
	if _, err := admin.Exec(ctx, statement); err != nil {
		t.Fatalf("configure authority test role %s: %v", roleName, err)
	}
	for _, candidate := range authorityGroupRoles {
		var direct bool
		if err := admin.QueryRow(
			ctx,
			`SELECT EXISTS (
				SELECT 1
				  FROM pg_catalog.pg_auth_members AS membership
				  JOIN pg_catalog.pg_roles AS parent ON parent.oid = membership.roleid
				  JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
				 WHERE parent.rolname = $1 AND member.rolname = $2
			)`,
			candidate,
			roleName,
		).Scan(&direct); err != nil {
			t.Fatalf("inspect %s membership in %s: %v", roleName, candidate, err)
		}
		if direct {
			if _, err := admin.Exec(
				ctx,
				fmt.Sprintf(
					"REVOKE %s FROM %s",
					pgx.Identifier{candidate}.Sanitize(),
					roleIdentifier,
				),
			); err != nil {
				t.Fatalf("revoke stale %s membership from %s: %v", candidate, roleName, err)
			}
		}
	}
	if _, err := admin.Exec(
		ctx,
		fmt.Sprintf(
			"GRANT %s TO %s",
			pgx.Identifier{groupName}.Sanitize(),
			roleIdentifier,
		),
	); err != nil {
		t.Fatalf("grant %s to %s: %v", groupName, roleName, err)
	}
}

func openAuthorityConnection(
	t *testing.T,
	ctx context.Context,
	adminConfig *pgx.ConnConfig,
	roleName string,
) *pgx.Conn {
	t.Helper()
	config := adminConfig.Copy()
	config.User = roleName
	config.Password = authorityTestPassword
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect as %s: %v", roleName, err)
	}
	return connection
}

func assertLeastPrivilegeLogin(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	expectedGroup string,
) {
	t.Helper()
	var currentUser string
	var canLogin, superuser, createDatabase, createRole, replication, bypassRLS bool
	if err := connection.QueryRow(
		ctx,
		`SELECT current_user, role.rolcanlogin, role.rolsuper,
			   role.rolcreatedb, role.rolcreaterole, role.rolreplication,
			   role.rolbypassrls
		  FROM pg_catalog.pg_roles AS role
		 WHERE role.rolname = current_user`,
	).Scan(
		&currentUser,
		&canLogin,
		&superuser,
		&createDatabase,
		&createRole,
		&replication,
		&bypassRLS,
	); err != nil {
		t.Fatalf("inspect authority login: %v", err)
	}
	if !canLogin || superuser || createDatabase || createRole || replication || bypassRLS {
		t.Fatalf(
			"authority login %s is overprivileged: login=%t super=%t db=%t role=%t replication=%t bypassRLS=%t",
			currentUser,
			canLogin,
			superuser,
			createDatabase,
			createRole,
			replication,
			bypassRLS,
		)
	}
	var member bool
	if err := connection.QueryRow(
		ctx,
		"SELECT pg_has_role(current_user, $1, 'MEMBER')",
		expectedGroup,
	).Scan(&member); err != nil {
		t.Fatalf("inspect authority login group %s: %v", expectedGroup, err)
	}
	if !member {
		t.Fatalf("authority login %s is not a member of %s", currentUser, expectedGroup)
	}
}

func assertAuthorityDatabaseAttackSurface(
	t *testing.T,
	ctx context.Context,
	iamAPI *pgx.Conn,
	iamWorker *pgx.Conn,
	auditRuntime *pgx.Conn,
) {
	t.Helper()
	var count int
	err := iamAPI.QueryRow(ctx, "SELECT count(*) FROM iam.organizations").Scan(&count)
	assertAuthorityPostgresCode(t, err, "42501")
	_, err = iamAPI.Exec(ctx, "SET ROLE matrix_iam_owner")
	assertAuthorityPostgresCode(t, err, "42501")
	err = iamAPI.QueryRow(
		ctx,
		"SELECT count(*) FROM audit.lookup_record('IAM', 'event-never')",
	).Scan(&count)
	assertAuthorityPostgresCode(t, err, "42501")

	err = iamWorker.QueryRow(ctx, "SELECT count(*) FROM iam.audit_outbox").Scan(&count)
	assertAuthorityPostgresCode(t, err, "42501")
	_, err = iamWorker.Exec(ctx, "SET ROLE matrix_iam_owner")
	assertAuthorityPostgresCode(t, err, "42501")

	err = auditRuntime.QueryRow(ctx, "SELECT count(*) FROM audit.records").Scan(&count)
	assertAuthorityPostgresCode(t, err, "42501")
	_, err = auditRuntime.Exec(ctx, "SET ROLE matrix_audit_owner")
	assertAuthorityPostgresCode(t, err, "42501")
	err = auditRuntime.QueryRow(
		ctx,
		"SELECT count(*) FROM iam.lookup_login('admin')",
	).Scan(&count)
	assertAuthorityPostgresCode(t, err, "42501")
	var digest string
	err = auditRuntime.QueryRow(
		ctx,
		`SELECT audit.calculate_record_hash(
			'organization-a', 1,
			'sha256:1111111111111111111111111111111111111111111111111111111111111111',
			'sha256:0000000000000000000000000000000000000000000000000000000000000000',
			transaction_timestamp(), 'INDEFINITE'
		)`,
	).Scan(&digest)
	assertAuthorityPostgresCode(t, err, "42501")
}

type iamBootstrapService struct {
	Purpose            string `json:"purpose"`
	PrincipalID        string `json:"principalId"`
	LookupDigest       string `json:"lookupDigest"`
	VerificationDigest string `json:"verificationDigest"`
}

type iamBootstrapFixture struct {
	InstallationID string
	ContentDigest  string
	TenantID       auditv1.TenantID
	Administrator  string
	LoginName      string
	PasswordHash   string
	Services       []iamBootstrapService
	AuditEvent     auditv1.Event
}

func applyIAMBootstrap(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	iamAPI *pgx.Conn,
) iamBootstrapFixture {
	t.Helper()
	fixture := iamBootstrapFixture{
		InstallationID: "installation-gatea",
		ContentDigest:  authorityDigest("exact-bootstrap-document"),
		TenantID:       "organization-a",
		Administrator:  "principal-admin",
		LoginName:      "admin",
		PasswordHash: "$matrix-iam-v1$argon2id$v=19$m=65536,t=3,p=1$" +
			strings.Repeat("A", 22) + "$" + strings.Repeat("A", 43),
	}
	for _, purpose := range iamv1.AllServicePurposes() {
		purposeText := string(purpose)
		fixture.Services = append(fixture.Services, iamBootstrapService{
			Purpose:            purposeText,
			PrincipalID:        "service-" + strings.ToLower(strings.ReplaceAll(purposeText, "_", "-")),
			LookupDigest:       authorityDigest("lookup-" + purposeText),
			VerificationDigest: authorityDigest("verify-" + purposeText),
		})
	}
	fixture.AuditEvent = authorityAuditEvent(
		"event-bootstrap",
		fixture.TenantID,
		fixture.InstallationID,
		auditv1.ActionIAMBootstrapApplied,
	)
	services := authorityJSON(t, fixture.Services)
	apply := func(contentDigest string) (string, auditv1.Event, error) {
		tx, err := iamAPI.Begin(ctx)
		if err != nil {
			return "", auditv1.Event{}, err
		}
		var databaseTime time.Time
		if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&databaseTime); err != nil {
			_ = tx.Rollback(context.Background())
			return "", auditv1.Event{}, err
		}
		event := fixture.AuditEvent
		event.OccurredAt = databaseTime.UTC()
		var outcome string
		err = tx.QueryRow(
			ctx,
			`SELECT iam.apply_bootstrap(
				$1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb
			)`,
			fixture.InstallationID,
			contentDigest,
			string(fixture.TenantID),
			"Organization A",
			fixture.Administrator,
			fixture.LoginName,
			"Initial Administrator",
			fixture.PasswordHash,
			services,
			authorityJSON(t, event),
		).Scan(&outcome)
		if err != nil {
			_ = tx.Rollback(context.Background())
			return "", auditv1.Event{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", auditv1.Event{}, err
		}
		return outcome, event, nil
	}
	outcome, appliedEvent, err := apply(fixture.ContentDigest)
	if err != nil || outcome != "APPLIED" {
		t.Fatalf("apply IAM bootstrap: outcome=%q err=%v", outcome, err)
	}
	fixture.AuditEvent = appliedEvent
	outcome, _, err = apply(fixture.ContentDigest)
	if err != nil || outcome != "EQUAL_REPLAY" {
		t.Fatalf("replay equal IAM bootstrap: outcome=%q err=%v", outcome, err)
	}
	_, _, err = apply(authorityDigest("changed-bootstrap-document"))
	assertAuthorityPostgresCode(t, err, "23505")

	var receiptCount, organizationCount, outboxCount int
	if err := admin.QueryRow(
		ctx,
		`SELECT
			(SELECT count(*) FROM iam.bootstrap_receipts),
			(SELECT count(*) FROM iam.organizations),
			(SELECT count(*) FROM iam.audit_outbox)`,
	).Scan(&receiptCount, &organizationCount, &outboxCount); err != nil {
		t.Fatalf("inspect applied IAM bootstrap: %v", err)
	}
	if receiptCount != 1 || organizationCount != 1 || outboxCount != 1 {
		t.Fatalf(
			"IAM bootstrap cardinality receipt=%d organization=%d outbox=%d",
			receiptCount,
			organizationCount,
			outboxCount,
		)
	}
	return fixture
}

func assertIAMLookupBoundaries(
	t *testing.T,
	ctx context.Context,
	iamAPI *pgx.Conn,
	fixture iamBootstrapFixture,
) {
	t.Helper()
	var state string
	var installationID, organizationID, contentDigest string
	var appliedAt time.Time
	if err := iamAPI.QueryRow(ctx, "SELECT * FROM iam.bootstrap_status()").Scan(
		&state,
		&installationID,
		&organizationID,
		&contentDigest,
		&appliedAt,
	); err != nil {
		t.Fatalf("read ready IAM bootstrap status: %v", err)
	}
	if state != "READY" || installationID != fixture.InstallationID ||
		organizationID != string(fixture.TenantID) || contentDigest != fixture.ContentDigest ||
		appliedAt.IsZero() {
		t.Fatalf(
			"IAM bootstrap status state=%q installation=%q organization=%q digest=%q applied=%s",
			state,
			installationID,
			organizationID,
			contentDigest,
			appliedAt,
		)
	}
	var ready bool
	var schemaVersion int64
	var checkedAt time.Time
	if err := iamAPI.QueryRow(ctx, "SELECT * FROM iam.readiness()").Scan(
		&ready,
		&schemaVersion,
		&checkedAt,
	); err != nil {
		t.Fatalf("read IAM readiness: %v", err)
	}
	if !ready || schemaVersion != 3 || checkedAt.IsZero() {
		t.Fatalf("IAM readiness ready=%t schema=%d checked=%s", ready, schemaVersion, checkedAt)
	}
	var tenantID, principalID, passwordHash, organizationStatus, principalStatus string
	var mustChangePassword bool
	if err := iamAPI.QueryRow(
		ctx,
		"SELECT * FROM iam.lookup_login($1)",
		fixture.LoginName,
	).Scan(
		&tenantID,
		&principalID,
		&passwordHash,
		&organizationStatus,
		&principalStatus,
		&mustChangePassword,
	); err != nil {
		t.Fatalf("lookup IAM login: %v", err)
	}
	if tenantID != string(fixture.TenantID) || principalID != fixture.Administrator ||
		passwordHash != fixture.PasswordHash || organizationStatus != "ACTIVE" ||
		principalStatus != "ACTIVE" || !mustChangePassword {
		t.Fatalf(
			"IAM login lookup tenant=%q principal=%q organization=%q principalStatus=%q mustChange=%t",
			tenantID,
			principalID,
			organizationStatus,
			principalStatus,
			mustChangePassword,
		)
	}
	for _, service := range fixture.Services {
		var purpose, verificationDigest, installationID string
		if err := iamAPI.QueryRow(
			ctx,
			"SELECT * FROM iam.lookup_service($1)",
			service.LookupDigest,
		).Scan(&tenantID, &principalID, &purpose, &verificationDigest, &installationID); err != nil {
			t.Fatalf("lookup IAM %s service credential: %v", service.Purpose, err)
		}
		if tenantID != string(fixture.TenantID) || principalID != service.PrincipalID ||
			purpose != service.Purpose || verificationDigest != service.VerificationDigest || installationID != fixture.InstallationID {
			t.Fatalf(
				"IAM service lookup tenant=%q principal=%q purpose=%q digest=%q",
				tenantID,
				principalID,
				purpose,
				verificationDigest,
			)
		}
	}
}

func assertIAMUninitialized(t *testing.T, ctx context.Context, iamAPI *pgx.Conn) {
	t.Helper()
	var state string
	var installationID, organizationID, contentDigest *string
	var appliedAt *time.Time
	if err := iamAPI.QueryRow(ctx, "SELECT * FROM iam.bootstrap_status()").Scan(
		&state,
		&installationID,
		&organizationID,
		&contentDigest,
		&appliedAt,
	); err != nil {
		t.Fatalf("read uninitialized IAM bootstrap status: %v", err)
	}
	if state != "UNINITIALIZED" || installationID != nil || organizationID != nil ||
		contentDigest != nil || appliedAt != nil {
		t.Fatalf("uninitialized IAM bootstrap status contains initialized authority")
	}
	var ready bool
	var schemaVersion int64
	var checkedAt time.Time
	if err := iamAPI.QueryRow(ctx, "SELECT * FROM iam.readiness()").Scan(
		&ready,
		&schemaVersion,
		&checkedAt,
	); err != nil {
		t.Fatalf("read uninitialized IAM readiness: %v", err)
	}
	if ready || schemaVersion != 3 || checkedAt.IsZero() {
		t.Fatalf("uninitialized IAM readiness ready=%t schema=%d checked=%s", ready, schemaVersion, checkedAt)
	}
}

type iamOutboxClaim struct {
	TenantID       string
	InstallationID string
	EventID        string
	EventDocument  string
	Attempts       int
	FencingToken   int64
	LeaseExpiresAt time.Time
	ClaimedAt      time.Time
	WorkerID       string
}

func claimIAMOutbox(
	t *testing.T,
	ctx context.Context,
	worker *pgx.Conn,
	workerID string,
	leaseSeconds int,
) iamOutboxClaim {
	t.Helper()
	claim := iamOutboxClaim{WorkerID: workerID}
	if err := worker.QueryRow(
		ctx,
		`SELECT claimed.tenant_id, claimed.event_id, claimed.event_document,
			   claimed.attempts, claimed.fencing_token,
			   claimed.lease_expires_at, transaction_timestamp(), claimed.installation_id
		  FROM iam.claim_audit_event($1, $2) AS claimed`,
		workerID,
		leaseSeconds,
	).Scan(
		&claim.TenantID,
		&claim.EventID,
		&claim.EventDocument,
		&claim.Attempts,
		&claim.FencingToken,
		&claim.LeaseExpiresAt,
		&claim.ClaimedAt,
		&claim.InstallationID,
	); err != nil {
		t.Fatalf("claim IAM Audit outbox event: %v", err)
	}
	claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
	claim.ClaimedAt = claim.ClaimedAt.UTC()
	return claim
}

func assertIAMOutboxDelivered(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	claim iamOutboxClaim,
) {
	t.Helper()
	var status string
	var attempts int
	var fencingToken int64
	var workerID *string
	var leaseExpiresAt *time.Time
	if err := admin.QueryRow(
		ctx,
		`SELECT status, attempts, fencing_token, worker_id, lease_expires_at
		   FROM iam.audit_outbox
		  WHERE tenant_id = $1 AND event_id = $2`,
		claim.TenantID,
		claim.EventID,
	).Scan(&status, &attempts, &fencingToken, &workerID, &leaseExpiresAt); err != nil {
		t.Fatalf("inspect delivered IAM Audit outbox event: %v", err)
	}
	if status != "DELIVERED" || attempts != claim.Attempts ||
		fencingToken != claim.FencingToken || workerID != nil || leaseExpiresAt != nil {
		t.Fatalf(
			"delivered IAM Audit outbox status=%q attempts=%d fence=%d worker=%v lease=%v",
			status,
			attempts,
			fencingToken,
			workerID,
			leaseExpiresAt,
		)
	}
}

type auditSubmission struct {
	Source        auditv1.Source
	Record        auditv1.AuditRecord
	Fact          auditauthority.CanonicalFact
	EventDocument string
}

func prepareAuditSubmission(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	source auditv1.Source,
	event auditv1.Event,
) auditSubmission {
	t.Helper()
	var lastSequence int64
	var lastRecordHash string
	var ingestedAt time.Time
	if err := tx.QueryRow(
		ctx,
		"SELECT * FROM audit.lock_chain_head($1)",
		string(auditauthority.ChainFor(event.TenantID, event.InstallationID)),
	).Scan(&lastSequence, &lastRecordHash, &ingestedAt); err != nil {
		t.Fatalf("lock Audit tenant head: %v", err)
	}
	ingestedAt = ingestedAt.UTC()
	record, fact, err := auditauthority.AppendRecord(
		auditauthority.Checkpoint{
			ChainID:    auditauthority.ChainFor(event.TenantID, event.InstallationID),
			Sequence:   uint64(lastSequence),
			RecordHash: lastRecordHash,
		},
		uint64(lastSequence+1),
		source,
		event,
		ingestedAt,
	)
	if err != nil {
		t.Fatalf("prepare Audit authority record: %v", err)
	}
	return auditSubmission{
		Source:        source,
		Record:        record,
		Fact:          fact,
		EventDocument: authorityJSON(t, event),
	}
}

func appendAcceptedAuditRecord(
	t *testing.T,
	ctx context.Context,
	runtimeConnection *pgx.Conn,
	source auditv1.Source,
	event auditv1.Event,
) (auditv1.AuditRecord, auditauthority.CanonicalFact) {
	t.Helper()
	tx, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Audit append transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	submission := prepareAuditSubmission(t, ctx, tx, source, event)
	outcome, storedSequence, storedRecordHash, err := submitAuditRecord(ctx, tx, submission)
	if err != nil {
		t.Fatalf("append Audit record: %v", err)
	}
	if outcome != "ACCEPTED" || storedSequence != submission.Record.Sequence ||
		storedRecordHash != submission.Record.RecordHash {
		t.Fatalf(
			"Audit append outcome=%q sequence=%d hash=%q record=%#v",
			outcome,
			storedSequence,
			storedRecordHash,
			submission.Record,
		)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit Audit append: %v", err)
	}
	return submission.Record, submission.Fact
}

func assertRejectedAuditAppend(
	t *testing.T,
	ctx context.Context,
	runtimeConnection *pgx.Conn,
	source auditv1.Source,
	event auditv1.Event,
	mutate func(*auditSubmission),
	postgresCode string,
) {
	t.Helper()
	tx, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin rejected Audit append transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	submission := prepareAuditSubmission(t, ctx, tx, source, event)
	mutate(&submission)
	_, _, _, err = submitAuditRecord(ctx, tx, submission)
	assertAuthorityPostgresCode(t, err, postgresCode)
}

type authorityQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func submitAuditRecord(
	ctx context.Context,
	querier authorityQueryRower,
	submission auditSubmission,
) (string, uint64, string, error) {
	var outcome string
	var storedSequence int64
	var storedRecordHash string
	err := querier.QueryRow(
		ctx,
		`SELECT * FROM audit.append_record(
			$1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10
		)`,
		string(submission.Source),
		string(submission.Record.Event.EventID),
		string(auditauthority.ChainFor(submission.Record.Event.TenantID, submission.Record.Event.InstallationID)),
		int64(submission.Record.Sequence),
		submission.EventDocument,
		submission.Fact.Document,
		submission.Fact.ContentDigest,
		submission.Record.PreviousHash,
		submission.Record.RecordHash,
		submission.Record.IngestedAt,
	).Scan(&outcome, &storedSequence, &storedRecordHash)
	return outcome, uint64(storedSequence), storedRecordHash, err
}

func assertEqualAndChangedAuditReplay(
	t *testing.T,
	ctx context.Context,
	runtimeConnection *pgx.Conn,
	record auditv1.AuditRecord,
	fact auditauthority.CanonicalFact,
) {
	t.Helper()
	submission := auditSubmission{
		Source:        record.Source,
		Record:        record,
		Fact:          fact,
		EventDocument: authorityJSON(t, record.Event),
	}
	outcome, storedSequence, storedRecordHash, err := submitAuditRecord(
		ctx,
		runtimeConnection,
		submission,
	)
	if err != nil || outcome != "DUPLICATE" || storedSequence != record.Sequence ||
		storedRecordHash != record.RecordHash {
		t.Fatalf(
			"equal Audit replay outcome=%q sequence=%d hash=%q err=%v",
			outcome,
			storedSequence,
			storedRecordHash,
			err,
		)
	}
	changed := record.Event
	changed.RequestDigest = authorityDigest("changed-replay-content")
	submission.EventDocument = authorityJSON(t, changed)
	_, _, _, err = submitAuditRecord(ctx, runtimeConnection, submission)
	assertAuthorityPostgresCode(t, err, "23505")
	changedFact, err := auditauthority.Canonicalize(record.Source, changed)
	if err != nil {
		t.Fatalf("canonicalize changed Audit replay: %v", err)
	}
	submission.EventDocument = authorityJSON(t, changed)
	submission.Fact = changedFact
	_, _, _, err = submitAuditRecord(ctx, runtimeConnection, submission)
	assertAuthorityPostgresCode(t, err, "23505")
}

func assertStoredAuditChains(
	t *testing.T,
	ctx context.Context,
	runtimeConnection *pgx.Conn,
	tenantA auditv1.TenantID,
) {
	t.Helper()
	tenantARecords := readAuditRecords(t, ctx, runtimeConnection, tenantA)
	if len(tenantARecords) != 2 || tenantARecords[0].Sequence != 2 ||
		tenantARecords[1].Sequence != 1 {
		t.Fatalf("tenant A descending Audit records = %#v", tenantARecords)
	}
	ascending := []auditv1.AuditRecord{tenantARecords[1], tenantARecords[0]}
	genesis, err := auditauthority.GenesisCheckpoint(auditauthority.TenantChain(tenantA))
	if err != nil {
		t.Fatalf("create tenant A Audit genesis: %v", err)
	}
	checkpoint, err := auditauthority.VerifyChain(genesis, ascending)
	if err != nil || checkpoint.Sequence != 2 ||
		checkpoint.RecordHash != tenantARecords[0].RecordHash {
		t.Fatalf("verify stored tenant A Audit chain: checkpoint=%#v err=%v", checkpoint, err)
	}

	tenantBRecords := readAuditRecords(t, ctx, runtimeConnection, "organization-b")
	if len(tenantBRecords) != 1 || tenantBRecords[0].Sequence != 1 ||
		tenantBRecords[0].PreviousHash != auditauthority.GenesisHash {
		t.Fatalf("tenant B Audit records = %#v", tenantBRecords)
	}
}

func readAuditRecords(
	t *testing.T,
	ctx context.Context,
	runtimeConnection *pgx.Conn,
	tenantID auditv1.TenantID,
) []auditv1.AuditRecord {
	t.Helper()
	return readAuditChainRecords(t, ctx, runtimeConnection, auditauthority.TenantChain(tenantID))
}

func readAuditChainRecords(
	t *testing.T,
	ctx context.Context,
	runtimeConnection *pgx.Conn,
	chainID auditauthority.ChainID,
) []auditv1.AuditRecord {
	t.Helper()
	rows, err := runtimeConnection.Query(
		ctx,
		`SELECT chain_id, sequence, source, event_id, event_document,
			   canonical_document, content_digest, previous_hash, record_hash,
			   ingested_at, retention
		  FROM audit.read_records($1, $2, $3, NULL, NULL, NULL, NULL, NULL)`,
		string(chainID),
		authorityMaximumSequence,
		200,
	)
	if err != nil {
		t.Fatalf("read Audit records: %v", err)
	}
	defer rows.Close()
	records := make([]auditv1.AuditRecord, 0)
	for rows.Next() {
		var storedTenantID, source, eventID, eventDocument, canonicalDocument string
		var contentDigest, previousHash, recordHash, retention string
		var sequence int64
		var ingestedAt time.Time
		if err := rows.Scan(
			&storedTenantID,
			&sequence,
			&source,
			&eventID,
			&eventDocument,
			&canonicalDocument,
			&contentDigest,
			&previousHash,
			&recordHash,
			&ingestedAt,
			&retention,
		); err != nil {
			t.Fatalf("scan Audit record: %v", err)
		}
		event := decodeAuthorityEvent(t, eventDocument)
		fact, err := auditauthority.Canonicalize(auditv1.Source(source), event)
		if err != nil || fact.Document != canonicalDocument || fact.ContentDigest != contentDigest ||
			storedTenantID != string(auditauthority.ChainFor(event.TenantID, event.InstallationID)) || eventID != string(event.EventID) {
			t.Fatalf(
				"stored Audit canonical fact tenant=%q event=%q fact=%#v err=%v",
				storedTenantID,
				eventID,
				fact,
				err,
			)
		}
		record := auditv1.AuditRecord{
			APIVersion:    auditv1.APIVersion,
			Kind:          "AuditRecord",
			Source:        auditv1.Source(source),
			Sequence:      uint64(sequence),
			Event:         event,
			ContentDigest: contentDigest,
			PreviousHash:  previousHash,
			RecordHash:    recordHash,
			IngestedAt:    ingestedAt.UTC(),
			Retention:     auditv1.RetentionPolicy(retention),
		}
		if err := auditv1.ValidateAuditRecord(record); err != nil {
			t.Fatalf("validate stored Audit record: %v", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate Audit records: %v", err)
	}
	return records
}

func assertForcedTenantIsolation(
	t *testing.T,
	ctx context.Context,
	iamMigrator *pgx.Conn,
	auditMigrator *pgx.Conn,
	tenantA auditv1.TenantID,
) {
	t.Helper()
	if count := ownerTenantCount(
		t, ctx, iamMigrator, "matrix_iam_owner", "matrix.iam_tenant_id",
		"iam.organizations", string(tenantA),
	); count != 1 {
		t.Fatalf("IAM owner tenant A row count = %d, want 1", count)
	}
	if count := ownerTenantCount(
		t, ctx, iamMigrator, "matrix_iam_owner", "matrix.iam_tenant_id",
		"iam.organizations", "organization-other",
	); count != 0 {
		t.Fatalf("IAM owner cross-tenant row count = %d, want 0", count)
	}
	if count := ownerTenantCount(
		t, ctx, auditMigrator, "matrix_audit_owner", "matrix.audit_chain_id",
		"audit.records", string(auditauthority.TenantChain(tenantA)),
	); count != 2 {
		t.Fatalf("Audit owner tenant A row count = %d, want 2", count)
	}
	if count := ownerTenantCount(
		t, ctx, auditMigrator, "matrix_audit_owner", "matrix.audit_chain_id",
		"audit.records", "tenant:organization-b",
	); count != 1 {
		t.Fatalf("Audit owner tenant B row count = %d, want 1", count)
	}
}

func ownerTenantCount(
	t *testing.T,
	ctx context.Context,
	migrator *pgx.Conn,
	ownerRole string,
	settingName string,
	tableName string,
	tenantID string,
) int {
	t.Helper()
	tx, err := migrator.Begin(ctx)
	if err != nil {
		t.Fatalf("begin forced RLS transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(
		ctx,
		fmt.Sprintf("SET LOCAL ROLE %s", pgx.Identifier{ownerRole}.Sanitize()),
	); err != nil {
		t.Fatalf("assume authority owner role: %v", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", settingName, tenantID); err != nil {
		t.Fatalf("set authority owner tenant: %v", err)
	}
	var count int
	if err := tx.QueryRow(
		ctx,
		fmt.Sprintf("SELECT count(*) FROM %s", tableName),
	).Scan(&count); err != nil {
		t.Fatalf("query forced RLS table %s: %v", tableName, err)
	}
	return count
}

func assertAuditImmutability(
	t *testing.T,
	ctx context.Context,
	auditMigrator *pgx.Conn,
	tenantID auditv1.TenantID,
) {
	t.Helper()
	for name, statement := range map[string]string{
		"update":   "UPDATE audit.records SET retention = 'INDEFINITE' WHERE sequence = 1",
		"delete":   "DELETE FROM audit.records WHERE sequence = 1",
		"truncate": "TRUNCATE TABLE audit.records CASCADE",
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := auditMigrator.Begin(ctx)
			if err != nil {
				t.Fatalf("begin Audit immutability attack: %v", err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE matrix_audit_owner"); err != nil {
				t.Fatalf("assume Audit owner role: %v", err)
			}
			if _, err := tx.Exec(
				ctx,
				"SELECT set_config('matrix.audit_chain_id', $1, true)",
				string(auditauthority.TenantChain(tenantID)),
			); err != nil {
				t.Fatalf("set Audit immutability tenant: %v", err)
			}
			_, err = tx.Exec(ctx, statement)
			assertAuthorityPostgresCode(t, err, "42501")
		})
	}
}

func assertIAMSessionDatabaseTime(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	iamAPI *pgx.Conn,
	fixture iamBootstrapFixture,
) {
	t.Helper()
	issue := func(sessionID, seed string) (string, string, time.Time, time.Time) {
		lookupDigest := authorityDigest("session-lookup-" + seed)
		verificationDigest := authorityDigest("session-verification-" + seed)
		event := authorityAuditEvent(
			"event-session-"+seed,
			fixture.TenantID,
			sessionID,
			auditv1.ActionIAMSessionIssued,
		)
		var before, after, issuedAt, expiresAt time.Time
		if err := admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&before); err != nil {
			t.Fatalf("read database time before session issue: %v", err)
		}
		tx, err := iamAPI.Begin(ctx)
		if err != nil {
			t.Fatalf("begin IAM session issue: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		var transactionTime time.Time
		if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&transactionTime); err != nil {
			t.Fatalf("read IAM session transaction time: %v", err)
		}
		event.OccurredAt = transactionTime.UTC()
		if err := tx.QueryRow(
			ctx,
			`SELECT * FROM iam.issue_session(
				$1, $2, $3, $4, $5, 60, $6::jsonb
			)`,
			sessionID,
			string(fixture.TenantID),
			fixture.Administrator,
			lookupDigest,
			verificationDigest,
			authorityJSON(t, event),
		).Scan(&issuedAt, &expiresAt); err != nil {
			t.Fatalf("issue IAM session %s: %v", sessionID, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit IAM session %s: %v", sessionID, err)
		}
		if err := admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&after); err != nil {
			t.Fatalf("read database time after session issue: %v", err)
		}
		before, after = before.UTC(), after.UTC()
		issuedAt, expiresAt = issuedAt.UTC(), expiresAt.UTC()
		if issuedAt.Before(before) || issuedAt.After(after) ||
			issuedAt != transactionTime.UTC() ||
			expiresAt.Sub(issuedAt) != time.Minute || issuedAt.Nanosecond()%1_000 != 0 {
			t.Fatalf(
				"database session time before=%s issued=%s expires=%s after=%s",
				before,
				issuedAt,
				expiresAt,
				after,
			)
		}
		return lookupDigest, verificationDigest, issuedAt, expiresAt
	}

	staleTimeEvent := authorityAuditEvent(
		"event-session-stale-time",
		fixture.TenantID,
		"session-stale-time",
		auditv1.ActionIAMSessionIssued,
	)
	var ignoredIssuedAt, ignoredExpiresAt time.Time
	err := iamAPI.QueryRow(
		ctx,
		`SELECT * FROM iam.issue_session(
			$1, $2, $3, $4, $5, 60, $6::jsonb
		)`,
		"session-stale-time",
		string(fixture.TenantID),
		fixture.Administrator,
		authorityDigest("stale-time-lookup"),
		authorityDigest("stale-time-verification"),
		authorityJSON(t, staleTimeEvent),
	).Scan(&ignoredIssuedAt, &ignoredExpiresAt)
	assertAuthorityPostgresCode(t, err, "22023")

	lookupA, verificationA, _, _ := issue("session-expiring", "expiring")
	assertIAMSessionLookup(t, ctx, iamAPI, fixture, lookupA, verificationA, "session-expiring")
	if _, err := admin.Exec(
		ctx,
		`UPDATE iam.sessions
			SET issued_at = transaction_timestamp() - interval '2 minutes',
				expires_at = transaction_timestamp() - interval '1 minute'
		  WHERE tenant_id = $1 AND id = 'session-expiring'`,
		string(fixture.TenantID),
	); err != nil {
		t.Fatalf("expire IAM session using database state: %v", err)
	}
	assertNoIAMSession(t, ctx, iamAPI, lookupA)

	lookupB, verificationB, _, _ := issue("session-revoked", "revoked")
	assertIAMSessionLookup(t, ctx, iamAPI, fixture, lookupB, verificationB, "session-revoked")
	if _, err := admin.Exec(
		ctx,
		`UPDATE iam.sessions
			SET status = 'REVOKED', revoked_at = transaction_timestamp()
		  WHERE tenant_id = $1 AND id = 'session-revoked'`,
		string(fixture.TenantID),
	); err != nil {
		t.Fatalf("revoke IAM session: %v", err)
	}
	assertNoIAMSession(t, ctx, iamAPI, lookupB)

	var beforeOutbox int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.audit_outbox").Scan(&beforeOutbox); err != nil {
		t.Fatalf("count IAM Audit outbox before rejected session: %v", err)
	}
	missingEvent := authorityAuditEvent(
		"event-session-missing",
		fixture.TenantID,
		"session-missing",
		auditv1.ActionIAMSessionIssued,
	)
	missingTx, err := iamAPI.Begin(ctx)
	if err != nil {
		t.Fatalf("begin rejected IAM session transaction: %v", err)
	}
	defer func() { _ = missingTx.Rollback(context.Background()) }()
	var missingTransactionTime time.Time
	if err := missingTx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&missingTransactionTime); err != nil {
		t.Fatalf("read rejected IAM session transaction time: %v", err)
	}
	missingEvent.OccurredAt = missingTransactionTime.UTC()
	err = missingTx.QueryRow(
		ctx,
		`SELECT * FROM iam.issue_session(
			$1, $2, $3, $4, $5, 60, $6::jsonb
		)`,
		"session-missing",
		string(fixture.TenantID),
		"principal-missing",
		authorityDigest("missing-lookup"),
		authorityDigest("missing-verification"),
		authorityJSON(t, missingEvent),
	).Scan(&ignoredIssuedAt, &ignoredExpiresAt)
	assertAuthorityPostgresCode(t, err, "42501")
	var afterOutbox int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.audit_outbox").Scan(&afterOutbox); err != nil {
		t.Fatalf("count IAM Audit outbox after rejected session: %v", err)
	}
	if beforeOutbox != afterOutbox || afterOutbox != 3 {
		t.Fatalf("IAM session/outbox atomicity before=%d after=%d, want 3", beforeOutbox, afterOutbox)
	}
}

func assertIAMSessionLookup(
	t *testing.T,
	ctx context.Context,
	iamAPI *pgx.Conn,
	fixture iamBootstrapFixture,
	lookupDigest string,
	verificationDigest string,
	sessionID string,
) {
	t.Helper()
	var tenantID, storedSessionID, principalID, principalType, storedVerification string
	var mustChangePassword bool
	var roles []string
	if err := iamAPI.QueryRow(
		ctx,
		`SELECT organization_id, session_id, principal_id, principal_type,
		        verification_digest, principal_must_change_password, roles
		   FROM iam.lookup_session($1)`,
		lookupDigest,
	).Scan(
		&tenantID,
		&storedSessionID,
		&principalID,
		&principalType,
		&storedVerification,
		&mustChangePassword,
		&roles,
	); err != nil {
		t.Fatalf("lookup IAM session %s: %v", sessionID, err)
	}
	if tenantID != string(fixture.TenantID) || storedSessionID != sessionID ||
		principalID != fixture.Administrator || principalType != "USER" ||
		storedVerification != verificationDigest || !mustChangePassword ||
		len(roles) != 2 || roles[0] != "ORGANIZATION_ADMIN" || roles[1] != "PLATFORM_OPERATOR" {
		t.Fatalf(
			"IAM session lookup tenant=%q session=%q principal=%q type=%q digest=%q mustChange=%t roles=%v",
			tenantID,
			storedSessionID,
			principalID,
			principalType,
			storedVerification,
			mustChangePassword,
			roles,
		)
	}
}

func assertNoIAMSession(
	t *testing.T,
	ctx context.Context,
	iamAPI *pgx.Conn,
	lookupDigest string,
) {
	t.Helper()
	var count int
	err := iamAPI.QueryRow(
		ctx,
		"SELECT count(*) FROM iam.lookup_session($1)",
		lookupDigest,
	).Scan(&count)
	if err != nil || count != 0 {
		t.Fatalf("inactive IAM session lookup count=%d err=%v, want zero", count, err)
	}
}

func assertIAMAuthorizationCatalog(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	iamAPI *pgx.Conn,
	fixture iamBootstrapFixture,
) {
	t.Helper()
	passwordTransaction, err := iamAPI.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var passwordTime time.Time
	if err := passwordTransaction.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&passwordTime); err != nil {
		_ = passwordTransaction.Rollback(ctx)
		t.Fatal(err)
	}
	passwordEvent := authorityAuditEvent("event-catalog-password", fixture.TenantID, fixture.Administrator, auditv1.ActionIAMPasswordChanged)
	passwordEvent.Actor = auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(fixture.Administrator)}
	passwordEvent.OccurredAt = passwordTime.UTC()
	sessionEvent := authorityAuditEvent("event-catalog-session", fixture.TenantID, "session-catalog", auditv1.ActionIAMSessionIssued)
	sessionEvent.Actor = passwordEvent.Actor
	sessionEvent.OccurredAt = passwordTime.UTC()
	if _, err := passwordTransaction.Exec(ctx, "SELECT * FROM iam.issue_session($1,$2,$3,$4,$5,60,$6::jsonb)",
		"session-catalog", string(fixture.TenantID), fixture.Administrator,
		authorityDigest("catalog-session-lookup"), authorityDigest("catalog-session-verification"), authorityJSON(t, sessionEvent)); err != nil {
		_ = passwordTransaction.Rollback(ctx)
		t.Fatalf("establish the current session for catalog password replacement: %v", err)
	}
	if _, err := passwordTransaction.Exec(ctx, "SELECT * FROM iam.change_password($1,$2,$3,$4,$5::jsonb,$6,$7)",
		string(fixture.TenantID), fixture.Administrator, fixture.PasswordHash,
		strings.TrimSuffix(fixture.PasswordHash, strings.Repeat("A", 43))+strings.Repeat("B", 42)+"A", authorityJSON(t, passwordEvent), "session-catalog", true); err != nil {
		_ = passwordTransaction.Rollback(ctx)
		t.Fatalf("prepare current platform authority through the password mutation: %v", err)
	}
	if err := passwordTransaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for index, action := range iamv1.AllActions() {
		resourceKind, known := iamv1.ResourceKindForAction(action)
		if !known {
			t.Fatalf("IAM action %q has no Go resource contract", action)
		}
		decisionID := fmt.Sprintf("decision-catalog-%d", index)
		requestID := fmt.Sprintf("request-catalog-%d", index)
		tx, err := iamAPI.Begin(ctx)
		if err != nil {
			t.Fatalf("begin IAM authorization catalog transaction: %v", err)
		}
		var transactionTime time.Time
		if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&transactionTime); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatalf("read IAM authorization transaction time: %v", err)
		}
		decision := iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion,
			Kind:       "AuthorizationDecision",
			ID:         iamv1.DecisionID(decisionID),
			Allowed:    true,
			Reason:     iamv1.DecisionAllowed,
			TenantID:   iamv1.OrganizationID(fixture.TenantID),
			Subject:    &iamv1.Subject{Type: iamv1.PrincipalUser, ID: iamv1.PrincipalID(fixture.Administrator)},
			Action:     action,
			Resource:   iamv1.ResourceReference{Kind: resourceKind, ID: fmt.Sprintf("resource-catalog-%d", index)},
			RequestID:  requestID,
			DecidedAt:  transactionTime.UTC(),
		}
		if iamv1.IsPlatformAction(action) {
			decision.TenantID, decision.InstallationID = "", fixture.InstallationID
		}
		event := authorityAuditEvent(
			fmt.Sprintf("event-authorization-catalog-%d", index),
			fixture.TenantID,
			decisionID,
			auditv1.ActionIAMAuthorizationDecided,
		)
		event.Actor = auditv1.ActorReference{
			Type: auditv1.ActorUser,
			ID:   auditv1.ActorID(fixture.Administrator),
		}
		event.IAMDecisionID = auditv1.DecisionID(decisionID)
		event.Target.ID = decisionID
		event.Result = auditv1.ResultAllowed
		event.RequestID = requestID
		event.OccurredAt = transactionTime.UTC()
		_, err = tx.Exec(
			ctx,
			"SELECT iam.record_authorization($1, $2, $3::jsonb, $4::jsonb)",
			string(fixture.TenantID),
			fixture.Administrator,
			authorityJSON(t, decision),
			authorityJSON(t, event),
		)
		if err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatalf("record IAM authorization action %q: %v", action, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit IAM authorization action %q: %v", action, err)
		}
	}

	var decisionCount int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM iam.authorization_decisions").Scan(&decisionCount); err != nil {
		t.Fatalf("count stored IAM authorization decisions: %v", err)
	}
	if decisionCount != len(iamv1.AllActions()) {
		t.Fatalf("stored IAM authorization decisions=%d want=%d", decisionCount, len(iamv1.AllActions()))
	}

	transaction, err := iamAPI.Begin(ctx)
	if err != nil {
		t.Fatalf("begin rejected IAM authorization transaction: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	var databaseTime time.Time
	if err := transaction.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&databaseTime); err != nil {
		t.Fatalf("read rejected IAM authorization time: %v", err)
	}
	decision := iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion,
		Kind:       "AuthorizationDecision",
		ID:         "decision-forged-kind",
		Allowed:    true,
		Reason:     iamv1.DecisionAllowed,
		TenantID:   iamv1.OrganizationID(fixture.TenantID),
		Subject:    &iamv1.Subject{Type: iamv1.PrincipalUser, ID: iamv1.PrincipalID(fixture.Administrator)},
		Action:     iamv1.ActionPaaSApplicationRead,
		Resource:   iamv1.ResourceReference{Kind: iamv1.ResourceDeployment, ID: "application-forged-kind"},
		RequestID:  "request-forged-kind",
		DecidedAt:  databaseTime.UTC(),
	}
	event := authorityAuditEvent(
		"event-authorization-forged-kind",
		fixture.TenantID,
		string(decision.ID),
		auditv1.ActionIAMAuthorizationDecided,
	)
	event.Actor = auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(fixture.Administrator)}
	event.IAMDecisionID = auditv1.DecisionID(decision.ID)
	event.Target.ID = string(decision.ID)
	event.Result = auditv1.ResultAllowed
	event.RequestID = decision.RequestID
	event.OccurredAt = databaseTime.UTC()
	_, err = transaction.Exec(
		ctx,
		"SELECT iam.record_authorization($1, $2, $3::jsonb, $4::jsonb)",
		string(fixture.TenantID),
		fixture.Administrator,
		authorityJSON(t, decision),
		authorityJSON(t, event),
	)
	assertAuthorityPostgresCode(t, err, "22023")
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, attack := range []string{"mixed authority", "wrong installation", "revoked platform role"} {
		if attack == "revoked platform role" {
			if _, err := admin.Exec(ctx, `UPDATE iam.role_bindings SET revoked_at = transaction_timestamp(), updated_at = transaction_timestamp(), resource_version = resource_version + 1
				WHERE tenant_id = $1 AND principal_id = $2 AND role_name = 'PLATFORM_OPERATOR' AND revoked_at IS NULL`,
				string(fixture.TenantID), fixture.Administrator); err != nil {
				t.Fatal(err)
			}
		}
		tx, err := iamAPI.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&databaseTime); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		decision.Action = iamv1.ActionPaaSExecutionTargetRegister
		decision.Resource.Kind = iamv1.ResourceExecutionTarget
		decision.TenantID, decision.InstallationID = "", fixture.InstallationID
		decision.DecidedAt, event.OccurredAt = databaseTime.UTC(), databaseTime.UTC()
		if attack == "mixed authority" {
			decision.TenantID = iamv1.OrganizationID(fixture.TenantID)
		}
		if attack == "wrong installation" {
			decision.InstallationID = "installation-other"
		}
		_, err = tx.Exec(ctx, "SELECT iam.record_authorization($1,$2,$3::jsonb,$4::jsonb)",
			string(fixture.TenantID), fixture.Administrator, authorityJSON(t, decision), authorityJSON(t, event))
		_ = tx.Rollback(ctx)
		assertAuthorityPostgresCode(t, err, "22023")
	}
}

func authorityAuditEvent(
	eventID string,
	tenantID auditv1.TenantID,
	targetID string,
	action auditv1.Action,
) auditv1.Event {
	contract, known := auditv1.ContractForAction(action)
	if !known {
		panic("authority integration action has no contract")
	}
	event := auditv1.Event{
		APIVersion:    auditv1.APIVersion,
		Kind:          "AuditEvent",
		EventID:       auditv1.EventID(eventID),
		TenantID:      tenantID,
		Actor:         auditv1.ActorReference{Type: auditv1.ActorSystem, ID: "system-gatea"},
		Action:        action,
		Target:        auditv1.TargetReference{Kind: contract.Target, ID: targetID},
		Result:        contract.Results[0],
		RequestDigest: authorityDigest("request-" + eventID),
		RequestID:     "request-" + eventID,
		CorrelationID: "correlation-" + eventID,
		OccurredAt:    time.Date(2026, 8, 26, 1, 2, 3, 0, time.UTC),
	}
	if contract.IAMDecisionRequired {
		event.IAMDecisionID = auditv1.DecisionID("decision-" + eventID)
	}
	if action == auditv1.ActionIAMAuthorizationDecided {
		event.Target.ID = string(event.IAMDecisionID)
	}
	if contract.OperationRequired {
		event.OperationID = auditv1.OperationID("operation-" + eventID)
	}
	if contract.PlatformOnly {
		event.TenantID, event.InstallationID = "", string(tenantID)
		event.Actor.Type = auditv1.ActorUser
	}
	if action == auditv1.ActionIAMTenantAdministratorRecovered {
		event.Target.TenantID = "organization-recovered"
	}
	return event
}

func decodeAuthorityEvent(t *testing.T, document string) auditv1.Event {
	t.Helper()
	var event auditv1.Event
	if err := auditv1.DecodeRequest(strings.NewReader(document), &event); err != nil {
		t.Fatalf("decode stored Audit event: %v", err)
	}
	if err := auditv1.ValidateEvent(event); err != nil {
		t.Fatalf("validate stored Audit event: %v", err)
	}
	return event
}

func authorityJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode authority integration fixture: %v", err)
	}
	return string(encoded)
}

func authorityDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func postgresLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func assertAuthorityPostgresCode(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}
