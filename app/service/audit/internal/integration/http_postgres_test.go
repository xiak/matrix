package integration

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	auditauthority "github.com/xiak/matrix/app/service/audit/internal/authority"
	auditpostgres "github.com/xiak/matrix/app/service/audit/internal/data/postgres"
	audithttp "github.com/xiak/matrix/app/service/audit/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
	auditmigration "github.com/xiak/matrix/app/service/audit/migration"
)

const (
	auditHTTPPostgresDSN       = "MATRIX_AUDIT_HTTP_POSTGRES_TEST_DSN"
	auditHTTPTestRole          = "matrix_audit_http_test_runtime"
	auditHTTPTestPassword      = "matrix-audit-http-test-only"
	producerCredentialA        = "mx1.AuditHTTPProducerCredentialA000000000000001"
	producerCredentialB        = "mx1.AuditHTTPProducerCredentialB000000000000001"
	platformProducerCredential = "mx1.AuditHTTPPlatformProducer000000000000000001"
	paasProducerCredential     = "mx1.AuditHTTPPaaSProducerCredential0000000000001"
	readerCredentialA          = "mx1.AuditHTTPReaderCredentialA0000000000000001"
	readerCredentialB          = "mx1.AuditHTTPReaderCredentialB0000000000000001"
	deniedCredential           = "mx1.AuditHTTPDeniedCredential00000000000000001"
	verifierCredential         = "mx1.AuditHTTPVerifierCredential0000000000000001"
)

func TestAuditHTTPPostgresVerticalSlice(t *testing.T) {
	dsn := os.Getenv(auditHTTPPostgresDSN)
	if dsn == "" {
		t.Skipf("set %s to a clean disposable PostgreSQL 18 database", auditHTTPPostgresDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse Audit HTTP PostgreSQL DSN: %v", err)
	}
	if !strings.HasPrefix(adminConfig.Database, "matrix_audit_") {
		t.Fatalf("refusing Audit HTTP database %q without matrix_audit_ prefix", adminConfig.Database)
	}
	adminConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect Audit HTTP PostgreSQL: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	assertAuditPostgres18(t, ctx, admin)
	assertCleanAuditSchema(t, ctx, admin)
	applyAuditSchema(t, ctx, admin)
	createAuditHTTPRole(t, ctx, admin)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse Audit HTTP pool DSN: %v", err)
	}
	poolConfig.ConnConfig.User = auditHTTPTestRole
	poolConfig.ConnConfig.Password = auditHTTPTestPassword
	poolConfig.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("open Audit HTTP runtime pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping Audit HTTP runtime pool: %v", err)
	}
	repository, err := auditpostgres.NewRepository(pool)
	if err != nil {
		t.Fatalf("create Audit PostgreSQL repository: %v", err)
	}
	iam := &integrationIAM{now: time.Date(2026, 8, 26, 16, 17, 18, 123000, time.UTC)}
	identifier := 0
	workflow, err := auditlog.NewService(repository, iam, auditlog.Config{
		CursorKey: bytes.Repeat([]byte{0x6a}, 32),
		NewID: func(prefix string) (string, error) {
			identifier++
			return fmt.Sprintf("%s-http-%d", prefix, identifier), nil
		},
	})
	if err != nil {
		t.Fatalf("create Audit HTTP workflow: %v", err)
	}
	handler, err := audithttp.NewHandler(workflow, audithttp.Config{
		NewRequestID: func() (string, error) { return "request-http-integration", nil },
	})
	if err != nil {
		t.Fatalf("create Audit HTTP handler: %v", err)
	}

	ready := performAuditRequest(handler, http.MethodGet, "/ready", "", nil)
	if ready.Code != http.StatusOK {
		t.Fatalf("Audit readiness status=%d body=%s", ready.Code, ready.Body.String())
	}
	first := integrationEvent(
		"event-bootstrap-a",
		"organization-a",
		auditv1.ActionIAMBootstrapApplied,
		auditv1.TargetInstallation,
		"installation-a",
		iam.now.Add(-3*time.Minute),
	)
	accepted := ingestAuditEvent(t, handler, producerCredentialA, first, http.StatusCreated)
	if accepted.Outcome != auditv1.IngestionAccepted || accepted.Record.Sequence != 1 ||
		accepted.Record.Source != auditv1.SourceIAM {
		t.Fatalf("accepted Audit event=%#v", accepted)
	}
	duplicate := ingestAuditEvent(t, handler, producerCredentialA, first, http.StatusOK)
	if duplicate.Outcome != auditv1.IngestionDuplicate || duplicate.Record != accepted.Record {
		t.Fatalf("duplicate Audit event=%#v", duplicate)
	}
	changed := first
	changed.RequestID = "request-event-bootstrap-changed"
	ingestAuditEvent(t, handler, producerCredentialA, changed, http.StatusConflict)

	wrongTenant := first
	wrongTenant.EventID = "event-wrong-tenant"
	wrongTenant.TenantID = "organization-unknown"
	ingestAuditEvent(t, handler, producerCredentialA, wrongTenant, http.StatusForbidden)
	wrongCredential := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/events",
		"wrong-producer-credential",
		mustJSON(t, first),
	)
	if wrongCredential.Code != http.StatusUnauthorized {
		t.Fatalf("wrong Audit producer status=%d body=%s", wrongCredential.Code, wrongCredential.Body.String())
	}

	second := integrationEvent(
		"event-session-a",
		"organization-a",
		auditv1.ActionIAMSessionIssued,
		auditv1.TargetSession,
		"session-a",
		iam.now.Add(-2*time.Minute),
	)
	accepted = ingestAuditEvent(t, handler, producerCredentialA, second, http.StatusCreated)
	if accepted.Record.Sequence != 2 {
		t.Fatalf("second tenant A sequence=%d want=2", accepted.Record.Sequence)
	}
	tenantB := integrationEvent(
		"event-bootstrap-b",
		"organization-b",
		auditv1.ActionIAMBootstrapApplied,
		auditv1.TargetInstallation,
		"installation-b",
		iam.now.Add(-time.Minute),
	)
	accepted = ingestAuditEvent(t, handler, producerCredentialB, tenantB, http.StatusCreated)
	if accepted.Record.Sequence != 1 || accepted.Record.Event.TenantID != "organization-b" {
		t.Fatalf("tenant B Audit record=%#v", accepted.Record)
	}

	firstPage := queryAuditRecords(
		t,
		handler,
		readerCredentialA,
		auditv1.QueryRecordsRequest{PageSize: 1},
		http.StatusOK,
	)
	if len(firstPage.Records) != 1 || firstPage.Records[0].Sequence != 2 ||
		firstPage.NextCursor == "" || firstPage.TenantID != "organization-a" {
		t.Fatalf("tenant A first Audit page=%#v", firstPage)
	}
	secondPage := queryAuditRecords(
		t,
		handler,
		readerCredentialA,
		auditv1.QueryRecordsRequest{PageSize: 1, Cursor: firstPage.NextCursor},
		http.StatusOK,
	)
	if len(secondPage.Records) != 1 || secondPage.Records[0].Sequence != 1 ||
		secondPage.NextCursor != "" || secondPage.TenantID != "organization-a" {
		t.Fatalf("tenant A second Audit page=%#v", secondPage)
	}
	actor := auditv1.ActorReference{Type: auditv1.ActorServiceAccount, ID: "service-iam"}
	from := first.OccurredAt.Add(-time.Second)
	to := first.OccurredAt.Add(time.Second)
	filtered := queryAuditRecords(
		t,
		handler,
		readerCredentialA,
		auditv1.QueryRecordsRequest{
			PageSize: 10,
			From:     &from,
			To:       &to,
			Action:   auditv1.ActionIAMBootstrapApplied,
			Actor:    &actor,
		},
		http.StatusOK,
	)
	if len(filtered.Records) != 1 || filtered.Records[0].Event.EventID != first.EventID {
		t.Fatalf("filtered tenant A Audit page=%#v", filtered)
	}

	tenantBPage := queryAuditRecords(
		t,
		handler,
		readerCredentialB,
		auditv1.QueryRecordsRequest{PageSize: 10},
		http.StatusOK,
	)
	if tenantBPage.TenantID != "organization-b" || len(tenantBPage.Records) != 1 ||
		tenantBPage.Records[0].Event.TenantID != "organization-b" {
		t.Fatalf("tenant B Audit page=%#v", tenantBPage)
	}
	queryAuditRecords(
		t,
		handler,
		readerCredentialB,
		auditv1.QueryRecordsRequest{PageSize: 1, Cursor: firstPage.NextCursor},
		http.StatusUnprocessableEntity,
	)

	verification := verifyAuditChain(
		t,
		handler,
		readerCredentialA,
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 5},
		http.StatusOK,
	)
	if verification.TenantID != "organization-a" || verification.RecordCount != 5 ||
		verification.ToSequence != 5 || !verification.Complete ||
		verification.State != auditv1.VerificationVerified {
		t.Fatalf("tenant A chain verification=%#v", verification)
	}
	queryAuditRecords(
		t,
		handler,
		deniedCredential,
		auditv1.QueryRecordsRequest{PageSize: 10},
		http.StatusForbidden,
	)
	installationRequest := auditv1.VerifyInstallationRequest{
		InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		OperationID:    "operation-installation-probe",
		DeploymentID:   "deployment-installation-probe",
	}
	pendingInstallation := verifyInstallationAudit(
		t, handler, verifierCredential, installationRequest, http.StatusOK,
	)
	if pendingInstallation.State != auditv1.InstallationVerificationPending {
		t.Fatalf("pending installation Audit verification=%#v", pendingInstallation)
	}
	paasEvent := integrationEvent(
		"event-installation-probe",
		"organization-a",
		auditv1.ActionPaaSDeploymentCreated,
		auditv1.TargetDeployment,
		installationRequest.DeploymentID,
		iam.now,
	)
	paasEvent.Actor = auditv1.ActorReference{
		Type: auditv1.ActorServiceAccount, ID: "service-installation-verifier",
	}
	paasEvent.IAMDecisionID = "decision-paas-installation-probe"
	paasEvent.Result = auditv1.ResultAccepted
	paasEvent.OperationID = installationRequest.OperationID
	paasAccepted := ingestAuditEvent(t, handler, paasProducerCredential, paasEvent, http.StatusCreated)
	if paasAccepted.Record.Sequence == 0 || paasAccepted.Record.Source != auditv1.SourcePaaS {
		t.Fatalf("PaaS installation Audit record=%#v", paasAccepted.Record)
	}
	verifiedInstallation := verifyInstallationAudit(
		t, handler, verifierCredential, installationRequest, http.StatusOK,
	)
	if verifiedInstallation.State != auditv1.InstallationVerificationVerified ||
		verifiedInstallation.EventID != paasEvent.EventID ||
		verifiedInstallation.RecordSequence != paasAccepted.Record.Sequence ||
		verifiedInstallation.RecordHash != paasAccepted.Record.RecordHash {
		t.Fatalf("verified installation Audit result=%#v", verifiedInstallation)
	}

	assertAuditFacts(t, ctx, admin)
	assertAuditRuntimeBoundary(t, ctx, pool)
	for index, action := range []auditv1.Action{auditv1.ActionIAMOrganizationCreated, auditv1.ActionIAMAccountAliasSet,
		auditv1.ActionIAMPrincipalStatusSet, auditv1.ActionIAMPasswordReset} {
		target := auditv1.TargetPrincipal
		if index < 2 {
			target = auditv1.TargetOrganization
		}
		event := integrationEvent(auditv1.EventID(fmt.Sprintf("event-account-%d", index)), "organization-b", action, target, "account-target", iam.now)
		event.Actor = auditv1.ActorReference{Type: auditv1.ActorUser, ID: "account-administrator"}
		event.IAMDecisionID = "decision-account"
		ingestAuditEvent(t, handler, producerCredentialA, event, http.StatusCreated)
		page := queryAuditRecords(t, handler, readerCredentialB, auditv1.QueryRecordsRequest{PageSize: 10, Action: action}, http.StatusOK)
		if len(page.Records) != 1 || page.Records[0].Event != event {
			t.Fatal("new tenant account audit fact was not queryable")
		}
		other := queryAuditRecords(t, handler, readerCredentialA, auditv1.QueryRecordsRequest{PageSize: 10, Action: action}, http.StatusOK)
		if len(other.Records) != 0 {
			t.Fatal("account audit fact escaped its tenant")
		}
	}
	chainB := verifyAuditChain(t, handler, readerCredentialB, auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 100}, http.StatusOK)
	if chainB.State != auditv1.VerificationVerified || !chainB.Complete {
		t.Fatal("account audit chain did not verify")
	}
	assertAuditPlaintextAbsent(
		t,
		ctx,
		admin,
		producerCredentialA,
		producerCredentialB,
		paasProducerCredential,
		readerCredentialA,
		readerCredentialB,
		deniedCredential,
		verifierCredential,
	)

	assertAuditedReadSerialization(t, ctx, admin, pool, repository, iam)
	assertCompetingAuditEvents(t, ctx, admin, repository, iam)
	assertIndependentAuditChainWriters(t, ctx, admin, repository, iam)
	iam.failure = errors.New("native IAM failure contains " + readerCredentialA + " and native-provider-path")
	failure := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/records:query",
		readerCredentialA,
		mustJSON(t, auditv1.QueryRecordsRequest{PageSize: 10}),
	)
	if failure.Code != http.StatusServiceUnavailable ||
		bytes.Contains(failure.Body.Bytes(), []byte(readerCredentialA)) ||
		bytes.Contains(failure.Body.Bytes(), []byte("native IAM failure")) ||
		bytes.Contains(failure.Body.Bytes(), []byte(`native-provider-path`)) {
		t.Fatalf("Audit IAM outage leaked native data: status=%d body=%s", failure.Code, failure.Body.String())
	}
}

// This barrier surrounds a real append, not a synthetic database error. It
// proves independent-chain progress and exercises actual lock/snapshot waits.
type auditAppendPauseRepository struct {
	auditlog.Repository
	arrived           chan<- struct{}
	resume            <-chan struct{}
	attempts          *atomic.Int32
	rejectAfterAppend bool
}

func (repository auditAppendPauseRepository) WithinTransaction(ctx context.Context, callback func(context.Context, auditlog.Transaction) error) error {
	repository.attempts.Add(1)
	return repository.Repository.WithinTransaction(ctx, func(ctx context.Context, tx auditlog.Transaction) error {
		return callback(ctx, auditAppendPauseTransaction{Transaction: tx, repository: repository})
	})
}

type auditAppendPauseTransaction struct {
	auditlog.Transaction
	repository auditAppendPauseRepository
}

func (tx auditAppendPauseTransaction) AppendRecord(ctx context.Context, mutation auditlog.AppendMutation) (auditv1.IngestionOutcome, error) {
	if tx.repository.arrived != nil {
		select {
		case tx.repository.arrived <- struct{}{}:
		default:
		}
		select {
		case <-tx.repository.resume:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	outcome, err := tx.Transaction.AppendRecord(ctx, mutation)
	if err == nil && tx.repository.rejectAfterAppend {
		return "", auditlog.ErrUnavailable
	}
	return outcome, err
}

func concurrentAuditEvent(id string, installation bool) auditv1.Event {
	event := integrationEvent(auditv1.EventID(id), "organization-a", auditv1.ActionIAMBootstrapApplied, auditv1.TargetInstallation, "installation-test", time.Now().UTC().Truncate(time.Microsecond))
	if installation {
		event.TenantID, event.InstallationID = "", "organization-a"
		event.Action = auditv1.ActionIAMTenantEnabled
		event.Target = auditv1.TargetReference{Kind: auditv1.TargetOrganization, ID: "organization-a"}
		event.Actor = auditv1.ActorReference{Type: auditv1.ActorUser, ID: "principal-test"}
		event.IAMDecisionID = auditv1.DecisionID("decision-" + id)
	}
	return event
}

func assertIndependentAuditChainWriters(t *testing.T, ctx context.Context, admin *pgx.Conn, repository auditlog.Repository, iam *integrationIAM) {
	t.Helper()
	for round := 0; round < 3; round++ {
		t.Run(fmt.Sprintf("independent-chains-%d", round), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			arrived, resume := make(chan struct{}, 2), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			type outcome struct {
				result auditv1.IngestionResult
				err    error
			}
			done := make(chan outcome, 2)
			attempts := []*atomic.Int32{new(atomic.Int32), new(atomic.Int32)}
			events := []auditv1.Event{concurrentAuditEvent(fmt.Sprintf("independent-%d-0", round), false), concurrentAuditEvent(fmt.Sprintf("independent-%d-1", round), round%2 == 0)}
			if round%2 != 0 {
				events[1].TenantID = "organization-b"
			}
			for _, event := range events {
				chain := auditauthority.ChainFor(event.TenantID, event.InstallationID)
				if err := repository.WithinTransaction(ctx, func(ctx context.Context, tx auditlog.Transaction) error {
					_, _, err := tx.LockChainHead(ctx, chain)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			for index, event := range events {
				writer, err := auditlog.NewService(auditAppendPauseRepository{Repository: repository, arrived: arrived, resume: resume, attempts: attempts[index]}, iam, auditlog.Config{CursorKey: bytes.Repeat([]byte{0x6a}, 32), MaxTransactionAttempts: 1})
				if err != nil {
					t.Fatal(err)
				}
				credential := producerCredentialA
				if index == 1 {
					credential = producerCredentialB
					if event.InstallationID != "" {
						credential = platformProducerCredential
					}
				}
				secret, err := iamv1.NewSecret(credential)
				if err != nil {
					t.Fatal(err)
				}
				go func() { result, err := writer.Ingest(ctx, secret, event); done <- outcome{result, err} }()
			}
			for range 2 {
				select {
				case <-arrived:
				case result := <-done:
					t.Fatal("writer ended before independent head barrier", result.err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			release()
			for range 2 {
				select {
				case result := <-done:
					if result.err != nil || result.result.Outcome != auditv1.IngestionAccepted {
						t.Fatal("independent chain required conflict retry", result.err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			for _, count := range attempts {
				if count.Load() != 1 {
					t.Fatal("independent chain silently retried")
				}
			}
			for _, event := range events {
				chain := auditauthority.ChainFor(event.TenantID, event.InstallationID)
				if err := repository.WithinTransaction(ctx, func(ctx context.Context, tx auditlog.Transaction) error {
					records, err := tx.ReadChain(ctx, chain, 1, 1000)
					if err != nil {
						return err
					}
					genesis, err := auditauthority.GenesisCheckpoint(chain)
					if err != nil {
						return err
					}
					last, err := auditauthority.VerifyChain(genesis, records)
					if err != nil {
						return err
					}
					var head uint64
					if err := admin.QueryRow(ctx, "SELECT last_sequence FROM audit.chain_heads WHERE chain_id=$1", string(chain)).Scan(&head); err != nil {
						return err
					}
					if head != last.Sequence {
						return errors.New("head and immutable chain differ")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func assertCompetingAuditEvents(t *testing.T, parent context.Context, admin *pgx.Conn, repository auditlog.Repository, iam *integrationIAM) {
	t.Helper()
	// The installation chain has never been used: its first pair proves the
	// absent-head race, not merely concurrent updates of an existing head.
	for _, scenario := range []string{"genesis", "same-chain", "equal-event", "changed-event", "cross-scope-event", "rollback-after-append"} {
		t.Run("competing-"+scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(parent, 10*time.Second)
			defer cancel()
			first := concurrentAuditEvent("competing-"+scenario+"-a", scenario == "genesis")
			second := concurrentAuditEvent("competing-"+scenario+"-b", scenario == "genesis")
			if scenario == "equal-event" || scenario == "changed-event" {
				second = first
			}
			if scenario == "changed-event" {
				second.RequestDigest = "sha256:" + strings.Repeat("7", 64)
			}
			if scenario == "cross-scope-event" {
				second = concurrentAuditEvent(string(first.EventID), true)
			}
			chain := auditauthority.ChainFor(first.TenantID, first.InstallationID)
			var before uint64
			var headExists bool
			if err := admin.QueryRow(ctx, "SELECT COALESCE((SELECT last_sequence FROM audit.chain_heads WHERE chain_id=$1),0),EXISTS(SELECT 1 FROM audit.chain_heads WHERE chain_id=$1)", string(chain)).Scan(&before, &headExists); err != nil {
				t.Fatal(err)
			}
			if scenario == "genesis" && (before != 0 || headExists) {
				t.Fatal("genesis fixture already exists")
			}
			arrived, resume := make(chan struct{}, 1), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			firstAttempts, secondAttempts := new(atomic.Int32), new(atomic.Int32)
			writerA, err := auditlog.NewService(auditAppendPauseRepository{Repository: repository, arrived: arrived, resume: resume, attempts: firstAttempts, rejectAfterAppend: scenario == "rollback-after-append"}, iam, auditlog.Config{CursorKey: bytes.Repeat([]byte{0x6a}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			writerB, err := auditlog.NewService(auditAppendPauseRepository{Repository: repository, attempts: secondAttempts}, iam, auditlog.Config{CursorKey: bytes.Repeat([]byte{0x6a}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			type completed struct {
				result auditv1.IngestionResult
				err    error
			}
			doneA, doneB := make(chan completed, 1), make(chan completed, 1)
			start := func(writer *auditlog.Service, event auditv1.Event, done chan<- completed) {
				credential := producerCredentialA
				if event.InstallationID != "" {
					credential = platformProducerCredential
				}
				secret, err := iamv1.NewSecret(credential)
				if err != nil {
					t.Fatal(err)
				}
				go func() { result, err := writer.Ingest(ctx, secret, event); done <- completed{result, err} }()
			}
			start(writerA, first, doneA)
			select {
			case <-arrived:
			case result := <-doneA:
				t.Fatal("first writer ended before append barrier", result.err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			start(writerB, second, doneB)
			// Observe an actual PostgreSQL lock wait, not a sleep or goroutine
			// launch, before releasing the first transaction. B's snapshot is
			// already taken when it waits on event/head/genesis uniqueness.
			for {
				var waiting bool
				if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0)", auditHTTPTestRole).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case result := <-doneB:
					t.Fatal("second writer did not wait on the real event/head", result.err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(5 * time.Millisecond):
				}
			}
			release()
			var a, b completed
			select {
			case a = <-doneA:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case b = <-doneB:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			expectedIncrease := uint64(2)
			if scenario == "rollback-after-append" {
				if !errors.Is(a.err, auditlog.ErrUnavailable) || a.result.Record.Sequence != 0 || firstAttempts.Load() != 1 {
					t.Fatal("unknown/unavailable transaction was retried or returned a record", a.err)
				}
				expectedIncrease = 1
			} else if a.err != nil || a.result.Outcome != auditv1.IngestionAccepted || a.result.Record.Sequence != before+1 {
				t.Fatal("first writer failed", a.err)
			}
			switch scenario {
			case "equal-event":
				expectedIncrease = 1
				if b.err != nil || b.result.Outcome != auditv1.IngestionDuplicate || b.result.Record.RecordHash != a.result.Record.RecordHash || b.result.Record.Sequence != a.result.Record.Sequence || secondAttempts.Load() < 2 {
					t.Fatal("waiting equal event did not retry its old snapshot and return the exact original", b.err)
				}
			case "changed-event", "cross-scope-event":
				expectedIncrease = 1
				if !errors.Is(b.err, auditlog.ErrConflict) || b.result.Record.Sequence != 0 {
					t.Fatal("changed replay did not remain a conflict", b.err)
				}
			default:
				if b.err != nil || b.result.Outcome != auditv1.IngestionAccepted || b.result.Record.Sequence != before+expectedIncrease {
					t.Fatal("same-chain writer lost ordering or genesis", b.err)
				}
				if scenario != "rollback-after-append" && secondAttempts.Load() < 2 {
					t.Fatal("changed head did not trigger a whole-transaction retry")
				}
			}
			var after, records, registry uint64
			if err := admin.QueryRow(ctx, "SELECT (SELECT last_sequence FROM audit.chain_heads WHERE chain_id=$1),(SELECT count(*) FROM audit.records WHERE chain_id=$1),(SELECT count(*) FROM audit.event_registry WHERE chain_id=$1)", string(chain)).Scan(&after, &records, &registry); err != nil {
				t.Fatal(err)
			}
			if after != before+expectedIncrease || records != after || registry != after {
				t.Fatalf("head/record/registry partial write: before=%d after=%d records=%d registry=%d", before, after, records, registry)
			}
			if scenario == "rollback-after-append" {
				var records, registry int
				if err := admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM audit.records WHERE source='IAM' AND event_id=$1),(SELECT count(*) FROM audit.event_registry WHERE source='IAM' AND event_id=$1)", string(first.EventID)).Scan(&records, &registry); err != nil {
					t.Fatal(err)
				}
				if records != 0 || registry != 0 {
					t.Fatal("rolled-back event left durable evidence")
				}
			}
			if err := repository.WithinTransaction(ctx, func(ctx context.Context, tx auditlog.Transaction) error {
				records, err := tx.ReadChain(ctx, chain, 1, 1000)
				if err != nil {
					return err
				}
				checkpoint, err := auditauthority.GenesisCheckpoint(chain)
				if err != nil {
					return err
				}
				last, err := auditauthority.VerifyChain(checkpoint, records)
				if err != nil {
					return err
				}
				if last.Sequence != after {
					return errors.New("committed chain does not reach its head")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A read is itself a chain writer because a successful response must commit
// its access fact. Pause after the real database read, then try the real
// restricted writer on another connection: the selected head must already be
// protected, while the other tenant's head must remain independently writable.
func assertAuditedReadSerialization(t *testing.T, ctx context.Context, admin *pgx.Conn, pool *pgxpool.Pool, repository auditlog.Repository, iam *integrationIAM) {
	t.Helper()
	for _, verify := range []bool{false, true} {
		for _, reject := range []bool{false, true} {
			t.Run(fmt.Sprintf("audited-read-verify-%t-reject-%t", verify, reject), func(t *testing.T) {
				arrived, resume := make(chan struct{}, 1), make(chan struct{})
				release := sync.OnceFunc(func() { close(resume) })
				defer release()
				workflow, err := auditlog.NewService(auditReadPauseRepository{Repository: repository, arrived: arrived, resume: resume, reject: reject}, iam, auditlog.Config{CursorKey: bytes.Repeat([]byte{0x6a}, 32)})
				if err != nil {
					t.Fatal(err)
				}
				requestID := fmt.Sprintf("request-locked-read-%t-%t", verify, reject)
				handler, err := audithttp.NewHandler(workflow, audithttp.Config{NewRequestID: func() (string, error) { return requestID, nil }})
				if err != nil {
					t.Fatal(err)
				}
				var before uint64
				var beforeHash string
				if err := admin.QueryRow(ctx, "SELECT last_sequence,last_record_hash FROM audit.chain_heads WHERE chain_id='tenant:organization-a'").Scan(&before, &beforeHash); err != nil {
					t.Fatal(err)
				}
				path := "/v1/records:query"
				var request any = auditv1.QueryRecordsRequest{PageSize: 100}
				if verify {
					path, request = "/v1/integrity:verify", auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 100}
				}
				body := mustJSON(t, request)
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- performAuditRequest(handler, http.MethodPost, path, readerCredentialA, body) }()
				select {
				case <-arrived:
				case response := <-done:
					t.Fatalf("audited read ended before contention probe: %d", response.Code)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				tryHead := func(chainID string) error {
					tx, err := pool.Begin(ctx)
					if err != nil {
						return err
					}
					defer func() { _ = tx.Rollback(context.Background()) }()
					if _, err = tx.Exec(ctx, "SET LOCAL lock_timeout='150ms'"); err != nil {
						return err
					}
					_, err = tx.Exec(ctx, "SELECT * FROM audit.lock_chain_head($1)", chainID)
					return err
				}
				selectedErr, otherErr := tryHead("tenant:organization-a"), tryHead("tenant:organization-b")
				release()
				var response *httptest.ResponseRecorder
				select {
				case response = <-done:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				assertPostgresCode(t, selectedErr, "55P03")
				if otherErr != nil {
					t.Fatalf("an audited read blocked a different tenant: %v", otherErr)
				}
				var after uint64
				var facts int
				if err := admin.QueryRow(ctx, "SELECT last_sequence FROM audit.chain_heads WHERE chain_id='tenant:organization-a'").Scan(&after); err != nil {
					t.Fatal(err)
				}
				if err := admin.QueryRow(ctx, "SELECT count(*) FROM audit.records WHERE source='AUDIT' AND event_document->>'requestId'=$1", requestID).Scan(&facts); err != nil {
					t.Fatal(err)
				}
				if reject {
					if response.Code != http.StatusConflict || after != before || facts != 0 {
						t.Fatal("failed read committed an access fact or changed the head")
					}
					return
				}
				if response.Code != http.StatusOK || after != before+1 || facts != 1 {
					t.Fatalf("audited read did not commit exactly one access fact: status=%d before=%d after=%d facts=%d", response.Code, before, after, facts)
				}
				if verify {
					var result auditv1.ChainVerification
					if json.Unmarshal(response.Body.Bytes(), &result) != nil || auditv1.ValidateChainVerification(result) != nil || result.FromSequence != 1 || result.ToSequence != before || uint64(result.RecordCount) != before || result.LastRecordHash != beforeHash || !result.Complete {
						t.Fatal("verification did not return the complete locked prefix excluding its own fact")
					}
				} else {
					var result auditv1.RecordPage
					if json.Unmarshal(response.Body.Bytes(), &result) != nil || auditv1.ValidateRecordPage(result) != nil || len(result.Records) == 0 || uint64(len(result.Records)) != before || result.Records[0].RecordHash != beforeHash || result.NextCursor != "" {
						t.Fatal("query did not return the complete locked prefix excluding its own fact")
					}
					for index, record := range result.Records {
						if record.Sequence != before-uint64(index) || record.Event.TenantID != "organization-a" || record.Event.InstallationID != "" {
							t.Fatal("query returned a gap, duplicate, or another chain in the locked prefix")
						}
					}
				}
			})
		}
	}
}

type auditReadPauseRepository struct {
	auditlog.Repository
	arrived chan<- struct{}
	resume  <-chan struct{}
	reject  bool
}

func (repository auditReadPauseRepository) WithinTransaction(ctx context.Context, callback func(context.Context, auditlog.Transaction) error) error {
	return repository.Repository.WithinTransaction(ctx, func(ctx context.Context, transaction auditlog.Transaction) error {
		return callback(ctx, auditReadPauseTransaction{Transaction: transaction, repository: repository})
	})
}

type auditReadPauseTransaction struct {
	auditlog.Transaction
	repository auditReadPauseRepository
}

func (transaction auditReadPauseTransaction) pause(ctx context.Context) error {
	select {
	case transaction.repository.arrived <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-transaction.repository.resume:
	}
	if transaction.repository.reject {
		return auditlog.ErrConflict
	}
	return nil
}

func (transaction auditReadPauseTransaction) ReadRecords(ctx context.Context, query auditlog.RecordQuery) ([]auditv1.AuditRecord, error) {
	result, err := transaction.Transaction.ReadRecords(ctx, query)
	if err == nil {
		err = transaction.pause(ctx)
	}
	return result, err
}

func (transaction auditReadPauseTransaction) ReadChain(ctx context.Context, chainID auditauthority.ChainID, from uint64, limit int) ([]auditv1.AuditRecord, error) {
	result, err := transaction.Transaction.ReadChain(ctx, chainID, from, limit)
	if err == nil {
		err = transaction.pause(ctx)
	}
	return result, err
}

func verifyInstallationAudit(
	t *testing.T,
	handler http.Handler,
	credential string,
	request auditv1.VerifyInstallationRequest,
	status int,
) auditv1.InstallationVerification {
	t.Helper()
	response := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/installation:verify",
		credential,
		mustJSON(t, request),
	)
	if response.Code != status {
		t.Fatalf("installation Audit verification status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if status != http.StatusOK {
		return auditv1.InstallationVerification{}
	}
	var verification auditv1.InstallationVerification
	if err := json.Unmarshal(response.Body.Bytes(), &verification); err != nil ||
		auditv1.ValidateInstallationVerification(verification) != nil {
		t.Fatalf("decode installation Audit verification=%#v err=%v", verification, err)
	}
	return verification
}

func integrationEvent(
	eventID auditv1.EventID,
	tenantID auditv1.TenantID,
	action auditv1.Action,
	targetKind auditv1.TargetKind,
	targetID string,
	occurredAt time.Time,
) auditv1.Event {
	return auditv1.Event{
		APIVersion: auditv1.APIVersion,
		Kind:       "AuditEvent",
		EventID:    eventID,
		TenantID:   tenantID,
		Actor: auditv1.ActorReference{
			Type: auditv1.ActorServiceAccount,
			ID:   "service-iam",
		},
		Action:        action,
		Target:        auditv1.TargetReference{Kind: targetKind, ID: targetID},
		Result:        auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("2", 64),
		RequestID:     "request-" + string(eventID),
		CorrelationID: "correlation-" + string(eventID),
		OccurredAt:    occurredAt,
	}
}

func ingestAuditEvent(
	t *testing.T,
	handler http.Handler,
	credential string,
	event auditv1.Event,
	status int,
) auditv1.IngestionResult {
	t.Helper()
	response := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/events",
		credential,
		mustJSON(t, event),
	)
	if response.Code != status {
		t.Fatalf("Audit ingest %s status=%d want=%d body=%s", event.EventID, response.Code, status, response.Body.String())
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return auditv1.IngestionResult{}
	}
	var result auditv1.IngestionResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil ||
		auditv1.ValidateIngestionResult(result) != nil {
		t.Fatalf("decode Audit ingestion result=%#v err=%v", result, err)
	}
	return result
}

func queryAuditRecords(
	t *testing.T,
	handler http.Handler,
	credential string,
	request auditv1.QueryRecordsRequest,
	status int,
) auditv1.RecordPage {
	t.Helper()
	response := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/records:query",
		credential,
		mustJSON(t, request),
	)
	if response.Code != status {
		t.Fatalf("Audit query status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if status != http.StatusOK {
		return auditv1.RecordPage{}
	}
	var page auditv1.RecordPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil ||
		auditv1.ValidateRecordPage(page) != nil {
		t.Fatalf("decode Audit record page=%#v err=%v", page, err)
	}
	return page
}

func verifyAuditChain(
	t *testing.T,
	handler http.Handler,
	credential string,
	request auditv1.VerifyChainRequest,
	status int,
) auditv1.ChainVerification {
	t.Helper()
	response := performAuditRequest(
		handler,
		http.MethodPost,
		"/v1/integrity:verify",
		credential,
		mustJSON(t, request),
	)
	if response.Code != status {
		t.Fatalf("Audit verification status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if status != http.StatusOK {
		return auditv1.ChainVerification{}
	}
	var verification auditv1.ChainVerification
	if err := json.Unmarshal(response.Body.Bytes(), &verification); err != nil ||
		auditv1.ValidateChainVerification(verification) != nil {
		t.Fatalf("decode Audit chain verification=%#v err=%v", verification, err)
	}
	return verification
}

func performAuditRequest(
	handler http.Handler,
	method string,
	target string,
	bearer string,
	body []byte,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode Audit HTTP value: %v", err)
	}
	return encoded
}

func assertAuditPostgres18(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var version int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil {
		t.Fatalf("read PostgreSQL version: %v", err)
	}
	if version < 180000 || version >= 190000 {
		t.Fatalf("PostgreSQL version=%d want major 18", version)
	}
}

func assertCleanAuditSchema(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT to_regnamespace('audit') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatalf("inspect Audit schema: %v", err)
	}
	if exists {
		t.Fatal("Audit HTTP integration database is not clean")
	}
}

func applyAuditSchema(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	if err := auditmigration.Bootstrap(ctx, admin); err != nil {
		t.Fatalf("bootstrap Audit migration: %v", err)
	}
	if err := auditmigration.Up(ctx, admin); err != nil {
		t.Fatalf("apply Audit migration: %v", err)
	}
	if err := auditmigration.Verify(ctx, admin); err != nil {
		t.Fatalf("verify Audit migration: %v", err)
	}
}

func createAuditHTTPRole(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	statement := `DO $matrix_audit_http_role$
	BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '` + auditHTTPTestRole + `') THEN
			CREATE ROLE ` + auditHTTPTestRole + ` LOGIN
				NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		END IF;
	END
	$matrix_audit_http_role$;
	ALTER ROLE ` + auditHTTPTestRole + ` PASSWORD '` + auditHTTPTestPassword + `';
	GRANT matrix_audit_runtime TO ` + auditHTTPTestRole + `;`
	if _, err := admin.Exec(ctx, statement); err != nil {
		t.Fatalf("create Audit HTTP runtime role: %v", err)
	}
}

func assertAuditFacts(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var tenantA, tenantB, unexpectedTenants, accessA, accessB, verifierAccess, verifierAccessWithoutDecision int
	if err := admin.QueryRow(
		ctx,
		`SELECT
			count(*) FILTER (WHERE tenant_id = 'organization-a'),
			count(*) FILTER (WHERE tenant_id = 'organization-b'),
			count(*) FILTER (WHERE tenant_id NOT IN ('organization-a', 'organization-b')),
			count(*) FILTER (
				WHERE tenant_id = 'organization-a' AND source = 'AUDIT'
			),
			count(*) FILTER (
				WHERE tenant_id = 'organization-b' AND source = 'AUDIT'
			),
			count(*) FILTER (
				WHERE tenant_id = 'organization-a'
				  AND source = 'AUDIT'
				  AND event_document->>'action' = $1
				  AND event_document#>>'{actor,type}' = 'SERVICE_ACCOUNT'
				  AND event_document#>>'{actor,id}' = 'service-installation-verifier'
				  AND event_document#>>'{target,id}' = 'installation-verification'
			),
			count(*) FILTER (
				WHERE tenant_id = 'organization-a'
				  AND source = 'AUDIT'
				  AND event_document->>'action' = $1
				  AND event_document#>>'{actor,id}' = 'service-installation-verifier'
				  AND COALESCE(event_document->>'iamDecisionId', '') = ''
			)
		 FROM audit.records`,
		string(auditv1.ActionAuditIntegrityVerified),
	).Scan(
		&tenantA, &tenantB, &unexpectedTenants, &accessA, &accessB,
		&verifierAccess, &verifierAccessWithoutDecision,
	); err != nil {
		t.Fatalf("inspect Audit HTTP facts: %v", err)
	}
	if tenantA == 0 || tenantB == 0 || unexpectedTenants != 0 ||
		accessA == 0 || accessB == 0 || verifierAccess != 1 ||
		verifierAccessWithoutDecision != 0 {
		t.Fatalf(
			"Audit facts tenantA=%d tenantB=%d unexpected=%d accessA=%d accessB=%d verifierAccess=%d verifierMissingDecision=%d",
			tenantA, tenantB, unexpectedTenants, accessA, accessB,
			verifierAccess, verifierAccessWithoutDecision,
		)
	}
}

func assertAuditRuntimeBoundary(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) {
	t.Helper()
	var count int
	err := pool.QueryRow(ctx, "SELECT count(*) FROM audit.records").Scan(&count)
	assertPostgresCode(t, err, "42501")
	err = pool.QueryRow(
		ctx,
		`SELECT audit.calculate_record_hash(
			'organization-a', 1, repeat('a', 71), repeat('b', 71),
			transaction_timestamp(), 'INDEFINITE'
		)`,
	).Scan(new(string))
	assertPostgresCode(t, err, "42501")
}

func assertPostgresCode(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("PostgreSQL error=%v want code=%s", err, code)
	}
}

func assertAuditPlaintextAbsent(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	plaintexts ...string,
) {
	t.Helper()
	for _, plaintext := range plaintexts {
		var present bool
		if err := admin.QueryRow(
			ctx,
			`SELECT EXISTS (
				SELECT 1 FROM audit.records
				 WHERE event_document::text LIKE '%' || $1 || '%'
				    OR canonical_document LIKE '%' || $1 || '%'
			)`,
			plaintext,
		).Scan(&present); err != nil {
			t.Fatalf("inspect Audit plaintext storage: %v", err)
		}
		if present {
			t.Fatal("Audit stored credential plaintext")
		}
	}
}

type integrationIAM struct {
	now      time.Time
	sequence int
	failure  error
}

func (client *integrationIAM) ResolveAuditProducer(
	_ context.Context,
	credential iamv1.Secret,
	request iamv1.ResolveAuditProducerRequest,
) (iamv1.AuditProducerAuthorization, error) {
	organizationID := iamv1.AccountID("")
	purpose := iamv1.ServiceIAM
	principalID := iamv1.PrincipalID("service-iam")
	installationID := "installation-example"
	switch {
	case secretEquals(credential, producerCredentialA):
		organizationID = "organization-a"
	case secretEquals(credential, producerCredentialB):
		organizationID = "organization-b"
	case secretEquals(credential, platformProducerCredential):
		organizationID, installationID = "organization-a", "organization-a"
	case secretEquals(credential, paasProducerCredential):
		organizationID, purpose, principalID = "organization-a", iamv1.ServicePaaS, "service-paas"
	default:
		return iamv1.AuditProducerAuthorization{}, auditlog.ErrUnauthenticated
	}
	if secretEquals(credential, platformProducerCredential) {
		if request.Event.InstallationID != installationID || request.Event.TenantID != "" {
			return iamv1.AuditProducerAuthorization{}, auditlog.ErrForbidden
		}
	} else if request.Event.TenantID != "organization-a" && request.Event.TenantID != "organization-b" {
		return iamv1.AuditProducerAuthorization{}, auditlog.ErrForbidden
	}
	source := auditv1.SourceIAM
	if purpose == iamv1.ServicePaaS {
		source = auditv1.SourcePaaS
	}
	_, digest, err := auditv1.CanonicalizeEvent(source, request.Event)
	if err != nil {
		return iamv1.AuditProducerAuthorization{}, auditlog.ErrInvalidArgument
	}
	return iamv1.AuditProducerAuthorization{
		APIVersion: iamv1.APIVersion, Kind: "AuditProducerAuthorization",
		TenantID: iamv1.AccountID(request.Event.TenantID), InstallationID: request.Event.InstallationID, ContentDigest: digest,
		Producer: iamv1.ServiceIdentity{
			APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity",
			InstallationID: installationID,
			AccountID:      organizationID, PrincipalID: principalID, Purpose: purpose,
		},
	}, nil
}

func (client *integrationIAM) Authorize(
	_ context.Context,
	credential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if client.failure != nil {
		return iamv1.AuthorizationDecision{}, client.failure
	}
	client.sequence++
	decision := iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion,
		Kind:       "AuthorizationDecision",
		ID:         iamv1.DecisionID(fmt.Sprintf("decision-http-%d", client.sequence)),
		Allowed:    true,
		Reason:     iamv1.DecisionAllowed,
		Subject:    &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-reader"},
		Action:     request.Action,
		Resource:   request.Resource,
		RequestID:  request.RequestID,
		DecidedAt:  client.now,
		Profile:    &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage, CorrelationID: request.CorrelationID,
	}
	switch {
	case secretEquals(credential, readerCredentialA):
		decision.TenantID = "organization-a"
	case secretEquals(credential, readerCredentialB):
		decision.TenantID = "organization-b"
	case secretEquals(credential, deniedCredential):
		decision.Allowed = false
		decision.Reason = iamv1.DecisionDenied
		decision.Subject = nil
	default:
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnauthenticated
	}
	return decision, nil
}

func (client *integrationIAM) VerifyInstallation(
	_ context.Context,
	credential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if client.failure != nil {
		return iamv1.AuthorizationDecision{}, client.failure
	}
	if !secretEquals(credential, verifierCredential) {
		return iamv1.AuthorizationDecision{}, auditlog.ErrUnauthenticated
	}
	client.sequence++
	return iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
		ID:      iamv1.DecisionID(fmt.Sprintf("decision-http-%d", client.sequence)),
		Allowed: true, Reason: iamv1.DecisionAllowed,
		TenantID: "organization-a",
		Subject: &iamv1.Subject{
			Type: iamv1.SubjectServiceAccount, ID: "service-installation-verifier",
		},
		Action: request.Action, Resource: request.Resource,
		RequestID: request.RequestID, DecidedAt: client.now,
		Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage, CorrelationID: request.CorrelationID,
	}, nil
}

func secretEquals(secret iamv1.Secret, expected string) bool {
	actual := secret.CopyBytes()
	defer clear(actual)
	return subtle.ConstantTimeCompare(actual, []byte(expected)) == 1
}
