package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/terminalsession"
)

func assertTerminalSessionPersistence(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool, workerPool *pgxpool.Pool,
	fixture integrationFixture,
	prefix string,
) {
	t.Helper()
	deploymentID := paasv1.ResourceID(prefix + "-terminal-deployment")
	operationID := paasv1.OperationID(prefix + "-terminal-operation")
	decisionID := paasv1.ResourceID(prefix + "-terminal-placement")
	targetID := paasv1.ResourceID(prefix + "-node-a")
	instanceID := paasv1.ResourceID("instance-fedcba9876543210fedcba9876543210")

	var now time.Time
	if err := admin.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	now = databaseTime(now)
	seedDeployment(t, ctx, admin, fixture, deploymentID, operationID, now)

	var targetVersion uint64
	if err := admin.QueryRow(
		ctx,
		"SELECT resource_version FROM paas.execution_targets WHERE id=$1 AND binding_ref='node-binding'",
		targetID,
	).Scan(&targetVersion); err != nil {
		t.Fatalf("load terminal execution target: %v", err)
	}
	decision := paasv1.PlacementDecision{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementDecision",
		Metadata: integrationMetadata(
			decisionID, "terminal-placement", paasv1.AuthorityTenant, fixture.tenantA, 1, now, false,
		),
		DeploymentID:                   deploymentID,
		DeploymentGeneration:           1,
		DeploymentResourceVersion:      1,
		ApplicationRevisionID:          fixture.revisionID,
		PlacementPolicyID:              fixture.policyID,
		PolicyResourceVersion:          1,
		RequestedIsolationGuarantee:    paasv1.IsolationWorkload,
		Outcome:                        paasv1.PlacementScheduled,
		ExecutionTargetID:              targetID,
		ExecutionTargetResourceVersion: targetVersion,
		GrantedIsolationGuarantee:      paasv1.IsolationWorkload,
		CandidateSetDigest:             integrationDigest(prefix + "-terminal-candidates"),
		DecidedAt:                      now,
	}
	if err := paasv1.ValidatePlacementDecision(decision); err != nil {
		t.Fatalf("invalid terminal placement: %v", err)
	}
	execDocument(
		t,
		ctx,
		admin,
		`INSERT INTO paas.placement_decisions (
		    tenant_id,id,operation_id,request_digest,deployment_id,
		    deployment_generation,deployment_resource_version,
		    application_revision_id,policy_id,policy_resource_version,
		    requested_isolation,outcome,execution_target_id,
		    execution_target_resource_version,granted_isolation,
		    candidate_digest,reason,decided_at,document
		 ) VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NULL,$17,$18::jsonb
		 )`,
		fixture.tenantA,
		decisionID,
		operationID,
		integrationDigest(prefix+"-terminal-placement-request"),
		deploymentID,
		1,
		1,
		fixture.revisionID,
		fixture.policyID,
		1,
		paasv1.IsolationWorkload,
		paasv1.PlacementScheduled,
		targetID,
		targetVersion,
		paasv1.IsolationWorkload,
		decision.CandidateSetDigest,
		now,
		integrationJSON(t, decision),
	)
	if _, err := admin.Exec(
		ctx,
		`UPDATE paas.deployments
		    SET document=jsonb_set(document,'{status,placementDecisionId}',to_jsonb($3::text),true)
		  WHERE tenant_id=$1 AND id=$2`,
		fixture.tenantA,
		deploymentID,
		decisionID,
	); err != nil {
		t.Fatalf("bind terminal Deployment placement: %v", err)
	}

	observation := paasv1.DeploymentRuntimeObservation{
		DeploymentID: deploymentID, Generation: 1,
		ApplicationRevisionID: fixture.revisionID,
		ExecutionTargetID:     targetID,
		Instances: []paasv1.DeploymentRuntimeInstance{{
			ID: instanceID, ComponentName: "web",
			State: paasv1.DeploymentInstanceRunning, Health: paasv1.DeploymentInstanceHealthHealthy,
		}},
		ObservedAt: now,
	}
	if err := paasv1.ValidateDeploymentRuntimeObservation(observation); err != nil {
		t.Fatalf("invalid terminal runtime: %v", err)
	}
	var runtimeStored bool
	if err := workerPool.QueryRow(
		ctx,
		`SELECT paas.store_deployment_runtime_snapshot(
		    $1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb
		 )`,
		fixture.tenantA,
		deploymentID,
		1,
		fixture.revisionID,
		targetID,
		decisionID,
		now,
		now.Add(45*time.Second),
		integrationJSON(t, observation),
	).Scan(&runtimeStored); err != nil || !runtimeStored {
		t.Fatalf("store terminal runtime: stored=%v err=%v", runtimeStored, err)
	}

	repository, err := NewTerminalSessionRepository(apiPool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := terminalsession.New(repository, terminalsession.Config{MaxTransactionAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}
	authorization := port.Authorization{
		TenantID:   fixture.tenantA,
		Subject:    paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "terminal-user"},
		DecisionID: "terminal-create-decision", RequestID: "terminal-create-request",
	}
	command := terminalsession.CreateCommand{
		Authorization: authorization, DeploymentID: deploymentID,
		Request: paasv1.CreateTerminalSessionRequest{
			InstanceID: instanceID, Size: paasv1.TerminalSize{Columns: 120, Rows: 40},
		},
		IdempotencyKey: "terminal-create", TicketDigest: integrationDigest(prefix + "-ticket-one"),
	}
	created, err := service.Create(ctx, command)
	if err != nil || created.Replayed || created.Stored.Session.State != paasv1.TerminalSessionPending ||
		created.Stored.Binding.ExecutionTargetID != targetID || created.Stored.Binding.BindingRef != "node-binding" {
		t.Fatalf("create persisted terminal: %#v err=%v", created, err)
	}

	replay := command
	replay.TicketDigest = integrationDigest(prefix + "-ticket-two")
	replayed, err := service.Create(ctx, replay)
	if err != nil || !replayed.Replayed || replayed.Stored.Session.ID != created.Stored.Session.ID {
		t.Fatalf("rotate persisted terminal ticket: %#v err=%v", replayed, err)
	}
	if _, err := service.Consume(ctx, created.Stored.Session.ID, command.TicketDigest); !errors.Is(err, terminalsession.ErrNotFound) {
		t.Fatalf("rotated terminal ticket remained usable: %v", err)
	}
	consumed, err := service.Consume(ctx, created.Stored.Session.ID, replay.TicketDigest)
	if err != nil || consumed.Session.State != paasv1.TerminalSessionConnecting {
		t.Fatalf("consume persisted terminal ticket: %#v err=%v", consumed, err)
	}
	active, err := service.Activate(ctx, consumed)
	if err != nil || active.Session.State != paasv1.TerminalSessionActive || active.Session.ConnectedAt == nil {
		t.Fatalf("activate persisted terminal: %#v err=%v", active, err)
	}

	other := authorization
	other.Subject.ID = "other-terminal-user"
	if _, _, err := service.Close(ctx, terminalsession.CloseCommand{
		Authorization: other, SessionID: active.Session.ID,
	}); !errors.Is(err, terminalsession.ErrPermissionDenied) {
		t.Fatalf("another subject closed terminal: %v", err)
	}
	closed, changed, err := service.Close(ctx, terminalsession.CloseCommand{
		Authorization: authorization, SessionID: active.Session.ID,
	})
	if err != nil || !changed || closed.Session.State != paasv1.TerminalSessionEnded ||
		closed.Session.Outcome != paasv1.TerminalSessionRevoked {
		t.Fatalf("close persisted terminal: changed=%v session=%#v err=%v", changed, closed, err)
	}
	if _, err := service.Consume(ctx, active.Session.ID, replay.TicketDigest); !errors.Is(err, terminalsession.ErrNotFound) {
		t.Fatalf("consumed terminal ticket was reusable: %v", err)
	}
	if _, err := service.Create(ctx, replay); !errors.Is(err, terminalsession.ErrConflict) {
		t.Fatalf("consumed idempotency key opened a new terminal: %v", err)
	}

	var state, outcome string
	var ticketCleared bool
	var facts, operationFacts, targetFacts int
	if err := admin.QueryRow(
		ctx,
		`SELECT state,outcome,ticket_digest IS NULL,
		        (SELECT count(*) FROM paas.audit_outbox
		          WHERE tenant_id=$1 AND terminal_session_id=$2),
		        (SELECT count(*) FROM paas.audit_outbox
		          WHERE tenant_id=$1 AND terminal_session_id=$2 AND operation_id IS NOT NULL),
		        (SELECT count(*) FROM paas.audit_outbox
		          WHERE tenant_id=$1 AND terminal_session_id=$2
		            AND document#>>'{target,kind}'='TerminalSession'
		            AND NOT (document ? 'operationId'))
		   FROM paas.terminal_sessions WHERE tenant_id=$1 AND id=$2`,
		fixture.tenantA,
		active.Session.ID,
	).Scan(&state, &outcome, &ticketCleared, &facts, &operationFacts, &targetFacts); err != nil {
		t.Fatalf("read terminal persistence proof: %v", err)
	}
	if state != "ENDED" || outcome != "REVOKED" || !ticketCleared ||
		facts != 3 || operationFacts != 0 || targetFacts != 3 {
		t.Fatalf(
			"terminal persistence state=%s outcome=%s ticketCleared=%v facts=%d operationFacts=%d targetFacts=%d",
			state, outcome, ticketCleared, facts, operationFacts, targetFacts,
		)
	}
	if _, err := apiPool.Exec(ctx, "SELECT ticket_digest FROM paas.terminal_sessions"); err == nil {
		t.Fatal("API role could read terminal ticket digests directly")
	}
}
