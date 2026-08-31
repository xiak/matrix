package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
	auditpostgres "github.com/xiak/matrix/app/service/paas/internal/audit/data/postgres"
	"github.com/xiak/matrix/app/service/paas/internal/audit/usecase/auditdispatch"
)

// Extends the existing disposable PostgreSQL gate. This adapter supplies
// deterministic host facts; authenticated real-node behavior has its own
// process gate and is not inferred from this storage/transaction exercise.
func assertExecutionAdmission(t *testing.T, ctx context.Context, admin *pgx.Conn, apiPool, workerPool *pgxpool.Pool, prefix string) {
	t.Helper()
	installationID := prefix + "-installation"
	poolID, targetID := paasv1.ResourceID(prefix+"-nodes"), paasv1.ResourceID(prefix+"-node-a")
	adapter := &admissionAdapter{targetID: targetID, fingerprint: integrationDigest("node-" + prefix)}
	repository, err := NewExecutionAdmissionRepository(apiPool)
	if err != nil {
		t.Fatal(err)
	}
	config := executionadmission.Config{InstallationID: installationID, Bindings: []executionadmission.Binding{{Ref: "node-binding", TargetID: targetID, IdentityFingerprint: adapter.fingerprint, Adapter: adapter}},
		ObservationTimeout: time.Second, MaximumObservationAge: 15 * time.Second, MaxTransactionAttempts: 10}
	service, err := executionadmission.New(repository, config)
	if err != nil {
		t.Fatal(err)
	}
	authorization := port.Authorization{InstallationID: installationID, Subject: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"}, DecisionID: "decision-platform", RequestID: "request-platform"}
	create := executionadmission.CreatePoolCommand{Authorization: authorization, IdempotencyKey: "create-nodes", Request: paasv1.CreateExecutionPoolRequest{ID: poolID, Name: "nodes", Spec: paasv1.ExecutionPoolSpec{AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}}}}
	pool, poolOperation, replayed, err := service.CreatePool(ctx, create)
	if err != nil || replayed || pool.Metadata.ResourceVersion != 1 || poolOperation.InstallationID != installationID || poolOperation.Scope.TenantID != "" {
		t.Fatalf("create installation pool: replay=%v op=%#v err=%v", replayed, poolOperation, err)
	}
	_, replay, replayed, err := service.CreatePool(ctx, create)
	if err != nil || !replayed || replay.ID != poolOperation.ID {
		t.Fatalf("pool replay: replay=%v err=%v", replayed, err)
	}
	changed := create
	changed.Request.Name = "changed"
	if _, _, _, err := service.CreatePool(ctx, changed); !errors.Is(err, executionadmission.ErrIdempotencyConflict) {
		t.Fatalf("pool changed replay = %v", err)
	}
	changed = create
	changed.Authorization.TenantID = paasv1.TenantID(installationID)
	if _, _, _, err := service.CreatePool(ctx, changed); !errors.Is(err, port.ErrPermissionDenied) {
		t.Fatalf("mixed authority create = %v", err)
	}

	registration := executionadmission.RegisterTargetCommand{Authorization: authorization, IdempotencyKey: "register-node", Request: paasv1.RegisterExecutionTargetRequest{ID: targetID, Name: "node-a", ExecutionPoolID: poolID, BindingRef: "node-binding", Labels: map[string]string{"rack": "rack-a"}}}
	badBinding := registration
	badBinding.Request.BindingRef = "unconfigured"
	if _, _, _, err := service.RegisterTarget(ctx, badBinding); !errors.Is(err, executionadmission.ErrConflict) || adapter.calls.Load() != 0 {
		t.Fatalf("unconfigured binding reached node: %v", err)
	}
	var results [2]paasv1.Operation
	var registrationErrors [2]error
	var workers sync.WaitGroup
	for index := range results {
		workers.Go(func() { _, results[index], _, registrationErrors[index] = service.RegisterTarget(ctx, registration) })
	}
	workers.Wait()
	for index, err := range registrationErrors {
		if err != nil || results[index].ID == "" || results[index].ID != results[0].ID {
			t.Fatalf("concurrent node registration %d: %v %#v", index, err, results)
		}
	}
	var resourceCount, operationCount, eventCount int
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM paas.execution_targets WHERE installation_id=$1),
		(SELECT count(*) FROM paas.operations WHERE installation_id=$1),(SELECT count(*) FROM paas.audit_outbox WHERE installation_id=$1)`, installationID).Scan(&resourceCount, &operationCount, &eventCount); err != nil {
		t.Fatal(err)
	}
	if resourceCount != 1 || operationCount != 2 || eventCount != 2 {
		t.Fatalf("admission was not atomic/deduplicated: target=%d operations=%d events=%d", resourceCount, operationCount, eventCount)
	}
	target, err := service.GetTarget(ctx, authorization, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if target.Metadata.Labels["matrix-machine-fingerprint"] != adapter.fingerprint || target.Spec.DesiredState != paasv1.ExecutionTargetActive || target.Status.Usage == nil {
		t.Fatalf("registered target = %#v", target)
	}
	var documentBefore string
	if err := admin.QueryRow(ctx, `SELECT document::text FROM paas.execution_targets
		WHERE installation_id=$1 AND id=$2`, installationID, targetID).Scan(&documentBefore); err != nil {
		t.Fatal(err)
	}
	callsBeforeList := adapter.calls.Load()
	inventory, err := service.ListTargets(ctx, authorization)
	if err != nil || paasv1.ValidateExecutionTargetList(inventory) != nil || len(inventory.Items) != 1 ||
		inventory.Items[0].Metadata.ID != targetID || adapter.calls.Load() != callsBeforeList {
		t.Fatalf("installation inventory probed or crossed scope: inventory=%#v calls=%d err=%v", inventory, adapter.calls.Load(), err)
	}
	var documentAfter string
	if err := admin.QueryRow(ctx, `SELECT document::text FROM paas.execution_targets
		WHERE installation_id=$1 AND id=$2`, installationID, targetID).Scan(&documentAfter); err != nil {
		t.Fatal(err)
	}
	if documentAfter != documentBefore || inventory.Items[0].Status.Usage.ObservedAt != target.Status.Usage.ObservedAt {
		t.Fatal("inventory read renewed or persisted a source observation")
	}
	pool, err = service.GetPool(ctx, authorization, poolID)
	if err != nil || pool.Status.ReadyExecutionTargetCount != 1 {
		t.Fatalf("registered pool = %#v %v", pool, err)
	}
	if operation, err := service.GetOperation(ctx, authorization, results[0].ID); err != nil || operation.InstallationID != installationID {
		t.Fatalf("read platform Operation: %v", err)
	}
	tenantRepository, _ := NewApplicationRepository(apiPool)
	tenantWorkflow, _ := applicationlifecycle.NewUsecase(tenantRepository, applicationlifecycle.Config{MaxTransactionAttempts: 3})
	tenantAuthorization := authorization
	tenantAuthorization.InstallationID = ""
	tenantAuthorization.TenantID = paasv1.TenantID(installationID)
	if _, err := tenantWorkflow.GetOperation(ctx, tenantAuthorization, results[0].ID); !errors.Is(err, applicationlifecycle.ErrNotFound) {
		t.Fatalf("tenant with same raw id read platform Operation: %v", err)
	}
	otherConfig := config
	otherConfig.InstallationID = prefix + "-other-installation"
	otherConfig.Bindings = nil
	otherService, _ := executionadmission.New(repository, otherConfig)
	otherAuthorization := authorization
	otherAuthorization.InstallationID = otherConfig.InstallationID
	if _, err := otherService.GetTarget(ctx, otherAuthorization, targetID); !errors.Is(err, executionadmission.ErrNotFound) {
		t.Fatalf("another installation read node: %v", err)
	}
	otherInventory, err := otherService.ListTargets(ctx, otherAuthorization)
	if err != nil || otherInventory.Items == nil || len(otherInventory.Items) != 0 {
		t.Fatalf("another installation listed node: inventory=%#v err=%v", otherInventory, err)
	}
	assertAdmissionRLS(t, ctx, apiPool, installationID, poolID, targetID)
	_, err = admin.Exec(ctx, `INSERT INTO paas.execution_targets(id,execution_pool_id,resource_version,document,installation_id,binding_ref,identity_fingerprint)
		SELECT $2,execution_pool_id,resource_version,jsonb_set(document,'{metadata,id}',to_jsonb($2::text)),installation_id,'second-binding',identity_fingerprint
		FROM paas.execution_targets WHERE id=$1`, targetID, string(targetID)+"-collision")
	assertPostgresCode(t, err, "23505")
	failedPoolID := paasv1.ResourceID(prefix + "-failed-pool")
	failedOperationID := paasv1.OperationID(prefix + "-failed-operation")
	failedEventID := prefix + "-failed-event"
	err = repository.WithinTransaction(ctx, installationID, func(ctx context.Context, transaction executionadmission.Transaction) error {
		now, err := transaction.TransactionTime(ctx)
		if err != nil {
			return err
		}
		failedPool := pool
		failedPool.Metadata = paasv1.ResourceMetadata{ID: failedPoolID, Name: "failed-pool", Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
		failedPool.Status = paasv1.ExecutionPoolStatus{Phase: paasv1.ExecutionPoolUnavailable, ObservedAt: now}
		failedOperation := poolOperation
		failedOperation.ID, failedOperation.Target.ID, failedOperation.IdempotencyFingerprint = failedOperationID, failedPoolID, integrationDigest("failed-pool-"+prefix)
		failedOperation.CreatedAt, failedOperation.UpdatedAt, failedOperation.TerminalAt = now, now, &now
		event := audit.Event{SchemaVersion: "v1", EventID: failedEventID, InstallationID: installationID, Actor: authorization.Subject, IAMDecisionID: authorization.DecisionID,
			Action: audit.ExecutionPoolCreated, Target: poolOperation.Target, OperationID: failedOperationID, RequestDigest: failedOperation.RequestDigest, Result: audit.Succeeded, RequestID: authorization.RequestID, OccurredAt: now}
		return transaction.CreatePool(ctx, failedPool, executionadmission.Submission{Operation: failedOperation, AuditEvent: event})
	})
	if !errors.Is(err, executionadmission.ErrInvalidArgument) {
		t.Fatalf("mismatched Audit target was accepted: %v", err)
	}
	var partialRows int
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM paas.execution_pools WHERE id=$1)+(SELECT count(*) FROM paas.operations WHERE installation_id=$2 AND id=$3)+(SELECT count(*) FROM paas.audit_outbox WHERE installation_id=$2 AND event_id=$4)`, failedPoolID, installationID, failedOperationID, failedEventID).Scan(&partialRows); err != nil {
		t.Fatal(err)
	}
	if partialRows != 0 {
		t.Fatal("failed Audit admission left partial resource/Operation/outbox writes")
	}

	// A committed replay does not need a reachable node and never rewrites the
	// original IAM decision/request fact with the new request's correlation.
	adapter.fail.Store(true)
	calls := adapter.calls.Load()
	retry := registration
	retry.Authorization.RequestID = "new-request"
	retry.Authorization.DecisionID = "new-decision"
	if _, operation, replayed, err := service.RegisterTarget(ctx, retry); err != nil || !replayed || operation.ID != results[0].ID || adapter.calls.Load() != calls {
		t.Fatalf("offline exact replay: %v replay=%v", err, replayed)
	}
	if err := service.Refresh(ctx); !errors.Is(err, executionadmission.ErrUnavailable) {
		t.Fatalf("disconnected refresh: %v", err)
	}
	unavailable, err := service.GetTarget(ctx, authorization, targetID)
	if err != nil || unavailable.Status.Health != paasv1.ExecutionTargetHealthUnavailable || unavailable.Status.Capacity != target.Status.Capacity || unavailable.Status.ObservedAt != target.Status.ObservedAt {
		t.Fatalf("disconnection changed capacity/time: %#v %v", unavailable, err)
	}
	adapter.fail.Store(false)
	if err := service.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := service.GetTarget(ctx, authorization, targetID)
	if err != nil || recovered.Status.Health != paasv1.ExecutionTargetHealthReady {
		t.Fatalf("node recovery: %v", err)
	}
	if err := service.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	measured, err := service.GetTarget(ctx, authorization, targetID)
	if err != nil || measured.Metadata.ResourceVersion != recovered.Metadata.ResourceVersion || !measured.Status.Usage.ObservedAt.After(recovered.Status.Usage.ObservedAt) {
		t.Fatalf("metric-only refresh changed placement version or did not advance: %#v %v", measured, err)
	}
	staleConfig := config
	staleConfig.Clock = func() time.Time { return time.Now().Add(time.Minute) }
	staleService, _ := executionadmission.New(repository, staleConfig)
	stale, err := staleService.GetTarget(ctx, authorization, targetID)
	if err != nil || stale.Status.Health != paasv1.ExecutionTargetHealthUnavailable || stale.Status.Usage.CPU.State != paasv1.MeasurementStale || stale.Status.Usage.ObservedAt != measured.Status.Usage.ObservedAt {
		t.Fatalf("expired reader view renewed a sample: %#v %v", stale, err)
	}

	// The SQL refresh capability itself refuses operator intent changes, even
	// when called directly with a correctly scoped API database credential.
	err = repository.WithinTransaction(ctx, installationID, func(ctx context.Context, transaction executionadmission.Transaction) error {
		current, _, err := transaction.LoadTarget(ctx, targetID)
		if err != nil {
			return err
		}
		pool, _, err := transaction.LoadPool(ctx, poolID)
		if err != nil {
			return err
		}
		now, err := transaction.TransactionTime(ctx)
		if err != nil {
			return err
		}
		version := current.Target.Metadata.ResourceVersion
		current.Target.Spec.DesiredState = paasv1.ExecutionTargetDraining
		current.Target.Metadata.UpdatedAt = now
		pool.Metadata.UpdatedAt, pool.Status.ObservedAt = now, now
		return transaction.RefreshTarget(ctx, version, current.Target, pool.Metadata.ResourceVersion, pool)
	})
	if !errors.Is(err, executionadmission.ErrInvalidArgument) {
		t.Fatalf("SQL refresh could overwrite desired state: %v", err)
	}
	unchanged, err := service.GetTarget(ctx, authorization, targetID)
	if err != nil || unchanged.Spec.DesiredState != paasv1.ExecutionTargetActive {
		t.Fatal("rejected refresh persisted")
	}
	var originalRequest, originalDecision string
	if err := admin.QueryRow(ctx, `SELECT document->>'requestId',document->>'iamDecisionId' FROM paas.audit_outbox WHERE installation_id=$1 AND operation_id=$2`, installationID, results[0].ID).Scan(&originalRequest, &originalDecision); err != nil {
		t.Fatal(err)
	}
	if originalRequest != authorization.RequestID || originalDecision != authorization.DecisionID {
		t.Fatal("replay replaced original audit evidence")
	}

	// Exercise terminal removal on a distinct target. The original node remains
	// available to the terminal-session gate, while the tombstone below remains
	// permanent and cannot be resurrected merely to satisfy another test.
	lifecycleTargetID := paasv1.ResourceID(prefix + "-node-lifecycle")
	lifecycleAdapter := &admissionAdapter{
		targetID:    lifecycleTargetID,
		bindingRef:  "node-lifecycle-binding",
		fingerprint: integrationDigest("node-lifecycle-" + prefix),
	}
	lifecycleConfig := config
	lifecycleConfig.Bindings = append(
		append([]executionadmission.Binding(nil), config.Bindings...),
		executionadmission.Binding{
			Ref:                 "node-lifecycle-binding",
			TargetID:            lifecycleTargetID,
			IdentityFingerprint: lifecycleAdapter.fingerprint,
			Adapter:             lifecycleAdapter,
		},
	)
	lifecycleService, err := executionadmission.New(repository, lifecycleConfig)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleRegistration := executionadmission.RegisterTargetCommand{
		Authorization:  authorization,
		IdempotencyKey: "register-lifecycle-node",
		Request: paasv1.RegisterExecutionTargetRequest{
			ID: lifecycleTargetID, Name: "node-lifecycle", ExecutionPoolID: poolID,
			BindingRef: "node-lifecycle-binding", Labels: map[string]string{"rack": "rack-b"},
		},
	}
	lifecycleTarget, _, lifecycleReplayed, err := lifecycleService.RegisterTarget(ctx, lifecycleRegistration)
	if err != nil || lifecycleReplayed || lifecycleTarget.Spec.DesiredState != paasv1.ExecutionTargetActive {
		t.Fatalf("register lifecycle target: replay=%v target=%#v err=%v", lifecycleReplayed, lifecycleTarget, err)
	}

	transition := func(action paasv1.OperationAction, expected uint64, key string) executionadmission.TransitionTargetResult {
		t.Helper()
		lifecycleAuthorization := authorization
		lifecycleAuthorization.DecisionID = "decision-" + key
		lifecycleAuthorization.RequestID = "request-" + key
		result, err := lifecycleService.TransitionTarget(ctx, executionadmission.TransitionTargetCommand{
			Authorization: lifecycleAuthorization, TargetID: lifecycleTargetID, Action: action,
			ExpectedResourceVersion: expected, IdempotencyKey: key,
		})
		if err != nil {
			t.Fatalf("transition %s: %v", action, err)
		}
		return result
	}
	callsBeforeLifecycle := lifecycleAdapter.calls.Load()
	drained := transition(paasv1.OperationDrainExecutionTarget, lifecycleTarget.Metadata.ResourceVersion, "drain-node")
	if drained.Replayed || drained.Target.Spec.DesiredState != paasv1.ExecutionTargetDraining ||
		drained.Operation.Action != paasv1.OperationDrainExecutionTarget || lifecycleAdapter.calls.Load() != callsBeforeLifecycle {
		t.Fatalf("drain called node or stored wrong state: %#v", drained)
	}
	pool, err = lifecycleService.GetPool(ctx, authorization, poolID)
	if err != nil || pool.Status.ExecutionTargetCount != 2 || pool.Status.ReadyExecutionTargetCount != 1 {
		t.Fatalf("drained pool = %#v err=%v", pool, err)
	}
	replayedDrain := transition(paasv1.OperationDrainExecutionTarget, lifecycleTarget.Metadata.ResourceVersion, "drain-node")
	if !replayedDrain.Replayed || replayedDrain.Operation.ID != drained.Operation.ID ||
		replayedDrain.Target.Metadata.ResourceVersion != drained.Target.Metadata.ResourceVersion {
		t.Fatalf("drain replay = %#v", replayedDrain)
	}
	changedActionAuthorization := authorization
	changedActionAuthorization.DecisionID = "decision-drain-node-changed-action"
	changedActionAuthorization.RequestID = "request-drain-node-changed-action"
	_, err = lifecycleService.TransitionTarget(ctx, executionadmission.TransitionTargetCommand{
		Authorization: changedActionAuthorization, TargetID: lifecycleTargetID,
		Action:                  paasv1.OperationActivateExecutionTarget,
		ExpectedResourceVersion: drained.Target.Metadata.ResourceVersion,
		IdempotencyKey:          "drain-node",
	})
	if !errors.Is(err, executionadmission.ErrIdempotencyConflict) {
		t.Fatalf("changed-action drain replay = %v", err)
	}
	_, err = lifecycleService.TransitionTarget(ctx, executionadmission.TransitionTargetCommand{
		Authorization: authorization, TargetID: lifecycleTargetID, Action: paasv1.OperationActivateExecutionTarget,
		ExpectedResourceVersion: lifecycleTarget.Metadata.ResourceVersion, IdempotencyKey: "stale-activate-node",
	})
	if !errors.Is(err, executionadmission.ErrResourceVersionConflict) {
		t.Fatalf("stale activation = %v", err)
	}
	activated := transition(paasv1.OperationActivateExecutionTarget, drained.Target.Metadata.ResourceVersion, "activate-node")
	var raced [2]executionadmission.TransitionTargetResult
	var raceErrors [2]error
	var raceWorkers sync.WaitGroup
	for index := range raced {
		raceWorkers.Go(func() {
			raceAuthorization := authorization
			raceAuthorization.DecisionID = fmt.Sprintf("decision-drain-race-%d", index)
			raceAuthorization.RequestID = fmt.Sprintf("request-drain-race-%d", index)
			raced[index], raceErrors[index] = lifecycleService.TransitionTarget(ctx, executionadmission.TransitionTargetCommand{
				Authorization: raceAuthorization, TargetID: lifecycleTargetID,
				Action:                  paasv1.OperationDrainExecutionTarget,
				ExpectedResourceVersion: activated.Target.Metadata.ResourceVersion,
				IdempotencyKey:          fmt.Sprintf("drain-node-race-%d", index),
			})
		})
	}
	raceWorkers.Wait()
	var drainedAgain executionadmission.TransitionTargetResult
	successes, conflicts := 0, 0
	for index, raceErr := range raceErrors {
		switch {
		case raceErr == nil:
			successes++
			drainedAgain = raced[index]
		case errors.Is(raceErr, executionadmission.ErrResourceVersionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent drain %d: %v", index, raceErr)
		}
	}
	if successes != 1 || conflicts != 1 || drainedAgain.Target.Spec.DesiredState != paasv1.ExecutionTargetDraining {
		t.Fatalf("concurrent drain successes=%d conflicts=%d result=%#v errors=%#v", successes, conflicts, drainedAgain, raceErrors)
	}

	// Observation commands complete through deployment_observations and never
	// receive an adapter_receipt. Retain real completed observation history on
	// this target while separately proving that an unfinished side-effecting
	// command still fences removal.
	var observationTenant, observationCommand string
	if err := admin.QueryRow(ctx, `
		WITH selected AS (
			SELECT command.tenant_id,command.id
			  FROM paas.adapter_commands AS command
			  JOIN paas.deployment_observations AS observation
			    ON observation.tenant_id=command.tenant_id
			   AND observation.command_id=command.id
			 WHERE command.action='OBSERVE_DEPLOYMENT'
			 ORDER BY command.tenant_id,command.id
			 LIMIT 1
		)
		UPDATE paas.adapter_commands AS command
		   SET execution_target_id=$1,
		       binding_ref=$2,
		       document=jsonb_set(
				jsonb_set(command.document,'{executionTargetId}',to_jsonb($1::text),false),
				'{bindingRef}',to_jsonb($2::text),false
			)
		  FROM selected
		 WHERE command.tenant_id=selected.tenant_id AND command.id=selected.id
		 RETURNING command.tenant_id,command.id`,
		lifecycleTargetID, lifecycleAdapter.bindingRef,
	).Scan(&observationTenant, &observationCommand); err != nil {
		t.Fatalf("retain completed observation history on lifecycle target: %v", err)
	}
	var observationResults, observationReceipts int
	if err := admin.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM paas.deployment_observations
		         WHERE tenant_id=$1 AND command_id=$2),
		       (SELECT count(*) FROM paas.adapter_receipts
		         WHERE tenant_id=$1 AND command_id=$2)`,
		observationTenant, observationCommand,
	).Scan(&observationResults, &observationReceipts); err != nil {
		t.Fatal(err)
	}
	if observationResults != 1 || observationReceipts != 0 {
		t.Fatalf("observation completion shape results=%d receipts=%d", observationResults, observationReceipts)
	}

	var effectTenant, effectCommand string
	if err := admin.QueryRow(ctx, `
		WITH selected AS (
			SELECT command.tenant_id,command.id
			  FROM paas.adapter_commands AS command
			  JOIN paas.adapter_receipts AS receipt
			    ON receipt.tenant_id=command.tenant_id
			   AND receipt.command_id=command.id
			 WHERE command.action<>'OBSERVE_DEPLOYMENT' AND receipt.state='SUCCEEDED'
			 ORDER BY command.tenant_id,command.id
			 LIMIT 1
		)
		UPDATE paas.adapter_commands AS command
		   SET execution_target_id=$1,
		       binding_ref=$2,
		       document=jsonb_set(
				jsonb_set(command.document,'{executionTargetId}',to_jsonb($1::text),false),
				'{bindingRef}',to_jsonb($2::text),false
			)
		  FROM selected
		 WHERE command.tenant_id=selected.tenant_id AND command.id=selected.id
		 RETURNING command.tenant_id,command.id`,
		lifecycleTargetID, lifecycleAdapter.bindingRef,
	).Scan(&effectTenant, &effectCommand); err != nil {
		t.Fatalf("retain completed effect history on lifecycle target: %v", err)
	}
	result, err := admin.Exec(ctx, `UPDATE paas.adapter_receipts SET state='IN_PROGRESS'
		WHERE tenant_id=$1 AND command_id=$2 AND state='SUCCEEDED'`, effectTenant, effectCommand)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("stage unresolved effect result: rows=%d err=%v", result.RowsAffected(), err)
	}
	removeAuthorization := authorization
	removeAuthorization.DecisionID = "decision-remove-node"
	removeAuthorization.RequestID = "request-remove-node"
	_, err = lifecycleService.TransitionTarget(ctx, executionadmission.TransitionTargetCommand{
		Authorization: removeAuthorization, TargetID: lifecycleTargetID,
		Action:                  paasv1.OperationRemoveExecutionTarget,
		ExpectedResourceVersion: drainedAgain.Target.Metadata.ResourceVersion,
		IdempotencyKey:          "remove-node",
	})
	if !errors.Is(err, executionadmission.ErrTargetInUse) {
		t.Fatalf("remove target with unresolved effect = %v", err)
	}
	result, err = admin.Exec(ctx, `UPDATE paas.adapter_receipts SET state='SUCCEEDED'
		WHERE tenant_id=$1 AND command_id=$2 AND state='IN_PROGRESS'`, effectTenant, effectCommand)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("complete effect result: rows=%d err=%v", result.RowsAffected(), err)
	}
	removed := transition(paasv1.OperationRemoveExecutionTarget, drainedAgain.Target.Metadata.ResourceVersion, "remove-node")
	if removed.Target.Spec.DesiredState != paasv1.ExecutionTargetRemoved || lifecycleAdapter.calls.Load() != callsBeforeLifecycle {
		t.Fatalf("remove called node or failed to retain tombstone: %#v", removed)
	}
	inventory, err = lifecycleService.ListTargets(ctx, authorization)
	if err != nil || len(inventory.Items) != 1 || inventory.Items[0].Metadata.ID != targetID {
		t.Fatalf("removed target remained in default inventory: %#v err=%v", inventory, err)
	}
	tombstone, err := lifecycleService.GetTarget(ctx, authorization, lifecycleTargetID)
	if err != nil || tombstone.Spec.DesiredState != paasv1.ExecutionTargetRemoved ||
		tombstone.Metadata.ResourceVersion != removed.Target.Metadata.ResourceVersion {
		t.Fatalf("removed target tombstone = %#v err=%v", tombstone, err)
	}
	if err := lifecycleService.Refresh(ctx); err != nil || lifecycleAdapter.calls.Load() != callsBeforeLifecycle {
		t.Fatalf("removed target was probed: err=%v calls=%d/%d", err, lifecycleAdapter.calls.Load(), callsBeforeLifecycle)
	}
	reRegister := lifecycleRegistration
	reRegister.IdempotencyKey = "register-removed-node"
	if _, _, _, err := lifecycleService.RegisterTarget(ctx, reRegister); !errors.Is(err, executionadmission.ErrConflict) || lifecycleAdapter.calls.Load() != callsBeforeLifecycle {
		t.Fatalf("removed target was re-admitted or probed: %v", err)
	}
	assertInstallationAuditDispatch(t, ctx, workerPool, installationID, 7)
}

func assertExecutionTargetRemovalFencesCurrentWork(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool, workerPool *pgxpool.Pool,
	prefix string,
) {
	t.Helper()
	installationID := prefix + "-installation"
	poolID := paasv1.ResourceID(prefix + "-nodes")
	targetID := paasv1.ResourceID(prefix + "-node-a")
	adapter := &admissionAdapter{
		targetID: targetID, fingerprint: integrationDigest("node-" + prefix),
	}
	repository, err := NewExecutionAdmissionRepository(apiPool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := executionadmission.New(repository, executionadmission.Config{
		InstallationID: installationID,
		Bindings: []executionadmission.Binding{{
			Ref: "node-binding", TargetID: targetID,
			IdentityFingerprint: adapter.fingerprint, Adapter: adapter,
		}},
		ObservationTimeout: time.Second, MaximumObservationAge: 15 * time.Second,
		MaxTransactionAttempts: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := port.Authorization{
		InstallationID: installationID,
		Subject:        paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"},
		DecisionID:     "decision-current-work-fence",
		RequestID:      "request-current-work-fence",
	}
	active, err := service.GetTarget(ctx, authorization, targetID)
	if err != nil || active.Spec.DesiredState != paasv1.ExecutionTargetActive {
		t.Fatalf("load current-work target: %#v err=%v", active, err)
	}
	drained, err := service.TransitionTarget(ctx, executionadmission.TransitionTargetCommand{
		Authorization: authorization, TargetID: targetID,
		Action:                  paasv1.OperationDrainExecutionTarget,
		ExpectedResourceVersion: active.Metadata.ResourceVersion,
		IdempotencyKey:          "drain-current-work-target",
	})
	if err != nil || drained.Target.Spec.DesiredState != paasv1.ExecutionTargetDraining {
		t.Fatalf("drain current-work target: %#v err=%v", drained, err)
	}

	type persistedProof struct {
		targetVersion, poolVersion   int64
		targetDocument, poolDocument string
		operations, events           int64
	}
	readProof := func() persistedProof {
		t.Helper()
		var proof persistedProof
		if err := admin.QueryRow(ctx, `
			SELECT target.resource_version,target.document::text,pool.resource_version,pool.document::text,
			       (SELECT count(*) FROM paas.operations WHERE installation_id=$1),
			       (SELECT count(*) FROM paas.audit_outbox WHERE installation_id=$1)
			  FROM paas.execution_targets AS target
			  JOIN paas.execution_pools AS pool ON pool.id=target.execution_pool_id
			 WHERE target.installation_id=$1 AND target.id=$2 AND pool.id=$3`,
			installationID, targetID, poolID,
		).Scan(
			&proof.targetVersion, &proof.targetDocument, &proof.poolVersion,
			&proof.poolDocument, &proof.operations, &proof.events,
		); err != nil {
			t.Fatal(err)
		}
		return proof
	}
	before := readProof()
	removeAuthorization := authorization
	removeAuthorization.DecisionID = "decision-remove-current-work"
	removeAuthorization.RequestID = "request-remove-current-work"
	_, err = service.TransitionTarget(ctx, executionadmission.TransitionTargetCommand{
		Authorization: removeAuthorization, TargetID: targetID,
		Action:                  paasv1.OperationRemoveExecutionTarget,
		ExpectedResourceVersion: drained.Target.Metadata.ResourceVersion,
		IdempotencyKey:          "remove-current-work-target",
	})
	if !errors.Is(err, executionadmission.ErrTargetInUse) {
		t.Fatalf("remove target with current tenant work = %v", err)
	}
	after := readProof()
	if after != before || adapter.calls.Load() != 0 {
		t.Fatalf("failed removal changed authority or called node: before=%#v after=%#v calls=%d", before, after, adapter.calls.Load())
	}
	activateAuthorization := authorization
	activateAuthorization.DecisionID = "decision-reactivate-current-work"
	activateAuthorization.RequestID = "request-reactivate-current-work"
	reactivated, err := service.TransitionTarget(ctx, executionadmission.TransitionTargetCommand{
		Authorization: activateAuthorization, TargetID: targetID,
		Action:                  paasv1.OperationActivateExecutionTarget,
		ExpectedResourceVersion: drained.Target.Metadata.ResourceVersion,
		IdempotencyKey:          "reactivate-current-work-target",
	})
	if err != nil || reactivated.Target.Spec.DesiredState != paasv1.ExecutionTargetActive || adapter.calls.Load() != 0 {
		t.Fatalf("reactivate after rejected removal: %#v err=%v calls=%d", reactivated, err, adapter.calls.Load())
	}
	assertInstallationAuditDispatch(t, ctx, workerPool, installationID, 2)
}

func assertAdmissionRLS(t *testing.T, ctx context.Context, pool *pgxpool.Pool, installationID string, poolID, targetID paasv1.ResourceID) {
	t.Helper()
	for _, scope := range []struct{ tenant, installation string }{{}, {installationID, ""}, {installationID, installationID}, {"", installationID}} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('matrix.tenant_id',$1,true),set_config('matrix.installation_id',$2,true)`, scope.tenant, scope.installation); err != nil {
			t.Fatal(err)
		}
		var visible int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM paas.execution_pools WHERE id=$1)+(SELECT count(*) FROM paas.execution_targets WHERE id=$2)`, poolID, targetID).Scan(&visible); err != nil {
			t.Fatal(err)
		}
		_ = tx.Rollback(ctx)
		want := 0
		if scope.tenant == "" && scope.installation == installationID {
			want = 2
		}
		if visible != want {
			t.Fatalf("RLS scope %+v saw %d want %d", scope, visible, want)
		}
	}
	_, err := pool.Exec(ctx, `UPDATE paas.execution_targets SET binding_ref='forged' WHERE id=$1`, targetID)
	assertPostgresCode(t, err, "42501")
}

func assertInstallationAuditDispatch(t *testing.T, ctx context.Context, pool *pgxpool.Pool, installationID string, expected int) {
	t.Helper()
	repository, err := auditpostgres.NewAuditOutboxRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for range 128 {
		claim, found, err := repository.Claim(ctx, "platform-audit-worker", 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			break
		}
		completion := auditdispatch.Completion{TenantID: claim.TenantID, InstallationID: claim.InstallationID, EventID: claim.EventID, Stream: claim.Stream, WorkerID: "platform-audit-worker", FencingToken: claim.FencingToken, Outcome: auditdispatch.OutcomeDelivered}
		if claim.InstallationID == installationID {
			if claim.TenantID != "" || claim.Event.TenantID != "" || claim.Event.InstallationID != installationID || claim.Stream != auditdispatch.StreamAppHosting {
				t.Fatal("platform audit claim used tenant scope")
			}
			wrongScope := completion
			wrongScope.TenantID = paasv1.TenantID(installationID)
			wrongScope.InstallationID = ""
			if err := repository.Complete(ctx, wrongScope); !errors.Is(err, auditdispatch.ErrStaleLease) {
				t.Fatalf("tenant completion crossed into installation outbox: %v", err)
			}
			seen++
		}
		if err := repository.Complete(ctx, completion); err != nil {
			t.Fatal(err)
		}
	}
	if seen != expected {
		t.Fatalf("delivered %d installation audit facts, want %d", seen, expected)
	}
}

type admissionAdapter struct {
	targetID    paasv1.ResourceID
	bindingRef  string
	fingerprint string
	fail        atomic.Bool
	calls       atomic.Int64
}

func (adapter *admissionAdapter) Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error) {
	return paasv1.AdapterCapabilitiesContract{Adapter: paasv1.AdapterRef{Kind: paasv1.AdapterInfrastructure, Name: "nodehttps", ContractVersion: "v1"}, Actions: []paasv1.AdapterAction{paasv1.AdapterCapabilities, paasv1.AdapterInspectExecutionTarget, paasv1.AdapterObserveExecutionTarget}, IsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}, ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}, nil
}
func (adapter *admissionAdapter) InspectExecutionTarget(ctx context.Context, request paasv1.InspectExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
	return adapter.ObserveExecutionTarget(ctx, paasv1.ObserveExecutionTargetRequest{Command: request.Command})
}
func (adapter *admissionAdapter) ObserveExecutionTarget(_ context.Context, request paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
	sequence := adapter.calls.Add(1)
	if adapter.fail.Load() {
		return paasv1.ExecutionTargetObservation{}, errors.New("node fixture disconnected")
	}
	expectedBindingRef := adapter.bindingRef
	if expectedBindingRef == "" {
		expectedBindingRef = "node-binding"
	}
	if request.Command.ExecutionTargetID != adapter.targetID || request.Command.BindingRef != expectedBindingRef {
		return paasv1.ExecutionTargetObservation{}, errors.New("wrong node binding")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return paasv1.ExecutionTargetObservation{ExecutionTargetID: adapter.targetID, IdentityFingerprint: adapter.fingerprint, Health: paasv1.ExecutionTargetHealthReady,
		Capacity: paasv1.Capacity{CPUMillis: 4000, MemoryBytes: 8 << 30, StorageBytes: 100 << 30, WorkloadSlots: 32}, Allocatable: paasv1.Capacity{CPUMillis: 3000, MemoryBytes: 6 << 30, StorageBytes: 80 << 30, WorkloadSlots: 24},
		SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}, ObservedAt: now, Usage: &paasv1.ExecutionTargetUsage{ObservedAt: now, ValidUntil: now.Add(15 * time.Second),
			CPU:    paasv1.CPUUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.CPUUsageValue{LogicalCPUs: 4, WindowMillis: 5000, UtilizationRatio: float64(sequence%100) / 100}},
			Memory: paasv1.MemoryUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.MemoryUsageValue{TotalBytes: 8 << 30, AvailableBytes: 6 << 30, UsedBytes: 2 << 30}}, FilesystemsState: paasv1.MeasurementUnavailable}}, nil
}
