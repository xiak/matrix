package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/refreshdeploymentruntime"
)

func assertDeploymentRuntimeProjection(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	fixture integrationFixture,
	deployment paasv1.Deployment,
) {
	t.Helper()
	repository, err := NewDeploymentRuntimeRepository(workerPool)
	if err != nil {
		t.Fatalf("create Deployment runtime repository: %v", err)
	}
	candidate := findDeploymentRuntimeCandidate(
		t,
		ctx,
		repository,
		fixture.tenantA,
		deployment.Metadata.ID,
	)
	if candidate.Generation != deployment.Generation ||
		candidate.ApplicationRevisionID != deployment.Spec.ApplicationRevisionID ||
		candidate.ExecutionTargetID != fixture.targetID {
		t.Fatalf("Deployment runtime candidate = %#v", candidate)
	}

	var databaseNow time.Time
	if err := admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		t.Fatalf("read database time: %v", err)
	}
	databaseNow = databaseTime(databaseNow)
	observation := paasv1.DeploymentRuntimeObservation{
		DeploymentID:          candidate.DeploymentID,
		Generation:            candidate.Generation,
		ApplicationRevisionID: candidate.ApplicationRevisionID,
		ExecutionTargetID:     candidate.ExecutionTargetID,
		Instances: []paasv1.DeploymentRuntimeInstance{{
			ID:            "instance-0123456789abcdef0123456789abcdef",
			ComponentName: "web",
			State:         paasv1.DeploymentInstanceRunning,
			Health:        paasv1.DeploymentInstanceHealthHealthy,
		}},
		ObservedAt: databaseNow.Add(-20 * time.Second),
	}
	stored, err := repository.Store(
		ctx,
		fixture.tenantA,
		candidate.PlacementDecisionID,
		deploymentTelemetrySnapshot(observation, databaseNow.Add(-5*time.Second)),
	)
	if err != nil || !stored {
		t.Fatalf("store stale Deployment runtime proof: stored=%v err=%v", stored, err)
	}

	applicationRepository, err := NewApplicationRepository(apiPool)
	if err != nil {
		t.Fatalf("create tenant application repository: %v", err)
	}
	applicationUsecase, err := applicationlifecycle.NewUsecase(
		applicationRepository,
		applicationlifecycle.Config{MaxTransactionAttempts: 3},
	)
	if err != nil {
		t.Fatalf("create tenant application use case: %v", err)
	}
	authorization := integrationAuthorization(
		fixture.tenantA,
		paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "runtime-reader"},
		"runtime-read",
	)
	snapshot, err := applicationUsecase.GetDeploymentRuntime(
		ctx,
		authorization,
		candidate.DeploymentID,
	)
	if err != nil || snapshot.State != paasv1.MeasurementStale ||
		snapshot.Value == nil ||
		!snapshot.Value.Observation.ObservedAt.Equal(observation.ObservedAt) ||
		snapshot.Resources.State != paasv1.MeasurementStale ||
		snapshot.Resources.Value == nil ||
		!snapshot.Resources.Value.Observation.ObservedAt.Equal(observation.ObservedAt) {
		t.Fatalf("stale Deployment runtime snapshot=%#v err=%v", snapshot, err)
	}

	observation.ObservedAt = databaseNow
	stored, err = repository.Store(
		ctx,
		fixture.tenantA,
		candidate.PlacementDecisionID,
		deploymentTelemetrySnapshot(observation, databaseNow.Add(15*time.Second)),
	)
	if err != nil || !stored {
		t.Fatalf("store fresh Deployment runtime proof: stored=%v err=%v", stored, err)
	}
	stored, err = repository.Store(
		ctx,
		fixture.tenantA,
		candidate.PlacementDecisionID,
		deploymentTelemetrySnapshot(observation, databaseNow.Add(15*time.Second)),
	)
	if err != nil || stored {
		t.Fatalf("replay Deployment runtime proof: stored=%v err=%v", stored, err)
	}

	changed := observation
	changed.Instances = append([]paasv1.DeploymentRuntimeInstance{}, observation.Instances...)
	changed.Instances[0].Health = paasv1.DeploymentInstanceHealthUnhealthy
	if _, err := repository.Store(
		ctx,
		fixture.tenantA,
		candidate.PlacementDecisionID,
		deploymentTelemetrySnapshot(changed, databaseNow.Add(15*time.Second)),
	); err == nil {
		t.Fatal("equal-timestamp variant Deployment runtime proof was accepted")
	}
	if _, err := repository.Store(
		ctx,
		fixture.tenantB,
		candidate.PlacementDecisionID,
		deploymentTelemetrySnapshot(observation, databaseNow.Add(15*time.Second)),
	); err == nil {
		t.Fatal("cross-tenant Deployment runtime proof was accepted")
	}
	if _, err := repository.Store(
		ctx,
		fixture.tenantA,
		"placement-decision-attacker",
		deploymentTelemetrySnapshot(observation, databaseNow.Add(15*time.Second)),
	); !errors.Is(err, refreshdeploymentruntime.ErrSnapshotRejected) {
		t.Fatalf("stale or substituted placement decision error = %v", err)
	}

	snapshot, err = applicationUsecase.GetDeploymentRuntime(
		ctx,
		authorization,
		candidate.DeploymentID,
	)
	if err != nil || snapshot.State != paasv1.MeasurementAvailable ||
		snapshot.Value == nil || len(snapshot.Value.Observation.Instances) != 1 ||
		!snapshot.Value.Observation.ObservedAt.Equal(databaseNow) ||
		snapshot.Resources.State != paasv1.MeasurementAvailable ||
		snapshot.Resources.Value == nil ||
		len(snapshot.Resources.Value.Observation.Instances) != 1 ||
		snapshot.Resources.Value.Observation.Instances[0].ID !=
			snapshot.Value.Observation.Instances[0].ID {
		t.Fatalf("available Deployment runtime snapshot=%#v err=%v", snapshot, err)
	}
	otherTenant := authorization
	otherTenant.TenantID = fixture.tenantB
	if _, err := applicationUsecase.GetDeploymentRuntime(
		ctx,
		otherTenant,
		candidate.DeploymentID,
	); !errors.Is(err, applicationlifecycle.ErrNotFound) {
		t.Fatalf("cross-tenant Deployment runtime read error=%v", err)
	}

	list, err := applicationUsecase.ListDeployments(ctx, authorization, "")
	if err != nil || !deploymentListContains(list, deployment.Metadata.ID) ||
		list.Scope.TenantID != fixture.tenantA {
		t.Fatalf("tenant Deployment list=%#v err=%v", list, err)
	}
	otherList, err := applicationUsecase.ListDeployments(ctx, otherTenant, "")
	if err != nil || len(otherList.Items) != 0 || otherList.Scope.TenantID != fixture.tenantB {
		t.Fatalf("cross-tenant Deployment list=%#v err=%v", otherList, err)
	}

	if _, err := apiPool.Exec(
		ctx,
		`SELECT paas.store_deployment_runtime_snapshot(
			$1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb
		)`,
		fixture.tenantA,
		observation.DeploymentID,
		observation.Generation,
		observation.ApplicationRevisionID,
		observation.ExecutionTargetID,
		candidate.PlacementDecisionID,
		observation.ObservedAt,
		databaseNow.Add(15*time.Second),
		integrationJSON(t, observation),
	); err == nil {
		t.Fatal("PaaS API role executed worker-only runtime snapshot function")
	}
	telemetry := deploymentTelemetrySnapshot(observation, databaseNow.Add(15*time.Second))
	if _, err := apiPool.Exec(
		ctx,
		`SELECT paas.store_deployment_telemetry_snapshot(
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9::jsonb, $10, $11, $12::jsonb
		)`,
		fixture.tenantA,
		observation.DeploymentID,
		observation.Generation,
		observation.ApplicationRevisionID,
		observation.ExecutionTargetID,
		candidate.PlacementDecisionID,
		observation.ObservedAt,
		telemetry.RuntimeValidUntil,
		integrationJSON(t, observation),
		telemetry.Resources.ObservedAt,
		telemetry.ResourcesValidUntil,
		integrationJSON(t, telemetry.Resources),
	); err == nil {
		t.Fatal("PaaS API role executed worker-only telemetry snapshot function")
	}
	if _, err := workerPool.Exec(
		ctx,
		`UPDATE paas.deployment_runtime_snapshots
		    SET valid_until = valid_until + interval '1 second'`,
	); err == nil {
		t.Fatal("PaaS worker role directly mutated runtime snapshot table")
	}
	if _, err := workerPool.Exec(
		ctx,
		`UPDATE paas.deployment_resource_snapshots
		    SET valid_until = valid_until + interval '1 second'`,
	); err == nil {
		t.Fatal("PaaS worker role directly mutated resource snapshot table")
	}

	malformedDocuments := []func(map[string]any){
		func(document map[string]any) { document["deploymentId"] = nil },
		func(document map[string]any) { document["generation"] = "1" },
		func(document map[string]any) {
			document["instances"] = []any{map[string]any{
				"id": nil, "componentName": "web",
				"state": "RUNNING", "health": "HEALTHY",
			}}
		},
		func(document map[string]any) {
			document["instances"] = []any{map[string]any{
				"id":            "instance-0123456789abcdef0123456789abcdef",
				"componentName": "web", "state": "EXITED",
				"health": "NONE", "exitCode": "1",
			}}
		},
	}
	for index, mutate := range malformedDocuments {
		observedAt := databaseNow.Add(time.Duration(index+1) * time.Millisecond)
		document := map[string]any{
			"deploymentId":          observation.DeploymentID,
			"generation":            observation.Generation,
			"applicationRevisionId": observation.ApplicationRevisionID,
			"executionTargetId":     observation.ExecutionTargetID,
			"instances":             []any{},
			"observedAt":            observedAt,
		}
		mutate(document)
		if _, err := workerPool.Exec(
			ctx,
			`SELECT paas.store_deployment_runtime_snapshot(
				$1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb
			)`,
			fixture.tenantA,
			observation.DeploymentID,
			observation.Generation,
			observation.ApplicationRevisionID,
			observation.ExecutionTargetID,
			candidate.PlacementDecisionID,
			observedAt,
			observedAt.Add(15*time.Second),
			integrationJSON(t, document),
		); err == nil {
			t.Fatalf("malformed Deployment runtime document %d was accepted", index)
		}
	}

	malformedResourceDocuments := []func(map[string]any){
		func(document map[string]any) { document["providerId"] = "docker-container-id" },
		func(document map[string]any) {
			instances := document["instances"].([]any)
			instances[0].(map[string]any)["id"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		},
		func(document map[string]any) {
			instances := document["instances"].([]any)
			delete(instances[0].(map[string]any), "cpu")
		},
		func(document map[string]any) {
			instances := document["instances"].([]any)
			instances[0].(map[string]any)["cpu"] = map[string]any{"state": "AVAILABLE"}
		},
		func(document map[string]any) {
			instances := document["instances"].([]any)
			instances[0].(map[string]any)["memory"] = map[string]any{
				"state": "AVAILABLE",
				"value": map[string]any{"usedBytes": 2, "limitBytes": 1},
			}
		},
		func(document map[string]any) {
			instances := document["instances"].([]any)
			instances[0].(map[string]any)["storage"] = map[string]any{
				"state": "AVAILABLE",
				"value": map[string]any{
					"observedAt":         databaseNow,
					"validUntil":         databaseNow.Add(30 * time.Second),
					"writableLayerBytes": 1,
					"imageTotalBytes":    10,
					"imageSharedBytes":   4,
					"imageUniqueBytes":   7,
					"volumesState":       "UNSUPPORTED",
				},
			}
		},
		func(document map[string]any) {
			instances := document["instances"].([]any)
			instances[0].(map[string]any)["secret"] = "provider-volume-name"
		},
	}
	for index, mutate := range malformedResourceDocuments {
		encoded, err := json.Marshal(telemetry.Resources)
		if err != nil {
			t.Fatalf("encode Deployment resource fixture: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatalf("decode Deployment resource fixture: %v", err)
		}
		mutate(document)
		if _, err := workerPool.Exec(
			ctx,
			`SELECT paas.store_deployment_telemetry_snapshot(
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9::jsonb, $10, $11, $12::jsonb
			)`,
			fixture.tenantA,
			observation.DeploymentID,
			observation.Generation,
			observation.ApplicationRevisionID,
			observation.ExecutionTargetID,
			candidate.PlacementDecisionID,
			observation.ObservedAt,
			telemetry.RuntimeValidUntil,
			integrationJSON(t, observation),
			telemetry.Resources.ObservedAt,
			telemetry.ResourcesValidUntil,
			integrationJSON(t, document),
		); err == nil {
			t.Fatalf("malformed Deployment resource document %d was accepted", index)
		}
	}

	advancedRuntime := observation
	advancedRuntime.Instances = append([]paasv1.DeploymentRuntimeInstance{}, observation.Instances...)
	advancedRuntime.Instances[0].Health = paasv1.DeploymentInstanceHealthUnhealthy
	advancedRuntime.ObservedAt = databaseNow.Add(time.Millisecond)
	advancedTelemetry := deploymentTelemetrySnapshot(
		advancedRuntime,
		advancedRuntime.ObservedAt.Add(15*time.Second),
	)
	encoded, err := json.Marshal(advancedTelemetry.Resources)
	if err != nil {
		t.Fatalf("encode atomic Deployment resource fixture: %v", err)
	}
	var invalidAdvancedResource map[string]any
	if err := json.Unmarshal(encoded, &invalidAdvancedResource); err != nil {
		t.Fatalf("decode atomic Deployment resource fixture: %v", err)
	}
	invalidAdvancedResource["providerId"] = "must-roll-back-runtime-update"
	if _, err := workerPool.Exec(
		ctx,
		`SELECT paas.store_deployment_telemetry_snapshot(
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9::jsonb, $10, $11, $12::jsonb
		)`,
		fixture.tenantA,
		advancedRuntime.DeploymentID,
		advancedRuntime.Generation,
		advancedRuntime.ApplicationRevisionID,
		advancedRuntime.ExecutionTargetID,
		candidate.PlacementDecisionID,
		advancedRuntime.ObservedAt,
		advancedTelemetry.RuntimeValidUntil,
		integrationJSON(t, advancedRuntime),
		advancedTelemetry.Resources.ObservedAt,
		advancedTelemetry.ResourcesValidUntil,
		integrationJSON(t, invalidAdvancedResource),
	); err == nil {
		t.Fatal("invalid resource proof committed an advanced runtime snapshot")
	}
	var retainedRuntimeAt, retainedResourceAt time.Time
	var retainedHealth string
	if err := admin.QueryRow(
		ctx,
		`SELECT runtime.observed_at,
		        runtime.document#>>'{instances,0,health}',
		        resources.observed_at
		   FROM paas.deployment_runtime_snapshots AS runtime
		   JOIN paas.deployment_resource_snapshots AS resources
		     ON resources.tenant_id = runtime.tenant_id
		    AND resources.deployment_id = runtime.deployment_id
		  WHERE runtime.tenant_id = $1 AND runtime.deployment_id = $2`,
		fixture.tenantA,
		observation.DeploymentID,
	).Scan(&retainedRuntimeAt, &retainedHealth, &retainedResourceAt); err != nil {
		t.Fatalf("read atomically retained telemetry snapshot: %v", err)
	}
	if !databaseTime(retainedRuntimeAt).Equal(databaseNow) ||
		!databaseTime(retainedResourceAt).Equal(databaseNow) ||
		retainedHealth != string(paasv1.DeploymentInstanceHealthHealthy) {
		t.Fatalf("invalid resource proof partially changed telemetry: runtime=%s resource=%s health=%s",
			retainedRuntimeAt, retainedResourceAt, retainedHealth)
	}
}

func deploymentTelemetrySnapshot(
	runtime paasv1.DeploymentRuntimeObservation,
	validUntil time.Time,
) refreshdeploymentruntime.TelemetrySnapshot {
	resources := paasv1.DeploymentResourceObservation{
		DeploymentID:          runtime.DeploymentID,
		Generation:            runtime.Generation,
		ApplicationRevisionID: runtime.ApplicationRevisionID,
		ExecutionTargetID:     runtime.ExecutionTargetID,
		Instances:             make([]paasv1.DeploymentResourceInstance, len(runtime.Instances)),
		ObservedAt:            runtime.ObservedAt,
	}
	for index, instance := range runtime.Instances {
		resources.Instances[index] = paasv1.DeploymentResourceInstance{
			ID:      instance.ID,
			CPU:     paasv1.DeploymentInstanceCPUUsage{State: paasv1.MeasurementUnsupported},
			Memory:  paasv1.DeploymentInstanceMemoryUsage{State: paasv1.MeasurementUnsupported},
			Network: paasv1.DeploymentInstanceNetworkUsage{State: paasv1.MeasurementUnsupported},
			BlockIO: paasv1.DeploymentInstanceBlockIOUsage{State: paasv1.MeasurementUnsupported},
			Storage: paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnsupported},
		}
	}
	return refreshdeploymentruntime.TelemetrySnapshot{
		Runtime:             runtime,
		RuntimeValidUntil:   validUntil,
		Resources:           resources,
		ResourcesValidUntil: validUntil,
	}
}

func deploymentListContains(list paasv1.DeploymentList, id paasv1.ResourceID) bool {
	for _, deployment := range list.Items {
		if deployment.Metadata.ID == id {
			return true
		}
	}
	return false
}

func findDeploymentRuntimeCandidate(
	t *testing.T,
	ctx context.Context,
	repository *DeploymentRuntimeRepository,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
) refreshdeploymentruntime.Candidate {
	t.Helper()
	var cursor refreshdeploymentruntime.Cursor
	for attempts := 0; attempts < 1024; attempts++ {
		candidate, found, err := repository.Next(ctx, cursor)
		if err != nil {
			t.Fatalf("scan Deployment runtime candidate: %v", err)
		}
		if !found {
			break
		}
		if candidate.TenantID == tenantID && candidate.DeploymentID == deploymentID {
			return candidate
		}
		cursor = refreshdeploymentruntime.Cursor{
			TenantID: candidate.TenantID, DeploymentID: candidate.DeploymentID,
		}
	}
	t.Fatalf("Deployment runtime candidate %s/%s not found", tenantID, deploymentID)
	return refreshdeploymentruntime.Candidate{}
}
