package refreshdeploymentruntime

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type runtimeRepository struct {
	candidates []Candidate
	cursors    []Cursor
	stored     []TelemetrySnapshot
	storeErr   error
}

func (repository *runtimeRepository) Next(_ context.Context, cursor Cursor) (Candidate, bool, error) {
	repository.cursors = append(repository.cursors, cursor)
	if len(repository.candidates) == 0 {
		return Candidate{}, false, nil
	}
	value := repository.candidates[0]
	repository.candidates = repository.candidates[1:]
	return value, true, nil
}

func (repository *runtimeRepository) Store(
	_ context.Context,
	_ paasv1.TenantID,
	_ paasv1.ResourceID,
	observation TelemetrySnapshot,
) (bool, error) {
	if repository.storeErr != nil {
		return false, repository.storeErr
	}
	repository.stored = append(repository.stored, observation)
	return true, nil
}

type runtimeObserver struct {
	value     paasv1.DeploymentRuntimeObservation
	resources paasv1.DeploymentResourceObservation
	err       error
	calls     int
	requests  []paasv1.ObserveDeploymentRuntimeRequest
}

func (observer *runtimeObserver) ObserveDeploymentTelemetry(
	_ context.Context,
	request paasv1.ObserveDeploymentRuntimeRequest,
) (
	paasv1.DeploymentRuntimeObservation,
	paasv1.DeploymentResourceObservation,
	error,
) {
	observer.calls++
	observer.requests = append(observer.requests, request)
	return observer.value, observer.resources, observer.err
}

func TestRuntimeRequestIdentityBindsTheExactPlacementAndScheduleIsBounded(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	candidate := runtimeCandidate()
	changed := candidate
	changed.PlacementDecisionID = "placement-b"
	if runtimeRequestID(candidate, now) == runtimeRequestID(changed, now) {
		t.Fatal("runtime request identity did not bind the placement decision")
	}
	service := &Service{nextDue: make(map[string]time.Time, maximumScheduledRuntimeCandidates)}
	for index := 0; index < maximumScheduledRuntimeCandidates; index++ {
		service.nextDue[strconv.Itoa(index)] = now
	}
	service.schedule("next", now.Add(time.Second))
	if len(service.nextDue) != 1 || !service.nextDue["next"].Equal(now.Add(time.Second)) {
		t.Fatal("runtime schedule exceeded its memory bound")
	}
}

func TestRefreshStoresOnlyExactCurrentTargetObservation(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	candidate := runtimeCandidate()
	repository := &runtimeRepository{candidates: []Candidate{candidate}}
	observer := &runtimeObserver{
		value: runtimeObservation(candidate, now), resources: resourceObservation(candidate, now),
	}
	service := newRuntimeService(t, repository, observer, now)
	processed, err := service.ProcessNext(context.Background())
	if err != nil || !processed || observer.calls != 1 || len(repository.stored) != 1 {
		t.Fatalf("refresh processed/error/calls/stored = %t/%v/%d/%d", processed, err, observer.calls, len(repository.stored))
	}

	repository.candidates = []Candidate{candidate}
	service.nextDue = map[string]time.Time{}
	observer.value.ExecutionTargetID = "target-b"
	processed, err = service.ProcessNext(context.Background())
	if err != nil || !processed || len(repository.stored) != 1 {
		t.Fatalf("retargeted observation changed proof: %t/%v/%d", processed, err, len(repository.stored))
	}
}

func TestRefreshRetainsProofAcrossProviderFailureAndSurfacesDatabaseFailure(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	candidate := runtimeCandidate()
	repository := &runtimeRepository{candidates: []Candidate{candidate}}
	observer := &runtimeObserver{err: errors.New("provider path and credential must not escape")}
	service := newRuntimeService(t, repository, observer, now)
	processed, err := service.ProcessNext(context.Background())
	if err != nil || !processed || len(repository.stored) != 0 {
		t.Fatalf("provider failure changed current proof: %t/%v/%d", processed, err, len(repository.stored))
	}

	repository.candidates = []Candidate{candidate}
	service.nextDue = map[string]time.Time{}
	observer.err = nil
	observer.value = runtimeObservation(candidate, now)
	observer.resources = resourceObservation(candidate, now)
	repository.storeErr = ErrSnapshotRejected
	if processed, err = service.ProcessNext(context.Background()); !processed || err != nil {
		t.Fatalf("concurrent authority change stopped refresh: %t/%v", processed, err)
	}

	repository.candidates = []Candidate{candidate}
	service.nextDue = map[string]time.Time{}
	repository.storeErr = errors.New("database unavailable")
	if processed, err = service.ProcessNext(context.Background()); !processed || err == nil {
		t.Fatalf("database failure was hidden: %t/%v", processed, err)
	}
}

func TestNotYetDueCandidateAdvancesTheBoundedScanWithoutProviderWork(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	candidate := runtimeCandidate()
	repository := &runtimeRepository{candidates: []Candidate{candidate}}
	observer := &runtimeObserver{
		value: runtimeObservation(candidate, now), resources: resourceObservation(candidate, now),
	}
	service := newRuntimeService(t, repository, observer, now)
	service.nextDue[string(candidate.TenantID)+"\x00"+string(candidate.DeploymentID)] = now.Add(time.Second)

	processed, err := service.ProcessNext(context.Background())
	if err != nil || !processed || observer.calls != 0 || len(repository.stored) != 0 {
		t.Fatalf(
			"scheduled scan progress/error/calls/stored = %t/%v/%d/%d",
			processed,
			err,
			observer.calls,
			len(repository.stored),
		)
	}
}

func TestRefreshValidatesTelemetryAgainstRequestCompletion(t *testing.T) {
	startedAt := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	completedAt := startedAt.Add(3 * time.Second)
	candidate := runtimeCandidate()
	repository := &runtimeRepository{candidates: []Candidate{candidate}}
	observer := &runtimeObserver{
		value: runtimeObservation(candidate, completedAt), resources: resourceObservation(candidate, completedAt),
	}
	clockValues := []time.Time{startedAt, completedAt}
	service, err := New(repository, []Route{{ExecutionTargetID: "target-a", Observer: observer}}, Config{
		ObservationInterval:   5 * time.Second,
		FailureBackoff:        time.Second,
		ObservationTimeout:    10 * time.Second,
		MaximumObservationAge: 5 * time.Second,
		ValidityDuration:      15 * time.Second,
		Clock: func() time.Time {
			if len(clockValues) == 1 {
				return clockValues[0]
			}
			value := clockValues[0]
			clockValues = clockValues[1:]
			return value
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	processed, err := service.ProcessNext(context.Background())
	if err != nil || !processed || len(repository.stored) != 1 {
		t.Fatalf("delayed telemetry processed/error/stored = %t/%v/%d", processed, err, len(repository.stored))
	}
	key := string(candidate.TenantID) + "\x00" + string(candidate.DeploymentID)
	if due := service.nextDue[key]; !due.Equal(completedAt.Add(5 * time.Second)) {
		t.Fatalf("next observation due = %s", due)
	}
}

func newRuntimeService(
	t *testing.T,
	repository Repository,
	observer *runtimeObserver,
	now time.Time,
) *Service {
	t.Helper()
	service, err := New(repository, []Route{{ExecutionTargetID: "target-a", Observer: observer}}, Config{
		ObservationInterval:   5 * time.Second,
		FailureBackoff:        time.Second,
		ObservationTimeout:    2 * time.Second,
		MaximumObservationAge: 5 * time.Second,
		ValidityDuration:      15 * time.Second,
		Clock:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func runtimeCandidate() Candidate {
	return Candidate{
		TenantID:              "tenant-a",
		DeploymentID:          "deployment-a",
		Generation:            2,
		ApplicationRevisionID: "revision-a",
		ExecutionTargetID:     "target-a",
		PlacementDecisionID:   "placement-a",
		ContentDigest:         "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func runtimeObservation(candidate Candidate, now time.Time) paasv1.DeploymentRuntimeObservation {
	return paasv1.DeploymentRuntimeObservation{
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
		ObservedAt: now,
	}
}

func resourceObservation(candidate Candidate, now time.Time) paasv1.DeploymentResourceObservation {
	return paasv1.DeploymentResourceObservation{
		DeploymentID:          candidate.DeploymentID,
		Generation:            candidate.Generation,
		ApplicationRevisionID: candidate.ApplicationRevisionID,
		ExecutionTargetID:     candidate.ExecutionTargetID,
		Instances: []paasv1.DeploymentResourceInstance{{
			ID:      "instance-0123456789abcdef0123456789abcdef",
			CPU:     paasv1.DeploymentInstanceCPUUsage{State: paasv1.MeasurementUnsupported},
			Memory:  paasv1.DeploymentInstanceMemoryUsage{State: paasv1.MeasurementUnsupported},
			Network: paasv1.DeploymentInstanceNetworkUsage{State: paasv1.MeasurementUnsupported},
			BlockIO: paasv1.DeploymentInstanceBlockIOUsage{State: paasv1.MeasurementUnsupported},
			Storage: paasv1.DeploymentInstanceStorageUsage{State: paasv1.MeasurementUnsupported},
		}},
		ObservedAt: now,
	}
}
