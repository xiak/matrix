package refreshdeploymentruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

const (
	maximumFutureSkew                 = 2 * time.Second
	maximumScheduledRuntimeCandidates = 4096
)

func New(repository Repository, routes []Route, config Config) (*Service, error) {
	if repository == nil || len(routes) == 0 {
		return nil, errors.New("Deployment runtime repository and routes are required")
	}
	if config.ObservationInterval <= 0 || config.ObservationInterval > time.Minute ||
		config.FailureBackoff <= 0 || config.FailureBackoff > time.Minute ||
		config.ObservationTimeout <= 0 || config.ObservationTimeout > time.Minute ||
		config.MaximumObservationAge <= 0 || config.MaximumObservationAge > time.Minute ||
		config.ValidityDuration <= 0 || config.ValidityDuration > time.Minute {
		return nil, errors.New("Deployment runtime refresh timing is invalid")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	bound := make(map[paasv1.ResourceID]struct{}, len(routes))
	observers := make(map[paasv1.ResourceID]port.DeploymentTelemetryObserver, len(routes))
	for _, route := range routes {
		if paasv1.ValidateID("executionTargetId", string(route.ExecutionTargetID)) != nil ||
			route.Observer == nil {
			return nil, errors.New("Deployment runtime route is invalid")
		}
		if _, duplicate := bound[route.ExecutionTargetID]; duplicate {
			return nil, errors.New("Deployment runtime route is duplicated")
		}
		bound[route.ExecutionTargetID] = struct{}{}
		observers[route.ExecutionTargetID] = route.Observer
	}
	return &Service{
		repository: repository,
		routes:     observers,
		config:     config,
		nextDue:    make(map[string]time.Time),
	}, nil
}

// ProcessNext scans one stable candidate. Provider failures retain the last
// committed proof and are retried after a bounded backoff; database failures
// remain fatal to the worker so readiness cannot silently diverge.
func (service *Service) ProcessNext(ctx context.Context) (bool, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return false, errors.New("Deployment runtime refresh service is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	candidate, found, err := service.repository.Next(ctx, service.cursor)
	if err != nil {
		return false, err
	}
	if !found {
		service.cursor = Cursor{}
		return false, nil
	}
	service.cursor = Cursor{TenantID: candidate.TenantID, DeploymentID: candidate.DeploymentID}
	if validateCandidate(candidate) != nil {
		return false, ErrInvalidCandidate
	}
	startedAt := service.config.Clock().UTC().Truncate(time.Microsecond)
	key := string(candidate.TenantID) + "\x00" + string(candidate.DeploymentID)
	if due := service.nextDue[key]; startedAt.Before(due) {
		// A candidate was consumed and the stable cursor advanced. Report progress
		// so the worker drains the rest of the bounded scan without sleeping once
		// per not-yet-due Deployment.
		return true, nil
	}
	observer, routed := service.routes[candidate.ExecutionTargetID]
	if !routed {
		service.schedule(key, startedAt.Add(service.config.FailureBackoff))
		return true, nil
	}
	request := paasv1.ObserveDeploymentRuntimeRequest{
		RequestID:             runtimeRequestID(candidate, startedAt),
		Scope:                 paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: candidate.TenantID},
		DeploymentID:          candidate.DeploymentID,
		Generation:            candidate.Generation,
		ApplicationRevisionID: candidate.ApplicationRevisionID,
		ExecutionTargetID:     candidate.ExecutionTargetID,
		ExpectedContentDigest: candidate.ContentDigest,
		Deadline:              startedAt.Add(service.config.ObservationTimeout),
	}
	observeContext, cancel := context.WithDeadline(ctx, request.Deadline)
	runtimeObservation, resourceObservation, observeErr :=
		observer.ObserveDeploymentTelemetry(observeContext, request)
	cancel()
	completedAt := service.config.Clock().UTC().Truncate(time.Microsecond)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if observeErr != nil || !validTelemetry(
		candidate,
		runtimeObservation,
		resourceObservation,
		completedAt,
		service.config.MaximumObservationAge,
	) {
		service.schedule(key, completedAt.Add(service.config.FailureBackoff))
		return true, nil
	}
	if _, err := service.repository.Store(
		ctx,
		candidate.TenantID,
		candidate.PlacementDecisionID,
		TelemetrySnapshot{
			Runtime:             runtimeObservation,
			RuntimeValidUntil:   runtimeObservation.ObservedAt.Add(service.config.ValidityDuration),
			Resources:           resourceObservation,
			ResourcesValidUntil: resourceObservation.ObservedAt.Add(service.config.ValidityDuration),
		},
	); err != nil {
		if errors.Is(err, ErrSnapshotRejected) {
			// Placement or generation changed while the provider was observed. The
			// database rejected the stale proof; retry the new authority normally.
			service.schedule(key, completedAt.Add(service.config.FailureBackoff))
			return true, nil
		}
		return true, err
	}
	service.schedule(key, completedAt.Add(service.config.ObservationInterval))
	return true, nil
}

func validateCandidate(value Candidate) error {
	if paasv1.ValidateID("tenantId", string(value.TenantID)) != nil ||
		paasv1.ValidateID("deploymentId", string(value.DeploymentID)) != nil ||
		paasv1.ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)) != nil ||
		paasv1.ValidateID("executionTargetId", string(value.ExecutionTargetID)) != nil ||
		paasv1.ValidateID("placementDecisionId", string(value.PlacementDecisionID)) != nil ||
		paasv1.ValidateDigest("contentDigest", value.ContentDigest) != nil || value.Generation == 0 {
		return ErrInvalidCandidate
	}
	return nil
}

func validTelemetry(
	candidate Candidate,
	runtime paasv1.DeploymentRuntimeObservation,
	resources paasv1.DeploymentResourceObservation,
	now time.Time,
	maximumAge time.Duration,
) bool {
	if paasv1.ValidateDeploymentRuntimeObservation(runtime) != nil ||
		paasv1.ValidateDeploymentResourceObservation(resources) != nil ||
		runtime.DeploymentID != candidate.DeploymentID ||
		runtime.Generation != candidate.Generation ||
		runtime.ApplicationRevisionID != candidate.ApplicationRevisionID ||
		runtime.ExecutionTargetID != candidate.ExecutionTargetID ||
		resources.DeploymentID != candidate.DeploymentID ||
		resources.Generation != candidate.Generation ||
		resources.ApplicationRevisionID != candidate.ApplicationRevisionID ||
		resources.ExecutionTargetID != candidate.ExecutionTargetID ||
		runtime.ObservedAt.After(now.Add(maximumFutureSkew)) ||
		resources.ObservedAt.After(now.Add(maximumFutureSkew)) ||
		!now.Before(runtime.ObservedAt.Add(maximumAge)) ||
		!now.Before(resources.ObservedAt.Add(maximumAge)) ||
		len(runtime.Instances) != len(resources.Instances) {
		return false
	}
	instances := make(map[paasv1.ResourceID]struct{}, len(runtime.Instances))
	for _, instance := range runtime.Instances {
		instances[instance.ID] = struct{}{}
	}
	for _, instance := range resources.Instances {
		if _, found := instances[instance.ID]; !found {
			return false
		}
	}
	return true
}

func runtimeRequestID(candidate Candidate, now time.Time) paasv1.CommandID {
	digest := sha256.Sum256([]byte(
		"matrix-deployment-telemetry-request-v1\x00" + string(candidate.TenantID) + "\x00" +
			string(candidate.DeploymentID) + "\x00" + strconv.FormatUint(candidate.Generation, 10) + "\x00" +
			string(candidate.ApplicationRevisionID) + "\x00" + string(candidate.ExecutionTargetID) + "\x00" +
			string(candidate.PlacementDecisionID) + "\x00" + candidate.ContentDigest + "\x00" +
			now.Format(time.RFC3339Nano),
	))
	return paasv1.CommandID("runtime-" + hex.EncodeToString(digest[:16]))
}

func (service *Service) schedule(key string, due time.Time) {
	if _, tracked := service.nextDue[key]; !tracked && len(service.nextDue) >= maximumScheduledRuntimeCandidates {
		// Scheduling is only an optimization; clearing cannot change the stored
		// proof or route identity, and bounds memory if tenants churn Deployments.
		clear(service.nextDue)
	}
	service.nextDue[key] = due
}
