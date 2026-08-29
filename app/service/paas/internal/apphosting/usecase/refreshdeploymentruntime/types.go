// Package refreshdeploymentruntime owns the asynchronous, read-only
// Deployment runtime projection. Its snapshots have a lifecycle independent
// from Deployment Operations.
package refreshdeploymentruntime

import (
	"context"
	"errors"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

var (
	ErrInvalidCandidate = errors.New("Deployment runtime candidate is invalid")
	ErrSnapshotRejected = errors.New("Deployment runtime snapshot was rejected")
)

type Cursor struct {
	TenantID     paasv1.TenantID
	DeploymentID paasv1.ResourceID
}

type Candidate struct {
	TenantID              paasv1.TenantID
	DeploymentID          paasv1.ResourceID
	Generation            uint64
	ApplicationRevisionID paasv1.ResourceID
	ExecutionTargetID     paasv1.ResourceID
	PlacementDecisionID   paasv1.ResourceID
	ContentDigest         string
}

type Repository interface {
	Next(context.Context, Cursor) (Candidate, bool, error)
	Store(
		context.Context,
		paasv1.TenantID,
		paasv1.ResourceID,
		paasv1.DeploymentRuntimeObservation,
		time.Time,
	) (bool, error)
}

type Route struct {
	ExecutionTargetID paasv1.ResourceID
	Observer          port.DeploymentRuntimeObserver
}

type Config struct {
	ObservationInterval   time.Duration
	FailureBackoff        time.Duration
	ObservationTimeout    time.Duration
	MaximumObservationAge time.Duration
	ValidityDuration      time.Duration
	Clock                 func() time.Time
}

type Service struct {
	repository Repository
	routes     map[paasv1.ResourceID]port.DeploymentRuntimeObserver
	config     Config
	cursor     Cursor
	nextDue    map[string]time.Time
}
