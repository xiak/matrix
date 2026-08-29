package reconciledeployment

import (
	"context"
	"errors"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

var (
	ErrNotFound            = errors.New("Deployment execution state not found")
	ErrStaleLease          = errors.New("Deployment execution lease or fencing token is stale")
	ErrIdempotencyConflict = errors.New("Deployment execution intent conflicts with stored state")
)

type OperationQueue interface {
	ClaimNext(context.Context, string) (operationqueue.Lease, bool, error)
	Advance(context.Context, operationqueue.Transition) (operationqueue.Lease, error)
	Release(context.Context, operationqueue.Lease, time.Time) (operationqueue.Lease, error)
}

type Placement interface {
	CreatePlacement(
		context.Context,
		createplacement.Command,
		operationqueue.LeaseGuard,
	) (createplacement.Result, error)
	BindStopPlacement(
		context.Context,
		createplacement.Command,
		operationqueue.LeaseGuard,
	) (createplacement.Result, error)
}

type StoredReceipt struct {
	CommandID     paasv1.CommandID
	RequestDigest string
	State         paasv1.AdapterResultState
	ReceiptDigest string
	Error         *paasv1.NormalizedAdapterError
	ObservedAt    time.Time
}

type State struct {
	Deployment             paasv1.Deployment
	Generation             paasv1.DeploymentGeneration
	ApplicationRevision    paasv1.ApplicationRevision
	ConfigurationRevisions []paasv1.ConfigurationRevision
	Placement              *paasv1.PlacementDecision
	EffectRequest          *paasv1.DeploymentExecutionRequest
	Receipt                *StoredReceipt
	ObserveRequest         *paasv1.ObserveDeploymentRequest
	Observation            *paasv1.DeploymentObservation
}

type Terminal struct {
	State          paasv1.OperationState
	Problem        *paasv1.Problem
	ReleasePending bool
}

type Repository interface {
	Load(context.Context, operationqueue.LeaseGuard) (State, error)
	UpdatePhase(
		context.Context,
		operationqueue.LeaseGuard,
		paasv1.DeploymentPhase,
	) (paasv1.Deployment, error)
	PrepareEffect(
		context.Context,
		operationqueue.Lease,
		paasv1.AdapterAction,
		string,
		time.Time,
	) (paasv1.DeploymentExecutionRequest, bool, error)
	PrepareObservation(
		context.Context,
		operationqueue.Lease,
		string,
		time.Time,
	) (paasv1.ObserveDeploymentRequest, bool, error)
	RecordResult(
		context.Context,
		operationqueue.LeaseGuard,
		string,
		paasv1.AdapterResult,
	) (bool, error)
	RecordObservation(
		context.Context,
		operationqueue.LeaseGuard,
		paasv1.CommandID,
		paasv1.DeploymentObservation,
	) (bool, error)
	FinalizeSuccess(
		context.Context,
		operationqueue.Lease,
		paasv1.DeploymentObservation,
	) (paasv1.Deployment, paasv1.Operation, error)
	FinalizeTerminal(
		context.Context,
		operationqueue.Lease,
		Terminal,
	) (paasv1.Deployment, paasv1.Operation, error)
}

type Clock func() time.Time

// DeploymentRoute binds one persisted execution target to exactly one
// installation-owned executor. It is immutable for a worker process and has no
// local or alternate-target fallback.
type DeploymentRoute struct {
	ExecutionTargetID paasv1.ResourceID
	BindingRef        string
	Executor          port.DeploymentExecutor
}

type Config struct {
	EffectTimeout    time.Duration
	ReconcileBackoff time.Duration
	MaxAttempts      uint32
	Clock            Clock
}

type Worker struct {
	queue      OperationQueue
	placement  Placement
	repository Repository
	routes     map[paasv1.ResourceID]DeploymentRoute
	config     Config
}
