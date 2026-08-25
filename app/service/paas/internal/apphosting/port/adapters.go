// Package port owns the interfaces apphosting requires from external
// infrastructure, deployment-executor, and gateway adapters.
package port

import (
	"context"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type InfrastructureAdapter interface {
	Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error)
	InspectExecutionTarget(context.Context, paasv1.InspectExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error)
	ObserveExecutionTarget(context.Context, paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error)
}

type DeploymentRequest struct {
	Command             paasv1.AdapterCommandEnvelope
	ApplicationRevision paasv1.ApplicationRevision
	Deployment          paasv1.Deployment
	Placement           paasv1.PlacementDecision
}

type ObserveDeploymentRequest struct {
	Command paasv1.AdapterCommandEnvelope
}

type DeploymentObservation struct {
	DeploymentID          paasv1.ResourceID
	ApplicationRevisionID paasv1.ResourceID
	Phase                 paasv1.DeploymentPhase
	ReadyComponents       uint32
	Evidence              []paasv1.Evidence
	ObservedAt            time.Time
}

type DeploymentExecutor interface {
	Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error)
	ValidateDeployment(context.Context, DeploymentRequest) (paasv1.AdapterResult, error)
	ApplyDeployment(context.Context, DeploymentRequest) (paasv1.AdapterResult, error)
	ObserveDeployment(context.Context, ObserveDeploymentRequest) (DeploymentObservation, error)
	StopDeployment(context.Context, DeploymentRequest) (paasv1.AdapterResult, error)
	RollbackDeployment(context.Context, DeploymentRequest) (paasv1.AdapterResult, error)
}

type Route struct {
	Name       string
	Endpoint   string
	Host       string
	PathPrefix string
	TLSRef     paasv1.ResourceID
}

type RouteRequest struct {
	Command paasv1.AdapterCommandEnvelope
	Routes  []Route
}

type RouteObservation struct {
	Ready      bool
	Evidence   []paasv1.Evidence
	ObservedAt time.Time
}

type GatewayAdapter interface {
	Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error)
	ReconcileRoutes(context.Context, RouteRequest) (paasv1.AdapterResult, error)
	ObserveRoutes(context.Context, RouteRequest) (RouteObservation, error)
	DeleteRoutes(context.Context, RouteRequest) (paasv1.AdapterResult, error)
}

type AdapterFault = paasv1.AdapterFault
