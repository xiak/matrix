// Package port owns the interfaces apphosting requires from external IAM,
// Audit, infrastructure, deployment-executor, and gateway adapters.
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

type DeploymentExecutor interface {
	Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error)
	ValidateDeployment(context.Context, paasv1.DeploymentExecutionRequest) (paasv1.AdapterResult, error)
	ApplyDeployment(context.Context, paasv1.DeploymentExecutionRequest) (paasv1.AdapterResult, error)
	ObserveDeployment(context.Context, paasv1.ObserveDeploymentRequest) (paasv1.DeploymentObservation, error)
	StopDeployment(context.Context, paasv1.DeploymentExecutionRequest) (paasv1.AdapterResult, error)
	RollbackDeployment(context.Context, paasv1.DeploymentExecutionRequest) (paasv1.AdapterResult, error)
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
