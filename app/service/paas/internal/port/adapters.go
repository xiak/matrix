// Package port owns the interfaces the PaaS service requires from external
// infrastructure, runtime, and gateway adapters.
package port

import (
	"context"
	"time"

	paasv1 "matrix/api/paas/v1"
)

type InfrastructureAdapter interface {
	Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error)
	InspectTarget(context.Context, paasv1.InspectTargetRequest) (paasv1.TargetObservation, error)
	ObserveTarget(context.Context, paasv1.ObserveTargetRequest) (paasv1.TargetObservation, error)
}

type ReleaseRequest struct {
	Command   paasv1.AdapterCommandEnvelope
	Release   paasv1.WorkloadRelease
	Placement paasv1.PlacementDecision
}

type ObserveReleaseRequest struct {
	Command paasv1.AdapterCommandEnvelope
}

type ReleaseObservation struct {
	ReleaseID       paasv1.ResourceID
	Phase           paasv1.ReleasePhase
	ReadyComponents uint32
	RevisionDigest  string
	Evidence        []paasv1.Evidence
	ObservedAt      time.Time
}

type RuntimeAdapter interface {
	Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error)
	ValidateRelease(context.Context, ReleaseRequest) (paasv1.AdapterResult, error)
	Apply(context.Context, ReleaseRequest) (paasv1.AdapterResult, error)
	Observe(context.Context, ObserveReleaseRequest) (ReleaseObservation, error)
	Stop(context.Context, ReleaseRequest) (paasv1.AdapterResult, error)
	Rollback(context.Context, ReleaseRequest) (paasv1.AdapterResult, error)
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
