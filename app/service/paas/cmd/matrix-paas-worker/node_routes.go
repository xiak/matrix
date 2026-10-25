package main

import (
	"context"
	"errors"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/paas/cmd/internal/nodeconnections"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/reconciledeployment"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/refreshdeploymentruntime"
)

func newDeploymentRoutes(
	config configuration,
	catalog apphostingv1.ArtifactCatalog,
	secrets nodehttps.DeploymentSecretResolver,
	local port.DeploymentExecutor,
	dynamicConnections *nodeconnections.Dynamic,
) (
	[]reconciledeployment.DeploymentRoute,
	[]refreshdeploymentruntime.Route,
	*dynamicDeploymentRoutes,
	func(),
	error,
) {
	invalid := errors.New("PaaS worker node execution routes are invalid")
	if local == nil || secrets == nil || dynamicConnections == nil {
		return nil, nil, nil, func() {}, invalid
	}
	localObserver, observesTelemetry := local.(port.DeploymentTelemetryObserver)
	if !observesTelemetry {
		return nil, nil, nil, func() {}, invalid
	}
	connections, err := nodeconnections.Load(
		config.nodeConnectionsFile,
		config.installationID,
	)
	if err != nil {
		return nil, nil, nil, func() {}, invalid
	}
	artifacts, err := nodehttps.NewCatalogDeploymentArtifactResolver(catalog)
	if err != nil {
		return nil, nil, nil, func() {}, invalid
	}
	clients := make([]*nodehttps.DeploymentClient, 0, len(connections.Nodes()))
	closeClients := func() {
		for _, client := range clients {
			client.Close()
		}
	}
	routes := []reconciledeployment.DeploymentRoute{{
		ExecutionTargetID: localExecutionProfileIDs.TargetID,
		BindingRef:        config.bindingRef,
		Executor:          local,
	}}
	runtimeRoutes := []refreshdeploymentruntime.Route{{
		ExecutionTargetID: localExecutionProfileIDs.TargetID,
		Observer:          localObserver,
	}}
	for _, connection := range connections.Nodes() {
		client, err := nodehttps.NewDeploymentClient(nodehttps.DeploymentConfig{
			Connection: nodehttps.Config{
				Endpoint: connection.Endpoint,
				Identity: nodev1.Identity{
					InstallationID:    config.installationID,
					ExecutionTargetID: connection.TargetID,
				},
				ControllerID:        connections.ControllerID(),
				BindingRef:          connection.BindingRef,
				ExpectedFingerprint: connection.IdentityFingerprint,
				Credentials:         connections.Credentials,
			},
			Artifacts: artifacts,
			Secrets:   secrets,
		})
		if err != nil {
			closeClients()
			return nil, nil, nil, func() {}, invalid
		}
		clients = append(clients, client)
		routes = append(routes, reconciledeployment.DeploymentRoute{
			ExecutionTargetID: connection.TargetID,
			BindingRef:        connection.BindingRef,
			Executor:          client,
		})
		runtimeRoutes = append(runtimeRoutes, refreshdeploymentruntime.Route{
			ExecutionTargetID: connection.TargetID,
			Observer:          client,
		})
	}
	return routes, runtimeRoutes, &dynamicDeploymentRoutes{
		connections: dynamicConnections, artifacts: artifacts, secrets: secrets,
	}, closeClients, nil
}

type dynamicDeploymentRoutes struct {
	connections *nodeconnections.Dynamic
	artifacts   nodehttps.DeploymentArtifactResolver
	secrets     nodehttps.DeploymentSecretResolver
}

type dynamicDeploymentExecutor struct {
	routes     *dynamicDeploymentRoutes
	targetID   paasv1.ResourceID
	bindingRef string
}

func (routes *dynamicDeploymentRoutes) ResolveDeploymentRoute(
	ctx context.Context,
	targetID paasv1.ResourceID,
) (reconciledeployment.DeploymentRoute, bool, error) {
	executor, bindingRef, found, err := routes.resolve(ctx, targetID)
	if err != nil || !found {
		return reconciledeployment.DeploymentRoute{}, found, err
	}
	return reconciledeployment.DeploymentRoute{
		ExecutionTargetID: targetID, BindingRef: bindingRef, Executor: executor,
	}, true, nil
}

func (routes *dynamicDeploymentRoutes) ResolveDeploymentTelemetryObserver(
	ctx context.Context,
	targetID paasv1.ResourceID,
) (port.DeploymentTelemetryObserver, bool, error) {
	executor, _, found, err := routes.resolve(ctx, targetID)
	if err != nil || !found {
		return nil, found, err
	}
	return executor, true, nil
}

func (routes *dynamicDeploymentRoutes) resolve(
	ctx context.Context,
	targetID paasv1.ResourceID,
) (*dynamicDeploymentExecutor, string, bool, error) {
	if routes == nil || routes.connections == nil || routes.artifacts == nil || routes.secrets == nil {
		return nil, "", false, errors.New("dynamic Deployment routes are unavailable")
	}
	connection, found, err := routes.connections.Resolve(ctx, targetID, "")
	if err != nil || !found {
		return nil, "", found, err
	}
	return &dynamicDeploymentExecutor{
		routes: routes, targetID: targetID, bindingRef: connection.BindingRef,
	}, connection.BindingRef, true, nil
}

func (executor *dynamicDeploymentExecutor) client(
	ctx context.Context,
	targetID paasv1.ResourceID,
	bindingRef string,
) (*nodehttps.DeploymentClient, error) {
	if executor == nil || executor.routes == nil || targetID != executor.targetID ||
		bindingRef != executor.bindingRef {
		return nil, errors.New("dynamic Deployment route identity changed")
	}
	connection, found, err := executor.routes.connections.Resolve(ctx, targetID, bindingRef)
	if err != nil || !found {
		return nil, errors.New("dynamic Deployment connection is unavailable")
	}
	config, err := executor.routes.connections.ConnectionConfig(connection)
	if err != nil {
		return nil, errors.New("dynamic Deployment connection is invalid")
	}
	client, err := nodehttps.NewDeploymentClient(nodehttps.DeploymentConfig{
		Connection: config, Artifacts: executor.routes.artifacts, Secrets: executor.routes.secrets,
	})
	if err != nil {
		return nil, errors.New("dynamic Deployment client is unavailable")
	}
	return client, nil
}

func (executor *dynamicDeploymentExecutor) Capabilities(
	ctx context.Context,
) (paasv1.AdapterCapabilitiesContract, error) {
	client, err := executor.client(ctx, executor.targetID, executor.bindingRef)
	if err != nil {
		return paasv1.AdapterCapabilitiesContract{}, err
	}
	defer client.Close()
	return client.Capabilities(ctx)
}

func (executor *dynamicDeploymentExecutor) ValidateDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	client, err := executor.client(ctx, request.Command.ExecutionTargetID, request.Command.BindingRef)
	if err != nil {
		return paasv1.AdapterResult{}, err
	}
	defer client.Close()
	return client.ValidateDeployment(ctx, request)
}

func (executor *dynamicDeploymentExecutor) ApplyDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	client, err := executor.client(ctx, request.Command.ExecutionTargetID, request.Command.BindingRef)
	if err != nil {
		return paasv1.AdapterResult{}, err
	}
	defer client.Close()
	return client.ApplyDeployment(ctx, request)
}

func (executor *dynamicDeploymentExecutor) RollbackDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	client, err := executor.client(ctx, request.Command.ExecutionTargetID, request.Command.BindingRef)
	if err != nil {
		return paasv1.AdapterResult{}, err
	}
	defer client.Close()
	return client.RollbackDeployment(ctx, request)
}

func (executor *dynamicDeploymentExecutor) StopDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	client, err := executor.client(ctx, request.Command.ExecutionTargetID, request.Command.BindingRef)
	if err != nil {
		return paasv1.AdapterResult{}, err
	}
	defer client.Close()
	return client.StopDeployment(ctx, request)
}

func (executor *dynamicDeploymentExecutor) ObserveDeployment(
	ctx context.Context,
	request paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	client, err := executor.client(ctx, request.Command.ExecutionTargetID, request.Command.BindingRef)
	if err != nil {
		return paasv1.DeploymentObservation{}, err
	}
	defer client.Close()
	return client.ObserveDeployment(ctx, request)
}

func (executor *dynamicDeploymentExecutor) ObserveDeploymentTelemetry(
	ctx context.Context,
	request paasv1.ObserveDeploymentRuntimeRequest,
) (paasv1.DeploymentRuntimeObservation, paasv1.DeploymentResourceObservation, error) {
	client, err := executor.client(ctx, request.ExecutionTargetID, executor.bindingRef)
	if err != nil {
		return paasv1.DeploymentRuntimeObservation{}, paasv1.DeploymentResourceObservation{}, err
	}
	defer client.Close()
	return client.ObserveDeploymentTelemetry(ctx, request)
}
