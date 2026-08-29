package main

import (
	"errors"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/paas/cmd/internal/nodeconnections"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/reconciledeployment"
)

func newDeploymentRoutes(
	config configuration,
	catalog apphostingv1.ArtifactCatalog,
	secrets nodehttps.DeploymentSecretResolver,
	local port.DeploymentExecutor,
) ([]reconciledeployment.DeploymentRoute, func(), error) {
	invalid := errors.New("PaaS worker node execution routes are invalid")
	if local == nil || secrets == nil {
		return nil, func() {}, invalid
	}
	connections, err := nodeconnections.Load(
		config.nodeConnectionsFile,
		config.installationID,
	)
	if err != nil {
		return nil, func() {}, invalid
	}
	artifacts, err := nodehttps.NewCatalogDeploymentArtifactResolver(catalog)
	if err != nil {
		return nil, func() {}, invalid
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
			return nil, func() {}, invalid
		}
		clients = append(clients, client)
		routes = append(routes, reconciledeployment.DeploymentRoute{
			ExecutionTargetID: connection.TargetID,
			BindingRef:        connection.BindingRef,
			Executor:          client,
		})
	}
	return routes, closeClients, nil
}
