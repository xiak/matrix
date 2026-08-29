package main

import (
	"errors"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/paas/cmd/internal/nodeconnections"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
)

func loadNodeBindings(path, installationID string) ([]executionadmission.Binding, func(), error) {
	clients := []*nodehttps.Client{}
	closeClients := func() {
		for _, client := range clients {
			client.Close()
		}
	}
	invalid := errors.New("protected node connections are invalid")
	connections, err := nodeconnections.Load(path, installationID)
	if err != nil {
		return nil, closeClients, invalid
	}
	nodes := connections.Nodes()
	if len(nodes) > executionadmission.MaximumTargets {
		return nil, closeClients, invalid
	}
	bindings := make([]executionadmission.Binding, 0, len(nodes))
	for _, connection := range nodes {
		client, err := nodehttps.New(nodehttps.Config{Endpoint: connection.Endpoint, Identity: nodev1.Identity{InstallationID: installationID, ExecutionTargetID: connection.TargetID},
			ControllerID: connections.ControllerID(), BindingRef: connection.BindingRef, ExpectedFingerprint: connection.IdentityFingerprint, Credentials: connections.Credentials})
		if err != nil {
			closeClients()
			return nil, func() {}, invalid
		}
		clients = append(clients, client)
		bindings = append(bindings, executionadmission.Binding{Ref: connection.BindingRef, TargetID: connection.TargetID, IdentityFingerprint: connection.IdentityFingerprint, Adapter: client})
	}
	return bindings, closeClients, nil
}
