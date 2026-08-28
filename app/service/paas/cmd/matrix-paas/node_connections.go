package main

import (
	"errors"
	"slices"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
)

func loadNodeBindings(path, installationID string) ([]executionadmission.Binding, func(), error) {
	clients := []*nodehttps.Client{}
	closeClients := func() {
		for _, client := range clients {
			client.Close()
		}
	}
	if path == "" {
		return nil, closeClients, nil
	}
	invalid := errors.New("protected node connections are invalid")
	configuration, err := readNodeConnections(path, installationID)
	if err != nil {
		return nil, closeClients, invalid
	}
	defer configuration.Clear()
	credentials := func() (nodehttps.Credentials, error) {
		current, err := readNodeConnections(path, installationID)
		defer current.Clear()
		if err != nil || current.ControllerID != configuration.ControllerID || !slices.Equal(current.Nodes, configuration.Nodes) {
			return nodehttps.Credentials{}, invalid
		}
		return nodehttps.NewCredentials(current.Certificate, current.PrivateKey, current.Trust)
	}
	bindings := make([]executionadmission.Binding, 0, len(configuration.Nodes))
	for _, connection := range configuration.Nodes {
		client, err := nodehttps.New(nodehttps.Config{Endpoint: connection.Endpoint, Identity: nodev1.Identity{InstallationID: installationID, ExecutionTargetID: connection.TargetID},
			ControllerID: configuration.ControllerID, BindingRef: connection.BindingRef, ExpectedFingerprint: connection.IdentityFingerprint, Credentials: credentials})
		if err != nil {
			closeClients()
			return nil, func() {}, invalid
		}
		clients = append(clients, client)
		bindings = append(bindings, executionadmission.Binding{Ref: connection.BindingRef, TargetID: connection.TargetID, IdentityFingerprint: connection.IdentityFingerprint, Adapter: client})
	}
	return bindings, closeClients, nil
}

func readNodeConnections(path, installationID string) (nodeconfig.ControllerConfiguration, error) {
	invalid := errors.New("protected node connections are invalid")
	document, err := processconfig.ReadFile(path, nodeconfig.MaximumControllerBytes, true)
	if err != nil {
		return nodeconfig.ControllerConfiguration{}, invalid
	}
	defer clear(document)
	configuration, err := nodeconfig.DecodeController(document)
	if err != nil || configuration.InstallationID != installationID || len(configuration.Nodes) > executionadmission.MaximumTargets {
		configuration.Clear()
		return nodeconfig.ControllerConfiguration{}, invalid
	}
	return configuration, nil
}
