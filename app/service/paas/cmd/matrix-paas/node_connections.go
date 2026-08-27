package main

import (
	"errors"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
)

// This is protected installation input, never a northbound request. One
// controller certificate admits only its installation's exact node identities.
type nodeConnections struct {
	InstallationID  string           `json:"installationId"`
	ControllerID    string           `json:"controllerId"`
	CertificateFile string           `json:"certificateFile"`
	PrivateKeyFile  string           `json:"privateKeyFile"`
	TrustFile       string           `json:"trustFile"`
	Nodes           []nodeConnection `json:"nodes"`
}

type nodeConnection struct {
	BindingRef          string            `json:"bindingRef"`
	TargetID            paasv1.ResourceID `json:"targetId"`
	Endpoint            string            `json:"endpoint"`
	IdentityFingerprint string            `json:"identityFingerprint"`
}

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
	document, err := processconfig.ReadFile(path, 256*1024, true)
	if err != nil {
		return nil, closeClients, invalid
	}
	defer clear(document)
	var configuration nodeConnections
	if contractjson.DecodeObjectBytes(document, 256*1024, &configuration) != nil || configuration.InstallationID != installationID ||
		paasv1.ValidateID("installationId", installationID) != nil || paasv1.ValidateID("controllerId", configuration.ControllerID) != nil ||
		len(configuration.Nodes) < 1 || len(configuration.Nodes) > executionadmission.MaximumTargets {
		return nil, closeClients, invalid
	}
	certificate, err := processconfig.ReadFile(configuration.CertificateFile, 64*1024, true)
	if err != nil {
		return nil, closeClients, invalid
	}
	defer clear(certificate)
	key, err := processconfig.ReadFile(configuration.PrivateKeyFile, 64*1024, true)
	if err != nil {
		return nil, closeClients, invalid
	}
	defer clear(key)
	trust, err := processconfig.ReadFile(configuration.TrustFile, 256*1024, true)
	if err != nil {
		return nil, closeClients, invalid
	}
	defer clear(trust)
	credentials, err := nodehttps.NewCredentials(certificate, key, trust)
	if err != nil {
		return nil, closeClients, invalid
	}
	bindings := make([]executionadmission.Binding, 0, len(configuration.Nodes))
	seenBindings, seenTargets, seenFingerprints := map[string]bool{}, map[paasv1.ResourceID]bool{}, map[string]bool{}
	for _, connection := range configuration.Nodes {
		if seenBindings[connection.BindingRef] || seenTargets[connection.TargetID] || seenFingerprints[connection.IdentityFingerprint] {
			closeClients()
			return nil, func() {}, invalid
		}
		client, err := nodehttps.New(nodehttps.Config{Endpoint: connection.Endpoint, Identity: nodev1.Identity{InstallationID: installationID, ExecutionTargetID: connection.TargetID},
			ControllerID: configuration.ControllerID, BindingRef: connection.BindingRef, ExpectedFingerprint: connection.IdentityFingerprint, Credentials: credentials})
		if err != nil {
			closeClients()
			return nil, func() {}, invalid
		}
		clients = append(clients, client)
		seenBindings[connection.BindingRef], seenTargets[connection.TargetID], seenFingerprints[connection.IdentityFingerprint] = true, true, true
		bindings = append(bindings, executionadmission.Binding{Ref: connection.BindingRef, TargetID: connection.TargetID, IdentityFingerprint: connection.IdentityFingerprint, Adapter: client})
	}
	return bindings, closeClients, nil
}
