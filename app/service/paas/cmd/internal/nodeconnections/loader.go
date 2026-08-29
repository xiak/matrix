// Package nodeconnections loads the installation-owned, protected node
// controller document for PaaS composition roots. It retains no key bytes and
// refuses target or binding changes underneath an already constructed client.
package nodeconnections

import (
	"errors"
	"slices"

	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

var errInvalid = errors.New("protected node connections are invalid")

type Set struct {
	path           string
	installationID string
	controllerID   string
	nodes          []nodeconfig.Connection
}

// Load accepts an empty path for an installation without enrolled nodes. A
// non-empty document is closed, installation-bound input written by mx.
func Load(path, installationID string) (Set, error) {
	if path == "" {
		return Set{installationID: installationID, nodes: []nodeconfig.Connection{}}, nil
	}
	configuration, err := read(path, installationID)
	if err != nil {
		return Set{}, errInvalid
	}
	defer configuration.Clear()
	if len(configuration.Nodes) > 0 {
		if _, err := nodehttps.NewCredentials(
			configuration.Certificate,
			configuration.PrivateKey,
			configuration.Trust,
		); err != nil {
			return Set{}, errInvalid
		}
	}
	return Set{
		path: path, installationID: installationID,
		controllerID: configuration.ControllerID,
		nodes:        slices.Clone(configuration.Nodes),
	}, nil
}

func (set Set) ControllerID() string { return set.controllerID }

func (set Set) Nodes() []nodeconfig.Connection { return slices.Clone(set.nodes) }

// Credentials rereads the whole private document for every new TLS
// connection. Credential rotation is allowed; authority, target, endpoint,
// binding and fingerprint changes require a process restart after installation
// has atomically replaced the document.
func (set Set) Credentials() (nodehttps.Credentials, error) {
	if set.path == "" || len(set.nodes) == 0 {
		return nodehttps.Credentials{}, errInvalid
	}
	current, err := read(set.path, set.installationID)
	if err != nil {
		return nodehttps.Credentials{}, errInvalid
	}
	defer current.Clear()
	if current.ControllerID != set.controllerID || !slices.Equal(current.Nodes, set.nodes) {
		return nodehttps.Credentials{}, errInvalid
	}
	credentials, err := nodehttps.NewCredentials(
		current.Certificate,
		current.PrivateKey,
		current.Trust,
	)
	if err != nil {
		return nodehttps.Credentials{}, errInvalid
	}
	return credentials, nil
}

func read(path, installationID string) (nodeconfig.ControllerConfiguration, error) {
	document, err := processconfig.ReadFile(path, nodeconfig.MaximumControllerBytes, true)
	if err != nil {
		return nodeconfig.ControllerConfiguration{}, errInvalid
	}
	defer clear(document)
	configuration, err := nodeconfig.DecodeController(document)
	if err != nil || configuration.InstallationID != installationID {
		configuration.Clear()
		return nodeconfig.ControllerConfiguration{}, errInvalid
	}
	return configuration, nil
}
