package nodeconnections

import (
	"context"
	"path/filepath"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

type DynamicConfig struct {
	InstallationID  string
	ControllerID    string
	CertificateFile string
	PrivateKeyFile  string
	TrustFile       string
}

// Dynamic resolves only connections atomically published by enrollment. It
// owns no route cache: every operation observes revocation/removal through the
// database, and every new TLS connection rereads installation-owned material.
type Dynamic struct {
	reader          port.EnrolledNodeConnectionReader
	installationID  string
	controllerID    string
	certificateFile string
	privateKeyFile  string
	trustFile       string
}

func NewDynamic(reader port.EnrolledNodeConnectionReader, config DynamicConfig) (*Dynamic, error) {
	if reader == nil || paasv1.ValidateID("installationId", config.InstallationID) != nil ||
		paasv1.ValidateID("controllerId", config.ControllerID) != nil ||
		!validCredentialFiles(config.CertificateFile, config.PrivateKeyFile, config.TrustFile) {
		return nil, errInvalid
	}
	resolver := &Dynamic{
		reader: reader, installationID: config.InstallationID, controllerID: config.ControllerID,
		certificateFile: config.CertificateFile, privateKeyFile: config.PrivateKeyFile,
		trustFile: config.TrustFile,
	}
	credentials, err := resolver.credentials()
	if err != nil {
		return nil, errInvalid
	}
	validationClient, err := nodehttps.New(nodehttps.Config{
		Endpoint: "https://127.0.0.1:16443",
		Identity: nodev1.Identity{
			InstallationID: config.InstallationID, ExecutionTargetID: "execution-target-validation",
		},
		ControllerID:        config.ControllerID,
		BindingRef:          "node-binding-00000000000000000000000000000000",
		ExpectedFingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Credentials:         func() (nodehttps.Credentials, error) { return credentials, nil },
	})
	if err != nil {
		return nil, errInvalid
	}
	validationClient.Close()
	return resolver, nil
}

func validCredentialFiles(paths ...string) bool {
	if len(paths) != 3 {
		return false
	}
	directory := ""
	seen := map[string]bool{}
	for _, value := range paths {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || seen[value] {
			return false
		}
		seen[value] = true
		if directory == "" {
			directory = filepath.Dir(value)
		} else if filepath.Dir(value) != directory {
			return false
		}
	}
	return true
}

func (resolver *Dynamic) credentials() (nodehttps.Credentials, error) {
	if resolver == nil {
		return nodehttps.Credentials{}, errInvalid
	}
	certificate, err := processconfig.ReadFile(resolver.certificateFile, 64*1024, true)
	if err != nil {
		return nodehttps.Credentials{}, errInvalid
	}
	defer clear(certificate)
	privateKey, err := processconfig.ReadFile(resolver.privateKeyFile, 64*1024, true)
	if err != nil {
		return nodehttps.Credentials{}, errInvalid
	}
	defer clear(privateKey)
	trust, err := processconfig.ReadFile(resolver.trustFile, 256*1024, true)
	if err != nil {
		return nodehttps.Credentials{}, errInvalid
	}
	defer clear(trust)
	credentials, err := nodehttps.NewCredentials(certificate, privateKey, trust)
	if err != nil {
		return nodehttps.Credentials{}, errInvalid
	}
	return credentials, nil
}

func (resolver *Dynamic) Resolve(
	ctx context.Context,
	targetID paasv1.ResourceID,
	bindingRef string,
) (port.EnrolledNodeConnection, bool, error) {
	if resolver == nil || resolver.reader == nil || ctx == nil ||
		paasv1.ValidateID("executionTargetId", string(targetID)) != nil ||
		(bindingRef != "" && paasv1.ValidateID("bindingRef", bindingRef) != nil) {
		return port.EnrolledNodeConnection{}, false, errInvalid
	}
	connection, found, err := resolver.reader.LoadEnrolledNodeConnection(
		ctx, resolver.installationID, targetID,
	)
	if err != nil {
		return port.EnrolledNodeConnection{}, false, err
	}
	if !found || !connection.Enabled {
		return port.EnrolledNodeConnection{}, false, nil
	}
	if port.ValidateEnrolledNodeConnection(connection) != nil ||
		connection.InstallationID != resolver.installationID ||
		connection.ExecutionTargetID != targetID ||
		connection.ControllerID != resolver.controllerID ||
		(bindingRef != "" && connection.BindingRef != bindingRef) {
		return port.EnrolledNodeConnection{}, false, errInvalid
	}
	return connection, true, nil
}

func (resolver *Dynamic) ConnectionConfig(connection port.EnrolledNodeConnection) (nodehttps.Config, error) {
	if resolver == nil || port.ValidateEnrolledNodeConnection(connection) != nil || !connection.Enabled ||
		connection.InstallationID != resolver.installationID ||
		connection.ControllerID != resolver.controllerID {
		return nodehttps.Config{}, errInvalid
	}
	return nodehttps.Config{
		Endpoint: connection.Endpoint,
		Identity: nodev1.Identity{
			InstallationID: connection.InstallationID, ExecutionTargetID: connection.ExecutionTargetID,
		},
		ControllerID: connection.ControllerID, BindingRef: connection.BindingRef,
		ExpectedFingerprint: connection.IdentityFingerprint, Credentials: resolver.credentials,
	}, nil
}

func (resolver *Dynamic) ResolveInfrastructureAdapter(
	ctx context.Context,
	targetID paasv1.ResourceID,
	bindingRef string,
	identityFingerprint string,
) (port.InfrastructureAdapter, func(), bool, error) {
	if paasv1.ValidateDigest("identityFingerprint", identityFingerprint) != nil {
		return nil, func() {}, false, errInvalid
	}
	connection, found, err := resolver.Resolve(ctx, targetID, bindingRef)
	if err != nil || !found {
		return nil, func() {}, found, err
	}
	if connection.IdentityFingerprint != identityFingerprint {
		return nil, func() {}, false, errInvalid
	}
	config, err := resolver.ConnectionConfig(connection)
	if err != nil {
		return nil, func() {}, false, err
	}
	client, err := nodehttps.New(config)
	if err != nil {
		return nil, func() {}, false, errInvalid
	}
	return client, client.Close, true, nil
}

func (resolver *Dynamic) Probe(
	ctx context.Context,
	connection port.EnrolledNodeConnection,
	request paasv1.InspectExecutionTargetRequest,
) (paasv1.AdapterCapabilitiesContract, paasv1.ExecutionTargetObservation, error) {
	config, err := resolver.ConnectionConfig(connection)
	if err != nil {
		return paasv1.AdapterCapabilitiesContract{}, paasv1.ExecutionTargetObservation{}, err
	}
	client, err := nodehttps.New(config)
	if err != nil {
		return paasv1.AdapterCapabilitiesContract{}, paasv1.ExecutionTargetObservation{}, err
	}
	defer client.Close()
	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		return paasv1.AdapterCapabilitiesContract{}, paasv1.ExecutionTargetObservation{}, err
	}
	observation, err := client.InspectExecutionTarget(ctx, request)
	if err != nil {
		return paasv1.AdapterCapabilitiesContract{}, paasv1.ExecutionTargetObservation{}, err
	}
	return capabilities, observation, nil
}
