package nodeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	ControllerKind         = "NodeControllerConfiguration"
	DefaultControllerID    = "paas-controller-v1"
	MaximumConnections     = 128
	MaximumControllerBytes = 1024 * 1024
)

// Connection is protected installation input, never a registration request.
// Its complete identity remains immutable once published to this controller.
type Connection struct {
	BindingRef          string            `json:"bindingRef"`
	TargetID            paasv1.ResourceID `json:"targetId"`
	Endpoint            string            `json:"endpoint"`
	IdentityFingerprint string            `json:"identityFingerprint"`
}

// ControllerConfiguration is one atomic private document. It avoids partially
// replaced key/path pairs and bind-mounted file inodes surviving rotation.
// No CA signing key or node/collector private key belongs in this document.
type ControllerConfiguration struct {
	APIVersion     string
	Kind           string
	InstallationID string
	ControllerID   string
	Nodes          []Connection
	Certificate    []byte
	PrivateKey     []byte
	Trust          []byte
}

func (ControllerConfiguration) String() string   { return "node controller configuration <redacted>" }
func (ControllerConfiguration) GoString() string { return "node controller configuration <redacted>" }
func (ControllerConfiguration) MarshalJSON() ([]byte, error) {
	return nil, errors.New("node controller configuration requires explicit private encoding")
}

func (configuration ControllerConfiguration) Clear() {
	clear(configuration.Certificate)
	clear(configuration.PrivateKey)
	clear(configuration.Trust)
}

type controllerDocument struct {
	APIVersion     string       `json:"apiVersion"`
	Kind           string       `json:"kind"`
	InstallationID string       `json:"installationId"`
	ControllerID   string       `json:"controllerId"`
	Nodes          []Connection `json:"nodes"`
	Certificate    []byte       `json:"certificate,omitempty"`
	PrivateKey     []byte       `json:"privateKey,omitempty"`
	Trust          []byte       `json:"trust,omitempty"`
}

func EmptyController(installationID string) ControllerConfiguration {
	return ControllerConfiguration{APIVersion: APIVersion, Kind: ControllerKind,
		InstallationID: installationID, ControllerID: DefaultControllerID, Nodes: []Connection{}}
}

func ValidateController(configuration ControllerConfiguration) error {
	invalid := errors.New("node controller configuration is invalid")
	if configuration.APIVersion != APIVersion || configuration.Kind != ControllerKind ||
		paasv1.ValidateID("installationId", configuration.InstallationID) != nil ||
		paasv1.ValidateID("controllerId", configuration.ControllerID) != nil ||
		configuration.Nodes == nil || len(configuration.Nodes) > MaximumConnections {
		return invalid
	}
	if len(configuration.Nodes) == 0 {
		if len(configuration.Certificate) != 0 || len(configuration.PrivateKey) != 0 || len(configuration.Trust) != 0 {
			return invalid
		}
		return nil
	}
	if len(configuration.Certificate) == 0 || len(configuration.Certificate) > 64*1024 ||
		len(configuration.PrivateKey) == 0 || len(configuration.PrivateKey) > 64*1024 ||
		len(configuration.Trust) == 0 || len(configuration.Trust) > 256*1024 {
		return invalid
	}
	bindings, targets, fingerprints, endpoints := map[string]bool{}, map[paasv1.ResourceID]bool{}, map[string]bool{}, map[string]bool{}
	for _, connection := range configuration.Nodes {
		endpoint, err := url.Parse(connection.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Opaque != "" ||
			endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
			!privateListenAddress(endpoint.Host) ||
			paasv1.ValidateID("bindingRef", connection.BindingRef) != nil || paasv1.ValidateID("targetId", string(connection.TargetID)) != nil ||
			paasv1.ValidateDigest("identityFingerprint", connection.IdentityFingerprint) != nil ||
			bindings[connection.BindingRef] || targets[connection.TargetID] || fingerprints[connection.IdentityFingerprint] || endpoints[connection.Endpoint] {
			return invalid
		}
		bindings[connection.BindingRef], targets[connection.TargetID], fingerprints[connection.IdentityFingerprint], endpoints[connection.Endpoint] = true, true, true, true
	}
	return nil
}

// ValidateControllerUpdate admits additions and credential rotation, never
// removal or replacement of a registered target's identity by a local file.
// Decommissioning is a separately authorized PaaS lifecycle, not this command.
func ValidateControllerUpdate(before, after ControllerConfiguration) error {
	if ValidateController(before) != nil || ValidateController(after) != nil ||
		before.InstallationID != after.InstallationID || before.ControllerID != after.ControllerID {
		return errors.New("node controller replacement changes its authority")
	}
	for _, connection := range before.Nodes {
		if !slices.Contains(after.Nodes, connection) {
			return errors.New("node controller replacement removes or rebinds a target")
		}
	}
	return nil
}

func EncodeController(configuration ControllerConfiguration) ([]byte, error) {
	if err := ValidateController(configuration); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(controllerDocument{configuration.APIVersion, configuration.Kind,
		configuration.InstallationID, configuration.ControllerID, configuration.Nodes,
		configuration.Certificate, configuration.PrivateKey, configuration.Trust})
	if err != nil || len(encoded) > MaximumControllerBytes {
		clear(encoded)
		return nil, errors.New("node controller private encoding failed")
	}
	return encoded, nil
}

func DecodeController(source []byte) (ControllerConfiguration, error) {
	var document controllerDocument
	if contractjson.DecodeObjectBytes(source, MaximumControllerBytes, &document) != nil {
		clear(document.PrivateKey)
		return ControllerConfiguration{}, errors.New("node controller private document is invalid")
	}
	configuration := ControllerConfiguration{document.APIVersion, document.Kind, document.InstallationID,
		document.ControllerID, document.Nodes, document.Certificate, document.PrivateKey, document.Trust}
	if len(document.Nodes) == 0 {
		var fields map[string]json.RawMessage
		if json.Unmarshal(source, &fields) != nil {
			configuration.Clear()
			return ControllerConfiguration{}, errors.New("node controller private document is invalid")
		}
		for _, key := range []string{"certificate", "privateKey", "trust"} {
			if _, present := fields[key]; present {
				configuration.Clear()
				return ControllerConfiguration{}, errors.New("empty node controller contains credential material")
			}
		}
	}
	if err := ValidateController(configuration); err != nil {
		configuration.Clear()
		return ControllerConfiguration{}, err
	}
	return configuration, nil
}

func ControllerDigest(configuration ControllerConfiguration) (string, error) {
	encoded, err := EncodeController(configuration)
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
