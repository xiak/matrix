package nodecommand

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

// Credentials is installation-only material. No controller key is accepted,
// serialized into a command result, or retained in a journal.
type Credentials struct {
	Certificate          []byte `json:"-"`
	PrivateKey           []byte `json:"-"`
	Trust                []byte `json:"-"`
	CollectorCertificate []byte `json:"-"`
	CollectorPrivateKey  []byte `json:"-"`
}

func (Credentials) String() string   { return "node enrollment credentials <redacted>" }
func (Credentials) GoString() string { return "node enrollment credentials <redacted>" }
func (value Credentials) Clear() {
	clear(value.Certificate)
	clear(value.PrivateKey)
	clear(value.Trust)
	clear(value.CollectorCertificate)
	clear(value.CollectorPrivateKey)
}

func enrollment(root, path string) (nodeconfig.Configuration, Credentials, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || len(root) > 4096 ||
		strings.ContainsAny(root, "\x00\r\n") {
		return nodeconfig.Configuration{}, Credentials{}, errors.New("node root is invalid")
	}
	source, err := processconfig.ReadFile(path, nodeconfig.MaximumBytes, true)
	if err != nil {
		return nodeconfig.Configuration{}, Credentials{}, errors.New("protected node enrollment is unavailable")
	}
	defer clear(source)
	input, err := nodeconfig.DecodeEnrollment(source)
	if err != nil || lifecycle.ValidateInstallationID(input.Node.Identity.InstallationID) != nil ||
		input.Node.StoragePath != filepath.Join(root, filepath.FromSlash(layout.ExecutorRoot)) {
		return nodeconfig.Configuration{}, Credentials{}, errors.New("node enrollment identity or storage is invalid")
	}
	var material Credentials
	for _, file := range []struct {
		path    string
		maximum int64
		secret  bool
		target  *[]byte
	}{
		{input.Node.CertificateFile, 64 * 1024, false, &material.Certificate},
		{input.Node.PrivateKeyFile, 64 * 1024, true, &material.PrivateKey},
		{input.Node.TrustFile, 256 * 1024, false, &material.Trust},
		{input.CollectorCertificateFile, 64 * 1024, false, &material.CollectorCertificate},
		{input.CollectorPrivateKeyFile, 64 * 1024, true, &material.CollectorPrivateKey},
	} {
		*file.target, err = processconfig.ReadFile(file.path, file.maximum, file.secret)
		if err != nil {
			material.Clear()
			return nodeconfig.Configuration{}, Credentials{}, errors.New("node enrollment credential is unavailable")
		}
	}
	config := input.Node
	config.CertificateFile = filepath.Join(root, filepath.FromSlash(layout.NodeCertificate))
	config.PrivateKeyFile = filepath.Join(root, filepath.FromSlash(layout.NodePrivateKey))
	config.TrustFile = filepath.Join(root, filepath.FromSlash(layout.NodeTrust))
	return config, material, nil
}

// Binding commits the effective configuration and all credential bytes. Input
// source filenames are not persisted; the effective paths belong to this root.
func Binding(config nodeconfig.Configuration, material Credentials) (lifecycle.NodeBinding, error) {
	if nodeconfig.ValidateConfiguration(config) != nil {
		return lifecycle.NodeBinding{}, errors.New("node configuration is invalid")
	}
	for _, value := range [][]byte{material.Certificate, material.PrivateKey, material.Trust,
		material.CollectorCertificate, material.CollectorPrivateKey} {
		if len(value) == 0 || len(value) > 256*1024 {
			return lifecycle.NodeBinding{}, errors.New("node credential is invalid")
		}
	}
	commitment := struct {
		Configuration        nodeconfig.Configuration `json:"configuration"`
		Certificate          string                   `json:"certificate"`
		PrivateKey           string                   `json:"privateKey"`
		Trust                string                   `json:"trust"`
		CollectorCertificate string                   `json:"collectorCertificate"`
		CollectorPrivateKey  string                   `json:"collectorPrivateKey"`
	}{config, digest(material.Certificate), digest(material.PrivateKey), digest(material.Trust),
		digest(material.CollectorCertificate), digest(material.CollectorPrivateKey)}
	encoded, err := json.Marshal(commitment)
	if err != nil {
		return lifecycle.NodeBinding{}, errors.New("node commitment cannot be encoded")
	}
	return lifecycle.NodeBinding{ExecutionTargetID: string(config.Identity.ExecutionTargetID),
		ConfigurationDigest: digest(encoded)}, nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ValidatePlan(plan Plan) error {
	config := plan.Configuration
	if !filepath.IsAbs(plan.Root) || filepath.Clean(plan.Root) != plan.Root ||
		ValidateRelease(plan.Bundle) != nil || nodeconfig.ValidateConfiguration(config) != nil ||
		lifecycle.ValidateInstallationID(config.Identity.InstallationID) != nil ||
		config.StoragePath != filepath.Join(plan.Root, filepath.FromSlash(layout.ExecutorRoot)) ||
		config.CertificateFile != filepath.Join(plan.Root, filepath.FromSlash(layout.NodeCertificate)) ||
		config.PrivateKeyFile != filepath.Join(plan.Root, filepath.FromSlash(layout.NodePrivateKey)) ||
		config.TrustFile != filepath.Join(plan.Root, filepath.FromSlash(layout.NodeTrust)) {
		return errors.New("node plan identity is invalid")
	}
	binding, err := Binding(config, plan.Credentials)
	if err != nil || binding != plan.Binding {
		return errors.New("node plan differs from its sealed commitment")
	}
	if previous := plan.Previous; previous != nil {
		if plan.ReleaseSource != nil || previous.Previous != nil || previous.ReleaseSource != nil ||
			previous.RevokePreviousCredentials || ValidatePlan(*previous) != nil ||
			previous.Root != plan.Root || previous.Configuration != config || previous.Binding == plan.Binding ||
			previous.Bundle.ManifestSHA256 != plan.Bundle.ManifestSHA256 || previous.Trust != plan.Trust {
			return errors.New("node rotation changes immutable enrollment or release state")
		}
	} else if plan.RevokePreviousCredentials {
		return errors.New("node retirement lacks its sealed predecessor")
	}
	if source := plan.ReleaseSource; source != nil {
		if source.ReleaseSource != nil || source.Previous != nil || source.RevokePreviousCredentials || ValidatePlan(*source) != nil ||
			source.Root != plan.Root || source.Configuration != config || source.Binding != plan.Binding ||
			source.Trust != plan.Trust || !bytes.Equal(source.TrustBytes, plan.TrustBytes) ||
			source.Bundle.ManifestSHA256 == plan.Bundle.ManifestSHA256 ||
			(!nodeReleaseSuccessor(plan.Bundle, source.Bundle) && !nodeReleaseSuccessor(source.Bundle, plan.Bundle)) {
			return errors.New("node release change differs from its sealed identity, credentials or adjacent releases")
		}
	}
	return nil
}

func nodeReleaseSuccessor(successor, predecessor release.VerifiedBundle) bool {
	next, previous := successor.Manifest.Release, predecessor.Manifest.Release
	return next.ID != previous.ID && next.PreviousID == previous.ID && next.PreviousVersion == previous.Version
}

func ValidateRelease(bundle release.VerifiedBundle) error {
	manifest := bundle.Manifest
	if release.ValidateManifest(manifest) != nil || manifest.Kind != release.NodeManifestKind ||
		manifest.Node == nil || manifest.Node.ProtocolAPIVersion != nodev1.APIVersion ||
		manifest.Node.RuntimeRevision != nodeconfig.RuntimeRevision ||
		manifest.Node.CollectorVersion != nodeconfig.CollectorVersion ||
		manifest.Host.MinimumSystemd != nodeconfig.MinimumSystemd ||
		manifest.Host.MinimumDocker != nodeconfig.MinimumDocker ||
		manifest.Host.MinimumCompose != nodeconfig.MinimumCompose ||
		manifest.TopologyDigest != nodeconfig.ContractDigest() {
		return errors.New("node release profile is unsupported")
	}
	return nil
}
