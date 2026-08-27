// Package release owns the authenticated offline release contract consumed by
// Matrix installation lifecycle commands.
package release

import "time"

const (
	ManifestAPIVersion = "installation.matrix.xiak.com/v2"
	// LegacyManifestAPIVersion is the published Phase 1 signed format. Its
	// canonical bytes remain valid, but its scalar is not a new schema profile.
	LegacyManifestAPIVersion = "installation.matrix.xiak.com/v1"
	ManifestKind             = "OfflineRelease"
	NodeManifestKind         = "OfflineNodeRelease"
	TrustAPIVersion          = "installation.matrix.xiak.com/v1"
	TrustKind                = "ReleaseTrustRoot"
	SignatureAlgorithm       = "Ed25519"

	BuiltImageLabelReleaseBuild = "com.xiak.matrix.release-build"
	BuiltImageLabelComponent    = "com.xiak.matrix.component"
	BuiltImageLabelSourceCommit = "com.xiak.matrix.source-commit"
	BuiltImageLabelBuildID      = "com.xiak.matrix.build-id"
)

type Manifest struct {
	APIVersion       string          `json:"apiVersion"`
	Kind             string          `json:"kind"`
	Release          ReleaseIdentity `json:"release"`
	Signer           Signer          `json:"signer"`
	Host             HostProfile     `json:"host"`
	MinimumFreeBytes uint64          `json:"minimumFreeBytes"`
	Database         DatabaseProfile `json:"database,omitzero"`
	Node             *NodeProfile    `json:"node,omitempty"`
	TopologyDigest   string          `json:"topologyDigest"`
	Files            []File          `json:"files"`
	Images           []Image         `json:"images,omitempty"`
}

type ReleaseIdentity struct {
	ID              string    `json:"id"`
	Version         string    `json:"version"`
	SourceCommit    string    `json:"sourceCommit"`
	BuildID         string    `json:"buildId"`
	CreatedAt       time.Time `json:"createdAt"`
	PreviousID      string    `json:"previousId,omitempty"`
	PreviousVersion string    `json:"previousVersion,omitempty"`
}

type Signer struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
}

type HostProfile struct {
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	MinimumDocker   string `json:"minimumDocker"`
	MinimumCompose  string `json:"minimumCompose"`
	CommandContract string `json:"commandContract"`
	MinimumSystemd  uint64 `json:"minimumSystemd,omitempty"`
}

type NodeProfile struct {
	ProtocolAPIVersion string `json:"protocolApiVersion"`
	RuntimeRevision    uint64 `json:"runtimeRevision"`
	CollectorVersion   string `json:"collectorVersion"`
}

type DatabaseProfile struct {
	SchemaVersion    uint64           `json:"schemaVersion,omitempty"`
	Compatibility    string           `json:"compatibility"`
	Authorities      AuthoritySchemas `json:"authorities,omitzero"`
	ContractRevision uint64           `json:"contractRevision,omitempty"`
}

// AuthoritySchemas keeps the independently owned databases explicit. It is
// not a promise that a binary can use another version's schema or functions.
type AuthoritySchemas struct {
	IAM   uint64 `json:"iam"`
	Audit uint64 `json:"audit"`
	PaaS  uint64 `json:"paas"`
}

// CurrentDatabaseProfile is the release composition supported by this source.
// Cross-profile upgrades need a separately proven retained-data/N-1 path.
// ContractRevision changes for incompatible function/wire contracts even when
// their owning services retain the same schema-version numbers.
func CurrentDatabaseProfile() DatabaseProfile {
	return DatabaseProfile{
		Compatibility:    "identical-authority-profile",
		Authorities:      AuthoritySchemas{IAM: 2, Audit: 2, PaaS: 2},
		ContractRevision: 1,
	}
}

type File struct {
	Path       string `json:"path"`
	MediaType  string `json:"mediaType"`
	Size       uint64 `json:"size"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}

type Image struct {
	Component      string       `json:"component"`
	Purpose        ImagePurpose `json:"purpose"`
	ArchivePath    string       `json:"archivePath"`
	ImageID        string       `json:"imageId"`
	SourceDigest   string       `json:"sourceDigest"`
	OS             string       `json:"os"`
	Architecture   string       `json:"architecture"`
	HealthContract string       `json:"healthContract"`
}

type ImagePurpose string

const (
	ImagePlatform ImagePurpose = "PLATFORM"
	ImageWorkload ImagePurpose = "WORKLOAD"
)

type ImageRequirement struct {
	Component      string
	Purpose        ImagePurpose
	HealthContract string
}

type TrustRoot struct {
	APIVersion           string `json:"apiVersion"`
	Kind                 string `json:"kind"`
	KeyID                string `json:"keyId"`
	Algorithm            string `json:"algorithm"`
	PublicKey            string `json:"publicKey"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
}

func RequiredImages() []ImageRequirement {
	return []ImageRequirement{
		{Component: "apisix", Purpose: ImagePlatform, HealthContract: "northbound-ready-v1"},
		{Component: "audit", Purpose: ImagePlatform, HealthContract: "audit-ready-deduplicate-v1"},
		{Component: "iam", Purpose: ImagePlatform, HealthContract: "iam-ready-authorize-v1"},
		{Component: "paas", Purpose: ImagePlatform, HealthContract: "paas-ready-worker-compose-v1"},
		{Component: "paas-ui", Purpose: ImagePlatform, HealthContract: "paas-ui-ready-v1"},
		{Component: "postgres", Purpose: ImagePlatform, HealthContract: "postgres-ready-schema-v1"},
		{Component: "verification", Purpose: ImageWorkload, HealthContract: "application-probe-v1"},
	}
}

// BuiltImageLabels is the authenticated build-metadata surface inherited by
// every Matrix-built release image. The fixed upstream PostgreSQL image is not
// Matrix-built and callers intentionally do not apply these labels to it.
func BuiltImageLabels(identity ReleaseIdentity, component string) map[string]string {
	return map[string]string{
		BuiltImageLabelReleaseBuild: "true",
		BuiltImageLabelComponent:    component,
		BuiltImageLabelSourceCommit: identity.SourceCommit,
		BuiltImageLabelBuildID:      identity.BuildID,
	}
}
