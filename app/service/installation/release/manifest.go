// Package release owns the authenticated offline release contract consumed by
// Matrix installation lifecycle commands.
package release

import (
	"slices"
	"strings"
	"time"
)

const (
	ManifestAPIVersion = "installation.matrix.xiak.com/v1"
	ManifestKind       = "OfflineRelease"
	TrustAPIVersion    = "installation.matrix.xiak.com/v1"
	TrustKind          = "ReleaseTrustRoot"
	SignatureAlgorithm = "Ed25519"

	BuiltImageLabelReleaseBuild = "com.xiak.matrix.release-build"
	BuiltImageLabelComponent    = "com.xiak.matrix.component"
	BuiltImageLabelSourceCommit = "com.xiak.matrix.source-commit"
	BuiltImageLabelBuildID      = "com.xiak.matrix.build-id"

	// legacyProductlessSourceCommit is the exact accepted Phase 1 runtime
	// lineage that predates the signed product inventory. It is admitted only
	// when authenticating an already-installed release for lifecycle replay;
	// current release assembly and new installation stay on Manifest.
	legacyProductlessSourceCommit = "c88a84f379afcf94431e2aca7332fe6ec3136dc7"
	legacyProductlessDocker       = "27.5.1"
	legacyProductlessCompose      = "2.33.0"
	legacyProductlessFreeBytes    = uint64(4 * 1024 * 1024 * 1024)

	RunnerBinaryPath           = "runner/linux-amd64/bin/matrix-devops-runner"
	RunnerToolchainArchivePath = "runner/linux-amd64/images/go-1.26-offline-v1.tar"
	RunnerGVisorArchivePath    = "runner/linux-amd64/runtime/gvisor-x86_64.tar.zstd"
	RunnerGVisorChecksumPath   = "runner/linux-amd64/runtime/gvisor-x86_64.tar.zstd.sha256"
	RunnerGVisorRelease        = "release-20260831.0"
	RunnerGVisorArchiveSHA256  = "sha256:b9ccc6e14ca4eb2c2e65ff66e011f3b7e79d3275fb12eab747b19f95caf8e891"
	RunnerToolchainID          = "GO_1_26_OFFLINE_V1"
	RunnerToolchainImage       = "docker.io/library/golang@sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3"
	RunnerToolchainImageDigest = "sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3"
	RunnerToolchainImageID     = "sha256:2e6f40580dfa8312d4aab4f49e5ab214d0daa5999ed51be6eb6fe1f246378e4f"
	RunnerEngineAPIVersion     = "1.46"
	RunnerDockerRelease        = "29.x"
	RunnerRuntimeName          = "runsc"
	RunnerMaximumSlots         = uint8(4)
	RunnerMinimumLogicalCPUs   = uint16(4)
	RunnerMinimumMemoryBytes   = uint64(8 * 1024 * 1024 * 1024)
	RunnerMinimumStorageBytes  = uint64(20 * 1024 * 1024 * 1024)
)

type Manifest struct {
	APIVersion       string          `json:"apiVersion"`
	Kind             string          `json:"kind"`
	Release          ReleaseIdentity `json:"release"`
	Signer           Signer          `json:"signer"`
	Host             HostProfile     `json:"host"`
	MinimumFreeBytes uint64          `json:"minimumFreeBytes"`
	Database         DatabaseProfile `json:"database"`
	Products         []Product       `json:"products"`
	TopologyDigest   string          `json:"topologyDigest"`
	Files            []File          `json:"files"`
	Images           []Image         `json:"images"`
}

// legacyProductlessManifest preserves the exact canonical wire shape emitted
// by the accepted Phase 1 release builder. Do not add fields: its sole purpose
// is signature-preserving authentication of an installed predecessor.
type legacyProductlessManifest struct {
	APIVersion       string          `json:"apiVersion"`
	Kind             string          `json:"kind"`
	Release          ReleaseIdentity `json:"release"`
	Signer           Signer          `json:"signer"`
	Host             HostProfile     `json:"host"`
	MinimumFreeBytes uint64          `json:"minimumFreeBytes"`
	Database         DatabaseProfile `json:"database"`
	TopologyDigest   string          `json:"topologyDigest"`
	Files            []File          `json:"files"`
	Images           []Image         `json:"images"`
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
}

type DatabaseProfile struct {
	SchemaVersion uint64 `json:"schemaVersion"`
	Compatibility string `json:"compatibility"`
}

type ProductID string

const (
	ProductApplicationPaaS ProductID = "APPLICATION_PAAS"
	ProductDevOps          ProductID = "DEVOPS"
)

type Product struct {
	ID                 ProductID   `json:"id"`
	Version            string      `json:"version"`
	RouteKey           string      `json:"routeKey"`
	ReadinessContract  string      `json:"readinessContract"`
	RequiredComponents []string    `json:"requiredComponents"`
	Dependencies       []ProductID `json:"dependencies"`
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

func RequiredImages(products []Product) []ImageRequirement {
	required := []ImageRequirement{
		{Component: "apisix", Purpose: ImagePlatform, HealthContract: "northbound-ready-v1"},
		{Component: "audit", Purpose: ImagePlatform, HealthContract: "audit-ready-deduplicate-v1"},
		{Component: "iam", Purpose: ImagePlatform, HealthContract: "iam-ready-authorize-v1"},
		{Component: "matrix-ui", Purpose: ImagePlatform, HealthContract: "matrix-ui-ready-v1"},
		{Component: "platform", Purpose: ImagePlatform, HealthContract: "product-discovery-ready-v1"},
		{Component: "postgres", Purpose: ImagePlatform, HealthContract: "postgres-ready-schema-v1"},
	}
	for _, product := range products {
		switch product.ID {
		case ProductApplicationPaaS:
			required = append(required,
				ImageRequirement{Component: "paas", Purpose: ImagePlatform, HealthContract: "paas-ready-worker-compose-v1"},
				ImageRequirement{Component: "verification", Purpose: ImageWorkload, HealthContract: "application-probe-v1"},
			)
		case ProductDevOps:
			required = append(required, ImageRequirement{
				Component: "devops", Purpose: ImagePlatform, HealthContract: "devops-ready-v1",
			})
		}
	}
	slices.SortFunc(required, func(left, right ImageRequirement) int {
		return strings.Compare(left.Component, right.Component)
	})
	return required
}

func legacyProductlessRequiredImages() []ImageRequirement {
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

func ApplicationPaaSProduct(version string) Product {
	return Product{
		ID:                 ProductApplicationPaaS,
		Version:            version,
		RouteKey:           "paas",
		ReadinessContract:  "application-paas-ready-v1",
		RequiredComponents: []string{"paas"},
		Dependencies:       []ProductID{},
	}
}

func DevOpsProduct(version string) Product {
	return Product{
		ID:                 ProductDevOps,
		Version:            version,
		RouteKey:           "devops",
		ReadinessContract:  "devops-ready-v1",
		RequiredComponents: []string{"devops"},
		Dependencies:       []ProductID{},
	}
}

// IncludesProduct reports membership in the authenticated product inventory.
// Callers must validate the manifest before using the result as authority.
func (manifest Manifest) IncludesProduct(id ProductID) bool {
	for _, product := range manifest.Products {
		if product.ID == id {
			return true
		}
	}
	return false
}

// RunnerPayloadPaths is the closed independently transferable payload carried
// by every DevOps-selected release. bin/mx is shared with the platform bundle
// and is added by RunnerReleasePayloadPaths for node-side verification.
func RunnerPayloadPaths() []string {
	return []string{
		RunnerBinaryPath,
		RunnerToolchainArchivePath,
		RunnerGVisorArchivePath,
		RunnerGVisorChecksumPath,
	}
}

// RunnerReleasePayloadPaths returns the exact signed subset required on a
// dedicated runner node. Callers receive a new slice and cannot mutate the
// release package's static contract.
func RunnerReleasePayloadPaths() []string {
	paths := append([]string{"bin/mx"}, RunnerPayloadPaths()...)
	slices.Sort(paths)
	return paths
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
