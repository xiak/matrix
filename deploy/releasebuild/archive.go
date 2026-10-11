package releasebuild

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

const (
	maximumArchiveMetadataBytes = 16 * 1024 * 1024
	ociIndexMediaType           = "application/vnd.oci.image.index.v1+json"
	ociManifestMediaType        = "application/vnd.oci.image.manifest.v1+json"
	ociConfigMediaType          = "application/vnd.oci.image.config.v1+json"
	dockerManifestListMediaType = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerManifestMediaType     = "application/vnd.docker.distribution.manifest.v2+json"
	dockerConfigMediaType       = "application/vnd.docker.container.image.v1+json"
)

type dockerArchiveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type ociDescriptor struct {
	MediaType string       `json:"mediaType"`
	Digest    string       `json:"digest"`
	Size      int64        `json:"size"`
	Platform  *ociPlatform `json:"platform,omitempty"`
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}

type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// inspectImageArchive derives the identity that a classic Docker daemon uses
// after `docker image load`. Containerd-backed builders expose an OCI
// manifest/index digest as Image.Id, while the portable load identity is the
// digest of the image configuration named by manifest.json. The OCI chain is
// verified when those identities differ so an unrelated config cannot be
// substituted into the signed release.
func inspectImageArchive(archive, sourceID string) (ImageMetadata, error) {
	if !validArchiveDigest(sourceID) {
		return ImageMetadata{}, errors.New("source image identity is invalid")
	}
	first, err := readArchiveEntries(archive, map[string]int64{
		"manifest.json": maximumArchiveMetadataBytes,
		"index.json":    maximumArchiveMetadataBytes,
	})
	if err != nil {
		return ImageMetadata{}, err
	}
	var manifests []dockerArchiveManifest
	if err := json.Unmarshal(first["manifest.json"], &manifests); err != nil ||
		len(manifests) != 1 || len(manifests[0].RepoTags) != 0 || len(manifests[0].Layers) == 0 {
		return ImageMetadata{}, errors.New("Docker archive manifest is invalid")
	}
	configID, ok := archiveConfigIdentity(manifests[0].Config)
	if !ok {
		return ImageMetadata{}, errors.New("Docker archive config identity is invalid")
	}

	targets := map[string]int64{manifests[0].Config: maximumArchiveMetadataBytes}
	var sourceDescriptor ociDescriptor
	if sourceID != configID {
		var index ociIndex
		if err := json.Unmarshal(first["index.json"], &index); err != nil ||
			index.SchemaVersion != 2 || index.MediaType != ociIndexMediaType ||
			len(index.Manifests) != 1 || index.Manifests[0].Digest != sourceID {
			return ImageMetadata{}, errors.New("Docker archive source descriptor is invalid")
		}
		sourceDescriptor = index.Manifests[0]
		if err := validateImageDescriptor(sourceDescriptor); err != nil {
			return ImageMetadata{}, err
		}
		targets[archiveBlobPath(sourceID)] = maximumArchiveMetadataBytes
	}
	second, err := readArchiveEntries(archive, targets)
	if err != nil {
		return ImageMetadata{}, err
	}
	configBytes, found := second[manifests[0].Config]
	if !found || digestBytes(configBytes) != configID {
		return ImageMetadata{}, errors.New("Docker archive config content is invalid")
	}
	var config imageConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return ImageMetadata{}, errors.New("Docker archive image config is invalid")
	}
	identity := ImageMetadata{ID: configID, OS: config.OS, Architecture: config.Architecture}
	if validateImageMetadata(identity) != nil {
		return ImageMetadata{}, errors.New("Docker archive load identity is invalid")
	}
	if sourceID == configID {
		return identity, nil
	}

	sourceBytes, found := second[archiveBlobPath(sourceID)]
	if !found || verifyDescriptorContent(sourceDescriptor, sourceBytes) != nil {
		return ImageMetadata{}, errors.New("Docker archive source descriptor is invalid")
	}
	switch sourceDescriptor.MediaType {
	case ociManifestMediaType, dockerManifestMediaType:
		if err := verifyImageManifest(sourceBytes, configID, int64(len(configBytes))); err != nil {
			return ImageMetadata{}, err
		}
	case ociIndexMediaType, dockerManifestListMediaType:
		platformManifest, err := selectPlatformManifest(sourceBytes)
		if err != nil {
			return ImageMetadata{}, err
		}
		third, err := readArchiveEntries(archive, map[string]int64{
			archiveBlobPath(platformManifest.Digest): maximumArchiveMetadataBytes,
		})
		if err != nil {
			return ImageMetadata{}, err
		}
		manifestBytes := third[archiveBlobPath(platformManifest.Digest)]
		if verifyDescriptorContent(platformManifest, manifestBytes) != nil ||
			verifyImageManifest(manifestBytes, configID, int64(len(configBytes))) != nil {
			return ImageMetadata{}, errors.New("Docker archive platform manifest is invalid")
		}
	default:
		return ImageMetadata{}, errors.New("Docker archive source media type is unsupported")
	}
	return identity, nil
}

func readArchiveEntries(archive string, limits map[string]int64) (map[string][]byte, error) {
	info, err := os.Lstat(archive)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		return nil, errors.New("Docker image archive is unsafe")
	}
	file, err := os.Open(archive)
	if err != nil {
		return nil, errors.New("open Docker image archive failed")
	}
	defer file.Close()
	result := make(map[string][]byte, len(limits))
	reader := tar.NewReader(file)
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, errors.New("read Docker image archive failed")
		}
		limit, wanted := limits[header.Name]
		if !wanted {
			continue
		}
		if _, duplicate := result[header.Name]; duplicate ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) ||
			header.Size <= 0 || header.Size > limit {
			return nil, errors.New("Docker image archive metadata is invalid")
		}
		content, readErr := io.ReadAll(io.LimitReader(reader, limit+1))
		if readErr != nil || int64(len(content)) != header.Size {
			return nil, errors.New("read Docker image archive metadata failed")
		}
		result[header.Name] = content
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return nil, errors.New("Docker image archive changed while inspected")
	}
	for target := range limits {
		if _, found := result[target]; !found && target != "index.json" {
			return nil, errors.New("Docker image archive metadata is incomplete")
		}
	}
	return result, nil
}

func archiveConfigIdentity(value string) (string, bool) {
	var encoded string
	switch {
	case strings.HasPrefix(value, "blobs/sha256:"):
		return "", false
	case strings.HasPrefix(value, "blobs/sha256/"):
		encoded = strings.TrimPrefix(value, "blobs/sha256/")
	case strings.HasSuffix(value, ".json") && !strings.Contains(strings.TrimSuffix(value, ".json"), "/"):
		encoded = strings.TrimSuffix(value, ".json")
	default:
		return "", false
	}
	digest := "sha256:" + encoded
	return digest, validArchiveDigest(digest)
}

func selectPlatformManifest(content []byte) (ociDescriptor, error) {
	var index ociIndex
	if err := json.Unmarshal(content, &index); err != nil || index.SchemaVersion != 2 ||
		!supportedIndexMediaType(index.MediaType) {
		return ociDescriptor{}, errors.New("Docker archive image index is invalid")
	}
	var selected ociDescriptor
	count := 0
	for _, descriptor := range index.Manifests {
		if descriptor.Platform == nil || descriptor.Platform.OS != "linux" ||
			descriptor.Platform.Architecture != "amd64" {
			continue
		}
		if !supportedManifestMediaType(descriptor.MediaType) || validateImageDescriptor(descriptor) != nil {
			return ociDescriptor{}, errors.New("Docker archive platform descriptor is invalid")
		}
		selected = descriptor
		count++
	}
	if count != 1 {
		return ociDescriptor{}, errors.New("Docker archive platform identity is ambiguous")
	}
	return selected, nil
}

func verifyImageManifest(content []byte, configID string, configSize int64) error {
	var manifest ociManifest
	if err := json.Unmarshal(content, &manifest); err != nil || manifest.SchemaVersion != 2 ||
		!supportedManifestMediaType(manifest.MediaType) || len(manifest.Layers) == 0 ||
		(manifest.Config.MediaType != ociConfigMediaType && manifest.Config.MediaType != dockerConfigMediaType) ||
		manifest.Config.Digest != configID || manifest.Config.Size != configSize {
		return errors.New("Docker archive image manifest is invalid")
	}
	return nil
}

func validateImageDescriptor(value ociDescriptor) error {
	if !validArchiveDigest(value.Digest) || value.Size <= 0 || value.Size > maximumArchiveMetadataBytes ||
		(!supportedIndexMediaType(value.MediaType) && !supportedManifestMediaType(value.MediaType)) {
		return errors.New("Docker archive image descriptor is invalid")
	}
	return nil
}

func supportedIndexMediaType(value string) bool {
	return value == ociIndexMediaType || value == dockerManifestListMediaType
}

func supportedManifestMediaType(value string) bool {
	return value == ociManifestMediaType || value == dockerManifestMediaType
}

func verifyDescriptorContent(descriptor ociDescriptor, content []byte) error {
	if int64(len(content)) != descriptor.Size || digestBytes(content) != descriptor.Digest {
		return errors.New("Docker archive OCI descriptor content differs")
	}
	return nil
}

func archiveBlobPath(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func validArchiveDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
