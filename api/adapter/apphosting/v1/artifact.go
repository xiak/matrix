// Package apphostingv1 owns versioned cross-process adapter contracts shared
// by Matrix installation and application-hosting runtime adapters.
package apphostingv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	ArtifactCatalogAPIVersion = "apphosting.matrix.xiak.com/v1"
	ArtifactCatalogKind       = "LocalArtifactCatalog"
	maximumArtifactCatalog    = 1024 * 1024
	maximumCatalogEntries     = 128
)

var (
	imageIDPattern             = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	localImageReferencePattern = regexp.MustCompile(
		`^matrix\.local/matrix/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?:sha256-[0-9a-f]{64}$`,
	)
)

// ArtifactCatalog is generated from authenticated release content. Artifact
// digests and their accepted local content identities are authority. A fixed
// Matrix-local reference is carried only as an offline lookup key and is
// rechecked against those identities before every use.
type ArtifactCatalog struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Entries    []ArtifactCatalogEntry `json:"entries"`
}

type ArtifactCatalogEntry struct {
	ArtifactDigest string   `json:"artifactDigest"`
	LocalReference string   `json:"localReference"`
	ImageIDs       []string `json:"imageIds"`
}

func EncodeArtifactCatalog(catalog ArtifactCatalog) ([]byte, error) {
	if err := ValidateArtifactCatalog(catalog); err != nil {
		return nil, err
	}
	content, err := json.Marshal(catalog)
	if err != nil || len(content) > maximumArtifactCatalog {
		return nil, errors.New("encode local artifact catalog failed")
	}
	return content, nil
}

func DecodeArtifactCatalog(content []byte) (ArtifactCatalog, error) {
	if len(content) == 0 || len(content) > maximumArtifactCatalog {
		return ArtifactCatalog{}, errors.New("local artifact catalog size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var catalog ArtifactCatalog
	if err := decoder.Decode(&catalog); err != nil {
		return ArtifactCatalog{}, errors.New("local artifact catalog is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ArtifactCatalog{}, errors.New("local artifact catalog has trailing content")
	}
	canonical, err := EncodeArtifactCatalog(catalog)
	if err != nil || !bytes.Equal(canonical, content) {
		return ArtifactCatalog{}, errors.New("local artifact catalog is not canonical")
	}
	return catalog, nil
}

func ValidateArtifactCatalog(catalog ArtifactCatalog) error {
	if catalog.APIVersion != ArtifactCatalogAPIVersion || catalog.Kind != ArtifactCatalogKind {
		return errors.New("local artifact catalog type is unsupported")
	}
	if len(catalog.Entries) == 0 || len(catalog.Entries) > maximumCatalogEntries {
		return errors.New("local artifact catalog inventory size is invalid")
	}
	previous := ""
	for _, entry := range catalog.Entries {
		if paasv1.ValidateDigest("artifactDigest", entry.ArtifactDigest) != nil ||
			ValidateLocalImageReference(entry.LocalReference) != nil ||
			len(entry.ImageIDs) == 0 || len(entry.ImageIDs) > 2 ||
			!slices.IsSorted(entry.ImageIDs) {
			return errors.New("local artifact catalog entry is invalid")
		}
		for index, imageID := range entry.ImageIDs {
			if !imageIDPattern.MatchString(imageID) ||
				(index > 0 && entry.ImageIDs[index-1] == imageID) {
				return errors.New("local artifact catalog entry is invalid")
			}
		}
		if imageIDPattern.MatchString(entry.LocalReference) {
			if len(entry.ImageIDs) != 1 || entry.ImageIDs[0] != entry.LocalReference {
				return errors.New("local artifact catalog entry is invalid")
			}
		} else if !strings.HasSuffix(
			entry.LocalReference, strings.TrimPrefix(entry.ArtifactDigest, "sha256:"),
		) {
			return errors.New("local artifact catalog entry is invalid")
		}
		if previous >= entry.ArtifactDigest {
			return errors.New("local artifact catalog entries are duplicated or not sorted")
		}
		previous = entry.ArtifactDigest
	}
	return nil
}

// ValidateLocalImageReference accepts either the immutable digest used by the
// supported predecessor contract or a current Matrix-owned offline tag. It
// deliberately rejects arbitrary registries and mutable tags.
func ValidateLocalImageReference(value string) error {
	if !imageIDPattern.MatchString(value) && !localImageReferencePattern.MatchString(value) {
		return errors.New("local image reference is invalid")
	}
	return nil
}
