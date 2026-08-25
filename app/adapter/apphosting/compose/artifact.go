package compose

import (
	"context"
	"errors"
	"slices"
	"strings"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type imageInspector interface {
	ConfirmExactImage(context.Context, string) error
}

type localImageInspector struct{}

func (localImageInspector) ConfirmExactImage(ctx context.Context, imageID string) error {
	if ctx == nil || !localImageDigestPattern.MatchString(imageID) {
		return errors.New("local image inspection input is invalid")
	}
	var output boundedBuffer
	output.maximum = 1024
	_, err := runDocker(ctx, &output, "image", "inspect", "--format", "{{.Id}}", imageID)
	if err != nil || output.exceeded || strings.TrimSpace(output.String()) != imageID {
		return errors.New("verified local image is unavailable")
	}
	return nil
}

// CatalogArtifactResolver admits only images in the authenticated local
// catalog and rechecks their exact content-addressed Docker identity before
// every compilation. It never uses an artifact locator, tag, registry, pull,
// or build as authority.
type CatalogArtifactResolver struct {
	entries   map[string]string
	ordered   []apphostingv1.ArtifactCatalogEntry
	inspector imageInspector
}

func NewCatalogArtifactResolver(catalog apphostingv1.ArtifactCatalog) (*CatalogArtifactResolver, error) {
	return newCatalogArtifactResolver(catalog, localImageInspector{})
}

func newCatalogArtifactResolver(
	catalog apphostingv1.ArtifactCatalog,
	inspector imageInspector,
) (*CatalogArtifactResolver, error) {
	if err := apphostingv1.ValidateArtifactCatalog(catalog); err != nil {
		return nil, err
	}
	if inspector == nil {
		return nil, errors.New("local image inspector is required")
	}
	entries := make(map[string]string, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		entries[entry.ArtifactDigest] = entry.ImageID
	}
	return &CatalogArtifactResolver{
		entries: entries, ordered: slices.Clone(catalog.Entries), inspector: inspector,
	}, nil
}

func (resolver *CatalogArtifactResolver) ResolveVerifiedImage(
	ctx context.Context,
	artifact paasv1.ArtifactRef,
) (VerifiedImage, error) {
	if resolver == nil || resolver.inspector == nil || resolver.entries == nil {
		return VerifiedImage{}, errors.New("local artifact resolver is not configured")
	}
	if ctx == nil {
		return VerifiedImage{}, errors.New("artifact resolution context is required")
	}
	if artifact.Kind != paasv1.ArtifactOCIImage ||
		paasv1.ValidateSafeExternalText("artifact.locator", artifact.Locator, 2048, true) != nil ||
		paasv1.ValidateDigest("artifact.digest", artifact.Digest) != nil {
		return VerifiedImage{}, errors.New("artifact reference is invalid")
	}
	imageID, found := resolver.entries[artifact.Digest]
	if !found {
		return VerifiedImage{}, errors.New("artifact digest is not admitted by the local catalog")
	}
	if err := resolver.inspector.ConfirmExactImage(ctx, imageID); err != nil {
		return VerifiedImage{}, errors.New("artifact image identity cannot be verified")
	}
	return VerifiedImage{ArtifactDigest: artifact.Digest, LocalReference: imageID}, nil
}

// Ready proves that every catalog image is still present by exact immutable
// identity. It is used by the worker's internal readiness endpoint.
func (resolver *CatalogArtifactResolver) Ready(ctx context.Context) error {
	if resolver == nil || resolver.inspector == nil || len(resolver.ordered) == 0 {
		return errors.New("local artifact resolver is not configured")
	}
	if ctx == nil {
		return errors.New("artifact readiness context is required")
	}
	for _, entry := range resolver.ordered {
		if err := resolver.inspector.ConfirmExactImage(ctx, entry.ImageID); err != nil {
			return errors.New("local artifact catalog is not ready")
		}
	}
	return nil
}
