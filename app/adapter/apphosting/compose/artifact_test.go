package compose

import (
	"context"
	"errors"
	"strings"
	"testing"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type catalogImageInspector struct {
	available map[string]bool
	calls     []string
}

func (inspector *catalogImageInspector) ConfirmExactImage(
	_ context.Context,
	imageID string,
) error {
	inspector.calls = append(inspector.calls, imageID)
	if !inspector.available[imageID] {
		return errors.New("native Docker failure must not escape")
	}
	return nil
}

func TestCatalogArtifactResolverAdmitsOnlyPresentCatalogDigests(t *testing.T) {
	catalog := artifactCatalogFixture()
	content, err := apphostingv1.EncodeArtifactCatalog(catalog)
	if err != nil {
		t.Fatalf("encode artifact catalog: %v", err)
	}
	decoded, err := apphostingv1.DecodeArtifactCatalog(content)
	if err != nil {
		t.Fatalf("decode artifact catalog: %v", err)
	}
	inspector := &catalogImageInspector{available: map[string]bool{
		catalog.Entries[0].ImageID: true,
		catalog.Entries[1].ImageID: true,
	}}
	resolver, err := newCatalogArtifactResolver(decoded, inspector)
	if err != nil {
		t.Fatalf("create artifact resolver: %v", err)
	}
	artifact := paasv1.ArtifactRef{
		Kind: paasv1.ArtifactOCIImage, Locator: "registry.customer.invalid/team/web",
		Digest: catalog.Entries[0].ArtifactDigest,
	}
	resolved, err := resolver.ResolveVerifiedImage(context.Background(), artifact)
	if err != nil {
		t.Fatalf("resolve admitted artifact: %v", err)
	}
	if resolved.ArtifactDigest != artifact.Digest ||
		resolved.LocalReference != catalog.Entries[0].ImageID {
		t.Fatalf("resolved artifact = %#v", resolved)
	}

	artifact.Digest = digestWith('f')
	if _, err := resolver.ResolveVerifiedImage(context.Background(), artifact); err == nil {
		t.Fatal("uncatalogued artifact digest must fail")
	}
	if len(inspector.calls) != 1 {
		t.Fatalf("uncatalogued artifact reached Docker inspector: %v", inspector.calls)
	}

	inspector.available[catalog.Entries[1].ImageID] = false
	if err := resolver.Ready(context.Background()); err == nil ||
		strings.Contains(err.Error(), "native Docker failure") {
		t.Fatalf("catalog readiness error = %v", err)
	}
}

func artifactCatalogFixture() apphostingv1.ArtifactCatalog {
	return apphostingv1.ArtifactCatalog{
		APIVersion: apphostingv1.ArtifactCatalogAPIVersion,
		Kind:       apphostingv1.ArtifactCatalogKind,
		Entries: []apphostingv1.ArtifactCatalogEntry{
			{ArtifactDigest: digestWith('1'), ImageID: digestWith('a')},
			{ArtifactDigest: digestWith('2'), ImageID: digestWith('b')},
		},
	}
}

func digestWith(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
