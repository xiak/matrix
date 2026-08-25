package compose

import (
	"context"
	"errors"
	"strings"
	"testing"

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
	content, err := EncodeArtifactCatalog(catalog)
	if err != nil {
		t.Fatalf("encode artifact catalog: %v", err)
	}
	decoded, err := DecodeArtifactCatalog(content)
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

func TestArtifactCatalogRejectsMeaningChangingDocuments(t *testing.T) {
	valid := artifactCatalogFixture()
	tests := map[string]func(*ArtifactCatalog){
		"type": func(value *ArtifactCatalog) { value.Kind = "ArtifactCatalog" },
		"unsorted": func(value *ArtifactCatalog) {
			value.Entries[0], value.Entries[1] = value.Entries[1], value.Entries[0]
		},
		"duplicate": func(value *ArtifactCatalog) {
			value.Entries[1].ArtifactDigest = value.Entries[0].ArtifactDigest
		},
		"mutable image reference": func(value *ArtifactCatalog) {
			value.Entries[0].ImageID = "matrix/smoke:latest"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := ArtifactCatalog{
				APIVersion: valid.APIVersion, Kind: valid.Kind,
				Entries: append([]ArtifactCatalogEntry(nil), valid.Entries...),
			}
			mutate(&candidate)
			if _, err := EncodeArtifactCatalog(candidate); err == nil {
				t.Fatal("invalid artifact catalog must fail")
			}
		})
	}

	content, err := EncodeArtifactCatalog(valid)
	if err != nil {
		t.Fatalf("encode valid artifact catalog: %v", err)
	}
	for name, candidate := range map[string][]byte{
		"unknown field": bytesReplaceOnce(
			content,
			[]byte(`"entries":`),
			[]byte(`"unexpected":true,"entries":`),
		),
		"noncanonical whitespace": append([]byte(" "), content...),
		"trailing document":       append(append([]byte(nil), content...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeArtifactCatalog(candidate); err == nil {
				t.Fatal("meaning-changing artifact catalog document must fail")
			}
		})
	}
}

func artifactCatalogFixture() ArtifactCatalog {
	return ArtifactCatalog{
		APIVersion: ArtifactCatalogAPIVersion,
		Kind:       ArtifactCatalogKind,
		Entries: []ArtifactCatalogEntry{
			{ArtifactDigest: digestWith('1'), ImageID: digestWith('a')},
			{ArtifactDigest: digestWith('2'), ImageID: digestWith('b')},
		},
	}
}

func digestWith(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func bytesReplaceOnce(content, old, replacement []byte) []byte {
	return []byte(strings.Replace(string(content), string(old), string(replacement), 1))
}
