package apphostingv1

import (
	"strings"
	"testing"
)

func TestArtifactCatalogCanonicalContractRejectsMeaningChanges(t *testing.T) {
	valid := artifactCatalogFixture()
	content, err := EncodeArtifactCatalog(valid)
	if err != nil {
		t.Fatalf("encode valid artifact catalog: %v", err)
	}
	decoded, err := DecodeArtifactCatalog(content)
	if err != nil || len(decoded.Entries) != len(valid.Entries) {
		t.Fatalf("decode valid artifact catalog = %#v / %v", decoded, err)
	}

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
