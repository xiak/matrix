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
			value.Entries[0].LocalReference = "matrix.local/matrix/smoke:latest"
		},
		"foreign image reference": func(value *ArtifactCatalog) {
			value.Entries[0].LocalReference = "registry.invalid/smoke@" + digestWith('1')
		},
		"reference digest mismatch": func(value *ArtifactCatalog) {
			value.Entries[0].LocalReference = localReference("smoke-a", '2')
		},
		"missing image identities": func(value *ArtifactCatalog) {
			value.Entries[0].ImageIDs = nil
		},
		"unsorted image identities": func(value *ArtifactCatalog) {
			value.Entries[0].ImageIDs[0], value.Entries[0].ImageIDs[1] =
				value.Entries[0].ImageIDs[1], value.Entries[0].ImageIDs[0]
		},
		"duplicate image identities": func(value *ArtifactCatalog) {
			value.Entries[0].ImageIDs[1] = value.Entries[0].ImageIDs[0]
		},
		"mutable image identity": func(value *ArtifactCatalog) {
			value.Entries[0].ImageIDs[0] = "matrix/smoke:latest"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := artifactCatalogFixture()
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
			{
				ArtifactDigest: digestWith('1'), LocalReference: localReference("smoke-a", '1'),
				ImageIDs: []string{digestWith('1'), digestWith('a')},
			},
			{
				ArtifactDigest: digestWith('2'), LocalReference: localReference("smoke-b", '2'),
				ImageIDs: []string{digestWith('2'), digestWith('b')},
			},
		},
	}
}

func localReference(component string, digestByte byte) string {
	return "matrix.local/matrix/" + component + ":sha256-" +
		strings.Repeat(string(digestByte), 64)
}

func digestWith(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func bytesReplaceOnce(content, old, replacement []byte) []byte {
	return []byte(strings.Replace(string(content), string(old), string(replacement), 1))
}
