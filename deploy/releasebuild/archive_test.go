package releasebuild

import (
	"archive/tar"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestImageArchiveMapsContainerdSourceToPortableLoadIdentity(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	configID := digestBytes(config)
	layerID := testDigest("layer")
	platformManifest, err := json.Marshal(ociManifest{
		SchemaVersion: 2,
		MediaType:     ociManifestMediaType,
		Config: ociDescriptor{
			MediaType: ociConfigMediaType, Digest: configID, Size: int64(len(config)),
		},
		Layers: []ociDescriptor{{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: layerID, Size: 1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	platformID := digestBytes(platformManifest)
	sourceIndex, err := json.Marshal(ociIndex{
		SchemaVersion: 2, MediaType: ociIndexMediaType,
		Manifests: []ociDescriptor{{
			MediaType: ociManifestMediaType, Digest: platformID,
			Size: int64(len(platformManifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceID := digestBytes(sourceIndex)
	archiveIndex, err := json.Marshal(ociIndex{
		SchemaVersion: 2, MediaType: ociIndexMediaType,
		Manifests: []ociDescriptor{{
			MediaType: ociIndexMediaType, Digest: sourceID, Size: int64(len(sourceIndex)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dockerManifest, err := json.Marshal([]dockerArchiveManifest{{
		Config: archiveBlobPath(configID), Layers: []string{archiveBlobPath(layerID)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "image.tar")
	writeTestImageArchive(t, archive, map[string][]byte{
		archiveBlobPath(configID):   config,
		archiveBlobPath(platformID): platformManifest,
		archiveBlobPath(sourceID):   sourceIndex,
		"index.json":                archiveIndex,
		"manifest.json":             dockerManifest,
	})

	identity, err := inspectImageArchive(archive, sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID != configID || identity.ID == sourceID ||
		identity.OS != "linux" || identity.Architecture != "amd64" {
		t.Fatalf("portable identity = %#v", identity)
	}
	if _, err := inspectImageArchive(archive, testDigest("unrelated-source")); err == nil {
		t.Fatal("archive unrelated to the inspected source identity was accepted")
	}
}

func writeTestImageArchive(t *testing.T, target string, entries map[string][]byte) {
	t.Helper()
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for name, content := range entries {
		if err := writer.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
