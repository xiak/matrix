package releasebuild

import (
	"archive/tar"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestImageArchiveBindsBothDockerStoreIdentities(t *testing.T) {
	for _, test := range []struct {
		name          string
		indexMedia    string
		manifestMedia string
		configMedia   string
		manifestRoot  bool
	}{
		{name: "OCI", indexMedia: ociIndexMediaType, manifestMedia: ociManifestMediaType, configMedia: ociConfigMediaType},
		{name: "Docker v2", indexMedia: dockerManifestListMediaType, manifestMedia: dockerManifestMediaType, configMedia: dockerConfigMediaType},
		{name: "classic OCI export", indexMedia: ociIndexMediaType, manifestMedia: ociManifestMediaType, configMedia: ociConfigMediaType, manifestRoot: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := []byte(`{"architecture":"amd64","os":"linux"}`)
			configID := digestBytes(config)
			layerID := testDigest("layer")
			platformManifest, err := json.Marshal(ociManifest{
				SchemaVersion: 2,
				MediaType:     test.manifestMedia,
				Config: ociDescriptor{
					MediaType: test.configMedia, Digest: configID, Size: int64(len(config)),
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
				SchemaVersion: 2, MediaType: test.indexMedia,
				Manifests: []ociDescriptor{{
					MediaType: test.manifestMedia, Digest: platformID,
					Size: int64(len(platformManifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			rootBytes, rootMedia := sourceIndex, test.indexMedia
			if test.manifestRoot {
				rootBytes, rootMedia = platformManifest, test.manifestMedia
			}
			sourceID := digestBytes(rootBytes)
			archiveIndex, err := json.Marshal(ociIndex{
				SchemaVersion: 2, MediaType: ociIndexMediaType,
				Manifests: []ociDescriptor{{
					MediaType: rootMedia, Digest: sourceID, Size: int64(len(rootBytes)),
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
			entries := map[string][]byte{
				archiveBlobPath(configID):   config,
				archiveBlobPath(platformID): platformManifest,
				"index.json":                archiveIndex,
				"manifest.json":             dockerManifest,
			}
			entries[archiveBlobPath(sourceID)] = rootBytes
			writeTestImageArchive(t, archive, entries)

			for _, inspectedSource := range []string{sourceID, configID} {
				identity, err := inspectImageArchive(archive, inspectedSource)
				if err != nil {
					t.Fatal(err)
				}
				if identity.ID != configID || identity.ArchiveSourceDigest != sourceID ||
					identity.OS != "linux" || identity.Architecture != "amd64" {
					t.Fatalf("portable identities = %#v", identity)
				}
			}
			if _, err := inspectImageArchive(archive, testDigest("unrelated-source")); err == nil {
				t.Fatal("archive unrelated to the inspected source identity was accepted")
			}
			entries[archiveBlobPath(sourceID)] = []byte(`{"unrelated":"manifest"}`)
			tampered := filepath.Join(t.TempDir(), "tampered.tar")
			writeTestImageArchive(t, tampered, entries)
			if _, err := inspectImageArchive(tampered, configID); err == nil {
				t.Fatal("classic source bypassed the archive descriptor's content binding")
			}
		})
	}
}

func TestImageArchiveWithoutOCIIndexKeepsClassicIdentity(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	configID := digestBytes(config)
	manifest, err := json.Marshal([]dockerArchiveManifest{{
		Config: archiveBlobPath(configID), Layers: []string{"layer/layer.tar"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "legacy.tar")
	writeTestImageArchive(t, archive, map[string][]byte{
		archiveBlobPath(configID): config, "manifest.json": manifest,
	})
	identity, err := inspectImageArchive(archive, configID)
	if err != nil || identity.ID != configID || identity.ArchiveSourceDigest != configID {
		t.Fatalf("classic archive identities=%#v err=%v", identity, err)
	}
	if _, err := inspectImageArchive(archive, testDigest("foreign-source")); err == nil {
		t.Fatal("unbound source without an OCI index was accepted")
	}
}

func TestImageArchiveMediaTypeCatalogIsClosed(t *testing.T) {
	for _, mediaType := range []string{ociIndexMediaType, dockerManifestListMediaType} {
		if !supportedIndexMediaType(mediaType) {
			t.Fatalf("supported index media type %q was rejected", mediaType)
		}
	}
	for _, mediaType := range []string{ociManifestMediaType, dockerManifestMediaType} {
		if !supportedManifestMediaType(mediaType) {
			t.Fatalf("supported manifest media type %q was rejected", mediaType)
		}
	}
	for _, mediaType := range []string{
		"", "application/json", "application/vnd.docker.distribution.manifest.v1+json",
	} {
		if supportedIndexMediaType(mediaType) || supportedManifestMediaType(mediaType) {
			t.Fatalf("unsupported image media type %q was accepted", mediaType)
		}
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
