// Package releasetest builds small authenticated bundle fixtures for tests of
// installation consumers. Payloads are metadata fixtures, never runtime image
// substitutes or accepted release artifacts.
package releasetest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

type Fixture struct {
	Root           string
	TrustPath      string
	Trust          release.TrustRoot
	Manifest       release.Manifest
	ManifestDigest string
}

func Write(base string) (Fixture, error) {
	fixtures, err := writeManifests(base, []release.Manifest{Manifest()})
	if err != nil {
		return Fixture{}, err
	}
	return fixtures[0], nil
}

// WriteSequence creates signed immediate-successor fixtures under one trust
// root. It is intentionally metadata-only and never substitutes for a real
// offline release in runtime acceptance.
func WriteSequence(base string, count int, profiles ...release.DatabaseProfile) ([]Fixture, error) {
	if count < 1 || count > 8 || (len(profiles) != 0 && len(profiles) != count) {
		return nil, errors.New("fixture release sequence length is invalid")
	}
	manifests := make([]release.Manifest, count)
	for index := range manifests {
		manifest := Manifest()
		if len(profiles) != 0 {
			manifest.Database = profiles[index]
			if manifest.Database.SchemaVersion != 0 {
				manifest.APIVersion = release.LegacyManifestAPIVersion
			}
		}
		commit := strings.Repeat(string("abcdef12"[index]), 40)
		version := fmt.Sprintf("v0.%d.0", index+1)
		manifest.Release.ID = "matrix-" + version + "-" + commit[:12]
		manifest.Release.Version = version
		manifest.Release.SourceCommit = commit
		manifest.Release.BuildID = fmt.Sprintf("installation-consumer-test-%d", index+1)
		manifest.Release.CreatedAt = manifest.Release.CreatedAt.Add(time.Duration(index) * time.Hour)
		if index > 0 {
			manifest.Release.PreviousID = manifests[index-1].Release.ID
			manifest.Release.PreviousVersion = manifests[index-1].Release.Version
		}
		manifests[index] = manifest
	}
	return writeManifests(base, manifests)
}

func writeManifests(base string, manifests []release.Manifest) ([]Fixture, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate fixture release key failed")
	}
	trust, err := release.NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		return nil, err
	}
	trustBytes, err := release.EncodeTrustRoot(trust)
	if err != nil {
		return nil, err
	}
	trustPath := filepath.Join(base, "release-trust.json")
	if err := os.WriteFile(trustPath, trustBytes, 0o600); err != nil {
		return nil, errors.New("write fixture trust root failed")
	}

	fixtures := make([]Fixture, 0, len(manifests))
	for index, manifest := range manifests {
		root := filepath.Join(base, fmt.Sprintf("bundle-%d", index+1))
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, errors.New("create fixture bundle failed")
		}
		for fileIndex := range manifest.Files {
			declaration := &manifest.Files[fileIndex]
			content := []byte("matrix-release-payload:" + declaration.Path)
			mode := os.FileMode(0o600)
			if declaration.Executable {
				mode = 0o700
			}
			target := filepath.Join(root, filepath.FromSlash(declaration.Path))
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return nil, errors.New("create fixture payload directory failed")
			}
			if err := os.WriteFile(target, content, mode); err != nil {
				return nil, errors.New("write fixture payload failed")
			}
			declaration.Size = uint64(len(content))
			digest := sha256.Sum256(content)
			declaration.SHA256 = "sha256:" + hex.EncodeToString(digest[:])
		}
		manifestBytes, err := release.EncodeCanonical(manifest)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(
			filepath.Join(root, release.ManifestFilename), manifestBytes, 0o600,
		); err != nil {
			return nil, errors.New("write fixture release manifest failed")
		}
		if err := os.WriteFile(
			filepath.Join(root, release.SignatureFilename),
			ed25519.Sign(privateKey, manifestBytes), 0o600,
		); err != nil {
			return nil, errors.New("write fixture release signature failed")
		}
		digest := sha256.Sum256(manifestBytes)
		fixtures = append(fixtures, Fixture{
			Root: root, TrustPath: trustPath, Trust: trust, Manifest: manifest,
			ManifestDigest: "sha256:" + hex.EncodeToString(digest[:]),
		})
	}
	return fixtures, nil
}

func Manifest() release.Manifest {
	required := release.RequiredImages()
	files := []release.File{{
		Path: "bin/mx", MediaType: "application/vnd.matrix.executable",
		Size: 1, SHA256: stableDigest("executable:mx"), Executable: true,
	}}
	images := make([]release.Image, 0, len(required))
	for _, requirement := range required {
		archive := "images/" + requirement.Component + ".tar"
		files = append(files, release.File{
			Path: archive, MediaType: "application/vnd.docker.image.archive",
			Size: 1, SHA256: stableDigest("archive:" + requirement.Component),
		})
		images = append(images, release.Image{
			Component: requirement.Component, Purpose: requirement.Purpose, ArchivePath: archive,
			ImageID:      stableDigest("image:" + requirement.Component),
			SourceDigest: stableDigest("source:" + requirement.Component),
			OS:           "linux", Architecture: "amd64", HealthContract: requirement.HealthContract,
		})
	}
	slices.SortFunc(files, func(left, right release.File) int {
		return strings.Compare(left.Path, right.Path)
	})
	commit := strings.Repeat("a", 40)
	return release.Manifest{
		APIVersion: release.ManifestAPIVersion, Kind: release.ManifestKind,
		Release: release.ReleaseIdentity{
			ID: "matrix-v0.1.0-" + commit[:12], Version: "v0.1.0",
			SourceCommit: commit, BuildID: "installation-consumer-test",
			CreatedAt: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
		},
		Signer: release.Signer{KeyID: "xiak-release-2026", Algorithm: release.SignatureAlgorithm},
		Host: release.HostProfile{
			OS: "linux", Architecture: "amd64", MinimumDocker: "29.0.0",
			MinimumCompose: "2.40.0", CommandContract: "v1",
		},
		MinimumFreeBytes: 1024 * 1024 * 1024,
		Database:         release.CurrentDatabaseProfile(),
		TopologyDigest:   topology.ContractDigest(), Files: files, Images: images,
	}
}

func stableDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
