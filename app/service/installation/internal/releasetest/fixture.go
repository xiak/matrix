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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/release"
	"github.com/xiak/matrix/app/service/installation/internal/topology"
)

type Fixture struct {
	Root           string
	TrustPath      string
	Trust          release.TrustRoot
	Manifest       release.Manifest
	ManifestDigest string
}

func Write(base string) (Fixture, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Fixture{}, errors.New("generate fixture release key failed")
	}
	trust, err := release.NewTrustRoot("xiak-release-2026", publicKey)
	if err != nil {
		return Fixture{}, err
	}
	trustBytes, err := release.EncodeTrustRoot(trust)
	if err != nil {
		return Fixture{}, err
	}
	trustPath := filepath.Join(base, "release-trust.json")
	if err := os.WriteFile(trustPath, trustBytes, 0o600); err != nil {
		return Fixture{}, errors.New("write fixture trust root failed")
	}

	root := filepath.Join(base, "bundle")
	if err := os.Mkdir(root, 0o700); err != nil {
		return Fixture{}, errors.New("create fixture bundle failed")
	}
	manifest := Manifest()
	for index := range manifest.Files {
		declaration := &manifest.Files[index]
		content := []byte("matrix-release-payload:" + declaration.Path)
		mode := os.FileMode(0o600)
		if declaration.Executable {
			mode = 0o700
		}
		target := filepath.Join(root, filepath.FromSlash(declaration.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return Fixture{}, errors.New("create fixture payload directory failed")
		}
		if err := os.WriteFile(target, content, mode); err != nil {
			return Fixture{}, errors.New("write fixture payload failed")
		}
		declaration.Size = uint64(len(content))
		digest := sha256.Sum256(content)
		declaration.SHA256 = "sha256:" + hex.EncodeToString(digest[:])
	}
	manifestBytes, err := release.EncodeCanonical(manifest)
	if err != nil {
		return Fixture{}, err
	}
	if err := os.WriteFile(filepath.Join(root, release.ManifestFilename), manifestBytes, 0o600); err != nil {
		return Fixture{}, errors.New("write fixture release manifest failed")
	}
	if err := os.WriteFile(
		filepath.Join(root, release.SignatureFilename),
		ed25519.Sign(privateKey, manifestBytes),
		0o600,
	); err != nil {
		return Fixture{}, errors.New("write fixture release signature failed")
	}
	digest := sha256.Sum256(manifestBytes)
	return Fixture{
		Root: root, TrustPath: trustPath, Trust: trust, Manifest: manifest,
		ManifestDigest: "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
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
		Database: release.DatabaseProfile{
			SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one",
		},
		TopologyDigest: topology.ContractDigest(), Files: files, Images: images,
	}
}

func stableDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
