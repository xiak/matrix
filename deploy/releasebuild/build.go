// Package releasebuild assembles the fixed Phase 1 offline distribution. It
// consumes the installation-owned release and topology contracts and cannot
// accept arbitrary packages, images, Dockerfiles, commands, or payloads.
package releasebuild

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	installationrelease "github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const (
	minimumFreeBytes      = 4 * 1024 * 1024 * 1024
	databaseSchemaVersion = 1
)

type SigningMaterial struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

type Config struct {
	RepositoryRoot  string
	Output          string
	Version         string
	BuildID         string
	SourceCommit    string
	CreatedAt       time.Time
	PreviousID      string
	PreviousVersion string
	Signer          SigningMaterial
	Entropy         io.Reader
}

type Result struct {
	Output    string
	Manifest  installationrelease.Manifest
	TrustRoot installationrelease.TrustRoot
}

type ImageMetadata struct {
	ID           string
	OS           string
	Architecture string
}

type Effects interface {
	BuildGoBinary(context.Context, string, string, string) error
	InspectImage(context.Context, string) (ImageMetadata, error)
	BuildImage(context.Context, string, string) error
	SaveImage(context.Context, string, string) error
	VerifyPaaSCLI(context.Context, string) error
	RemoveBuildTag(context.Context, string) error
}

func Assemble(ctx context.Context, config Config, effects Effects) (Result, error) {
	if ctx == nil || effects == nil {
		return Result{}, errors.New("release build boundary is unavailable")
	}
	config, trust, err := validateConfig(config)
	if err != nil {
		return Result{}, err
	}
	if err := verifyBaseImages(ctx, effects); err != nil {
		return Result{}, err
	}

	workspace, err := os.MkdirTemp(filepath.Dir(config.Output), ".matrix-release-build-")
	if err != nil {
		return Result{}, errors.New("create release build workspace failed")
	}
	defer os.RemoveAll(workspace)
	if err := os.Chmod(workspace, 0o700); err != nil {
		return Result{}, errors.New("protect release build workspace failed")
	}
	bundle := filepath.Join(workspace, "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil ||
		os.Mkdir(filepath.Join(bundle, "bin"), 0o700) != nil ||
		os.Mkdir(filepath.Join(bundle, "images"), 0o700) != nil {
		return Result{}, errors.New("create release bundle workspace failed")
	}

	binaries, err := buildBinaries(ctx, config, effects, workspace)
	if err != nil {
		return Result{}, err
	}
	if err := copyRegularFile(binaries["mx"], filepath.Join(bundle, "bin", "mx"), 0o700); err != nil {
		return Result{}, err
	}

	images, tags, err := buildImages(ctx, config, effects, workspace, bundle, binaries)
	defer removeBuildTags(tags, effects)
	if err != nil {
		return Result{}, err
	}
	files, err := inventoryPayloads(bundle)
	if err != nil {
		return Result{}, err
	}
	manifest := newManifest(config, files, images)
	manifestBytes, err := installationrelease.EncodeCanonical(manifest)
	if err != nil {
		return Result{}, errors.New("release manifest construction failed")
	}
	signature := ed25519.Sign(config.Signer.PrivateKey, manifestBytes)
	if err := writeExclusive(filepath.Join(bundle, installationrelease.ManifestFilename), manifestBytes, 0o600); err != nil {
		return Result{}, err
	}
	if err := writeExclusive(filepath.Join(bundle, installationrelease.SignatureFilename), signature, 0o600); err != nil {
		return Result{}, err
	}
	trustBytes, err := installationrelease.EncodeTrustRoot(trust)
	if err != nil {
		return Result{}, errors.New("release trust root construction failed")
	}
	verified, err := installationrelease.VerifyDirectory(bundle, trustBytes)
	if err != nil || verified.Manifest.Release.ID != manifest.Release.ID {
		return Result{}, errors.New("assembled release verification failed")
	}
	if err := os.Rename(bundle, config.Output); err != nil {
		return Result{}, errors.New("publish assembled release failed")
	}
	return Result{Output: config.Output, Manifest: manifest, TrustRoot: trust}, nil
}

func validateConfig(config Config) (Config, installationrelease.TrustRoot, error) {
	if config.Entropy == nil {
		config.Entropy = rand.Reader
	}
	for _, candidate := range []string{config.RepositoryRoot, config.Output} {
		if candidate == "" || len(candidate) > 4096 || !filepath.IsAbs(candidate) ||
			filepath.Clean(candidate) != candidate || isFilesystemRoot(candidate) {
			return Config{}, installationrelease.TrustRoot{}, errors.New("release build path is invalid")
		}
	}
	repositoryInfo, err := os.Lstat(config.RepositoryRoot)
	if err != nil || !repositoryInfo.IsDir() || repositoryInfo.Mode()&os.ModeSymlink != 0 {
		return Config{}, installationrelease.TrustRoot{}, errors.New("release repository root is unsafe")
	}
	moduleInfo, err := os.Lstat(filepath.Join(config.RepositoryRoot, "go.mod"))
	if err != nil || !moduleInfo.Mode().IsRegular() || moduleInfo.Mode()&os.ModeSymlink != 0 {
		return Config{}, installationrelease.TrustRoot{}, errors.New("release repository module is unavailable")
	}
	parentInfo, err := os.Lstat(filepath.Dir(config.Output))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return Config{}, installationrelease.TrustRoot{}, errors.New("release output parent is unsafe")
	}
	if _, err := os.Lstat(config.Output); !errors.Is(err, os.ErrNotExist) {
		return Config{}, installationrelease.TrustRoot{}, errors.New("release output already exists or cannot be inspected")
	}
	if len(config.Signer.PrivateKey) != ed25519.PrivateKeySize {
		return Config{}, installationrelease.TrustRoot{}, errors.New("release signing key is invalid")
	}
	publicKey, ok := config.Signer.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return Config{}, installationrelease.TrustRoot{}, errors.New("release signing key is invalid")
	}
	trust, err := installationrelease.NewTrustRoot(config.Signer.KeyID, publicKey)
	if err != nil {
		return Config{}, installationrelease.TrustRoot{}, err
	}
	placeholderFiles, placeholderImages := placeholderPayloads()
	if err := installationrelease.ValidateManifest(newManifest(config, placeholderFiles, placeholderImages)); err != nil {
		return Config{}, installationrelease.TrustRoot{}, errors.New("release build metadata is invalid")
	}
	return config, trust, nil
}

func buildBinaries(ctx context.Context, config Config, effects Effects, workspace string) (map[string]string, error) {
	root := filepath.Join(workspace, "binaries")
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, errors.New("create release binary workspace failed")
	}
	result := make(map[string]string, len(binarySpecifications))
	for _, specification := range binarySpecifications {
		target := filepath.Join(root, specification.name)
		if err := effects.BuildGoBinary(ctx, config.RepositoryRoot, specification.packagePath, target); err != nil {
			return nil, errors.New("build fixed release executable failed")
		}
		info, err := os.Lstat(target)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("built release executable is invalid")
		}
		result[specification.name] = target
	}
	return result, nil
}

func buildImages(
	ctx context.Context,
	config Config,
	effects Effects,
	workspace string,
	bundle string,
	binaries map[string]string,
) ([]installationrelease.Image, []string, error) {
	token, err := randomBuildToken(config.Entropy)
	if err != nil {
		return nil, nil, err
	}
	metadata := map[string]ImageMetadata{
		"postgres": {ID: PostgresImageID, OS: "linux", Architecture: "amd64"},
	}
	tags := make([]string, 0, len(imageRecipes))
	for _, recipe := range imageRecipes {
		contextRoot := filepath.Join(workspace, "images", recipe.component)
		if err := writeImageContext(contextRoot, recipe, config, binaries); err != nil {
			return nil, tags, err
		}
		tag := "matrix-release-build/" + recipe.component + ":" + token
		if err := effects.BuildImage(ctx, contextRoot, tag); err != nil {
			return nil, tags, errors.New("build fixed release image failed")
		}
		tags = append(tags, tag)
		image, err := effects.InspectImage(ctx, tag)
		if err != nil || validateImageMetadata(image) != nil {
			return nil, tags, errors.New("built release image identity is invalid")
		}
		metadata[recipe.component] = image
	}
	if err := effects.VerifyPaaSCLI(ctx, metadata["paas"].ID); err != nil {
		return nil, tags, errors.New("PaaS image Docker Compose contract failed")
	}

	images := make([]installationrelease.Image, 0, len(installationrelease.RequiredImages()))
	for _, requirement := range installationrelease.RequiredImages() {
		image, found := metadata[requirement.Component]
		if !found || validateImageMetadata(image) != nil {
			return nil, tags, errors.New("release image inventory is incomplete")
		}
		archive := filepath.Join(bundle, "images", requirement.Component+".tar")
		if err := effects.SaveImage(ctx, image.ID, archive); err != nil {
			return nil, tags, errors.New("save fixed release image failed")
		}
		images = append(images, installationrelease.Image{
			Component: requirement.Component, Purpose: requirement.Purpose,
			ArchivePath: "images/" + requirement.Component + ".tar",
			ImageID:     image.ID, SourceDigest: image.ID,
			OS: image.OS, Architecture: image.Architecture,
			HealthContract: requirement.HealthContract,
		})
	}
	return images, tags, nil
}

func verifyBaseImages(ctx context.Context, effects Effects) error {
	for _, required := range []struct{ reference, id string }{
		{APISIXBaseReference, APISIXBaseImageID},
		{DockerBaseReference, DockerBaseImageID},
		{PostgresReference, PostgresImageID},
	} {
		image, err := effects.InspectImage(ctx, required.reference)
		if err != nil || image.ID != required.id || validateImageMetadata(image) != nil {
			return errors.New("required fixed base image is unavailable or changed")
		}
	}
	return nil
}

func inventoryPayloads(bundle string) ([]installationrelease.File, error) {
	paths := []string{"bin/mx"}
	for _, requirement := range installationrelease.RequiredImages() {
		paths = append(paths, "images/"+requirement.Component+".tar")
	}
	slices.Sort(paths)
	files := make([]installationrelease.File, 0, len(paths))
	for _, relative := range paths {
		target := filepath.Join(bundle, filepath.FromSlash(relative))
		size, digest, err := hashRegularFile(target)
		if err != nil {
			return nil, err
		}
		file := installationrelease.File{
			Path: relative, Size: size, SHA256: digest,
			MediaType: "application/vnd.docker.image.archive",
		}
		if relative == "bin/mx" {
			file.MediaType = "application/vnd.matrix.executable"
			file.Executable = true
		}
		files = append(files, file)
	}
	return files, nil
}

func newManifest(
	config Config,
	files []installationrelease.File,
	images []installationrelease.Image,
) installationrelease.Manifest {
	releaseID := ""
	if len(config.SourceCommit) >= 12 {
		releaseID = "matrix-" + config.Version + "-" + config.SourceCommit[:12]
	}
	return installationrelease.Manifest{
		APIVersion: installationrelease.ManifestAPIVersion,
		Kind:       installationrelease.ManifestKind,
		Release: installationrelease.ReleaseIdentity{
			ID: releaseID, Version: config.Version, SourceCommit: config.SourceCommit,
			BuildID: config.BuildID, CreatedAt: config.CreatedAt,
			PreviousID: config.PreviousID, PreviousVersion: config.PreviousVersion,
		},
		Signer: installationrelease.Signer{
			KeyID: config.Signer.KeyID, Algorithm: installationrelease.SignatureAlgorithm,
		},
		Host: installationrelease.HostProfile{
			OS: "linux", Architecture: "amd64",
			MinimumDocker: minimumDockerVersion, MinimumCompose: minimumComposeVersion,
			CommandContract: "v1",
		},
		MinimumFreeBytes: minimumFreeBytes,
		Database: installationrelease.DatabaseProfile{
			SchemaVersion: databaseSchemaVersion,
			Compatibility: "expand-contract-n-minus-one",
		},
		TopologyDigest: topology.ContractDigest(), Files: files, Images: images,
	}
}

func placeholderPayloads() ([]installationrelease.File, []installationrelease.Image) {
	files := []installationrelease.File{{
		Path: "bin/mx", MediaType: "application/vnd.matrix.executable",
		Size: 1, SHA256: placeholderDigest("mx"), Executable: true,
	}}
	images := make([]installationrelease.Image, 0, len(installationrelease.RequiredImages()))
	for _, requirement := range installationrelease.RequiredImages() {
		archive := "images/" + requirement.Component + ".tar"
		files = append(files, installationrelease.File{
			Path: archive, MediaType: "application/vnd.docker.image.archive",
			Size: 1, SHA256: placeholderDigest(archive),
		})
		images = append(images, installationrelease.Image{
			Component: requirement.Component, Purpose: requirement.Purpose,
			ArchivePath: archive, ImageID: placeholderDigest("image:" + requirement.Component),
			SourceDigest: placeholderDigest("source:" + requirement.Component),
			OS:           "linux", Architecture: "amd64", HealthContract: requirement.HealthContract,
		})
	}
	slices.SortFunc(files, func(left, right installationrelease.File) int {
		return strings.Compare(left.Path, right.Path)
	})
	return files, images
}

func placeholderDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func randomBuildToken(entropy io.Reader) (string, error) {
	var value [12]byte
	if _, err := io.ReadFull(entropy, value[:]); err != nil {
		return "", errors.New("generate release build identity failed")
	}
	return hex.EncodeToString(value[:]), nil
}

func validateImageMetadata(image ImageMetadata) error {
	if len(image.ID) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(image.ID, "sha256:") ||
		image.OS != "linux" || image.Architecture != "amd64" {
		return errors.New("image metadata is invalid")
	}
	_, err := hex.DecodeString(strings.TrimPrefix(image.ID, "sha256:"))
	return err
}

func hashRegularFile(target string) (uint64, string, error) {
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Mode()&os.ModeSymlink != 0 {
		return 0, "", errors.New("release payload is invalid")
	}
	file, err := os.Open(target)
	if err != nil {
		return 0, "", errors.New("open release payload failed")
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, file)
	openedInfo, statErr := file.Stat()
	if err != nil || written != info.Size() || statErr != nil || !os.SameFile(info, openedInfo) {
		return 0, "", errors.New("hash release payload failed")
	}
	return uint64(written), "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func copyRegularFile(source, target string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return errors.New("open release executable failed")
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("create release executable failed")
	}
	succeeded := false
	defer func() {
		_ = output.Close()
		if !succeeded {
			_ = os.Remove(target)
		}
	}()
	if err := os.Chmod(target, mode); err != nil {
		return errors.New("protect release executable failed")
	}
	if _, err := io.Copy(output, input); err != nil || output.Sync() != nil || output.Close() != nil {
		return errors.New("copy release executable failed")
	}
	succeeded = true
	return nil
}

func writeExclusive(target string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("create release metadata failed")
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = os.Remove(target)
		}
	}()
	if err := os.Chmod(target, mode); err != nil {
		return errors.New("protect release metadata failed")
	}
	if _, err := file.Write(content); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("write release metadata failed")
	}
	succeeded = true
	return nil
}

func removeBuildTags(tags []string, effects Effects) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tag := range tags {
		_ = effects.RemoveBuildTag(ctx, tag)
	}
}

func isFilesystemRoot(target string) bool {
	volume := filepath.VolumeName(target)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	return filepath.Clean(target) == filepath.Clean(root)
}
