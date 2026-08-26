// Package composefixture imports the release-owned verification workload used
// by real offline Compose acceptance tests. It builds a static Linux Go binary
// and imports a root filesystem directly into the already-running Docker
// Engine; no Dockerfile, registry, pull, or network access is involved.
package composefixture

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var imageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Image struct {
	ID        string
	temporary string
}

func Import(ctx context.Context) (*Image, error) {
	if ctx == nil {
		return nil, errors.New("fixture import context is required")
	}
	architecture, err := dockerOutput(ctx, "info", "--format", "{{.Architecture}}")
	if err != nil {
		return nil, err
	}
	goArchitecture := map[string]string{
		"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
	}[strings.TrimSpace(architecture)]
	if goArchitecture == "" {
		return nil, errors.New("Docker architecture is unsupported by the fixture")
	}
	temporary, err := os.MkdirTemp("", "matrix-compose-fixture-")
	if err != nil {
		return nil, errors.New("create fixture workspace failed")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removeTemporary(temporary)
		}
	}()
	binaryPath := filepath.Join(temporary, "fixture")
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("resolve fixture source failed")
	}
	sourceDirectory := filepath.Join(
		filepath.Dir(sourceFile), "..", "..", "app", "service", "installation", "cmd", "matrix-verification",
	)
	command := exec.CommandContext(
		ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", binaryPath,
		sourceDirectory,
	)
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goArchitecture)
	if output, buildErr := command.CombinedOutput(); buildErr != nil {
		return nil, fmt.Errorf("build offline fixture failed: %w: %s", buildErr, bounded(output))
	}
	archivePath := filepath.Join(temporary, "rootfs.tar")
	if err := writeRootFS(archivePath, binaryPath); err != nil {
		return nil, err
	}
	identity, err := dockerOutput(
		ctx, "import", "--change", `ENTRYPOINT ["/fixture"]`, archivePath,
	)
	if err != nil {
		return nil, err
	}
	identity = strings.TrimSpace(identity)
	if !imageIDPattern.MatchString(identity) {
		return nil, errors.New("Docker import returned an invalid fixture identity")
	}
	cleanup = false
	return &Image{ID: identity, temporary: temporary}, nil
}

func (image *Image) Close(ctx context.Context) error {
	if image == nil {
		return nil
	}
	var problems []error
	if imageIDPattern.MatchString(image.ID) {
		command := exec.CommandContext(ctx, "docker", "image", "rm", "--force", image.ID)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		problems = append(problems, command.Run())
	} else if image.ID != "" {
		problems = append(problems, errors.New("refusing to remove an invalid fixture image identity"))
	}
	if image.temporary != "" {
		problems = append(problems, removeTemporary(image.temporary))
	}
	image.ID = ""
	image.temporary = ""
	return errors.Join(problems...)
}

func Probe(
	ctx context.Context,
	imageID string,
	networkID string,
	setting string,
	secretDigest string,
	generation string,
) error {
	if !imageIDPattern.MatchString(imageID) || strings.TrimSpace(networkID) == "" {
		return errors.New("fixture probe identity is invalid")
	}
	command := exec.CommandContext(
		ctx,
		"docker", "run", "--rm", "--pull", "never", "--network", networkID,
		imageID, "probe", "http://web:8080/ready", setting, secretDigest, generation,
	)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("network-scoped fixture probe failed: %w: %s", err, bounded(output))
	}
	return nil
}

func writeRootFS(archivePath, binaryPath string) (returnErr error) {
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("create fixture rootfs failed")
	}
	defer func() { returnErr = errors.Join(returnErr, archive.Close()) }()
	writer := tar.NewWriter(archive)
	defer func() { returnErr = errors.Join(returnErr, writer.Close()) }()
	binary, err := os.Open(binaryPath)
	if err != nil {
		return errors.New("open fixture binary failed")
	}
	defer func() { returnErr = errors.Join(returnErr, binary.Close()) }()
	info, err := binary.Stat()
	if err != nil {
		return errors.New("stat fixture binary failed")
	}
	if err := writer.WriteHeader(&tar.Header{
		Name: "fixture", Mode: 0o755, Size: info.Size(), Typeflag: tar.TypeReg,
	}); err != nil {
		return errors.New("write fixture rootfs header failed")
	}
	if _, err := io.Copy(writer, binary); err != nil {
		return errors.New("write fixture rootfs binary failed")
	}
	return nil
}

func dockerOutput(ctx context.Context, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Docker fixture command failed: %w: %s", err, bounded(output))
	}
	return string(output), nil
}

func bounded(output []byte) string {
	const maximum = 2048
	if len(output) > maximum {
		output = output[:maximum]
	}
	return string(output)
}

func removeTemporary(target string) error {
	absolute, err := filepath.Abs(target)
	if err != nil || filepath.Clean(absolute) != target ||
		!strings.HasPrefix(filepath.Base(target), "matrix-compose-fixture-") {
		return errors.New("refusing to remove an invalid fixture workspace")
	}
	temporaryRoot, err := filepath.Abs(os.TempDir())
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(temporaryRoot, target)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("fixture workspace is outside the temporary root")
	}
	return os.RemoveAll(target)
}
