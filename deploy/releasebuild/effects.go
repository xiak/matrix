package releasebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const maximumCommandOutputBytes = 1024 * 1024

var buildTagPattern = regexp.MustCompile(`^matrix-release-build/(?:apisix|audit|iam|paas|paas-ui|verification):[0-9a-f]{24}$`)

type localCommand struct {
	program string
	args    []string
	dir     string
	env     []string
	capture bool
}

type LocalEffects struct {
	run func(context.Context, localCommand) ([]byte, error)
}

func NewLocalEffects() *LocalEffects {
	return &LocalEffects{run: runLocalCommand}
}

func (effects *LocalEffects) BuildGoBinary(
	ctx context.Context,
	repositoryRoot string,
	packagePath string,
	output string,
) error {
	if effects == nil || effects.run == nil || !allowedBinaryPackage(packagePath) ||
		!filepath.IsAbs(repositoryRoot) || !filepath.IsAbs(output) {
		return errors.New("Go release build effect is invalid")
	}
	_, err := effects.run(ctx, localCommand{
		program: "go", dir: repositoryRoot,
		args: []string{
			"build", "-mod=readonly", "-buildvcs=true", "-trimpath",
			"-ldflags=-s -w", "-o", output, packagePath,
		},
		env: []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64"},
	})
	if err != nil {
		return errors.New("Go release build effect failed")
	}
	return nil
}

func (effects *LocalEffects) InspectImage(ctx context.Context, reference string) (ImageMetadata, error) {
	if effects == nil || effects.run == nil || !allowedImageReference(reference) {
		return ImageMetadata{}, errors.New("Docker image inspection effect is invalid")
	}
	output, err := effects.run(ctx, localCommand{
		program: "docker", args: []string{"image", "inspect", reference}, capture: true,
	})
	if err != nil {
		return ImageMetadata{}, errors.New("Docker image inspection effect failed")
	}
	var records []struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
	}
	if err := json.Unmarshal(output, &records); err != nil || len(records) != 1 {
		return ImageMetadata{}, errors.New("Docker image inspection output is invalid")
	}
	result := ImageMetadata{
		ID: records[0].ID, OS: records[0].OS, Architecture: records[0].Architecture,
	}
	if validateImageMetadata(result) != nil {
		return ImageMetadata{}, errors.New("Docker image inspection output is invalid")
	}
	return result, nil
}

func (effects *LocalEffects) BuildImage(ctx context.Context, contextRoot, tag string) error {
	if effects == nil || effects.run == nil || !filepath.IsAbs(contextRoot) ||
		!buildTagPattern.MatchString(tag) {
		return errors.New("Docker image build effect is invalid")
	}
	dockerfile := filepath.Join(contextRoot, "Dockerfile")
	info, err := os.Lstat(dockerfile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Docker image build context is invalid")
	}
	_, err = effects.run(ctx, localCommand{
		program: "docker",
		args: []string{
			"build", "--network=none", "--pull=false", "--file", dockerfile,
			"--tag", tag, contextRoot,
		},
	})
	if err != nil {
		return errors.New("Docker image build effect failed")
	}
	return nil
}

func (effects *LocalEffects) SaveImage(
	ctx context.Context,
	imageID string,
	output string,
) (ImageMetadata, error) {
	if effects == nil || effects.run == nil || validateImageMetadata(ImageMetadata{
		ID: imageID, OS: "linux", Architecture: "amd64",
	}) != nil || !filepath.IsAbs(output) || filepath.Ext(output) != ".tar" {
		return ImageMetadata{}, errors.New("Docker image save effect is invalid")
	}
	_, err := effects.run(ctx, localCommand{
		program: "docker", args: []string{"image", "save", "--output", output, imageID},
	})
	if err != nil {
		return ImageMetadata{}, errors.New("Docker image save effect failed")
	}
	info, statErr := os.Lstat(output)
	if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Mode()&os.ModeSymlink != 0 {
		return ImageMetadata{}, errors.New("Docker image archive effect is invalid")
	}
	identity, inspectErr := inspectImageArchive(output, imageID)
	if inspectErr != nil {
		return ImageMetadata{}, errors.New("Docker image archive identity is invalid")
	}
	return identity, nil
}

func (effects *LocalEffects) VerifyPaaSCLI(ctx context.Context, imageID string) error {
	if effects == nil || effects.run == nil || validateImageMetadata(ImageMetadata{
		ID: imageID, OS: "linux", Architecture: "amd64",
	}) != nil {
		return errors.New("PaaS image verification effect is invalid")
	}
	output, err := effects.run(ctx, localCommand{
		program: "docker", capture: true,
		args: []string{
			"run", "--rm", "--pull", "never", "--network", "none", "--read-only",
			"--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
			"--env", "DOCKER_CONFIG=/tmp/docker-config",
			"--entrypoint", "docker", imageID, "compose", "version", "--short",
		},
	})
	if err != nil || compareVersion(strings.TrimSpace(string(output)), minimumComposeVersion) < 0 {
		return errors.New("PaaS image Docker Compose verification failed")
	}
	return nil
}

func (effects *LocalEffects) RemoveBuildTag(ctx context.Context, tag string) error {
	if effects == nil || effects.run == nil || !buildTagPattern.MatchString(tag) {
		return errors.New("Docker build tag cleanup effect is invalid")
	}
	_, err := effects.run(ctx, localCommand{
		program: "docker", args: []string{"image", "rm", "--no-prune", tag},
	})
	if err != nil {
		return errors.New("Docker build tag cleanup effect failed")
	}
	return nil
}

func runLocalCommand(ctx context.Context, command localCommand) ([]byte, error) {
	if ctx == nil || command.program == "" {
		return nil, errors.New("release provider command is invalid")
	}
	process := exec.CommandContext(ctx, command.program, command.args...)
	process.Dir = command.dir
	process.Env = commandEnvironment(command.env)
	process.Stdin = nil
	process.Stderr = io.Discard
	if !command.capture {
		process.Stdout = io.Discard
		if err := process.Run(); err != nil {
			return nil, errors.New("release provider command failed")
		}
		return nil, nil
	}
	output := &boundedBuffer{maximum: maximumCommandOutputBytes}
	process.Stdout = output
	if err := process.Run(); err != nil || output.exceeded {
		return nil, errors.New("release provider command failed")
	}
	return append([]byte(nil), output.Bytes()...), nil
}

type boundedBuffer struct {
	bytes.Buffer
	maximum  int
	exceeded bool
}

func (buffer *boundedBuffer) Write(content []byte) (int, error) {
	if buffer.Len()+len(content) > buffer.maximum {
		buffer.exceeded = true
		remaining := buffer.maximum - buffer.Len()
		if remaining > 0 {
			_, _ = buffer.Buffer.Write(content[:remaining])
		}
		return len(content), nil
	}
	return buffer.Buffer.Write(content)
}

func commandEnvironment(overrides []string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for _, value := range overrides {
		key, _, _ := strings.Cut(value, "=")
		keys[strings.ToUpper(key)] = struct{}{}
	}
	result := make([]string, 0, len(os.Environ())+len(overrides))
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if _, replaced := keys[strings.ToUpper(key)]; !replaced {
			result = append(result, value)
		}
	}
	return append(result, overrides...)
}

func allowedBinaryPackage(value string) bool {
	for _, specifications := range [][]binarySpecification{binarySpecifications, nodeBinarySpecifications} {
		for _, specification := range specifications {
			if specification.packagePath == value {
				return true
			}
		}
	}
	return false
}

func allowedImageReference(value string) bool {
	return value == APISIXBaseReference || value == DockerBaseReference ||
		value == PostgresReference || buildTagPattern.MatchString(value)
}

func compareVersion(left, right string) int {
	parse := func(value string) ([]int, bool) {
		parts := strings.Split(value, ".")
		if len(parts) != 3 {
			return nil, false
		}
		result := make([]int, 3)
		for index, part := range parts {
			parsed, err := strconv.Atoi(part)
			if err != nil || parsed < 0 {
				return nil, false
			}
			result[index] = parsed
		}
		return result, true
	}
	leftParts, leftOK := parse(left)
	rightParts, rightOK := parse(right)
	if !leftOK || !rightOK {
		return -1
	}
	for index := range leftParts {
		if leftParts[index] < rightParts[index] {
			return -1
		}
		if leftParts[index] > rightParts[index] {
			return 1
		}
	}
	return 0
}
