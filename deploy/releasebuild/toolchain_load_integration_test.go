package releasebuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	installationrelease "github.com/xiak/matrix/app/service/installation/release"
)

const maximumDockerIntegrationOutput = 1024 * 1024

// TestRunnerToolchainOfflineLoadIntegration targets a fresh, disposable Docker
// 29 daemon. The harness must isolate that daemon from every network before it
// opts in; this test refuses the developer's ambient Docker endpoint.
func TestRunnerToolchainOfflineLoadIntegration(t *testing.T) {
	if os.Getenv("MATRIX_TEST_RUNNER_TOOLCHAIN_LOAD") != "1" {
		t.Skip("runner toolchain offline-load integration is not enabled")
	}
	host := os.Getenv("MATRIX_TEST_RUNNER_DOCKER_HOST")
	if !strings.HasPrefix(host, "tcp://127.0.0.1:") || strings.TrimPrefix(host, "tcp://127.0.0.1:") == "" {
		t.Fatal("MATRIX_TEST_RUNNER_DOCKER_HOST must identify a disposable loopback Docker daemon")
	}
	archive := os.Getenv("MATRIX_TEST_RUNNER_TOOLCHAIN_ARCHIVE")
	absArchive, err := filepath.Abs(archive)
	if err != nil || archive == "" || filepath.Clean(absArchive) != filepath.Clean(archive) {
		t.Fatal("MATRIX_TEST_RUNNER_TOOLCHAIN_ARCHIVE must be an absolute path")
	}
	wantLoadedID := os.Getenv("MATRIX_TEST_RUNNER_TOOLCHAIN_EXPECTED_ID")
	if wantLoadedID != RunnerToolchainSourceID && wantLoadedID != RunnerToolchainArchiveConfigID {
		t.Fatal("MATRIX_TEST_RUNNER_TOOLCHAIN_EXPECTED_ID must select one authenticated Docker store identity")
	}
	info, err := os.Lstat(absArchive)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		t.Fatal("runner toolchain archive is not a safe regular file")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	version, err := integrationDocker(ctx, host, "version", "--format", "{{.Server.Version}}")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(version)), "29.") {
		t.Fatalf("disposable Docker 29 daemon is unavailable: %v", err)
	}
	if _, err := integrationDocker(ctx, host, "image", "inspect", installationrelease.RunnerToolchainLocalReference); err == nil {
		t.Fatal("disposable daemon already contains the Matrix runner toolchain tag")
	}

	if _, err := integrationDocker(ctx, host, "image", "load", "--input", absArchive); err != nil {
		t.Fatalf("offline toolchain load failed: %v", err)
	}
	loadedID := ""
	for _, candidate := range []string{RunnerToolchainSourceID, RunnerToolchainArchiveConfigID} {
		content, inspectErr := integrationDocker(ctx, host, "image", "inspect", "--format", "{{.Id}}", candidate)
		if inspectErr == nil && strings.TrimSpace(string(content)) == candidate {
			if loadedID != "" {
				t.Fatal("Docker exposed more than one load identity for the signed archive")
			}
			loadedID = candidate
		}
	}
	if loadedID == "" {
		t.Fatal("Docker did not expose either authenticated archive identity after load")
	}
	if loadedID != wantLoadedID {
		t.Fatalf("Docker load identity = %q, want selected store identity %q", loadedID, wantLoadedID)
	}
	if _, err := integrationDocker(
		ctx, host, "image", "tag", loadedID, installationrelease.RunnerToolchainLocalReference,
	); err != nil {
		t.Fatalf("assign fixed local toolchain tag failed: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_, _ = integrationDocker(
			cleanupCtx, host, "image", "remove", "--force",
			installationrelease.RunnerToolchainLocalReference,
		)
	}()

	content, err := integrationDocker(
		ctx, host, "image", "inspect", "--format", "{{json .}}",
		installationrelease.RunnerToolchainLocalReference,
	)
	if err != nil {
		t.Fatalf("inspect installed local toolchain failed: %v", err)
	}
	var image struct {
		ID           string   `json:"Id"`
		RepoTags     []string `json:"RepoTags"`
		RepoDigests  []string `json:"RepoDigests"`
		OS           string   `json:"Os"`
		Architecture string   `json:"Architecture"`
	}
	if err := json.Unmarshal(content, &image); err != nil {
		t.Fatal("Docker returned invalid image inspection JSON")
	}
	wantDigests := []string{}
	if loadedID == RunnerToolchainSourceID {
		wantDigests = []string{installationrelease.RunnerToolchainLocalDigestReference}
	}
	if image.ID != loadedID || image.OS != "linux" || image.Architecture != "amd64" ||
		!slices.Equal(image.RepoTags, []string{installationrelease.RunnerToolchainLocalReference}) ||
		!slices.Equal(image.RepoDigests, wantDigests) {
		t.Fatalf("installed offline toolchain metadata is not closed: %#v", image)
	}
}

func integrationDocker(ctx context.Context, host string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", append([]string{"--host", host}, arguments...)...)
	var output boundedBuffer
	output.maximum = maximumDockerIntegrationOutput
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("disposable Docker command timed out: %w", ctx.Err())
	}
	if err != nil || output.exceeded {
		return nil, errors.New("disposable Docker command failed")
	}
	return append([]byte(nil), output.Bytes()...), nil
}
