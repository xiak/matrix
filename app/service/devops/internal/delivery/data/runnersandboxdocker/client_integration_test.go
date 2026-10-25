//go:build linux

package runnersandboxdocker

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestDockerEnginePreflightIntegration(t *testing.T) {
	if os.Getenv("MATRIX_RUNNER_DOCKER_INTEGRATION") != "1" {
		t.Skip("set MATRIX_RUNNER_DOCKER_INTEGRATION=1 on a dedicated Linux runner")
	}
	storageRoot := t.TempDir()
	if err := os.Chmod(storageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	client, err := New("/var/run/docker.sock", storageRoot)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := client.Preflight(ctx)
	wantReason := Reason(os.Getenv("MATRIX_RUNNER_DOCKER_EXPECT_INELIGIBLE_REASON"))
	if wantReason != "" {
		if !errors.Is(err, ErrIneligible) || report.Eligible || report.Reason != wantReason {
			t.Fatalf("report = %#v, error = %v", report, err)
		}
		var image imageInspection
		if readErr := client.getJSON(
			ctx, imagePath(ToolchainImage), maximumInspectBytes, &image,
		); readErr != nil || !validToolchainImage(image) {
			t.Fatalf("pinned image evidence = %#v, error = %v", image, readErr)
		}
		return
	}
	if err != nil || !report.Eligible || report.Reason != "" {
		t.Fatalf("report = %#v, error = %v", report, err)
	}
}
