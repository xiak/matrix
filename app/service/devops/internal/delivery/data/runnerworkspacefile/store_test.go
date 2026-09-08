package runnerworkspacefile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

func TestStorePublishesReprovesAndRecoversImmutableWorkspace(t *testing.T) {
	rootPath := workspaceRoot(t)
	runnerID := workspaceRunnerID('a')
	request, archive := workspaceFixture(t, []sourcearchive.File{
		workspaceFile("a.txt", "root\n", false),
		workspaceFile("a/main.go", "package a\n", runtime.GOOS != "windows"),
		workspaceFile("cmd/matrix/main.go", "package main\n", false),
	})
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(rootPath, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := store.Ensure(
		context.Background(), executionID, request, archiveReader(archive),
	)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.ExecutionID != executionID || workspace.TreeDigest == "" ||
		workspace.SourceRoot != filepath.Join(rootPath, executionKey(executionID), sourceDirectoryName) {
		t.Fatalf("workspace = %#v", workspace)
	}
	assertWorkspaceFile(t, workspace.SourceRoot, "a.txt", "root\n", 0o444)
	wantExecutableMode := os.FileMode(0o555)
	if runtime.GOOS == "windows" {
		wantExecutableMode = 0o444
	}
	assertWorkspaceFile(t, workspace.SourceRoot, "a/main.go", "package a\n", wantExecutableMode)
	assertWorkspaceFile(t, workspace.SourceRoot, "cmd/matrix/main.go", "package main\n", 0o444)
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(workspace.SourceRoot)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o555 {
			t.Fatalf("source root mode = %v", info.Mode().Perm())
		}
	}
	manifestContent, err := os.ReadFile(filepath.Join(
		rootPath, executionKey(executionID), manifestName,
	))
	if err != nil || bytes.Contains(manifestContent, []byte(rootPath)) ||
		bytes.Contains(manifestContent, []byte("main.go")) {
		t.Fatalf("unsafe manifest = %s, error = %v", manifestContent, err)
	}

	equal, err := store.Ensure(
		context.Background(), executionID, request, archiveReader(archive),
	)
	if err != nil || equal != workspace {
		t.Fatalf("equal workspace = %#v, error = %v", equal, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := New(rootPath, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	recovered, err := restarted.Ensure(
		context.Background(), executionID, request, archiveReader(archive),
	)
	if err != nil || recovered != workspace {
		t.Fatalf("recovered workspace = %#v, error = %v", recovered, err)
	}
}

func TestStoreOwnershipAndRunnerIdentityAreExclusive(t *testing.T) {
	rootPath := workspaceRoot(t)
	store, err := New(rootPath, workspaceRunnerID('b'))
	if err != nil {
		t.Fatal(err)
	}
	if competing, err := New(rootPath, workspaceRunnerID('b')); err == nil ||
		competing != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("competing store = %v, error = %v", competing, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if foreign, err := New(rootPath, workspaceRunnerID('c')); err == nil ||
		foreign != nil || !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign store = %v, error = %v", foreign, err)
	}
	recovered, err := New(rootPath, workspaceRunnerID('b'))
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectsWorkspaceAndManifestTampering(t *testing.T) {
	tests := map[string]func(*testing.T, string, Workspace){
		"writable mode": func(t *testing.T, _ string, workspace Workspace) {
			if runtime.GOOS == "windows" {
				t.Skip("Windows does not preserve Unix executable and write mode bits")
			}
			if err := os.Chmod(filepath.Join(workspace.SourceRoot, "go.mod"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"changed content": func(t *testing.T, _ string, workspace Workspace) {
			name := filepath.Join(workspace.SourceRoot, "go.mod")
			if err := os.Chmod(name, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, []byte("changed\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(name, 0o444); err != nil {
				t.Fatal(err)
			}
		},
		"extra directory": func(t *testing.T, _ string, workspace Workspace) {
			if err := os.Chmod(workspace.SourceRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(workspace.SourceRoot, "empty")
			if err := os.Mkdir(name, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(name, 0o555); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(workspace.SourceRoot, 0o555); err != nil {
				t.Fatal(err)
			}
		},
		"changed manifest": func(t *testing.T, root string, workspace Workspace) {
			name := filepath.Join(root, executionKey(workspace.ExecutionID), manifestName)
			content, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, append(content, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			rootPath, store, request, archive, workspace := publishedWorkspace(t, 'd')
			defer store.Close()
			mutate(t, rootPath, workspace)
			if got, err := store.Ensure(
				context.Background(), workspace.ExecutionID, request, archiveReader(archive),
			); err == nil || got != (Workspace{}) || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("workspace = %#v, error = %v", got, err)
			}
		})
	}
}

func TestStoreRejectsSymlinkAndCrossExecutionReplay(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		_, store, request, archive, workspace := publishedWorkspace(t, 'e')
		defer store.Close()
		if err := os.Chmod(workspace.SourceRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(workspace.SourceRoot, "link")
		if err := os.Symlink(filepath.Join(workspace.SourceRoot, "go.mod"), link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if err := os.Chmod(workspace.SourceRoot, 0o555); err != nil {
			t.Fatal(err)
		}
		if got, err := store.Ensure(
			context.Background(), workspace.ExecutionID, request, archiveReader(archive),
		); err == nil || got != (Workspace{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("workspace = %#v, error = %v", got, err)
		}
	})

	t.Run("changed request", func(t *testing.T) {
		_, store, request, archive, workspace := publishedWorkspace(t, 'f')
		defer store.Close()
		request.SourcePathCount++
		if err := devopsbuildv1.ValidateRequest(request); err != nil {
			t.Fatal(err)
		}
		if got, err := store.Ensure(
			context.Background(), workspace.ExecutionID, request, archiveReader(archive),
		); !errors.Is(err, ErrConflict) || got != (Workspace{}) {
			t.Fatalf("workspace = %#v, error = %v", got, err)
		}
	})
}

func TestStoreRejectsInvalidArchiveAndRemovesStaging(t *testing.T) {
	tests := map[string]func(*testing.T) (devopsbuildv1.Request, []byte){
		"changed bytes": func(t *testing.T) (devopsbuildv1.Request, []byte) {
			request, archive := workspaceFixture(t, []sourcearchive.File{
				workspaceFile("go.mod", "module example.invalid/project\n", false),
			})
			return request, append(archive, 0)
		},
		"file directory collision": func(t *testing.T) (devopsbuildv1.Request, []byte) {
			return workspaceFixture(t, []sourcearchive.File{
				workspaceFile("a", "file\n", false),
				workspaceFile("a/b", "collision\n", false),
			})
		},
	}
	for name, fixture := range tests {
		t.Run(name, func(t *testing.T) {
			rootPath := workspaceRoot(t)
			store, err := New(rootPath, workspaceRunnerID('1'))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			request, archive := fixture(t)
			executionID, err := devopsbuildv1.ExecutionID(request)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := store.Ensure(
				context.Background(), executionID, request, archiveReader(archive),
			); err == nil || got != (Workspace{}) || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("workspace = %#v, error = %v", got, err)
			}
			entries, err := os.ReadDir(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if validStagingName(entry.Name()) || validWorkspaceKey(entry.Name()) {
					t.Fatalf("partial workspace survived: %s", entry.Name())
				}
			}
		})
	}
}

func TestStoreRecoversAbandonedPrivateStagingOnly(t *testing.T) {
	rootPath := workspaceRoot(t)
	key := strings.Repeat("a", 64)
	staging := ".workspace-" + key + "-" + strings.Repeat("b", 16)
	if err := os.Mkdir(filepath.Join(rootPath, staging), 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := New(rootPath, workspaceRunnerID('2'))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := os.Lstat(filepath.Join(rootPath, staging)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging still exists: %v", err)
	}
}

func TestStorePreservesPublishedTruthWhenArchiveCloseIsAmbiguous(t *testing.T) {
	rootPath := workspaceRoot(t)
	store, err := New(rootPath, workspaceRunnerID('3'))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request, archive := workspaceFixture(t, []sourcearchive.File{
		workspaceFile("go.mod", "module example.invalid/project\n", false),
	})
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	reader := &closeErrorReader{
		Reader: bytes.NewReader(archive), closeErr: errors.New("close failed"),
	}
	if workspace, err := store.Ensure(
		context.Background(), executionID, request, reader,
	); workspace != (Workspace{}) || !errors.Is(err, ErrOutcomeUnknown) ||
		strings.Contains(err.Error(), "module example") {
		t.Fatalf("workspace = %#v, error = %v", workspace, err)
	}
	recovered, err := store.Ensure(
		context.Background(), executionID, request, archiveReader(archive),
	)
	if err != nil || recovered.SourceRoot == "" {
		t.Fatalf("recovered workspace = %#v, error = %v", recovered, err)
	}
}

func TestStoreRejectsUnsafeRootAndCancelledInput(t *testing.T) {
	if store, err := New("relative/workspace", workspaceRunnerID('4')); err == nil || store != nil {
		t.Fatalf("relative store = %v, error = %v", store, err)
	}
	if runtime.GOOS != "windows" {
		publicRoot := t.TempDir()
		if err := os.Chmod(publicRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if store, err := New(publicRoot, workspaceRunnerID('4')); err == nil || store != nil {
			t.Fatalf("public store = %v, error = %v", store, err)
		}
	}
	target := workspaceRoot(t)
	link := filepath.Join(t.TempDir(), "workspace-link")
	if err := os.Symlink(target, link); err == nil {
		if store, err := New(link, workspaceRunnerID('4')); err == nil || store != nil {
			t.Fatalf("symlink store = %v, error = %v", store, err)
		}
	}

	rootPath := workspaceRoot(t)
	store, err := New(rootPath, workspaceRunnerID('4'))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request, archive := workspaceFixture(t, []sourcearchive.File{
		workspaceFile("go.mod", "module example.invalid/project\n", false),
	})
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if workspace, err := store.Ensure(
		ctx, executionID, request, archiveReader(archive),
	); workspace != (Workspace{}) || !errors.Is(err, context.Canceled) {
		t.Fatalf("workspace = %#v, error = %v", workspace, err)
	}
}

func publishedWorkspace(
	t *testing.T,
	identity byte,
) (string, *Store, devopsbuildv1.Request, []byte, Workspace) {
	t.Helper()
	rootPath := workspaceRoot(t)
	store, err := New(rootPath, workspaceRunnerID(identity))
	if err != nil {
		t.Fatal(err)
	}
	request, archive := workspaceFixture(t, []sourcearchive.File{
		workspaceFile("go.mod", "module example.invalid/project\n\ngo 1.26.0\n", false),
	})
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := store.Ensure(
		context.Background(), executionID, request, archiveReader(archive),
	)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	return rootPath, store, request, archive, workspace
}

func workspaceFixture(
	t *testing.T,
	files []sourcearchive.File,
) (devopsbuildv1.Request, []byte) {
	t.Helper()
	var archive bytes.Buffer
	content, err := sourcearchive.Write(context.Background(), &archive, files)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Date(2026, 9, 8, 12, 34, 56, 123000, time.UTC)
	runID := devopsv1.ResourceID("pipeline-run-" + strings.Repeat("a", 48))
	request := devopsbuildv1.Request{
		TenantID: "tenant-one", RunID: runID,
		CommandID:              string(runID) + ":verify:1",
		InputDigest:            "sha256:" + strings.Repeat("1", 64),
		SourceArchiveDigest:    workspaceDigest(archive.Bytes()),
		SourceArchiveBytes:     int64(archive.Len()),
		SourceExpandedBytes:    content.ExpandedBytes,
		SourcePathCount:        content.PathCount,
		PipelineRevisionID:     "pipeline-revision-" + devopsv1.ResourceID(strings.Repeat("b", 48)),
		PipelineRevisionDigest: "sha256:" + strings.Repeat("2", 64),
		VerificationProfile:    devopsv1.VerificationGo126OfflineV1,
		ExecutorProfile:        devopsv1.ExecutorMatrixNativeIsolatedV1,
		ToolchainImageDigest:   devopsv1.Go126OfflineToolchainImageDigest,
		DependencyEgress:       devopsv1.DependencyEgressNone,
		Steps: [2]devopsv1.VerificationStep{
			{Ordinal: 1, Kind: devopsv1.VerificationStepGoTest},
			{Ordinal: 2, Kind: devopsv1.VerificationStepGoVet},
		},
		Limits: devopsv1.FixedVerificationLimits(), StartedAt: startedAt,
		DeadlineAt: startedAt.Add(time.Duration(devopsv1.FixedRunTimeoutSeconds) * time.Second),
	}
	if err := devopsbuildv1.ValidateRequest(request); err != nil {
		t.Fatal(err)
	}
	return request, append([]byte(nil), archive.Bytes()...)
}

func workspaceFile(name, content string, executable bool) sourcearchive.File {
	return sourcearchive.File{
		Path: name, Executable: executable, Size: int64(len(content)),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(content)), nil
		},
	}
}

func workspaceRoot(t *testing.T) string {
	t.Helper()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	return rootPath
}

func workspaceRunnerID(identity byte) string {
	return "runner-" + strings.Repeat(string(identity), sha256.Size*2)
}

func archiveReader(content []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(content))
}

type closeErrorReader struct {
	io.Reader
	closeErr error
}

func (reader *closeErrorReader) Close() error {
	return reader.closeErr
}

func workspaceDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func assertWorkspaceFile(
	t *testing.T,
	rootPath string,
	name string,
	wantContent string,
	wantMode os.FileMode,
) {
	t.Helper()
	path := filepath.Join(rootPath, filepath.FromSlash(name))
	content, err := os.ReadFile(path)
	if err != nil || string(content) != wantContent {
		t.Fatalf("%s content = %q, error = %v", name, content, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != wantMode {
			t.Fatalf("%s mode = %v", name, info.Mode().Perm())
		}
	}
}
