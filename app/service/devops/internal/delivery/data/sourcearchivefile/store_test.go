package sourcearchivefile

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
)

func TestStorePublishesOnceAndTakeoverReprovesExactArchive(t *testing.T) {
	rootPath := privateRoot(t)
	store, err := New(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	command := archiveCommand(t, runlifecycle.ClaimExecute)
	writeCalls := 0
	write := func(destination io.Writer) (sourceacquisition.ArchiveContent, error) {
		writeCalls++
		return sourcearchive.Write(context.Background(), destination, []sourcearchive.File{
			archiveFile("cmd/matrix/main.go", "package main\n", true),
			archiveFile("README.md", "matrix\n", false),
		})
	}
	receipt, err := store.Publish(context.Background(), command, write)
	if err != nil || writeCalls != 1 {
		t.Fatalf("publish receipt=%#v calls=%d err=%v", receipt, writeCalls, err)
	}
	if err := sourceacquisition.ValidateReceipt(command, receipt); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	key := commandKey(command)
	if len(key) != sha256.Size*2 || strings.Contains(key, string(command.Lease.Run.ID)) {
		t.Fatalf("unsafe command directory %q", key)
	}
	directoryEntries, err := os.ReadDir(filepath.Join(rootPath, key))
	if err != nil || len(directoryEntries) != 2 {
		t.Fatalf("published entries=%v err=%v", directoryEntries, err)
	}
	expectedArchive, err := archiveName(receipt.ArchiveDigest)
	if err != nil || !entryNames(directoryEntries)[receiptName] ||
		!entryNames(directoryEntries)[expectedArchive] {
		t.Fatalf("published names=%v archive=%q err=%v", entryNames(directoryEntries), expectedArchive, err)
	}
	receiptDocument, err := os.ReadFile(filepath.Join(rootPath, key, receiptName))
	if err != nil || bytesContain(receiptDocument, []byte(rootPath)) {
		t.Fatalf("receipt contains host layout or cannot be read: %s err=%v", receiptDocument, err)
	}

	takeover := command
	takeover.Lease.Mode = runlifecycle.ClaimObserve
	takeover.Lease.FencingToken = 2
	observed, found, err := store.Observe(context.Background(), takeover)
	if err != nil || !found || observed != receipt {
		t.Fatalf("observed=%#v found=%t want=%#v err=%v", observed, found, receipt, err)
	}
	idempotent, err := store.Publish(
		context.Background(), command,
		func(io.Writer) (sourceacquisition.ArchiveContent, error) {
			t.Fatal("idempotent publish fetched source again")
			return sourceacquisition.ArchiveContent{}, nil
		},
	)
	if err != nil || idempotent != receipt {
		t.Fatalf("idempotent receipt=%#v want=%#v err=%v", idempotent, receipt, err)
	}
}

func TestStoreNeverPublishesPartialOrStructurallyInvalidContent(t *testing.T) {
	rootPath := privateRoot(t)
	store, err := New(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	command := archiveCommand(t, runlifecycle.ClaimExecute)
	_, err = store.Publish(
		context.Background(), command,
		func(destination io.Writer) (sourceacquisition.ArchiveContent, error) {
			_, writeErr := io.WriteString(destination, "not a gzip tar")
			return sourceacquisition.ArchiveContent{ExpandedBytes: 14, PathCount: 1}, writeErr
		},
	)
	if !errors.Is(err, sourceacquisition.ErrSourceUnavailable) {
		t.Fatalf("invalid archive error=%v", err)
	}
	entries, readErr := os.ReadDir(rootPath)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("partial publication survived: %v err=%v", entryNames(entries), readErr)
	}
}

func TestStoreRejectsChangedArchiveAndNonCanonicalReceipt(t *testing.T) {
	t.Run("changed archive", func(t *testing.T) {
		rootPath, store, command, receipt := publishedStore(t)
		archive, err := archiveName(receipt.ArchiveDigest)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(
			filepath.Join(rootPath, commandKey(command), archive), os.O_APPEND|os.O_WRONLY, 0,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, found, err := store.Observe(context.Background(), takeover(command)); err == nil || found || !errors.Is(err, sourceacquisition.ErrSourceUnavailable) {
			t.Fatalf("changed archive found=%t err=%v", found, err)
		}
	})

	t.Run("non canonical receipt", func(t *testing.T) {
		rootPath, store, command, _ := publishedStore(t)
		path := filepath.Join(rootPath, commandKey(command), receiptName)
		document, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(document, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, found, err := store.Observe(context.Background(), takeover(command)); err == nil || found || !errors.Is(err, sourceacquisition.ErrSourceUnavailable) {
			t.Fatalf("non-canonical receipt found=%t err=%v", found, err)
		}
	})
}

func TestStoreRejectsUnsafeRootAndBoundedWriterOverflow(t *testing.T) {
	if _, err := New("relative/source-archives"); err == nil {
		t.Fatal("relative archive root was accepted")
	}
	if runtime.GOOS != "windows" {
		publicRoot := t.TempDir()
		if err := os.Chmod(publicRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := New(publicRoot); err == nil {
			t.Fatal("public archive root was accepted")
		}
	}
	target := privateRoot(t)
	link := filepath.Join(t.TempDir(), "archive-link")
	if err := os.Symlink(target, link); err == nil {
		if _, err := New(link); err == nil {
			t.Fatal("symbolic-link archive root was accepted")
		}
	}

	writer := &boundedWriter{
		destination: io.Discard, digest: sha256.New(),
		written: sourcearchive.MaximumArchiveBytes,
	}
	if _, err := writer.Write([]byte{1}); !errors.Is(err, sourceacquisition.ErrSourceUnavailable) {
		t.Fatalf("overflow error=%v", err)
	}
}

func publishedStore(
	t *testing.T,
) (string, *Store, sourceacquisition.Command, sourceacquisition.SourceArchiveReceipt) {
	t.Helper()
	rootPath := privateRoot(t)
	store, err := New(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	command := archiveCommand(t, runlifecycle.ClaimExecute)
	receipt, err := store.Publish(
		context.Background(), command,
		func(destination io.Writer) (sourceacquisition.ArchiveContent, error) {
			return sourcearchive.Write(context.Background(), destination, []sourcearchive.File{
				archiveFile("README.md", "matrix\n", false),
			})
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return rootPath, store, command, receipt
}

func privateRoot(t *testing.T) string {
	t.Helper()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	return rootPath
}

func takeover(command sourceacquisition.Command) sourceacquisition.Command {
	command.Lease.Mode = runlifecycle.ClaimObserve
	command.Lease.FencingToken = 2
	return command
}

func archiveFile(name, content string, executable bool) sourcearchive.File {
	return sourcearchive.File{
		Path: name, Executable: executable, Size: int64(len(content)),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(content)), nil
		},
	}
}

func entryNames(entries []os.DirEntry) map[string]bool {
	result := make(map[string]bool, len(entries))
	for _, entry := range entries {
		result[entry.Name()] = true
	}
	return result
}

func bytesContain(value, contained []byte) bool {
	return strings.Contains(string(value), string(contained))
}

func archiveCommand(t *testing.T, mode runlifecycle.ClaimMode) sourceacquisition.Command {
	t.Helper()
	base := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "organization-acme"}
	project, err := domain.NewDevOpsProject(devopsv1.CreateDevOpsProjectRequest{
		ID: "devops-project-platform", Name: "platform",
	}, scope, base)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := domain.NewSourceConnection(devopsv1.CreateSourceConnectionRequest{
		ID: "source-connection-primary", Name: "primary",
		Spec: devopsv1.SourceConnectionSpec{
			AdapterID: "source-adapter-gitea", EndpointOrigin: "https://git.example.com",
			WebhookSecretRef: "webhook-secret", FetchCredentialRef: "fetch-secret",
			ReportCredentialRef: "report-secret",
		},
	}, scope, base)
	if err != nil {
		t.Fatal(err)
	}
	connection.Status.Health = devopsv1.SourceConnectionReady
	connection.Status.Reason = devopsv1.SourceConnectionReasonObserved
	binding, err := domain.NewRepositoryBinding(devopsv1.CreateRepositoryBindingRequest{
		ID: "repository-binding-api", Name: "api", ProjectID: project.Metadata.ID,
		Spec: devopsv1.RepositoryBindingSpec{
			SourceConnectionID: connection.Metadata.ID, ExternalRepositoryID: "repository-42",
			RepositoryPath: "platform/api", TrustedDefaultBranch: "main",
		},
	}, project, connection, base)
	if err != nil {
		t.Fatal(err)
	}
	binding.Status.Health = devopsv1.RepositoryBindingReady
	binding.Status.Reason = devopsv1.RepositoryBindingReasonObserved
	pipeline, err := domain.NewPipeline(devopsv1.CreatePipelineRequest{
		ID: "pipeline-source", Name: "pipeline-source", ProjectID: project.Metadata.ID,
		Draft: devopsv1.PipelineDraftSpec{
			RepositoryBindingID: binding.Metadata.ID, TriggerPolicy: devopsv1.TriggerChange,
			VerificationProfile: devopsv1.VerificationGo126OfflineV1,
			DependencyEgress:    devopsv1.DependencyEgressNone,
			ReporterPolicy:      devopsv1.ReporterChangeCheckV1,
		},
	}, project, binding, base)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := domain.ActivatePipeline(
		pipeline, pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"},
		binding, base.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	change := domain.NormalizedChange{
		Scope: scope, SourceConnectionID: connection.Metadata.ID,
		VerifiedSourceConnectionVersion: connection.Metadata.ResourceVersion,
		ExternalRepositoryID:            binding.Spec.ExternalRepositoryID,
		TrustedBaseBranch:               binding.Spec.TrustedDefaultBranch,
		DeliveryID:                      "123e4567-e89b-42d3-a456-426614174000",
		CanonicalPayloadDigest:          "sha256:" + strings.Repeat("a", 64),
		Change: devopsv1.ChangeIdentity{
			Number: 42, Action: devopsv1.ChangeOpened,
			HeadCommit: strings.Repeat("1", 40), TrustedBaseCommit: strings.Repeat("2", 40),
		},
	}
	event, err := domain.NewSourceEvent(change, connection, binding, base.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewPipelineRun(event, activation.Pipeline, activation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	run, err = domain.AdvancePipelineRun(
		run, devopsv1.PipelineRunFetching, "", run.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	fence := uint64(1)
	if mode == runlifecycle.ClaimObserve {
		fence = 2
	}
	intent := runlifecycle.TaskIntent{
		RunID: run.ID, InputDigest: run.InputDigest,
		Stage: devopsv1.PipelineRunStageFetch, Attempt: 1,
	}
	intent.CommandID = runlifecycle.TaskCommandID(intent.RunID, intent.Stage, intent.Attempt)
	return sourceacquisition.Command{
		Lease: runlifecycle.Lease{
			TenantID: scope.TenantID, Run: run, Intent: intent, Mode: mode,
			WorkerID: "source-fetcher-one", FencingToken: fence,
			LeaseExpiresAt: run.UpdatedAt.Add(sourceacquisition.LeaseDuration),
		},
		Connection: connection, BindingRevision: binding,
		Revision: activation.Revision, Event: event,
	}
}
