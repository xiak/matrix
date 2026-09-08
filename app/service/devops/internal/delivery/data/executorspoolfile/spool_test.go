package executorspoolfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

func TestSpoolPublishesOnceObservesAcrossRestartAndConflictsOnChangedReplay(t *testing.T) {
	root := spoolRoot(t)
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := executionFixture(t, 'a', fixtureStart())
	created, err := spool.Create(context.Background(), submissionFrame(t, request, archive))
	if err != nil || created.State != devopsbuildv1.ExecutionQueued {
		t.Fatalf("create execution = %#v / %v", created, err)
	}

	restarted, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := restarted.Observe(context.Background(), request)
	if err != nil || !reflect.DeepEqual(observed, created) {
		t.Fatalf("observe restarted execution = %#v / %v", observed, err)
	}
	replayed, err := restarted.Create(
		context.Background(), submissionFrame(t, request, archive),
	)
	if err != nil || !reflect.DeepEqual(replayed, created) {
		t.Fatalf("replay execution = %#v / %v", replayed, err)
	}

	changed := request
	changed.SourceExpandedBytes++
	if _, err := restarted.Create(
		context.Background(), submissionFrame(t, changed, archive),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay error=%v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("published spool entries=%#v err=%v", entries, err)
	}
}

func TestConcurrentEqualCreatePublishesOneExecution(t *testing.T) {
	root := spoolRoot(t)
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := executionFixture(t, 'a', fixtureStart())
	var framed bytes.Buffer
	if err := devopsbuildv1.WriteSubmission(
		&framed, request, bytes.NewReader(archive),
	); err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(nil), framed.Bytes()...)
	const callers = 8
	start := make(chan struct{})
	errorsByCaller := make(chan error, callers)
	var group sync.WaitGroup
	for caller := 0; caller < callers; caller++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			observation, createErr := spool.Create(
				context.Background(), bytes.NewReader(frame),
			)
			if createErr == nil && observation.State != devopsbuildv1.ExecutionQueued {
				createErr = errors.New("equal create returned a non-queued execution")
			}
			errorsByCaller <- createErr
		}()
	}
	close(start)
	group.Wait()
	close(errorsByCaller)
	for createErr := range errorsByCaller {
		if createErr != nil {
			t.Fatalf("concurrent equal create: %v", createErr)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("concurrent spool entries=%#v err=%v", entries, err)
	}
}

func TestQueuedCancellationIsDurableIdempotentAndNeverAssigned(t *testing.T) {
	root := spoolRoot(t)
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := executionFixture(t, 'a', fixtureStart())
	if _, err := spool.Create(
		context.Background(), submissionFrame(t, request, archive),
	); err != nil {
		t.Fatal(err)
	}
	cancelled, err := spool.Cancel(context.Background(), request)
	if err != nil || cancelled.State != devopsbuildv1.ExecutionCancelled ||
		cancelled.Receipt != nil {
		t.Fatalf("cancel queued execution = %#v / %v", cancelled, err)
	}
	replayed, err := spool.Cancel(context.Background(), request)
	if err != nil || !reflect.DeepEqual(replayed, cancelled) {
		t.Fatalf("replay cancellation = %#v / %v", replayed, err)
	}

	restarted, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := restarted.Observe(context.Background(), request)
	if err != nil || !reflect.DeepEqual(observed, cancelled) {
		t.Fatalf("observe cancellation = %#v / %v", observed, err)
	}
	assignment, archiveReader, found, err := restarted.Claim(
		context.Background(), "runner-one", request.StartedAt.Add(time.Second),
	)
	if err != nil || found || archiveReader != nil || assignment != (devopsbuildv1.Assignment{}) {
		t.Fatalf("claim cancelled = %#v / %v / %t / %v", assignment, archiveReader, found, err)
	}
}

func TestRunnerAssignmentRenewalCancellationAndTerminalReplayAreFenced(t *testing.T) {
	root := spoolRoot(t)
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := executionFixture(t, 'a', fixtureStart())
	if _, err := spool.Create(
		context.Background(), submissionFrame(t, request, archive),
	); err != nil {
		t.Fatal(err)
	}
	claimedAt := request.StartedAt.Add(time.Second)
	assignment, archiveReader, found, err := spool.Claim(
		context.Background(), "runner-one", claimedAt,
	)
	if err != nil || !found || assignment.Mode != devopsbuildv1.AssignmentExecute ||
		assignment.FencingToken != 1 || archiveReader == nil {
		t.Fatalf("claim execution = %#v / %v / %t / %v", assignment, archiveReader, found, err)
	}
	receivedArchive, readErr := io.ReadAll(archiveReader)
	closeErr := archiveReader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(receivedArchive, archive) {
		t.Fatalf("claimed archive = %d bytes / %v / %v", len(receivedArchive), readErr, closeErr)
	}
	if _, _, found, err := spool.Claim(
		context.Background(), "runner-two", claimedAt.Add(time.Second),
	); err != nil || found {
		t.Fatalf("second runner active claim found=%t err=%v", found, err)
	}

	renewedAt := claimedAt.Add(10 * time.Second)
	renewal, err := spool.Renew(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, renewedAt,
	)
	if err != nil || !renewal.LeaseExpiresAt.Equal(renewedAt.Add(RunnerLeaseDuration)) ||
		renewal.CancellationRequested {
		t.Fatalf("renew assignment = %#v / %v", renewal, err)
	}
	cancelling, err := spool.Cancel(context.Background(), request)
	if err != nil || cancelling.State != devopsbuildv1.ExecutionCancellationRequested {
		t.Fatalf("request cancellation = %#v / %v", cancelling, err)
	}
	renewal, err = spool.Renew(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, renewedAt.Add(10*time.Second),
	)
	if err != nil || !renewal.CancellationRequested {
		t.Fatalf("renew cancellation = %#v / %v", renewal, err)
	}

	receipt := receiptFixture(
		request,
		devopsbuildv1.ConclusionCancelled,
		devopsbuildv1.StepConclusionCancelled,
		devopsbuildv1.StepConclusionNotRun,
	)
	completedAt := renewedAt.Add(11 * time.Second)
	terminal, err := spool.Complete(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, receipt, completedAt,
	)
	if err != nil || terminal.State != devopsbuildv1.ExecutionTerminal ||
		terminal.Receipt == nil || *terminal.Receipt != receipt {
		t.Fatalf("complete assignment = %#v / %v", terminal, err)
	}
	replayed, err := spool.Complete(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, receipt, completedAt.Add(time.Second),
	)
	if err != nil || replayed.Receipt == nil || *replayed.Receipt != receipt {
		t.Fatalf("replay completion = %#v / %v", replayed, err)
	}
	changed := receipt
	changed.ExecutorID = "executor-other"
	changed.ContentDigest = devopsbuildv1.DigestReceipt(changed)
	if _, err := spool.Complete(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, changed, completedAt.Add(time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed completion error=%v", err)
	}
	if _, err := spool.Renew(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, completedAt.Add(time.Second),
	); !errors.Is(err, ErrStaleAssignment) {
		t.Fatalf("terminal renewal error=%v", err)
	}

	restarted, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := restarted.Observe(context.Background(), request)
	if err != nil || observed.Receipt == nil || *observed.Receipt != receipt {
		t.Fatalf("observe restarted terminal = %#v / %v", observed, err)
	}
}

func TestExpiredAssignmentCanOnlyReturnToSameRunnerInRecoveryModes(t *testing.T) {
	root := spoolRoot(t)
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := executionFixture(t, 'a', fixtureStart())
	if _, err := spool.Create(
		context.Background(), submissionFrame(t, request, archive),
	); err != nil {
		t.Fatal(err)
	}
	claimedAt := request.StartedAt.Add(time.Second)
	first, firstArchive, found, err := spool.Claim(
		context.Background(), "runner-one", claimedAt,
	)
	if err != nil || !found || firstArchive == nil {
		t.Fatalf("first claim = %#v / %t / %v", first, found, err)
	}
	_ = firstArchive.Close()
	recoveryAt := first.LeaseExpiresAt.Add(time.Microsecond)
	if _, _, found, err := spool.Claim(
		context.Background(), "runner-two", recoveryAt,
	); err != nil || found {
		t.Fatalf("different runner recovery found=%t err=%v", found, err)
	}
	second, secondArchive, found, err := spool.Claim(
		context.Background(), "runner-one", recoveryAt,
	)
	if err != nil || !found || secondArchive != nil ||
		second.Mode != devopsbuildv1.AssignmentObserve || second.FencingToken != 2 {
		t.Fatalf("observe recovery = %#v / %v / %t / %v", second, secondArchive, found, err)
	}
	if _, err := spool.Renew(
		context.Background(), "runner-one", first.ExecutionID,
		first.FencingToken, recoveryAt.Add(time.Second),
	); !errors.Is(err, ErrStaleAssignment) {
		t.Fatalf("stale first fence renewal error=%v", err)
	}
	if _, err := spool.Cancel(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	thirdAt := second.LeaseExpiresAt.Add(time.Microsecond)
	third, thirdArchive, found, err := spool.Claim(
		context.Background(), "runner-one", thirdAt,
	)
	if err != nil || !found || thirdArchive != nil ||
		third.Mode != devopsbuildv1.AssignmentCancel || third.FencingToken != 3 {
		t.Fatalf("cancel recovery = %#v / %v / %t / %v", third, thirdArchive, found, err)
	}
}

func TestRunnerLeaseNeverCrossesFixedBuildDeadline(t *testing.T) {
	root := spoolRoot(t)
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := executionFixture(t, 'a', fixtureStart())
	if _, err := spool.Create(
		context.Background(), submissionFrame(t, request, archive),
	); err != nil {
		t.Fatal(err)
	}
	claimedAt := request.DeadlineAt.Add(-10 * time.Second)
	assignment, archiveReader, found, err := spool.Claim(
		context.Background(), "runner-one", claimedAt,
	)
	if archiveReader != nil {
		defer archiveReader.Close()
	}
	if err != nil || !found || !assignment.LeaseExpiresAt.Equal(request.DeadlineAt) {
		t.Fatalf("deadline claim = %#v / %t / %v", assignment, found, err)
	}
	renewal, err := spool.Renew(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, request.DeadlineAt.Add(-5*time.Second),
	)
	if err != nil || !renewal.LeaseExpiresAt.Equal(request.DeadlineAt) {
		t.Fatalf("deadline renewal = %#v / %v", renewal, err)
	}
}

func TestClaimChoosesOldestEligibleExecution(t *testing.T) {
	root := spoolRoot(t)
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	start := fixtureStart()
	newer, newerArchive := executionFixture(t, 'b', start.Add(time.Second))
	older, olderArchive := executionFixture(t, 'a', start)
	for _, fixture := range []struct {
		request devopsbuildv1.Request
		archive []byte
	}{
		{request: newer, archive: newerArchive},
		{request: older, archive: olderArchive},
	} {
		if _, err := spool.Create(
			context.Background(), submissionFrame(t, fixture.request, fixture.archive),
		); err != nil {
			t.Fatal(err)
		}
	}
	assignment, archiveReader, found, err := spool.Claim(
		context.Background(), "runner-one", start.Add(2*time.Second),
	)
	if archiveReader != nil {
		defer archiveReader.Close()
	}
	if err != nil || !found || assignment.Request != older {
		t.Fatalf("oldest claim = %#v / %t / %v", assignment, found, err)
	}
}

func TestSpoolRejectsNonArchiveAndDetectsPublishedTampering(t *testing.T) {
	request, _ := executionFixture(t, 'a', fixtureStart())
	invalidArchive := []byte("not a canonical source archive")
	request.SourceArchiveBytes = int64(len(invalidArchive))
	request.SourceArchiveDigest = digestBytes(invalidArchive)
	root := spoolRoot(t)
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Create(
		context.Background(), submissionFrame(t, request, invalidArchive),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid source archive error=%v", err)
	}

	for name, tamper := range map[string]func(string){
		"submission": func(directory string) {
			path := filepath.Join(directory, submissionName)
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			content = bytes.Replace(content, []byte(`"request":`), []byte(`"extra":true,"request":`), 1)
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"archive": func(directory string) {
			path := filepath.Join(directory, archiveName)
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			content[len(content)-1] ^= 0xff
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"state": func(directory string) {
			path := filepath.Join(directory, stateFileName(1))
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			content = bytes.Replace(content, []byte(`"phase":"QUEUED"`), []byte(`"phase":"TERMINAL"`), 1)
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := spoolRoot(t)
			spool, err := New(root)
			if err != nil {
				t.Fatal(err)
			}
			validRequest, archive := executionFixture(t, 'a', fixtureStart())
			if _, err := spool.Create(
				context.Background(), submissionFrame(t, validRequest, archive),
			); err != nil {
				t.Fatal(err)
			}
			executionID, _ := devopsbuildv1.ExecutionID(validRequest)
			tamper(filepath.Join(root, executionKey(executionID)))
			if _, err := spool.Observe(
				context.Background(), validRequest,
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("tampered %s observation error=%v", name, err)
			}
		})
	}
}

func TestSpoolStartupRemovesOnlyStrictTemporaryEntries(t *testing.T) {
	root := spoolRoot(t)
	staging := filepath.Join(root, ".staging-"+strings.Repeat("a", 16))
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(
		root,
		".state-"+strings.Repeat("b", 64)+"-00000000000000000002-"+
			strings.Repeat("c", 16)+".tmp",
	)
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{staging, temporary} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary path survived recovery %s: %v", path, err)
		}
	}
}

func spoolRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func fixtureStart() time.Time {
	return time.Date(2026, 9, 8, 10, 11, 12, 123000, time.UTC)
}

func executionFixture(
	t *testing.T,
	identity byte,
	startedAt time.Time,
) (devopsbuildv1.Request, []byte) {
	t.Helper()
	fileContent := []byte("module example.invalid/project\n\ngo 1.26.0\n")
	var archive bytes.Buffer
	content, err := sourcearchive.Write(
		context.Background(),
		&archive,
		[]sourcearchive.File{
			{
				Path: "go.mod", Size: int64(len(fileContent)),
				Open: func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(fileContent)), nil
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("create source archive: %v", err)
	}
	runID := devopsv1.ResourceID("pipeline-run-" + strings.Repeat(string(identity), 48))
	request := devopsbuildv1.Request{
		TenantID: "tenant-one", RunID: runID,
		CommandID:           string(runID) + ":verify:1",
		InputDigest:         "sha256:" + strings.Repeat("1", 64),
		SourceArchiveDigest: digestBytes(archive.Bytes()),
		SourceArchiveBytes:  int64(archive.Len()),
		SourceExpandedBytes: content.ExpandedBytes,
		SourcePathCount:     content.PathCount,
		PipelineRevisionID: "pipeline-revision-" +
			devopsv1.ResourceID(strings.Repeat(string(identity), 48)),
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
		DeadlineAt: startedAt.Add(
			time.Duration(devopsv1.FixedRunTimeoutSeconds) * time.Second,
		),
	}
	if err := devopsbuildv1.ValidateRequest(request); err != nil {
		t.Fatalf("validate execution fixture: %v", err)
	}
	return request, append([]byte(nil), archive.Bytes()...)
}

func submissionFrame(
	t *testing.T,
	request devopsbuildv1.Request,
	archive []byte,
) io.Reader {
	t.Helper()
	var frame bytes.Buffer
	if err := devopsbuildv1.WriteSubmission(
		&frame, request, bytes.NewReader(archive),
	); err != nil {
		t.Fatalf("frame submission: %v", err)
	}
	return bytes.NewReader(frame.Bytes())
}

func receiptFixture(
	request devopsbuildv1.Request,
	conclusion devopsbuildv1.Conclusion,
	first devopsbuildv1.StepConclusion,
	second devopsbuildv1.StepConclusion,
) devopsbuildv1.Receipt {
	receipt := devopsbuildv1.Receipt{
		TenantID:               request.TenantID,
		RunID:                  request.RunID,
		CommandID:              request.CommandID,
		InputDigest:            request.InputDigest,
		SourceArchiveDigest:    request.SourceArchiveDigest,
		PipelineRevisionID:     request.PipelineRevisionID,
		PipelineRevisionDigest: request.PipelineRevisionDigest,
		ExecutorID:             "executor-one",
		ExecutorProfile:        request.ExecutorProfile,
		ToolchainImageDigest:   request.ToolchainImageDigest,
		Conclusion:             conclusion,
		Steps: [2]devopsbuildv1.StepReceipt{
			{
				Ordinal: request.Steps[0].Ordinal,
				Kind:    request.Steps[0].Kind, Conclusion: first,
			},
			{
				Ordinal: request.Steps[1].Ordinal,
				Kind:    request.Steps[1].Kind, Conclusion: second,
			},
		},
	}
	receipt.ContentDigest = devopsbuildv1.DigestReceipt(receipt)
	return receipt
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
