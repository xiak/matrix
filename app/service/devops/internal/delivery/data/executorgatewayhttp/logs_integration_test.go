package executorgatewayhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

func TestRunnerAndAdminClientsRoundTripDurableLogsOverMTLS(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	request, archive := gatewayExecutionFixture(t, '7')
	createGatewayExecution(t, spool, request, archive)
	now := request.StartedAt.Add(2 * time.Second)
	runnerServer := startRunnerServer(t, spool, pki, func() time.Time { return now })
	adminServer := startAdminServer(t, spool, pki)
	runner, err := NewRunnerClient(
		runnerServer.URL, gatewayServerName, pki.runnerOneCertificate,
		pki.serverRoots, runnerNamespace,
	)
	if err != nil {
		t.Fatal(err)
	}
	otherRunner, err := NewRunnerClient(
		runnerServer.URL, gatewayServerName, pki.runnerTwoCertificate,
		pki.serverRoots, runnerNamespace,
	)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := NewAdminClient(
		adminServer.URL, gatewayServerName, pki.adminCertificate, pki.serverRoots,
	)
	if err != nil {
		t.Fatal(err)
	}

	var received bytes.Buffer
	assignment, found, err := runner.Claim(
		context.Background(),
		func(devopsbuildv1.Assignment) (io.Writer, error) { return &received, nil },
	)
	if err != nil || !found || assignment.Mode != devopsbuildv1.AssignmentExecute ||
		!bytes.Equal(received.Bytes(), archive) {
		t.Fatalf(
			"claim=%#v found=%t archive=%d err=%v",
			assignment, found, received.Len(), err,
		)
	}
	firstChunks := []runnerlog.Chunk{
		{Sequence: 1, Content: "[stdout] test ok\n"},
		{Sequence: 2, Content: "[stdout] coverage ok\n"},
	}
	firstNext := runnerlog.Progress{
		NativeBytes:     int64(len(firstChunks[0].Content) + len(firstChunks[1].Content)),
		NormalizedBytes: int64(len(firstChunks[0].Content) + len(firstChunks[1].Content)),
		LastSequence:    2,
	}
	if err := otherRunner.Publish(
		context.Background(), assignment, request.Steps[0],
		runnerlog.Progress{}, firstNext, firstChunks,
	); !errors.Is(err, ErrRunnerStale) {
		t.Fatalf("foreign runner append error=%v", err)
	}
	if err := runner.Publish(
		context.Background(), assignment, request.Steps[0],
		runnerlog.Progress{}, firstNext, firstChunks,
	); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if err := runner.Publish(
		context.Background(), assignment, request.Steps[0],
		runnerlog.Progress{}, firstNext, firstChunks,
	); err != nil {
		t.Fatalf("equal append replay: %v", err)
	}
	changed := append([]runnerlog.Chunk(nil), firstChunks...)
	changed[0].Content = "[stdout] best ok\n"
	if err := runner.Publish(
		context.Background(), assignment, request.Steps[0],
		runnerlog.Progress{}, firstNext, changed,
	); !errors.Is(err, ErrRunnerStale) {
		t.Fatalf("changed append replay error=%v", err)
	}

	secondChunks := []runnerlog.Chunk{{Sequence: 3, Content: "[stdout] vet ok\n"}}
	secondNext := runnerlog.Progress{
		NativeBytes:     firstNext.NativeBytes + int64(len(secondChunks[0].Content)),
		NormalizedBytes: firstNext.NormalizedBytes + int64(len(secondChunks[0].Content)),
		LastSequence:    3,
	}
	if err := runner.Publish(
		context.Background(), assignment, request.Steps[1],
		firstNext, secondNext, secondChunks,
	); err != nil {
		t.Fatalf("second append: %v", err)
	}

	first, found, err := admin.ReadLogs(context.Background(), request, 0)
	if err != nil || !found || first.ExecutionID != assignment.ExecutionID ||
		first.Step != request.Steps[0] || first.Previous != (devopsbuildv1.LogProgress{}) ||
		first.Next.LastSequence != firstNext.LastSequence ||
		len(first.Chunks) != len(firstChunks) ||
		first.Chunks[0].Content != firstChunks[0].Content ||
		first.Chunks[1].Content != firstChunks[1].Content {
		t.Fatalf("first read=%#v found=%t err=%v", first, found, err)
	}
	second, found, err := admin.ReadLogs(
		context.Background(), request, first.Next.LastSequence,
	)
	if err != nil || !found || second.Step != request.Steps[1] ||
		second.Previous != first.Next || second.Next.LastSequence != secondNext.LastSequence ||
		len(second.Chunks) != 1 || second.Chunks[0].Content != secondChunks[0].Content {
		t.Fatalf("second read=%#v found=%t err=%v", second, found, err)
	}
	if _, found, err := admin.ReadLogs(
		context.Background(), request, second.Next.LastSequence,
	); err != nil || found {
		t.Fatalf("tail read found=%t err=%v", found, err)
	}
	if _, found, err := admin.ReadLogs(
		context.Background(), request, 1,
	); found || !errors.Is(err, port.ErrBuildConflict) {
		t.Fatalf("mid-batch read found=%t err=%v", found, err)
	}

	now = assignment.LeaseExpiresAt
	var recoveryDestinationMode devopsbuildv1.AssignmentMode
	recovery, found, err := runner.Claim(
		context.Background(),
		func(value devopsbuildv1.Assignment) (io.Writer, error) {
			recoveryDestinationMode = value.Mode
			return nil, nil
		},
	)
	if err != nil || !found || recovery.Mode != devopsbuildv1.AssignmentObserve ||
		recoveryDestinationMode != devopsbuildv1.AssignmentObserve ||
		recovery.FencingToken != assignment.FencingToken+1 {
		t.Fatalf("recovery=%#v found=%t err=%v", recovery, found, err)
	}
	if err := runner.Publish(
		context.Background(), recovery, request.Steps[0],
		runnerlog.Progress{}, firstNext, firstChunks,
	); err != nil {
		t.Fatalf("recovery replay: %v", err)
	}
	receipt := gatewayReceipt(
		request, runner.RunnerID(), devopsbuildv1.ConclusionPassed,
		devopsbuildv1.StepConclusionPassed, devopsbuildv1.StepConclusionPassed,
	)
	if err := runner.Complete(context.Background(), recovery, receipt); err != nil {
		t.Fatalf("completion after durable logs: %v", err)
	}
	if _, found, err := admin.ReadLogs(context.Background(), request, 0); err != nil || !found {
		t.Fatalf("terminal log read found=%t err=%v", found, err)
	}
}
