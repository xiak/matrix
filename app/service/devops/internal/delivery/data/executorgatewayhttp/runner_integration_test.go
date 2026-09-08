package executorgatewayhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorspoolfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnerjournalfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

func TestRunnerClientAndJournalCompleteDurableMTLSRoundTrip(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	request, archive := gatewayExecutionFixture(t, '9')
	createGatewayExecution(t, spool, request, archive)
	now := request.StartedAt.Add(2 * time.Second)
	server := startRunnerServer(t, spool, pki, func() time.Time { return now })
	client, err := NewRunnerClient(
		server.URL, gatewayServerName, pki.runnerOneCertificate,
		pki.serverRoots, runnerNamespace,
	)
	if err != nil {
		t.Fatal(err)
	}
	journalRoot := t.TempDir()
	if err := os.Chmod(journalRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := runnerjournalfile.New(journalRoot, client.RunnerID())
	if err != nil {
		t.Fatal(err)
	}

	claim, err := journal.BeginClaim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assignment, found, err := client.Claim(context.Background(), claim.Destination)
	if err != nil || !found {
		_ = claim.Abort()
		t.Fatalf("claim found=%t assignment=%#v err=%v", found, assignment, err)
	}
	received, err := claim.Commit(context.Background())
	if err != nil || received.Phase != runnerjournalfile.PhaseReceived ||
		received.Assignment != assignment {
		t.Fatalf("durable claim = %#v / %v", received, err)
	}
	started, err := journal.MarkEffectStarted(
		context.Background(), received.Assignment, now.Add(time.Second),
	)
	if err != nil || started.Phase != runnerjournalfile.PhaseEffectStarted {
		t.Fatalf("durable effect marker = %#v / %v", started, err)
	}

	now = now.Add(2 * time.Second)
	renewal, err := client.Renew(context.Background(), started.Assignment)
	if err != nil {
		t.Fatalf("renew over mTLS: %v", err)
	}
	renewed, err := journal.ApplyRenewal(
		context.Background(), started.Assignment, renewal,
	)
	if err != nil || !renewed.Assignment.LeaseExpiresAt.Equal(renewal.LeaseExpiresAt) {
		t.Fatalf("durable renewal = %#v / %v", renewed, err)
	}
	progress := renewed
	for _, step := range request.Steps {
		progress, err = journal.MarkStepStarted(
			context.Background(), progress.Assignment, step,
			now.Add(time.Duration(step.Ordinal)*time.Second),
		)
		if err != nil {
			t.Fatalf("durable step start = %#v / %v", progress, err)
		}
		progress, err = journal.RecordStepConclusion(
			context.Background(), progress.Assignment, step,
			devopsbuildv1.StepConclusionPassed, runnerlog.Progress{},
		)
		if err != nil {
			t.Fatalf("durable step conclusion = %#v / %v", progress, err)
		}
	}
	receipt := gatewayReceipt(
		request, client.RunnerID(), devopsbuildv1.ConclusionPassed,
		devopsbuildv1.StepConclusionPassed, devopsbuildv1.StepConclusionPassed,
	)
	terminal, err := journal.RecordReceipt(
		context.Background(), progress.Assignment, receipt,
	)
	if err != nil || terminal.Phase != runnerjournalfile.PhaseTerminal {
		t.Fatalf("durable terminal receipt = %#v / %v", terminal, err)
	}
	if err := client.Complete(context.Background(), progress.Assignment, receipt); err != nil {
		t.Fatalf("complete over mTLS: %v", err)
	}
	acknowledged, err := journal.Acknowledge(
		context.Background(), progress.Assignment, receipt,
	)
	if err != nil || acknowledged.Phase != runnerjournalfile.PhaseAcknowledged {
		t.Fatalf("durable acknowledgement = %#v / %v", acknowledged, err)
	}

	restarted, err := runnerjournalfile.New(journalRoot, client.RunnerID())
	if err != nil {
		t.Fatalf("restart completed journal: %v", err)
	}
	loaded, err := restarted.Load(context.Background(), assignment.ExecutionID)
	if err != nil || loaded.Phase != runnerjournalfile.PhaseAcknowledged ||
		loaded.Receipt == nil || *loaded.Receipt != receipt {
		t.Fatalf("restarted completed entry = %#v / %v", loaded, err)
	}
	status, err := spool.Observe(context.Background(), request)
	if err != nil || status.State != devopsbuildv1.ExecutionTerminal ||
		status.Receipt == nil || *status.Receipt != receipt {
		t.Fatalf("gateway terminal state = %#v / %v", status, err)
	}
}

func TestRunnerClientRecoversLocallyTerminalReceiptAfterLeaseExpiry(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	request, archive := gatewayExecutionFixture(t, '8')
	createGatewayExecution(t, spool, request, archive)
	now := request.StartedAt.Add(2 * time.Second)
	server := startRunnerServer(t, spool, pki, func() time.Time { return now })
	client, err := NewRunnerClient(
		server.URL, gatewayServerName, pki.runnerOneCertificate,
		pki.serverRoots, runnerNamespace,
	)
	if err != nil {
		t.Fatal(err)
	}
	journalRoot := t.TempDir()
	if err := os.Chmod(journalRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := runnerjournalfile.New(journalRoot, client.RunnerID())
	if err != nil {
		t.Fatal(err)
	}

	claim, err := journal.BeginClaim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assignment, found, err := client.Claim(context.Background(), claim.Destination)
	if err != nil || !found {
		_ = claim.Abort()
		t.Fatalf("initial claim found=%t assignment=%#v err=%v", found, assignment, err)
	}
	received, err := claim.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started, err := journal.MarkEffectStarted(
		context.Background(), received.Assignment, now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	started, err = journal.MarkStepStarted(
		context.Background(), started.Assignment, request.Steps[0], now.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := journal.RecordStepConclusion(
		context.Background(), started.Assignment, request.Steps[0],
		devopsbuildv1.StepConclusionFailed, runnerlog.Progress{},
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt := gatewayReceipt(
		request, client.RunnerID(), devopsbuildv1.ConclusionFailed,
		devopsbuildv1.StepConclusionFailed, devopsbuildv1.StepConclusionNotRun,
	)
	terminal, err := journal.RecordReceipt(
		context.Background(), failed.Assignment, receipt,
	)
	if err != nil || terminal.Phase != runnerjournalfile.PhaseTerminal {
		t.Fatalf("local terminal = %#v / %v", terminal, err)
	}

	now = assignment.LeaseExpiresAt.Add(time.Microsecond)
	if err := client.Complete(
		context.Background(), terminal.Assignment, receipt,
	); !errors.Is(err, ErrRunnerStale) {
		t.Fatalf("expired completion error = %v", err)
	}
	recoveryClaim, err := journal.BeginClaim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recovery, found, err := client.Claim(
		context.Background(), recoveryClaim.Destination,
	)
	if err != nil || !found || recovery.Mode != devopsbuildv1.AssignmentObserve ||
		recovery.FencingToken != assignment.FencingToken+1 {
		_ = recoveryClaim.Abort()
		t.Fatalf("recovery claim found=%t assignment=%#v err=%v", found, recovery, err)
	}
	recovered, err := recoveryClaim.Commit(context.Background())
	if err != nil || recovered.Phase != runnerjournalfile.PhaseTerminal ||
		recovered.Receipt == nil || *recovered.Receipt != receipt {
		t.Fatalf("recovered local terminal = %#v / %v", recovered, err)
	}
	if err := client.Complete(
		context.Background(), recovered.Assignment, receipt,
	); err != nil {
		t.Fatalf("recovered completion: %v", err)
	}
	acknowledged, err := journal.Acknowledge(
		context.Background(), recovered.Assignment, receipt,
	)
	if err != nil || acknowledged.Phase != runnerjournalfile.PhaseAcknowledged {
		t.Fatalf("recovered acknowledgement = %#v / %v", acknowledged, err)
	}
}

func TestRunnerClientClaimsRenewsAndCompletesCurrentFence(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	request, archive := gatewayExecutionFixture(t, 'a')
	createGatewayExecution(t, spool, request, archive)
	now := request.StartedAt.Add(2 * time.Second)
	server := startRunnerServer(t, spool, pki, func() time.Time { return now })
	client, err := NewRunnerClient(
		server.URL, gatewayServerName, pki.runnerOneCertificate,
		pki.serverRoots, runnerNamespace,
	)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewRunnerClient(
		server.URL, gatewayServerName, pki.runnerTwoCertificate,
		pki.serverRoots, runnerNamespace,
	)
	if err != nil {
		t.Fatal(err)
	}
	if client.RunnerID() != testRunnerID(t, runnerOneIdentity) ||
		other.RunnerID() == client.RunnerID() {
		t.Fatalf("runner identities=%q/%q", client.RunnerID(), other.RunnerID())
	}

	var received bytes.Buffer
	assignment, found, err := client.Claim(
		context.Background(),
		func(devopsbuildv1.Assignment) (io.Writer, error) { return &received, nil },
	)
	if err != nil || !found || assignment.Mode != devopsbuildv1.AssignmentExecute ||
		!bytes.Equal(received.Bytes(), archive) {
		t.Fatalf(
			"client claim=%#v found=%t bytes=%d err=%v",
			assignment, found, received.Len(), err,
		)
	}
	if _, err := other.Renew(context.Background(), assignment); !errors.Is(err, ErrRunnerStale) {
		t.Fatalf("other runner renewal error=%v", err)
	}
	now = now.Add(time.Second)
	renewal, err := client.Renew(context.Background(), assignment)
	if err != nil || renewal.CancellationRequested ||
		!renewal.LeaseExpiresAt.Equal(now.Add(executorspoolfile.RunnerLeaseDuration)) {
		t.Fatalf("client renewal=%#v err=%v", renewal, err)
	}
	if _, err := spool.Cancel(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	renewal, err = client.Renew(context.Background(), assignment)
	if err != nil || !renewal.CancellationRequested {
		t.Fatalf("client cancellation renewal=%#v err=%v", renewal, err)
	}

	receipt := gatewayReceipt(
		request, client.RunnerID(), devopsbuildv1.ConclusionCancelled,
		devopsbuildv1.StepConclusionCancelled, devopsbuildv1.StepConclusionNotRun,
	)
	if err := other.Complete(context.Background(), assignment, receipt); !errors.Is(err, ErrRunnerInvalid) {
		t.Fatalf("other runner receipt identity error=%v", err)
	}
	if err := client.Complete(context.Background(), assignment, receipt); err != nil {
		t.Fatalf("client complete error=%v", err)
	}
	if err := client.Complete(context.Background(), assignment, receipt); err != nil {
		t.Fatalf("client completion replay error=%v", err)
	}
	changed := gatewayReceipt(
		request, client.RunnerID(), devopsbuildv1.ConclusionFailed,
		devopsbuildv1.StepConclusionFailed, devopsbuildv1.StepConclusionNotRun,
	)
	if err := client.Complete(context.Background(), assignment, changed); !errors.Is(err, ErrRunnerStale) {
		t.Fatalf("changed completion error=%v", err)
	}
	bound := false
	if _, found, err := client.Claim(
		context.Background(),
		func(devopsbuildv1.Assignment) (io.Writer, error) {
			bound = true
			return nil, nil
		},
	); err != nil || found || bound {
		t.Fatalf(
			"terminal claim found=%t destination-bound=%t err=%v",
			found, bound, err,
		)
	}
}

func TestRunnerClientRejectsNonRunnerCertificateAndConfiguration(t *testing.T) {
	pki := newGatewayTestPKI(t)
	for name, certificate := range map[string]tls.Certificate{
		"admin identity":    pki.adminCertificate,
		"outside namespace": pki.runnerOutsideCertificate,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRunnerClient(
				"https://gateway.test", gatewayServerName, certificate,
				pki.serverRoots, runnerNamespace,
			); err == nil {
				t.Fatal("non-runner client certificate was accepted")
			}
		})
	}
	if _, err := NewRunnerClient(
		"http://gateway.test", gatewayServerName, pki.runnerOneCertificate,
		pki.serverRoots, runnerNamespace,
	); err == nil {
		t.Fatal("non-TLS runner origin was accepted")
	}
	if _, err := NewRunnerClient(
		"https://gateway.test", "UPPER.gateway.test", pki.runnerOneCertificate,
		pki.serverRoots, runnerNamespace,
	); err == nil {
		t.Fatal("noncanonical runner server identity was accepted")
	}
	if _, err := NewRunnerClient(
		"https://gateway.test", gatewayServerName, pki.runnerOneCertificate,
		pki.serverRoots, "https://not-spiffe",
	); err == nil {
		t.Fatal("non-SPIFFE runner namespace was accepted")
	}
}

func TestRunnerMTLSListenerBindsIdentityFenceAndArchive(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	request, archive := gatewayExecutionFixture(t, 'a')
	createGatewayExecution(t, spool, request, archive)
	now := request.StartedAt.Add(2 * time.Second)
	server := startRunnerServer(t, spool, pki, func() time.Time { return now })
	runnerOne := newRunnerHTTPClient(t, pki.runnerOneCertificate, pki.serverRoots)
	runnerTwo := newRunnerHTTPClient(t, pki.runnerTwoCertificate, pki.serverRoots)
	runnerOneID := testRunnerID(t, runnerOneIdentity)

	assignment, receivedArchive, found := claimRunner(
		t, runnerOne, server.URL, true,
	)
	if !found || assignment.Mode != devopsbuildv1.AssignmentExecute ||
		assignment.FencingToken != 1 || assignment.Request != request ||
		!bytes.Equal(receivedArchive, archive) {
		t.Fatalf(
			"execute assignment=%#v found=%t archive=%d",
			assignment, found, len(receivedArchive),
		)
	}
	if _, _, found := claimRunner(t, runnerTwo, server.URL, false); found {
		t.Fatal("second runner received an in-flight execution")
	}

	renewalRequest, err := devopsbuildv1.EncodeRenewalRequest(
		assignment.ExecutionID, assignment.FencingToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	response := postRunner(
		t, runnerTwo,
		server.URL+runnerExecutionsPath+"/"+url.PathEscape(assignment.ExecutionID)+"/renew",
		devopsbuildv1.DocumentMediaType, renewalRequest,
	)
	assertEmptyRunnerResponse(t, response, http.StatusConflict)

	now = now.Add(time.Second)
	response = postRunner(
		t, runnerOne,
		server.URL+runnerExecutionsPath+"/"+url.PathEscape(assignment.ExecutionID)+"/renew",
		devopsbuildv1.DocumentMediaType, renewalRequest,
	)
	renewal := decodeRunnerRenewal(t, response, request)
	if renewal.CancellationRequested ||
		!renewal.LeaseExpiresAt.Equal(now.Add(executorspoolfile.RunnerLeaseDuration)) {
		t.Fatalf("renewal=%#v", renewal)
	}
	if _, err := spool.Cancel(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	response = postRunner(
		t, runnerOne,
		server.URL+runnerExecutionsPath+"/"+url.PathEscape(assignment.ExecutionID)+"/renew",
		devopsbuildv1.DocumentMediaType, renewalRequest,
	)
	renewal = decodeRunnerRenewal(t, response, request)
	if !renewal.CancellationRequested {
		t.Fatalf("renewal omitted cancellation: %#v", renewal)
	}

	receipt := gatewayReceipt(
		request, runnerOneID, devopsbuildv1.ConclusionCancelled,
		devopsbuildv1.StepConclusionCancelled,
		devopsbuildv1.StepConclusionNotRun,
	)
	completion := devopsbuildv1.Completion{
		APIVersion: devopsbuildv1.APIVersion, Kind: devopsbuildv1.CompletionKind,
		ExecutionID: assignment.ExecutionID, FencingToken: assignment.FencingToken,
		Receipt: receipt,
	}
	completionContent, err := devopsbuildv1.EncodeCompletion(request, completion)
	if err != nil {
		t.Fatal(err)
	}
	response = postRunner(
		t, runnerTwo,
		server.URL+runnerExecutionsPath+"/"+url.PathEscape(assignment.ExecutionID)+"/complete",
		devopsbuildv1.DocumentMediaType, completionContent,
	)
	assertEmptyRunnerResponse(t, response, http.StatusConflict)
	response = postRunner(
		t, runnerOne,
		server.URL+runnerExecutionsPath+"/"+url.PathEscape(assignment.ExecutionID)+"/complete",
		devopsbuildv1.DocumentMediaType, completionContent,
	)
	assertEmptyRunnerResponse(t, response, http.StatusNoContent)
	response = postRunner(
		t, runnerOne,
		server.URL+runnerExecutionsPath+"/"+url.PathEscape(assignment.ExecutionID)+"/complete",
		devopsbuildv1.DocumentMediaType, completionContent,
	)
	assertEmptyRunnerResponse(t, response, http.StatusNoContent)

	changedReceipt := gatewayReceipt(
		request, runnerOneID, devopsbuildv1.ConclusionFailed,
		devopsbuildv1.StepConclusionFailed,
		devopsbuildv1.StepConclusionNotRun,
	)
	completion.Receipt = changedReceipt
	completionContent, err = devopsbuildv1.EncodeCompletion(request, completion)
	if err != nil {
		t.Fatal(err)
	}
	response = postRunner(
		t, runnerOne,
		server.URL+runnerExecutionsPath+"/"+url.PathEscape(assignment.ExecutionID)+"/complete",
		devopsbuildv1.DocumentMediaType, completionContent,
	)
	assertEmptyRunnerResponse(t, response, http.StatusConflict)
	if _, _, found := claimRunner(t, runnerOne, server.URL, false); found {
		t.Fatal("terminal execution was assigned again")
	}
}

func TestRunnerRecoveryAssignmentNeverCarriesArchive(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	request, archive := gatewayExecutionFixture(t, 'a')
	createGatewayExecution(t, spool, request, archive)
	now := request.StartedAt.Add(time.Second)
	server := startRunnerServer(t, spool, pki, func() time.Time { return now })
	runnerOne := newRunnerHTTPClient(t, pki.runnerOneCertificate, pki.serverRoots)
	runnerTwo := newRunnerHTTPClient(t, pki.runnerTwoCertificate, pki.serverRoots)
	first, receivedArchive, found := claimRunner(t, runnerOne, server.URL, true)
	if !found || first.Mode != devopsbuildv1.AssignmentExecute ||
		!bytes.Equal(receivedArchive, archive) {
		t.Fatalf("first assignment=%#v archive=%d", first, len(receivedArchive))
	}
	now = first.LeaseExpiresAt
	if _, _, found := claimRunner(t, runnerTwo, server.URL, false); found {
		t.Fatal("expired possible effect moved to another runner")
	}
	recovery, recoveryArchive, found := claimRunner(t, runnerOne, server.URL, false)
	if !found || recovery.Mode != devopsbuildv1.AssignmentObserve ||
		recovery.FencingToken != first.FencingToken+1 || len(recoveryArchive) != 0 {
		t.Fatalf("recovery=%#v found=%t archive=%d", recovery, found, len(recoveryArchive))
	}
}

func TestRunnerListenerRejectsOtherRolesTLSVersionsAndAuthority(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	server := startRunnerServer(t, spool, pki, time.Now)
	claim, err := devopsbuildv1.EncodeClaim()
	if err != nil {
		t.Fatal(err)
	}

	for name, certificate := range map[string]tls.Certificate{
		"admin root":        pki.adminCertificate,
		"outside namespace": pki.runnerOutsideCertificate,
	} {
		t.Run(name, func(t *testing.T) {
			client := newRunnerHTTPClient(t, certificate, pki.serverRoots)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			request, requestErr := http.NewRequestWithContext(
				ctx, http.MethodPost, server.URL+runnerClaimsPath, bytes.NewReader(claim),
			)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			request.Header.Set("Content-Type", devopsbuildv1.DocumentMediaType)
			request.Header.Set("Accept", devopsbuildv1.FramedMediaType)
			if _, requestErr = client.Do(request); requestErr == nil {
				t.Fatal("unauthorized runner TLS identity was accepted")
			}
		})
	}

	tls12Client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		ServerName:   gatewayServerName,
		RootCAs:      pki.serverRoots,
		Certificates: []tls.Certificate{pki.runnerOneCertificate},
	}}}
	if _, err := tls12Client.Get(server.URL); err == nil {
		t.Fatal("TLS 1.2 runner connection was accepted")
	}

	runnerOne := newRunnerHTTPClient(t, pki.runnerOneCertificate, pki.serverRoots)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, server.URL+runnerClaimsPath, bytes.NewReader(claim),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", devopsbuildv1.DocumentMediaType)
	request.Header.Set("Accept", devopsbuildv1.FramedMediaType)
	request.Header["Authorization"] = []string{"", "Bearer must-not-enter"}
	response, err := runnerOne.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertEmptyRunnerResponse(t, response, http.StatusBadRequest)

	request, err = http.NewRequestWithContext(
		ctx, http.MethodPost, server.URL+runnerClaimsPath+"?runner=forged",
		bytes.NewReader(claim),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", devopsbuildv1.DocumentMediaType)
	request.Header.Set("Accept", devopsbuildv1.FramedMediaType)
	response, err = runnerOne.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertEmptyRunnerResponse(t, response, http.StatusBadRequest)

	response = postRunner(
		t, runnerOne, server.URL+executionsPath,
		devopsbuildv1.DocumentMediaType, claim,
	)
	assertEmptyRunnerResponse(t, response, http.StatusNotFound)
}

func createGatewayExecution(
	t *testing.T,
	spool *executorspoolfile.Spool,
	request devopsbuildv1.Request,
	archive []byte,
) {
	t.Helper()
	var submission bytes.Buffer
	if err := devopsbuildv1.WriteSubmission(
		&submission, request, bytes.NewReader(archive),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Create(context.Background(), &submission); err != nil {
		t.Fatal(err)
	}
}

func claimRunner(
	t *testing.T,
	client *http.Client,
	origin string,
	wantArchive bool,
) (devopsbuildv1.Assignment, []byte, bool) {
	t.Helper()
	claim, err := devopsbuildv1.EncodeClaim()
	if err != nil {
		t.Fatal(err)
	}
	response := postRunner(
		t, client, origin+runnerClaimsPath, devopsbuildv1.FramedMediaType, claim,
	)
	if response.StatusCode == http.StatusNoContent {
		assertEmptyRunnerResponse(t, response, http.StatusNoContent)
		return devopsbuildv1.Assignment{}, nil, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Type") != devopsbuildv1.FramedMediaType ||
		response.ContentLength <= 8 || len(response.TransferEncoding) != 0 {
		t.Fatalf("claim response=%d headers=%v", response.StatusCode, response.Header)
	}
	var archive bytes.Buffer
	assignment, err := devopsbuildv1.ReadAssignment(
		response.Body,
		func(devopsbuildv1.Assignment) (io.Writer, error) {
			if wantArchive {
				return &archive, nil
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return assignment, archive.Bytes(), true
}

func decodeRunnerRenewal(
	t *testing.T,
	response *http.Response,
	request devopsbuildv1.Request,
) devopsbuildv1.Renewal {
	t.Helper()
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Type") != devopsbuildv1.DocumentMediaType ||
		int64(len(content)) != response.ContentLength {
		t.Fatalf("renew response=%d headers=%v err=%v", response.StatusCode, response.Header, err)
	}
	renewal, err := devopsbuildv1.DecodeRenewal(request, content)
	if err != nil {
		t.Fatal(err)
	}
	return renewal
}

func postRunner(
	t *testing.T,
	client *http.Client,
	target string,
	accept string,
	content []byte,
) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, target, bytes.NewReader(content),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", devopsbuildv1.DocumentMediaType)
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "matrix-devops-runner/v1")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertEmptyRunnerResponse(t *testing.T, response *http.Response, status int) {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != status || len(body) != 0 ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf(
			"runner response=%d headers=%v body=%q err=%v",
			response.StatusCode, response.Header, body, err,
		)
	}
}

func startRunnerServer(
	t *testing.T,
	spool *executorspoolfile.Spool,
	pki gatewayTestPKI,
	now func() time.Time,
) *httptest.Server {
	t.Helper()
	httpHandler, err := NewRunnerHandler(spool, runnerNamespace)
	if err != nil {
		t.Fatal(err)
	}
	handler := httpHandler.(*runnerHandler)
	handler.now = now
	tlsConfig, err := NewRunnerTLSConfig(
		pki.serverCertificate, pki.runnerRoots, runnerNamespace,
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newRunnerHTTPClient(
	t *testing.T,
	certificate tls.Certificate,
	serverRoots *x509.CertPool,
) *http.Client {
	t.Helper()
	transport := &http.Transport{
		Proxy:              nil,
		DialContext:        (&net.Dialer{Timeout: time.Second}).DialContext,
		ForceAttemptHTTP2:  false,
		DisableCompression: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			ServerName: gatewayServerName, RootCAs: serverRoots,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"http/1.1"},
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("runner redirects are disabled")
		},
	}
}

func testRunnerID(t *testing.T, identity string) string {
	t.Helper()
	value, err := RunnerID(identity)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
