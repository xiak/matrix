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
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorspoolfile"
)

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
	var destination io.Writer
	if wantArchive {
		destination = &archive
	}
	assignment, err := devopsbuildv1.ReadAssignment(response.Body, destination)
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
	parsed, err := parseSPIFFEIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	value, err := runnerID(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
