package executorgatewayhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorspoolfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

const (
	adminIdentity         = "spiffe://matrix.test/devops/build-worker"
	wrongAdminIdentity    = "spiffe://matrix.test/devops/not-build-worker"
	gatewayServerName     = "executor-gateway.matrix.test"
	runnerNamespace       = "spiffe://matrix.test/devops/runners"
	runnerOneIdentity     = "spiffe://matrix.test/devops/runners/node-one"
	runnerTwoIdentity     = "spiffe://matrix.test/devops/runners/node-two"
	runnerOutsideIdentity = "spiffe://matrix.test/devops/operators/node-one"
)

func TestAdminMTLSClientDrivesDurableExecution(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	server := startAdminServer(t, spool, pki)
	client, err := NewAdminClient(
		server.URL, gatewayServerName, pki.adminCertificate, pki.serverRoots,
	)
	if err != nil {
		t.Fatal(err)
	}
	client.pollInterval = 5 * time.Millisecond
	request, archive := gatewayExecutionFixture(t, 'a')
	type executeResult struct {
		receipt devopsbuildv1.Receipt
		err     error
	}
	result := make(chan executeResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		receipt, executeErr := client.Execute(ctx, request, bytes.NewReader(archive))
		result <- executeResult{receipt: receipt, err: executeErr}
	}()

	assignment, receivedArchive := waitForAssignment(t, ctx, spool, request.StartedAt.Add(time.Second))
	if assignment.Mode != devopsbuildv1.AssignmentExecute ||
		assignment.FencingToken != 1 || !bytes.Equal(receivedArchive, archive) {
		t.Fatalf("admin-driven assignment=%#v archive=%d", assignment, len(receivedArchive))
	}
	receipt := gatewayReceipt(
		request,
		"runner-one",
		devopsbuildv1.ConclusionPassed,
		devopsbuildv1.StepConclusionPassed,
		devopsbuildv1.StepConclusionPassed,
	)
	if _, err := spool.Complete(
		ctx,
		"runner-one",
		assignment.ExecutionID,
		assignment.FencingToken,
		receipt,
		assignment.LeaseExpiresAt.Add(-time.Second),
	); err != nil {
		t.Fatalf("complete simulated runner: %v", err)
	}
	completed := <-result
	if completed.err != nil || completed.receipt != receipt {
		t.Fatalf("execute result=%#v err=%v", completed.receipt, completed.err)
	}
	observed, found, err := client.Observe(ctx, request)
	if err != nil || !found || observed != receipt {
		t.Fatalf("observe result=%#v found=%t err=%v", observed, found, err)
	}
	cancelled, found, err := client.Cancel(ctx, request)
	if err != nil || !found || cancelled != receipt {
		t.Fatalf("cancel terminal=%#v found=%t err=%v", cancelled, found, err)
	}

	changed := request
	changed.SourceExpandedBytes++
	if _, err := client.Execute(ctx, changed, bytes.NewReader(archive)); !errors.Is(err, port.ErrBuildConflict) {
		t.Fatalf("changed create error=%v", err)
	}
	missing, _ := gatewayExecutionFixture(t, 'b')
	if _, found, err := client.Observe(ctx, missing); found || !errors.Is(err, port.ErrBuildUnavailable) {
		t.Fatalf("missing observe found=%t err=%v", found, err)
	}
}

func TestAdminListenerRejectsWrongIdentityTLSVersionAndBearerAuthority(t *testing.T) {
	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	server := startAdminServer(t, spool, pki)
	request, archive := gatewayExecutionFixture(t, 'a')

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for name, certificate := range map[string]tls.Certificate{
		"wrong admin identity": pki.wrongAdminCertificate,
		"runner root":          pki.runnerOneCertificate,
	} {
		t.Run(name, func(t *testing.T) {
			wrongClient, err := NewAdminClient(
				server.URL, gatewayServerName, certificate, pki.serverRoots,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrongClient.Execute(ctx, request, bytes.NewReader(archive)); !errors.Is(err, port.ErrBuildOutcomeUnknown) {
				t.Fatalf("wrong admin identity error=%v", err)
			}
		})
	}

	tls12Client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		ServerName:   gatewayServerName,
		RootCAs:      pki.serverRoots,
		Certificates: []tls.Certificate{pki.adminCertificate},
	}}}
	if _, err := tls12Client.Get(server.URL); err == nil {
		t.Fatal("TLS 1.2 admin connection was accepted")
	}

	authorized, err := NewAdminClient(
		server.URL, gatewayServerName, pki.adminCertificate, pki.serverRoots,
	)
	if err != nil {
		t.Fatal(err)
	}
	control, err := devopsbuildv1.EncodeControl(devopsbuildv1.ControlObserve, request)
	if err != nil {
		t.Fatal(err)
	}
	executionID, _ := devopsbuildv1.ExecutionID(request)
	httpRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		server.URL+executionsPath+"/"+url.PathEscape(executionID)+"/observe",
		bytes.NewReader(control),
	)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest.ContentLength = int64(len(control))
	setRequestHeaders(
		httpRequest, devopsbuildv1.DocumentMediaType,
		devopsbuildv1.DocumentMediaType,
	)
	httpRequest.Header.Set("Authorization", "Bearer must-not-enter")
	response, err := authorized.httpClient.Do(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusBadRequest || len(body) != 0 ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("bearer response=%d headers=%v body=%q", response.StatusCode, response.Header, body)
	}
}

func TestAdminConstructorsRejectOpenTLSAndOrigins(t *testing.T) {
	pki := newGatewayTestPKI(t)
	for _, origin := range []string{
		"http://gateway.test",
		"https://user@gateway.test",
		"https://Gateway.test",
		"https://gateway.test/path",
		"https://gateway.test?query=1",
		"https://gateway.test:443",
		"https://gateway.test:0443",
		"https://[0:0:0:0:0:0:0:1]",
	} {
		if _, err := NewAdminClient(
			origin, gatewayServerName, pki.adminCertificate, pki.serverRoots,
		); err == nil {
			t.Fatalf("unsafe gateway origin accepted: %s", origin)
		}
	}
	if _, err := NewAdminClient(
		"https://gateway.test", "UPPER.gateway.test",
		pki.adminCertificate, pki.serverRoots,
	); err == nil {
		t.Fatal("noncanonical server identity was accepted")
	}
	if _, err := NewAdminTLSConfig(
		pki.serverCertificate, pki.adminRoots, "https://not-spiffe",
	); err == nil {
		t.Fatal("non-SPIFFE client identity was accepted")
	}
	if _, err := NewAdminHandler(nil, adminIdentity); err == nil {
		t.Fatal("nil admin spool was accepted")
	}
	if _, err := NewRunnerTLSConfig(
		pki.serverCertificate, pki.runnerRoots, "https://not-spiffe",
	); err == nil {
		t.Fatal("non-SPIFFE runner namespace was accepted")
	}
	if _, err := NewRunnerHandler(nil, runnerNamespace); err == nil {
		t.Fatal("nil runner spool was accepted")
	}
}

func waitForAssignment(
	t *testing.T,
	ctx context.Context,
	spool *executorspoolfile.Spool,
	observedAt time.Time,
) (devopsbuildv1.Assignment, []byte) {
	t.Helper()
	for {
		assignment, archive, found, err := spool.Claim(
			ctx, "runner-one", observedAt,
		)
		if err != nil {
			t.Fatalf("claim gateway assignment: %v", err)
		}
		if found {
			if archive == nil {
				t.Fatal("execute assignment omitted archive")
			}
			content, readErr := io.ReadAll(archive)
			closeErr := archive.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read gateway archive: %v / %v", readErr, closeErr)
			}
			return assignment, content
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
}

type gatewayTestPKI struct {
	serverCertificate        tls.Certificate
	adminCertificate         tls.Certificate
	wrongAdminCertificate    tls.Certificate
	runnerOneCertificate     tls.Certificate
	runnerTwoCertificate     tls.Certificate
	runnerOutsideCertificate tls.Certificate
	serverRoots              *x509.CertPool
	adminRoots               *x509.CertPool
	runnerRoots              *x509.CertPool
}

func newGatewayTestPKI(t *testing.T) gatewayTestPKI {
	t.Helper()
	now := time.Now().UTC()
	serverCA, serverKey := createTestCA(t, "server-ca", 1, now)
	adminCA, adminKey := createTestCA(t, "admin-ca", 2, now)
	runnerCA, runnerKey := createTestCA(t, "runner-ca", 6, now)
	serverCertificate := issueTestCertificate(
		t, serverCA, serverKey, 3, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{gatewayServerName}, nil,
	)
	adminCertificate := issueTestCertificate(
		t, adminCA, adminKey, 4, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, []string{adminIdentity},
	)
	wrongAdminCertificate := issueTestCertificate(
		t, adminCA, adminKey, 5, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, []string{wrongAdminIdentity},
	)
	runnerOneCertificate := issueTestCertificate(
		t, runnerCA, runnerKey, 7, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, []string{runnerOneIdentity},
	)
	runnerTwoCertificate := issueTestCertificate(
		t, runnerCA, runnerKey, 8, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, []string{runnerTwoIdentity},
	)
	runnerOutsideCertificate := issueTestCertificate(
		t, runnerCA, runnerKey, 9, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, []string{runnerOutsideIdentity},
	)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverCA)
	adminRoots := x509.NewCertPool()
	adminRoots.AddCert(adminCA)
	runnerRoots := x509.NewCertPool()
	runnerRoots.AddCert(runnerCA)
	return gatewayTestPKI{
		serverCertificate: serverCertificate, adminCertificate: adminCertificate,
		wrongAdminCertificate:    wrongAdminCertificate,
		runnerOneCertificate:     runnerOneCertificate,
		runnerTwoCertificate:     runnerTwoCertificate,
		runnerOutsideCertificate: runnerOutsideCertificate,
		serverRoots:              serverRoots, adminRoots: adminRoots,
		runnerRoots: runnerRoots,
	}
}

func createTestCA(
	t *testing.T,
	name string,
	serial int64,
	now time.Time,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func issueTestCertificate(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	serial int64,
	now time.Time,
	usage []x509.ExtKeyUsage,
	dnsNames []string,
	uriNames []string,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
		DNSNames:     dnsNames,
	}
	for _, value := range uriNames {
		identity, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = append(template.URIs, identity)
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, issuer, &key.PublicKey, issuerKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func startAdminServer(
	t *testing.T,
	spool *executorspoolfile.Spool,
	pki gatewayTestPKI,
) *httptest.Server {
	t.Helper()
	handler, err := NewAdminHandler(spool, adminIdentity)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := NewAdminTLSConfig(
		pki.serverCertificate, pki.adminRoots, adminIdentity,
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

func gatewaySpool(t *testing.T) *executorspoolfile.Spool {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	spool, err := executorspoolfile.New(root)
	if err != nil {
		t.Fatal(err)
	}
	return spool
}

func gatewayExecutionFixture(
	t *testing.T,
	identity byte,
) (devopsbuildv1.Request, []byte) {
	t.Helper()
	fileContent := []byte("module example.invalid/project\n\ngo 1.26.0\n")
	var archive bytes.Buffer
	content, err := sourcearchive.Write(
		context.Background(), &archive,
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
		t.Fatal(err)
	}
	startedAt := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	runID := devopsv1.ResourceID("pipeline-run-" + strings.Repeat(string(identity), 48))
	request := devopsbuildv1.Request{
		TenantID: "tenant-one", RunID: runID,
		CommandID:           string(runID) + ":verify:1",
		InputDigest:         "sha256:" + strings.Repeat("1", 64),
		SourceArchiveDigest: digestGatewayBytes(archive.Bytes()),
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
	return request, append([]byte(nil), archive.Bytes()...)
}

func gatewayReceipt(
	request devopsbuildv1.Request,
	executorID string,
	conclusion devopsbuildv1.Conclusion,
	first devopsbuildv1.StepConclusion,
	second devopsbuildv1.StepConclusion,
) devopsbuildv1.Receipt {
	receipt := devopsbuildv1.Receipt{
		TenantID: request.TenantID, RunID: request.RunID,
		CommandID: request.CommandID, InputDigest: request.InputDigest,
		SourceArchiveDigest:    request.SourceArchiveDigest,
		PipelineRevisionID:     request.PipelineRevisionID,
		PipelineRevisionDigest: request.PipelineRevisionDigest,
		ExecutorID:             executorID, ExecutorProfile: request.ExecutorProfile,
		ToolchainImageDigest: request.ToolchainImageDigest, Conclusion: conclusion,
		Steps: [2]devopsbuildv1.StepReceipt{
			{Ordinal: request.Steps[0].Ordinal, Kind: request.Steps[0].Kind, Conclusion: first},
			{Ordinal: request.Steps[1].Ordinal, Kind: request.Steps[1].Kind, Conclusion: second},
		},
	}
	receipt.ContentDigest = devopsbuildv1.DigestReceipt(receipt)
	return receipt
}

func digestGatewayBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
