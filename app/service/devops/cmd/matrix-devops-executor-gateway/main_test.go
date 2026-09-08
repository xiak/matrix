package main

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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorgatewayhttp"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

const (
	processGatewayServerName = "executor-gateway.matrix.test"
	processAdminIdentity     = "spiffe://matrix.test/devops/build-worker"
	processRunnerNamespace   = "spiffe://matrix.test/devops/runners"
	processRunnerIdentity    = "spiffe://matrix.test/devops/runners/node-one"
)

func TestLoadConfigurationRequiresTwoClosedListeners(t *testing.T) {
	for _, name := range gatewayEnvironmentNames() {
		t.Setenv(name, "")
	}
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("incomplete gateway environment was accepted")
	}
	root := t.TempDir()
	setGatewayEnvironment(
		t,
		root,
		"127.0.0.1:8443",
		"127.0.0.1:8444",
		filepath.Join(root, "server.crt"),
		filepath.Join(root, "server.key"),
		filepath.Join(root, "admin-ca.crt"),
		filepath.Join(root, "runner-ca.crt"),
	)
	config, err := loadConfiguration()
	if err != nil || config.adminAddress != "127.0.0.1:8443" ||
		config.runnerAddress != "127.0.0.1:8444" ||
		config.adminIdentity != processAdminIdentity ||
		config.runnerNamespace != processRunnerNamespace {
		t.Fatalf("gateway configuration=%#v error=%v", config, err)
	}

	for name, address := range map[string]string{
		"DNS bind":          "gateway.test:8443",
		"implicit host":     ":8443",
		"ephemeral port":    "127.0.0.1:0",
		"noncanonical port": "127.0.0.1:08443",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(adminAddressEnvironment, address)
			if _, err := loadConfiguration(); err == nil {
				t.Fatalf("unsafe listener address accepted: %s", address)
			}
		})
	}
	t.Setenv(adminAddressEnvironment, "127.0.0.1:8443")
	t.Setenv(runnerAddressEnvironment, "127.0.0.1:8443")
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("one address was accepted for both gateway roles")
	}
}

func TestGatewayTLSMaterialIsCanonicalAndRoleRootsDoNotOverlap(t *testing.T) {
	pki := newProcessPKI(t)
	root := t.TempDir()
	certificatePath := writeProcessFile(t, root, "server.crt", pki.serverPEM, 0o644)
	keyPath := writeProcessFile(t, root, "server.key", pki.serverKeyPEM, 0o600)
	adminCAPath := writeProcessFile(t, root, "admin-ca.crt", pki.adminCAPEM, 0o644)
	runnerCAPath := writeProcessFile(t, root, "runner-ca.crt", pki.runnerCAPEM, 0o644)
	now := time.Now()
	certificate, err := loadServerCertificate(certificatePath, keyPath, now)
	if err != nil || certificate.Leaf == nil ||
		certificate.Leaf.VerifyHostname(processGatewayServerName) != nil {
		t.Fatalf("server certificate=%#v error=%v", certificate.Leaf, err)
	}
	adminRoots, err := loadClientRoots(adminCAPath, now)
	if err != nil {
		t.Fatal(err)
	}
	runnerRoots, err := loadClientRoots(runnerCAPath, now)
	if err != nil || rootsOverlap(adminRoots, runnerRoots) ||
		!rootsOverlap(adminRoots, adminRoots) {
		t.Fatalf("root separation error=%v overlap=%t", err, rootsOverlap(adminRoots, runnerRoots))
	}

	noncanonicalPath := writeProcessFile(
		t, root, "noncanonical-ca.crt", append(append([]byte(nil), pki.adminCAPEM...), '\n'), 0o644,
	)
	if _, err := loadClientRoots(noncanonicalPath, now); err == nil {
		t.Fatal("noncanonical root bundle was accepted")
	}
	clientLeafPath := writeProcessFile(t, root, "client.crt", pki.adminPEM, 0o644)
	if _, err := loadClientRoots(clientLeafPath, now); err == nil {
		t.Fatal("client leaf was accepted as a trust root")
	}
}

func TestGatewayProcessComposesAdminAndRunnerBoundaries(t *testing.T) {
	pki := newProcessPKI(t)
	root := t.TempDir()
	spoolRoot := filepath.Join(root, "spool")
	if err := os.Mkdir(spoolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePath := writeProcessFile(t, root, "server.crt", pki.serverPEM, 0o644)
	keyPath := writeProcessFile(t, root, "server.key", pki.serverKeyPEM, 0o600)
	adminCAPath := writeProcessFile(t, root, "admin-ca.crt", pki.adminCAPEM, 0o644)
	runnerCAPath := writeProcessFile(t, root, "runner-ca.crt", pki.runnerCAPEM, 0o644)
	adminAddress := reserveProcessAddress(t)
	runnerAddress := reserveProcessAddress(t)
	for runnerAddress == adminAddress {
		runnerAddress = reserveProcessAddress(t)
	}
	setGatewayEnvironment(
		t, spoolRoot, adminAddress, runnerAddress,
		certificatePath, keyPath, adminCAPath, runnerCAPath,
	)

	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- run(ctx) }()
	stopped := false
	t.Cleanup(func() {
		cancel()
		if !stopped {
			select {
			case <-runResult:
			case <-time.After(5 * time.Second):
			}
		}
	})
	runnerClient := newProcessHTTPClient(
		t, pki.runnerCertificate, pki.serverRoots,
	)
	waitForGatewayRunnerListener(t, runResult, runnerClient, runnerAddress)

	adminClient, err := executorgatewayhttp.NewAdminClient(
		"https://"+adminAddress,
		processGatewayServerName,
		pki.adminCertificate,
		pki.serverRoots,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := processExecutionFixture(t)
	type result struct {
		receipt devopsbuildv1.Receipt
		err     error
	}
	execution := make(chan result, 1)
	executionContext, stopExecution := context.WithTimeout(context.Background(), 8*time.Second)
	defer stopExecution()
	go func() {
		receipt, executeErr := adminClient.Execute(
			executionContext, request, bytes.NewReader(archive),
		)
		execution <- result{receipt: receipt, err: executeErr}
	}()

	assignment, receivedArchive := waitForProcessAssignment(
		t, executionContext, runnerClient, runnerAddress,
	)
	if assignment.Mode != devopsbuildv1.AssignmentExecute ||
		!bytes.Equal(receivedArchive, archive) {
		t.Fatalf("process assignment=%#v archive=%d", assignment, len(receivedArchive))
	}
	runnerID, err := executorgatewayhttp.RunnerID(processRunnerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	receipt := processReceipt(request, runnerID)
	completion := devopsbuildv1.Completion{
		APIVersion:   devopsbuildv1.APIVersion,
		Kind:         devopsbuildv1.CompletionKind,
		ExecutionID:  assignment.ExecutionID,
		FencingToken: assignment.FencingToken,
		Receipt:      receipt,
	}
	completionContent, err := devopsbuildv1.EncodeCompletion(request, completion)
	if err != nil {
		t.Fatal(err)
	}
	response, err := processPost(
		executionContext,
		runnerClient,
		"https://"+runnerAddress+"/v1/runner/executions/"+
			url.PathEscape(assignment.ExecutionID)+"/complete",
		devopsbuildv1.DocumentMediaType,
		completionContent,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertProcessEmptyResponse(t, response, http.StatusNoContent)
	completed := <-execution
	if completed.err != nil || completed.receipt != receipt {
		t.Fatalf("process execution=%#v error=%v", completed.receipt, completed.err)
	}

	cancel()
	select {
	case err := <-runResult:
		stopped = true
		if err != nil {
			t.Fatalf("stop gateway process: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway process did not stop")
	}
}

type processPKI struct {
	serverPEM         []byte
	serverKeyPEM      []byte
	adminCAPEM        []byte
	runnerCAPEM       []byte
	adminPEM          []byte
	adminCertificate  tls.Certificate
	runnerCertificate tls.Certificate
	serverRoots       *x509.CertPool
}

func newProcessPKI(t *testing.T) processPKI {
	t.Helper()
	now := time.Now()
	serverCA, serverCAKey, _ := processCA(t, "server-ca", 1, now)
	adminCA, adminCAKey, adminCAPEM := processCA(t, "admin-ca", 2, now)
	runnerCA, runnerCAKey, runnerCAPEM := processCA(t, "runner-ca", 3, now)
	serverCertificate, serverPEM, serverKeyPEM := processLeaf(
		t, serverCA, serverCAKey, 4, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{processGatewayServerName}, nil,
	)
	_ = serverCertificate
	adminCertificate, adminPEM, _ := processLeaf(
		t, adminCA, adminCAKey, 5, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, []string{processAdminIdentity},
	)
	runnerCertificate, _, _ := processLeaf(
		t, runnerCA, runnerCAKey, 6, now,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil, []string{processRunnerIdentity},
	)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverCA)
	return processPKI{
		serverPEM: serverPEM, serverKeyPEM: serverKeyPEM,
		adminCAPEM: adminCAPEM, runnerCAPEM: runnerCAPEM,
		adminPEM: adminPEM, adminCertificate: adminCertificate,
		runnerCertificate: runnerCertificate, serverRoots: serverRoots,
	}
}

func processCA(
	t *testing.T,
	name string,
	serial int64,
	now time.Time,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func processLeaf(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	serial int64,
	now time.Time,
	usage []x509.ExtKeyUsage,
	dnsNames []string,
	uriNames []string,
) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usage, DNSNames: dnsNames,
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
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certificatePEM, privateKeyPEM
}

func gatewayEnvironmentNames() []string {
	return []string{
		spoolRootEnvironment,
		adminAddressEnvironment,
		runnerAddressEnvironment,
		serverCertEnvironment,
		serverKeyEnvironment,
		adminCAEnvironment,
		adminIdentityEnvironment,
		runnerCAEnvironment,
		runnerNamespaceEnvironment,
	}
}

func setGatewayEnvironment(
	t *testing.T,
	spoolRoot string,
	adminAddress string,
	runnerAddress string,
	serverCertFile string,
	serverKeyFile string,
	adminCAFile string,
	runnerCAFile string,
) {
	t.Helper()
	values := map[string]string{
		spoolRootEnvironment:       spoolRoot,
		adminAddressEnvironment:    adminAddress,
		runnerAddressEnvironment:   runnerAddress,
		serverCertEnvironment:      serverCertFile,
		serverKeyEnvironment:       serverKeyFile,
		adminCAEnvironment:         adminCAFile,
		adminIdentityEnvironment:   processAdminIdentity,
		runnerCAEnvironment:        runnerCAFile,
		runnerNamespaceEnvironment: processRunnerNamespace,
	}
	for name, value := range values {
		t.Setenv(name, value)
	}
}

func writeProcessFile(
	t *testing.T,
	root string,
	name string,
	content []byte,
	mode os.FileMode,
) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func reserveProcessAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func newProcessHTTPClient(
	t *testing.T,
	certificate tls.Certificate,
	roots *x509.CertPool,
) *http.Client {
	t.Helper()
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			ServerName: processGatewayServerName, RootCAs: roots,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"http/1.1"},
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func waitForGatewayRunnerListener(
	t *testing.T,
	runResult <-chan error,
	client *http.Client,
	address string,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	claim, err := devopsbuildv1.EncodeClaim()
	if err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		response, requestErr := processPost(
			ctx, client, "https://"+address+"/v1/runner/claims",
			devopsbuildv1.FramedMediaType, claim,
		)
		if requestErr == nil {
			assertProcessEmptyResponse(t, response, http.StatusNoContent)
			cancel()
			return
		}
		cancel()
		select {
		case runErr := <-runResult:
			t.Fatalf("gateway stopped before readiness: %v", runErr)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("gateway runner listener did not become ready")
}

func waitForProcessAssignment(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	address string,
) (devopsbuildv1.Assignment, []byte) {
	t.Helper()
	claim, err := devopsbuildv1.EncodeClaim()
	if err != nil {
		t.Fatal(err)
	}
	for {
		response, requestErr := processPost(
			ctx, client, "https://"+address+"/v1/runner/claims",
			devopsbuildv1.FramedMediaType, claim,
		)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if response.StatusCode == http.StatusNoContent {
			assertProcessEmptyResponse(t, response, http.StatusNoContent)
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
			continue
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("runner claim status=%d body=%q", response.StatusCode, body)
		}
		var archive bytes.Buffer
		assignment, err := devopsbuildv1.ReadAssignment(
			response.Body,
			func(devopsbuildv1.Assignment) (io.Writer, error) {
				return &archive, nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		return assignment, archive.Bytes()
	}
}

func processPost(
	ctx context.Context,
	client *http.Client,
	target string,
	accept string,
	content []byte,
) (*http.Response, error) {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, target, bytes.NewReader(content),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", devopsbuildv1.DocumentMediaType)
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "matrix-devops-runner-process-test/v1")
	return client.Do(request)
}

func assertProcessEmptyResponse(t *testing.T, response *http.Response, status int) {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != status || len(body) != 0 {
		t.Fatalf("gateway response=%d body=%q error=%v", response.StatusCode, body, err)
	}
}

func processExecutionFixture(t *testing.T) (devopsbuildv1.Request, []byte) {
	t.Helper()
	fileContent := []byte("module example.invalid/process\n\ngo 1.26.0\n")
	var archive bytes.Buffer
	content, err := sourcearchive.Write(
		context.Background(),
		&archive,
		[]sourcearchive.File{{
			Path: "go.mod", Size: int64(len(fileContent)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(fileContent)), nil
			},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	runID := devopsv1.ResourceID("pipeline-run-" + strings.Repeat("a", 48))
	request := devopsbuildv1.Request{
		TenantID: "tenant-one", RunID: runID,
		CommandID:              string(runID) + ":verify:1",
		InputDigest:            "sha256:" + strings.Repeat("1", 64),
		SourceArchiveDigest:    processDigest(archive.Bytes()),
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
	return request, archive.Bytes()
}

func processReceipt(request devopsbuildv1.Request, runnerID string) devopsbuildv1.Receipt {
	receipt := devopsbuildv1.Receipt{
		TenantID: request.TenantID, RunID: request.RunID,
		CommandID: request.CommandID, InputDigest: request.InputDigest,
		SourceArchiveDigest:    request.SourceArchiveDigest,
		PipelineRevisionID:     request.PipelineRevisionID,
		PipelineRevisionDigest: request.PipelineRevisionDigest,
		ExecutorID:             runnerID, ExecutorProfile: request.ExecutorProfile,
		ToolchainImageDigest: request.ToolchainImageDigest,
		Conclusion:           devopsbuildv1.ConclusionPassed,
		Steps: [2]devopsbuildv1.StepReceipt{
			{Ordinal: 1, Kind: devopsv1.VerificationStepGoTest, Conclusion: devopsbuildv1.StepConclusionPassed},
			{Ordinal: 2, Kind: devopsv1.VerificationStepGoVet, Conclusion: devopsbuildv1.StepConclusionPassed},
		},
	}
	receipt.ContentDigest = devopsbuildv1.DigestReceipt(receipt)
	return receipt
}

func processDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
