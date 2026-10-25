//go:build linux

package nethttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

// TestLinuxCurrentNodeSelfEnrollment proves the current release can perform a
// fresh signed join on a real Linux host. The fixed-predecessor gate remains
// separate so this test cannot accidentally turn N-1 compatibility evidence
// into current-source installation evidence.
func TestLinuxCurrentNodeSelfEnrollment(t *testing.T) {
	if os.Getenv("MATRIX_NODE_SELF_ENROLLMENT_REAL_RUNTIME") != "1" {
		t.Skip("set MATRIX_NODE_SELF_ENROLLMENT_REAL_RUNTIME=1 on an isolated native systemd host")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" {
		t.Fatal("node self-enrollment gate requires native Linux/amd64 root")
	}
	bundle, releaseTrust := os.Getenv("MATRIX_NODE_SELF_ENROLLMENT_BUNDLE"), os.Getenv("MATRIX_NODE_RELEASE_TRUST")
	for _, path := range []string{bundle, releaseTrust} {
		if !filepath.IsAbs(path) {
			t.Fatal("node self-enrollment gate requires a release-builder bundle and its trust root")
		}
	}
	trustBytes, _, err := release.ReadTrustRootFile(releaseTrust)
	if err != nil {
		t.Fatal("node self-enrollment release trust root is unavailable")
	}
	verified, err := release.VerifyDirectory(bundle, trustBytes)
	if err != nil || verified.Manifest.Kind != release.NodeManifestKind || verified.Manifest.Node == nil ||
		verified.Manifest.Node.RuntimeRevision != nodeconfig.RuntimeRevision ||
		verified.Manifest.TopologyDigest != nodeconfig.ContractDigest() ||
		verified.Manifest.Release.PreviousID != "" || verified.Manifest.Release.PreviousVersion != "" {
		t.Fatal("node self-enrollment gate requires an authenticated current fresh-install release")
	}
	installer := filepath.Join(bundle, "bin", "mx")
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	base := t.TempDir()
	root := filepath.Join(base, "installation")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	facts, err := localmachine.NewLocalHostProbe().Inspect(ctx, base)
	cancel()
	if err != nil || !facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatal("node self-enrollment host prerequisites unavailable")
	}
	fingerprint, err := localmachine.DeriveMachineFingerprint(facts)
	if err != nil {
		t.Fatal(err)
	}
	managementIP := nativePrivateIPv4(t)
	managementAddress := net.JoinHostPort(managementIP.String(), strconv.Itoa(int(nodeconfig.DefaultManagementPort)))
	collectorAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(nodeconfig.DefaultCollectorPort)))
	for _, address := range []string{managementAddress, collectorAddress} {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatalf("node self-enrollment listener %s is unavailable", address)
		}
		if err := listener.Close(); err != nil {
			t.Fatal("node self-enrollment listener probe could not close")
		}
	}

	installationID := "mxi-" + nativeEnrollmentEntropy(t)
	enrollmentID := paasv1.ResourceID("node-enrollment-" + nativeEnrollmentEntropy(t))
	executionTargetID := paasv1.ResourceID("execution-target-" + nativeEnrollmentEntropy(t))
	identity := nodev1.Identity{InstallationID: installationID, ExecutionTargetID: executionTargetID}
	nodeUnit, _ := nodeconfig.ServiceName(identity, false)
	collectorUnit, _ := nodeconfig.ServiceName(identity, true)
	startupUnit, _ := nodeconfig.StartupServiceName(identity)
	for _, unit := range []string{startupUnit, nodeUnit, collectorUnit} {
		if nativeUnitProperty(t, unit, "LoadState") != "not-found" {
			t.Fatal("node self-enrollment unit identity already exists")
		}
	}
	t.Cleanup(func() { cleanupNativeSelfEnrollment(t, root, identity) })

	credential := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, credential); err != nil {
		t.Fatal(err)
	}
	defer clear(credential)
	fixture := newNativeEnrollmentFixture(
		t, installationID, enrollmentID, executionTargetID, fingerprint, managementIP, credential,
	)
	server := fixture.start(t)
	joinFile := fixture.joinFile(t, server.URL)
	joinBytes, err := json.Marshal(joinFile)
	if err != nil {
		t.Fatal(err)
	}
	joinPath := filepath.Join(base, "node-join.json")
	if err := os.WriteFile(joinPath, joinBytes, 0o600); err != nil {
		clear(joinBytes)
		t.Fatal(err)
	}
	clear(joinBytes)
	joinCredential := joinFile.Credential
	joinFile.Clear()

	installArguments := []string{
		"node", "install", "--root", root, "--bundle", bundle, "--trust-key", releaseTrust, "--join", joinPath,
	}
	installed := nativeMX(t, installer, true, installArguments...)
	if installed.State != "READY" || !installed.Changed ||
		installed.ExecutionTargetID != string(executionTargetID) || installed.ReleaseID != verified.Manifest.Release.ID ||
		paasv1.ValidateDigest("configurationDigest", installed.ConfigurationDigest) != nil {
		t.Fatal("current signed join did not commit a ready node installation")
	}
	fixture.assertCalls(t, 1, 1)
	if nativeUnitProperty(t, startupUnit, "UnitFileState") != "enabled" ||
		nativeUnitProperty(t, nodeUnit, "ActiveState") != "active" ||
		nativeUnitProperty(t, collectorUnit, "ActiveState") != "active" ||
		nativeUnitProperty(t, collectorUnit, "DynamicUser") != "yes" {
		t.Fatal("current signed join did not establish the owned native services")
	}

	client, err := nodehttps.New(nodehttps.Config{
		Endpoint: "https://" + managementAddress, Identity: identity,
		ControllerID: fixture.controllerID, BindingRef: fixture.bindingRef, ExpectedFingerprint: fingerprint,
		Credentials: func() (nodehttps.Credentials, error) { return fixture.controller.credentials, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	command := observationCommand()
	command.ExecutionTargetID = executionTargetID
	command.BindingRef = fixture.bindingRef
	command.Deadline = time.Now().UTC().Add(5 * time.Second).Truncate(time.Microsecond)
	observationContext, stopObservation := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopObservation()
	observed, err := client.ObserveExecutionTarget(
		observationContext, paasv1.ObserveExecutionTargetRequest{Command: command},
	)
	if err != nil || paasv1.ValidateExecutionTargetObservation(observed) != nil ||
		observed.ExecutionTargetID != executionTargetID || observed.IdentityFingerprint != fingerprint ||
		observed.Health != paasv1.ExecutionTargetHealthReady || observed.Usage == nil {
		t.Fatal("controller mTLS could not observe the freshly enrolled real node")
	}

	for _, transient := range []string{
		"node-enrollment-intent.json", "node-enrollment-attempted",
		"node-enrollment-response.json", "node-enrollment-cleanup.json",
	} {
		if _, err := os.Lstat(filepath.Join(root, "state", transient)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("completed node enrollment retained ephemeral ceremony state")
		}
	}
	firstPID := nativeUnitProperty(t, nodeUnit, "MainPID")
	if firstPID == "" || firstPID == "0" {
		t.Fatal("freshly enrolled node has no supervised process")
	}

	// A terminal replay must not need the now-unavailable bootstrap ingress or
	// consume the same credential again.
	server.Close()
	replayed := nativeMX(t, installer, true, installArguments...)
	if replayed.Changed || replayed.State != "READY" || replayed.CorrelationID != installed.CorrelationID ||
		replayed.ConfigurationDigest != installed.ConfigurationDigest || nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID {
		t.Fatal("completed node enrollment was not an exact local replay")
	}
	fixture.assertCalls(t, 1, 1)

	supportPath := filepath.Join(root, "support", "self-enrollment.json")
	supported := nativeMX(t, installer, true, "node", "support", "--root", root, "--output", supportPath)
	if supported.State != "SUPPORT_WRITTEN" || !supported.Changed {
		t.Fatal("freshly enrolled node did not produce bounded support evidence")
	}
	for _, path := range []string{filepath.Join(root, "state", "journal.json"), supportPath} {
		content, err := os.ReadFile(path)
		if err != nil || bytes.Contains(content, []byte(joinCredential)) || bytes.Contains(content, credential) {
			clear(content)
			t.Fatal("node enrollment credential entered durable or support evidence")
		}
		clear(content)
	}
}

type nativeEnrollmentAuthority struct {
	certificate *x509.Certificate
	der         []byte
	key         ed25519.PrivateKey
	pem         []byte
}

type nativeEnrollmentFixture struct {
	mu                 sync.Mutex
	authority          nativeEnrollmentAuthority
	controller         issuedCertificate
	controllerID       string
	bindingRef         string
	installationID     string
	enrollmentID       paasv1.ResourceID
	executionTargetID  paasv1.ResourceID
	machineFingerprint string
	managementIP       net.IP
	credential         string
	join               paasv1.NodeEnrollmentJoin
	createdAt          time.Time
	exchangedAt        time.Time
	exchange           paasv1.NodeEnrollmentExchangeResponse
	exchangeCalls      int
	completionCalls    int
	failure            string
}

func newNativeEnrollmentFixture(
	t *testing.T,
	installationID string,
	enrollmentID paasv1.ResourceID,
	executionTargetID paasv1.ResourceID,
	machineFingerprint string,
	managementIP net.IP,
	credential []byte,
) *nativeEnrollmentFixture {
	t.Helper()
	authority := newNativeEnrollmentAuthority(t, installationID)
	controllerID := "paas-controller-v1"
	controllerURI, err := nodev1.ControllerURI(installationID, controllerID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &nativeEnrollmentFixture{
		authority: authority, controllerID: controllerID,
		bindingRef:     "node-binding-" + nativeEnrollmentEntropy(t),
		installationID: installationID, enrollmentID: enrollmentID, executionTargetID: executionTargetID,
		machineFingerprint: machineFingerprint, managementIP: append(net.IP(nil), managementIP...),
		credential: base64.RawURLEncoding.EncodeToString(credential),
		createdAt:  time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond),
	}
	fixture.controller = authority.issueIdentity(t, controllerURI, net.ParseIP("127.0.0.1"), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 3)
	t.Cleanup(func() {
		clear(fixture.authority.key)
		fixture.credential = ""
	})
	return fixture
}

func (fixture *nativeEnrollmentFixture) start(t *testing.T) *httptest.Server {
	t.Helper()
	serverName, err := paasv1.NodeEnrollmentIngressServerName(fixture.installationID)
	if err != nil {
		t.Fatal(err)
	}
	certificate := fixture.authority.issueServer(t, serverName)
	server := httptest.NewUnstartedServer(fixture)
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func (fixture *nativeEnrollmentFixture) joinFile(t *testing.T, endpoint string) nodeconfig.JoinFile {
	t.Helper()
	credential, err := base64.RawURLEncoding.Strict().DecodeString(fixture.credential)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(credential)
	clear(credential)
	join := paasv1.NodeEnrollmentJoin{
		APIVersion: paasv1.NodeEnrollmentJoinAPIVersion, Kind: paasv1.NodeEnrollmentJoinKind,
		EnrollmentID: fixture.enrollmentID, InstallationID: fixture.installationID,
		ExecutionTargetID:  fixture.executionTargetID,
		ControlPlaneURL:    endpoint + "/api/paas/v1/node-enrollments/" + string(fixture.enrollmentID) + "/exchange",
		CredentialDigest:   "sha256:" + hex.EncodeToString(digest[:]),
		ExpiresAt:          time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond),
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(fixture.authority.der),
		SignatureAlgorithm: paasv1.NodeJoinSignatureEd25519,
	}
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(join)
	if err != nil {
		t.Fatal(err)
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.authority.key, commitment))
	if paasv1.ValidateNodeEnrollmentJoin(join) != nil {
		t.Fatal("native enrollment fixture produced an invalid signed join")
	}
	fixture.join = join
	return nodeconfig.JoinFile{
		APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.JoinFileKind,
		Join: join, Credential: fixture.credential,
	}
}

func (fixture *nativeEnrollmentFixture) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if err := validateNativeEnrollmentHTTP(request); err != nil {
		fixture.reject(response, err)
		return
	}
	base := "/api/paas/v1/node-enrollments/" + string(fixture.enrollmentID)
	switch request.URL.Path {
	case base + "/exchange":
		fixture.serveExchange(response, request)
	case base + "/complete":
		fixture.serveCompletion(response, request)
	default:
		fixture.reject(response, errors.New("unexpected node enrollment route"))
	}
}

func validateNativeEnrollmentHTTP(request *http.Request) error {
	if request == nil || request.Method != http.MethodPost || request.URL.RawQuery != "" ||
		len(request.Header.Values("Content-Type")) != 1 || request.Header.Get("Content-Type") != "application/json" ||
		len(request.Header.Values("Accept")) != 1 || request.Header.Get("Accept") != "application/json" ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Content-Encoding") != "" {
		return errors.New("node enrollment request metadata is invalid")
	}
	return nil
}

func (fixture *nativeEnrollmentFixture) serveExchange(response http.ResponseWriter, httpRequest *http.Request) {
	var request paasv1.ExchangeNodeEnrollmentRequest
	if contractjson.DecodeObject(
		io.LimitReader(httpRequest.Body, int64(nodeconfig.MaximumBytes)+1), int64(nodeconfig.MaximumBytes), &request,
	) != nil || paasv1.ValidateExchangeNodeEnrollmentRequest(request) != nil ||
		request.EnrollmentID != fixture.enrollmentID || request.InstallationID != fixture.installationID ||
		request.ExecutionTargetID != fixture.executionTargetID || request.MachineFingerprint != fixture.machineFingerprint ||
		request.RuntimeContractDigest != nodeconfig.ContractDigest() ||
		request.Listener != (paasv1.NodeEnrollmentListenerClaim{
			ManagementPort: nodeconfig.DefaultManagementPort, CollectorPort: nodeconfig.DefaultCollectorPort,
		}) || subtle.ConstantTimeCompare([]byte(request.Credential), []byte(fixture.credential)) != 1 {
		request.Credential = ""
		fixture.reject(response, errors.New("node enrollment exchange differs from the signed join"))
		return
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.exchangeCalls != 0 {
		request.Credential = ""
		fixture.rejectLocked(response, errors.New("node enrollment credential was exchanged more than once"))
		return
	}
	exchanged, err := fixture.exchangeResponse(request)
	request.Credential = ""
	if err != nil {
		fixture.rejectLocked(response, err)
		return
	}
	fixture.exchangeCalls = 1
	fixture.exchangedAt = time.Now().UTC().Truncate(time.Microsecond)
	fixture.exchange = exchanged
	writeNativeEnrollmentJSON(response, exchanged)
}

func (fixture *nativeEnrollmentFixture) exchangeResponse(
	request paasv1.ExchangeNodeEnrollmentRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	nodePKIX, collectorPKIX, err := paasv1.NodeEnrollmentExchangePublicKeys(request)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, errors.New("node enrollment public keys are invalid")
	}
	notBefore := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
	notAfter := notBefore.Add(24 * time.Hour)
	nodeCertificate, err := fixture.authority.issueRole(
		nodePKIX, fixture.installationID, fixture.executionTargetID, "nodes", fixture.managementIP,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, notBefore, notAfter, 4,
	)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	collectorCertificate, err := fixture.authority.issueRole(
		collectorPKIX, fixture.installationID, fixture.executionTargetID, "collectors", net.ParseIP("127.0.0.1"),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, notBefore, notAfter, 5,
	)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	value := paasv1.NodeEnrollmentExchangeResponse{
		APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentExchangeResponseKind,
		EnrollmentID: request.EnrollmentID, InstallationID: request.InstallationID,
		ExecutionTargetID: request.ExecutionTargetID, ExchangeID: request.ExchangeID,
		MachineFingerprint: request.MachineFingerprint, RuntimeContractDigest: request.RuntimeContractDigest,
		ControllerID: fixture.controllerID, BindingRef: fixture.bindingRef,
		NodeListenAddress: net.JoinHostPort(fixture.managementIP.String(), strconv.Itoa(int(request.Listener.ManagementPort))),
		CollectorEndpoint: "https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(int(request.Listener.CollectorPort))),
		NodeCertificate:   nodeCertificate, CollectorCertificate: collectorCertificate,
		IssuerCertificate:    base64.RawURLEncoding.EncodeToString(fixture.authority.der),
		CertificateNotBefore: notBefore, CertificateNotAfter: notAfter,
	}
	if paasv1.ValidateNodeEnrollmentExchangeResponseForRequest(value, request) != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, errors.New("node enrollment exchange response is invalid")
	}
	return value, nil
}

func (fixture *nativeEnrollmentFixture) serveCompletion(response http.ResponseWriter, httpRequest *http.Request) {
	var request paasv1.CompleteNodeEnrollmentRequest
	if contractjson.DecodeObject(
		io.LimitReader(httpRequest.Body, int64(nodeconfig.MaximumBytes)+1), int64(nodeconfig.MaximumBytes), &request,
	) != nil || paasv1.ValidateCompleteNodeEnrollmentRequest(request) != nil {
		fixture.reject(response, errors.New("node enrollment completion request is invalid"))
		return
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.exchangeCalls != 1 || fixture.completionCalls != 0 {
		fixture.rejectLocked(response, errors.New("node enrollment completion sequence is invalid"))
		return
	}
	expected, err := nativeEnrollmentCompletionRequest(fixture.exchange)
	if err != nil || request != expected {
		fixture.rejectLocked(response, errors.New("node enrollment completion differs from its exchange"))
		return
	}
	completed := fixture.completionResponse(request)
	if paasv1.ValidateCompleteNodeEnrollmentResponse(completed) != nil {
		fixture.rejectLocked(response, errors.New("node enrollment completion response is invalid"))
		return
	}
	fixture.completionCalls = 1
	writeNativeEnrollmentJSON(response, completed)
}

func nativeEnrollmentCompletionRequest(
	exchange paasv1.NodeEnrollmentExchangeResponse,
) (paasv1.CompleteNodeEnrollmentRequest, error) {
	fingerprint := func(value string) (string, error) {
		der, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil {
			return "", err
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
		return "sha256:" + hex.EncodeToString(digest[:]), nil
	}
	nodeFingerprint, err := fingerprint(exchange.NodeCertificate)
	if err != nil {
		return paasv1.CompleteNodeEnrollmentRequest{}, err
	}
	collectorFingerprint, err := fingerprint(exchange.CollectorCertificate)
	if err != nil {
		return paasv1.CompleteNodeEnrollmentRequest{}, err
	}
	return paasv1.CompleteNodeEnrollmentRequest{
		APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentCompletionRequestKind,
		EnrollmentID: exchange.EnrollmentID, InstallationID: exchange.InstallationID,
		ExecutionTargetID: exchange.ExecutionTargetID, ExchangeID: exchange.ExchangeID,
		MachineFingerprint: exchange.MachineFingerprint, RuntimeContractDigest: exchange.RuntimeContractDigest,
		ControllerID: exchange.ControllerID, BindingRef: exchange.BindingRef,
		NodeListenAddress: exchange.NodeListenAddress, CollectorEndpoint: exchange.CollectorEndpoint,
		NodePublicKeyFingerprint: nodeFingerprint, CollectorPublicKeyFingerprint: collectorFingerprint,
	}, nil
}

func (fixture *nativeEnrollmentFixture) completionResponse(
	request paasv1.CompleteNodeEnrollmentRequest,
) paasv1.CompleteNodeEnrollmentResponse {
	readyAt := time.Now().UTC().Truncate(time.Microsecond)
	consumedAt := fixture.exchangedAt
	poolID := paasv1.ResourceID("pool-a")
	operationID := paasv1.OperationID("operation-enrollment-a")
	enrollment := paasv1.NodeEnrollment{
		APIVersion: paasv1.APIVersion, Kind: "NodeEnrollment",
		Metadata: paasv1.ResourceMetadata{
			ID: request.EnrollmentID, Name: "host-a", Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
			Labels: map[string]string{"zone": "private-a"}, ResourceVersion: 3,
			CreatedAt: fixture.createdAt, UpdatedAt: readyAt,
		},
		ExecutionTargetID: request.ExecutionTargetID, ExecutionPoolID: poolID,
		OperationID: operationID, State: paasv1.NodeEnrollmentReady,
		ExpiresAt: fixture.join.ExpiresAt, CredentialConsumedAt: &consumedAt, ReadyAt: &readyAt,
	}
	target := paasv1.ExecutionTarget{
		APIVersion: paasv1.APIVersion, Kind: "ExecutionTarget",
		Metadata: paasv1.ResourceMetadata{
			ID: request.ExecutionTargetID, Name: "host-a", Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
			Labels:          map[string]string{"zone": "private-a", "matrix-machine-fingerprint": request.MachineFingerprint},
			ResourceVersion: 1, CreatedAt: readyAt, UpdatedAt: readyAt,
		},
		Spec: paasv1.ExecutionTargetSpec{
			ExecutionPoolID:       poolID,
			InfrastructureAdapter: paasv1.AdapterRef{Kind: paasv1.AdapterInfrastructure, Name: "nodehttps", ContractVersion: "v1"},
			DeploymentExecutor:    paasv1.AdapterRef{Kind: paasv1.AdapterDeploymentExecutor, Name: "compose", ContractVersion: "v1"},
			DesiredState:          paasv1.ExecutionTargetActive,
		},
		Status: paasv1.ExecutionTargetStatus{
			Capacity:                     paasv1.Capacity{CPUMillis: 4000, MemoryBytes: 8 << 30, StorageBytes: 100 << 30, WorkloadSlots: 32},
			Allocatable:                  paasv1.Capacity{CPUMillis: 3000, MemoryBytes: 6 << 30, StorageBytes: 80 << 30, WorkloadSlots: 24},
			Health:                       paasv1.ExecutionTargetHealthReady,
			SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}, ObservedAt: readyAt,
		},
	}
	operation := paasv1.Operation{
		APIVersion: paasv1.APIVersion, Kind: "Operation", ID: operationID,
		Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, InstallationID: request.InstallationID,
		Action:                 paasv1.OperationRegisterExecutionTarget,
		Target:                 paasv1.ResourceRef{Kind: "ExecutionTarget", ID: request.ExecutionTargetID},
		RequestedBy:            paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "platform-user"},
		IdempotencyFingerprint: "sha256:" + strings.Repeat("a", 64),
		RequestDigest:          "sha256:" + strings.Repeat("b", 64), State: paasv1.OperationSucceeded, Attempt: 1,
		CreatedAt: fixture.createdAt, UpdatedAt: readyAt, TerminalAt: &readyAt,
	}
	return paasv1.CompleteNodeEnrollmentResponse{Enrollment: enrollment, ExecutionTarget: target, Operation: operation}
}

func (fixture *nativeEnrollmentFixture) reject(response http.ResponseWriter, err error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.rejectLocked(response, err)
}

func (fixture *nativeEnrollmentFixture) rejectLocked(response http.ResponseWriter, err error) {
	if fixture.failure == "" {
		fixture.failure = err.Error()
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(http.StatusInternalServerError)
}

func (fixture *nativeEnrollmentFixture) assertCalls(t *testing.T, exchanges, completions int) {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.failure != "" || fixture.exchangeCalls != exchanges || fixture.completionCalls != completions {
		t.Fatalf(
			"node enrollment fixture calls exchange=%d completion=%d failure=%q",
			fixture.exchangeCalls, fixture.completionCalls, fixture.failure,
		)
	}
}

func writeNativeEnrollmentJSON(response http.ResponseWriter, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func newNativeEnrollmentAuthority(t *testing.T, installationID string) nativeEnrollmentAuthority {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Matrix native enrollment issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, URIs: []*url.URL{issuerURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return nativeEnrollmentAuthority{
		certificate: certificate, der: der, key: private,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (authority nativeEnrollmentAuthority) issueServer(t *testing.T, serverName string) tls.Certificate {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{serverName},
	}
	return authority.issuePair(t, template, private)
}

func (authority nativeEnrollmentAuthority) issueIdentity(
	t *testing.T,
	identity string,
	address net.IP,
	usages []x509.ExtKeyUsage,
	serial int64,
) issuedCertificate {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityURI, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages, URIs: []*url.URL{identityURI}, IPAddresses: []net.IP{address},
	}
	pair := authority.issuePair(t, template, private)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	credentials, err := nodehttps.NewCredentials(certificatePEM, privatePEM, authority.pem)
	clear(privateDER)
	clear(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return issuedCertificate{credentials: credentials, pair: pair}
}

func (authority nativeEnrollmentAuthority) issuePair(
	t *testing.T,
	template *x509.Certificate,
	private ed25519.PrivateKey,
) tls.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, private.Public(), authority.key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	pair, err := tls.X509KeyPair(certificatePEM, privatePEM)
	clear(privateDER)
	clear(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func (authority nativeEnrollmentAuthority) issueRole(
	publicKeyInfo []byte,
	installationID string,
	executionTargetID paasv1.ResourceID,
	role string,
	address net.IP,
	usages []x509.ExtKeyUsage,
	notBefore time.Time,
	notAfter time.Time,
	serial int64,
) (string, error) {
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyInfo)
	if err != nil {
		return "", errors.New("node enrollment public key is invalid")
	}
	if _, ok := publicKey.(ed25519.PublicKey); !ok {
		return "", errors.New("node enrollment public key algorithm is invalid")
	}
	identity := &url.URL{
		Scheme: "spiffe", Host: "matrix.xiak.com",
		Path: "/installations/" + installationID + "/" + role + "/" + string(executionTargetID),
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages, URIs: []*url.URL{identity}, IPAddresses: []net.IP{address},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, publicKey, authority.key)
	if err != nil {
		return "", fmt.Errorf("issue node enrollment role certificate: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(der), nil
}

func nativeEnrollmentEntropy(t *testing.T) string {
	t.Helper()
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		t.Fatal(err)
	}
	result := hex.EncodeToString(value)
	clear(value)
	return result
}

func nativePrivateIPv4(t *testing.T) net.IP {
	t.Helper()
	type candidate struct {
		virtual bool
		name    string
		address net.IP
	}
	var candidates []candidate
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal("node self-enrollment cannot inspect local interfaces")
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		name := strings.ToLower(networkInterface.Name)
		virtual := strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "virbr") || strings.HasPrefix(name, "tun")
		for _, value := range addresses {
			address, _, err := net.ParseCIDR(value.String())
			if err != nil || address.To4() == nil || !address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() {
				continue
			}
			candidates = append(candidates, candidate{virtual: virtual, name: name, address: append(net.IP(nil), address.To4()...)})
		}
	}
	if len(candidates) == 0 {
		t.Fatal("node self-enrollment requires a bindable private IPv4 address")
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].virtual != candidates[right].virtual {
			return !candidates[left].virtual
		}
		if candidates[left].name != candidates[right].name {
			return candidates[left].name < candidates[right].name
		}
		return bytes.Compare(candidates[left].address, candidates[right].address) < 0
	})
	return candidates[0].address
}

func cleanupNativeSelfEnrollment(t *testing.T, root string, identity nodev1.Identity) {
	t.Helper()
	nodeUnit, _ := nodeconfig.ServiceName(identity, false)
	collectorUnit, _ := nodeconfig.ServiceName(identity, true)
	startupUnit, _ := nodeconfig.StartupServiceName(identity)
	source := filepath.Join(root, "config", "native", startupUnit)
	changed := false
	for _, path := range []string{
		filepath.Join("/etc/systemd/system/multi-user.target.wants", startupUnit),
		filepath.Join("/etc/systemd/system", startupUnit),
	} {
		target, err := os.Readlink(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || target != source {
			t.Error("node self-enrollment refuses to remove foreign boot registration")
			continue
		}
		if !changed && nativeUnitProperty(t, startupUnit, "LoadState") == "loaded" {
			if nativeUnitProperty(t, startupUnit, "FragmentPath") != filepath.Join("/etc/systemd/system", startupUnit) {
				t.Error("node self-enrollment refuses to stop a foreign boot service")
				continue
			}
			nativeSystemctl(t, "stop", startupUnit)
		}
		if err := os.Remove(path); err != nil {
			t.Error("remove node self-enrollment boot registration")
		}
		changed = true
	}
	if changed {
		nativeSystemctl(t, "daemon-reload")
	}
	for _, unit := range []string{nodeUnit, collectorUnit} {
		description := nativeUnitProperty(t, unit, "Description")
		if description == "" || description == unit {
			continue
		}
		if !strings.HasPrefix(description, "Matrix node ") && !strings.HasPrefix(description, "Matrix collector ") {
			t.Error("node self-enrollment refuses to clean a foreign service")
			continue
		}
		nativeSystemctl(t, "stop", unit)
		if nativeUnitProperty(t, unit, "LoadState") == "loaded" {
			nativeSystemctl(t, "reset-failed", unit)
		}
	}
}
