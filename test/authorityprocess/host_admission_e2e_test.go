package authorityprocess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
)

const processHostPool = "execution-pool-process"
const processHostTarget = "execution-target-process"
const processHostFingerprint = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// The five real authority processes use the production mTLS node client
// against this closed wire fixture. OS/collector effects remain in the real
// Linux node process gate, not simulated as physical evidence here.
type processNodeFixture struct {
	configurationPath string
	unavailable       atomic.Bool
	wrongIdentity     atomic.Bool
	samples           atomic.Uint64
}

func newProcessNodeFixture(t *testing.T, directory, installationID string) *processNodeFixture {
	t.Helper()
	identity := nodev1.Identity{InstallationID: installationID, ExecutionTargetID: processHostTarget}
	controllerID := "process-controller"
	nodeURI, _ := nodev1.NodeURI(identity)
	controllerURI, _ := nodev1.ControllerURI(installationID, controllerID)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "process-node-test-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certificate := func(serial int64, uri string, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identityURI, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{identityURI}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}
	nodeCertificate, nodeKey := certificate(2, nodeURI, x509.ExtKeyUsageServerAuth)
	controllerCertificate, controllerKey := certificate(3, controllerURI, x509.ExtKeyUsageClientAuth)
	defer clear(nodeKey)
	defer clear(controllerKey)
	credentials, err := nodehttps.NewCredentials(nodeCertificate, nodeKey, trust)
	if err != nil {
		t.Fatal(err)
	}
	security, err := nodehttps.ServerTLS(credentials, identity, controllerID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &processNodeFixture{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != nodev1.ObservationPath {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := nodev1.DecodeObservationRequest(request.Body)
		if err != nil || body.Identity != identity || body.Command.BindingRef != "process-node-binding" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if fixture.unavailable.Load() {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		sequence := fixture.samples.Add(1)
		now := time.Now().UTC().Truncate(time.Microsecond)
		fingerprint := processHostFingerprint
		if fixture.wrongIdentity.Load() {
			fingerprint = "sha256:" + strings.Repeat("d", 64)
		}
		observation := paasv1.ExecutionTargetObservation{ExecutionTargetID: processHostTarget, IdentityFingerprint: fingerprint, Health: paasv1.ExecutionTargetHealthReady,
			Capacity: paasv1.Capacity{CPUMillis: 4000, MemoryBytes: 8 << 30, StorageBytes: 100 << 30, WorkloadSlots: 32}, Allocatable: paasv1.Capacity{CPUMillis: 3000, MemoryBytes: 6 << 30, StorageBytes: 80 << 30, WorkloadSlots: 24}, SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}, ObservedAt: now,
			Usage: &paasv1.ExecutionTargetUsage{ObservedAt: now, ValidUntil: now.Add(15 * time.Second), CPU: paasv1.CPUUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.CPUUsageValue{LogicalCPUs: 4, WindowMillis: 5000, UtilizationRatio: float64(sequence%100) / 100}}, Memory: paasv1.MemoryUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.MemoryUsageValue{TotalBytes: 8 << 30, AvailableBytes: 6 << 30, UsedBytes: 2 << 30}}, FilesystemsState: paasv1.MeasurementUnavailable}}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(nodev1.ObservationResponse{APIVersion: nodev1.APIVersion, Kind: nodev1.ObservationResponseKind, Identity: identity, CommandID: body.Command.CommandID, Observation: observation})
	}))
	server.TLS = security
	server.StartTLS()
	t.Cleanup(server.Close)
	configuration := map[string]any{"installationId": installationID, "controllerId": controllerID,
		"certificateFile": writeProtectedFile(t, directory, "node-controller.crt", controllerCertificate), "privateKeyFile": writeProtectedFile(t, directory, "node-controller.key", controllerKey), "trustFile": writeProtectedFile(t, directory, "node-trust.crt", trust),
		"nodes": []any{map[string]any{"bindingRef": "process-node-binding", "targetId": processHostTarget, "endpoint": server.URL, "identityFingerprint": processHostFingerprint}}}
	document, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	fixture.configurationPath = writeProtectedFile(t, directory, "node-connections.json", document)
	return fixture
}

func processHostRegistration() paasv1.RegisterExecutionTargetRequest {
	return paasv1.RegisterExecutionTargetRequest{ID: processHostTarget, Name: "process-node", ExecutionPoolID: processHostPool, BindingRef: "process-node-binding"}
}

func createPlatformHost(t *testing.T, ctx context.Context, admin *pgx.Conn, paasEndpoint, auditEndpoint, credential string, node *processNodeFixture) auditv1.AuditRecord {
	t.Helper()
	poolRequest := paasv1.CreateExecutionPoolRequest{ID: processHostPool, Name: "process-nodes", Spec: paasv1.ExecutionPoolSpec{AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}}}
	created := performJSONWithIdempotency(t, http.MethodPost, paasEndpoint+"/v1/execution-pools", credential, "create-process-nodes", poolRequest)
	var poolOperation paasv1.Operation
	if created.Status != http.StatusCreated || json.Unmarshal(created.Body, &poolOperation) != nil || paasv1.ValidateOperation(poolOperation) != nil || poolOperation.InstallationID != "installation-process" {
		t.Fatalf("real PaaS pool admission: status=%d body=%s", created.Status, created.Body)
	}
	node.wrongIdentity.Store(true)
	wrong := performJSONWithIdempotency(t, http.MethodPost, paasEndpoint+"/v1/execution-targets", credential, "register-process-node", processHostRegistration())
	if wrong.Status != http.StatusServiceUnavailable {
		t.Fatalf("wrong node identity reached admission: status=%d", wrong.Status)
	}
	var partial int
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM paas.execution_targets WHERE id=$1)+(SELECT count(*) FROM paas.operations WHERE installation_id='installation-process' AND target_id=$1)`, processHostTarget).Scan(&partial); err != nil || partial != 0 {
		t.Fatalf("wrong node identity left partial authority: rows=%d err=%v", partial, err)
	}
	node.wrongIdentity.Store(false)
	created = performJSONWithIdempotency(t, http.MethodPost, paasEndpoint+"/v1/execution-targets", credential, "register-process-node", processHostRegistration())
	var operation paasv1.Operation
	if created.Status != http.StatusCreated || json.Unmarshal(created.Body, &operation) != nil || paasv1.ValidateOperation(operation) != nil || operation.InstallationID != "installation-process" || operation.Scope.TenantID != "" || operation.Action != paasv1.OperationRegisterExecutionTarget || operation.Target.ID != processHostTarget {
		t.Fatalf("real PaaS node admission: status=%d body=%s", created.Status, created.Body)
	}
	if got := performJSON(t, http.MethodGet, paasEndpoint+"/v1/platform/operations/"+string(operation.ID), credential, nil); got.Status != http.StatusOK {
		t.Fatalf("platform Operation query=%d", got.Status)
	}
	if got := performJSON(t, http.MethodGet, paasEndpoint+"/v1/operations/"+string(operation.ID), credential, nil); got.Status != http.StatusNotFound {
		t.Fatalf("tenant Operation route read platform Operation=%d", got.Status)
	}
	initial := readProcessHost(t, paasEndpoint, credential)
	waitDatabase(t, ctx, "background node refresh without a reader", func() (bool, error) {
		var observed time.Time
		err := admin.QueryRow(ctx, `SELECT (document#>>'{status,usage,observedAt}')::timestamptz FROM paas.execution_targets WHERE id=$1`, processHostTarget).Scan(&observed)
		return observed.After(initial.Status.Usage.ObservedAt), err
	})
	measured := readProcessHost(t, paasEndpoint, credential)
	if measured.Metadata.ResourceVersion != initial.Metadata.ResourceVersion || !measured.Status.Usage.ObservedAt.After(initial.Status.Usage.ObservedAt) {
		t.Fatal("background node samples changed placement version or stopped")
	}
	node.unavailable.Store(true)
	waitProcessHostHealth(t, ctx, admin, "UNAVAILABLE")
	unavailable := readProcessHost(t, paasEndpoint, credential)
	if unavailable.Status.Capacity != measured.Status.Capacity || unavailable.Status.ObservedAt.Before(measured.Status.ObservedAt) {
		t.Fatal("node outage fabricated capacity or lost retained observation")
	}
	replay := performJSONWithIdempotency(t, http.MethodPost, paasEndpoint+"/v1/execution-targets", credential, "register-process-node", processHostRegistration())
	var replayOperation paasv1.Operation
	if replay.Status != http.StatusOK || json.Unmarshal(replay.Body, &replayOperation) != nil || replayOperation.ID != operation.ID {
		t.Fatal("node outage broke committed admission replay")
	}
	node.unavailable.Store(false)
	waitProcessHostHealth(t, ctx, admin, "READY")
	waitAllPaaSOutboxDelivered(t, ctx, admin)
	response := performJSON(t, http.MethodPost, auditEndpoint+"/v1/platform/records:query", credential, auditv1.QueryRecordsRequest{PageSize: 200})
	var page auditv1.RecordPage
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &page) != nil || auditv1.ValidateRecordPage(page) != nil {
		t.Fatal("cannot query installation admission Audit")
	}
	for _, record := range page.Records {
		if record.Event.OperationID != auditv1.OperationID(operation.ID) {
			continue
		}
		if record.Event.Action != auditv1.ActionPaaSExecutionTargetRegistered || record.Event.Target.ID != processHostTarget || record.Event.Actor.ID != "principal-admin" || record.Event.InstallationID != operation.InstallationID || record.Event.TenantID != "" {
			t.Fatal("admitted node Audit lost exact authority")
		}
		var bound bool
		if err := admin.QueryRow(ctx, `SELECT allowed AND action_name='paas.execution-target.register' AND target_kind='EXECUTION_TARGET' AND target_id=$2 AND request_id=$3 AND principal_id='principal-admin' AND document->>'installationId'='installation-process' FROM iam.authorization_decisions WHERE id=$1`, record.Event.IAMDecisionID, processHostTarget, record.Event.RequestID).Scan(&bound); err != nil || !bound {
			t.Fatalf("host fact lacks exact original IAM resource decision: %v", err)
		}
		wrong := record.Event
		wrong.EventID = "event-wrong-platform"
		wrong.InstallationID = "another-installation"
		if got := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", paasServiceCredential, wrong); got.Status != http.StatusForbidden {
			t.Fatalf("wrong installation Audit accepted=%d", got.Status)
		}
		if got := performJSON(t, http.MethodPost, auditEndpoint+"/v1/events", iamServiceCredential, record.Event); got.Status != http.StatusForbidden {
			t.Fatalf("wrong source Audit accepted=%d", got.Status)
		}
		return record
	}
	t.Fatal("registered node Audit was not delivered")
	return auditv1.AuditRecord{}
}

func readProcessHost(t *testing.T, endpoint, credential string) paasv1.ExecutionTarget {
	t.Helper()
	response := performJSON(t, http.MethodGet, endpoint+"/v1/execution-targets/"+processHostTarget, credential, nil)
	var target paasv1.ExecutionTarget
	if response.Status != http.StatusOK || json.Unmarshal(response.Body, &target) != nil || paasv1.ValidateExecutionTarget(target) != nil || target.Metadata.ID != processHostTarget || target.Status.Usage == nil {
		t.Fatalf("node query=%d body=%s", response.Status, response.Body)
	}
	return target
}

func waitProcessHostHealth(t *testing.T, ctx context.Context, admin *pgx.Conn, health string) {
	t.Helper()
	waitDatabase(t, ctx, "node health "+health, func() (bool, error) {
		var current string
		err := admin.QueryRow(ctx, `SELECT document#>>'{status,health}' FROM paas.execution_targets WHERE id=$1`, processHostTarget).Scan(&current)
		return current == health, err
	})
}

func assertProcessHostAccess(t *testing.T, endpoint, credential string, status int) {
	t.Helper()
	for _, path := range []string{"/v1/execution-pools/" + processHostPool, "/v1/execution-targets/" + processHostTarget} {
		if response := performJSON(t, http.MethodGet, endpoint+path, credential, nil); response.Status != status {
			t.Fatalf("platform host access %s status=%d want=%d", path, response.Status, status)
		}
	}
	response := performJSONWithIdempotency(t, http.MethodPost, endpoint+"/v1/execution-targets", credential, "register-process-node", processHostRegistration())
	if response.Status != status {
		t.Fatalf("host replay skipped current authorization: status=%d want=%d", response.Status, status)
	}
}
