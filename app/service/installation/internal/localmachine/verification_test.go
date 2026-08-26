package localmachine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

var verificationTestTime = time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)

func TestHTTPInstallationVerifierPollsExactPaaSAndAuditFacts(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage verification fixture: %v", err)
	}
	credential := readTestFile(t, plan.Root, layout.InstallationVerifierCredential)
	defer clear(credential)
	paasCalls := 0
	auditCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.RawQuery != "" ||
			request.Header.Get("Authorization") != "Bearer "+string(credential) ||
			request.Header.Get("Matrix-Subject-Credential") != "" {
			t.Errorf("verification request method=%s path=%s", request.Method, request.URL.RequestURI())
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case paasVerificationPath:
			paasCalls++
			var body paasv1.VerifyInstallationRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
				body.InstallationID != plan.InstallationID ||
				body.ReleaseID != plan.Bundle.Manifest.Release.ID {
				t.Errorf("PaaS verification request=%#v err=%v", body, err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			state := paasv1.InstallationVerificationPending
			operationState := paasv1.OperationAccepted
			deploymentPhase := paasv1.DeploymentPending
			if paasCalls > 1 {
				state = paasv1.InstallationVerificationReady
				operationState = paasv1.OperationSucceeded
				deploymentPhase = paasv1.DeploymentReady
			}
			_ = json.NewEncoder(response).Encode(paasv1.InstallationVerification{
				APIVersion: paasv1.APIVersion, Kind: "InstallationVerification",
				InstallationID: body.InstallationID, ReleaseID: body.ReleaseID,
				State: state, DeploymentID: "deployment-verification",
				Generation: 1, OperationID: "operation-verification",
				OperationState: operationState, DeploymentPhase: deploymentPhase,
				CheckedAt: verificationTestTime,
			})
		case auditVerificationPath:
			auditCalls++
			var body auditv1.VerifyInstallationRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
				body != (auditv1.VerifyInstallationRequest{
					InstallationID: plan.InstallationID,
					OperationID:    "operation-verification",
					DeploymentID:   "deployment-verification",
				}) {
				t.Errorf("Audit verification request=%#v err=%v", body, err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			result := auditv1.InstallationVerification{
				APIVersion: auditv1.APIVersion, Kind: "InstallationVerification",
				InstallationID: body.InstallationID, OperationID: body.OperationID,
				DeploymentID: body.DeploymentID,
				State:        auditv1.InstallationVerificationPending,
				CheckedAt:    verificationTestTime,
			}
			if auditCalls > 1 {
				result.State = auditv1.InstallationVerificationVerified
				result.EventID = "event-verification"
				result.IAMDecisionID = "decision-verification"
				result.RecordSequence = 7
				result.FromSequence = 1
				result.ToSequence = 7
				result.RecordHash = "sha256:" + strings.Repeat("a", 64)
			}
			_ = json.NewEncoder(response).Encode(result)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	plan.Port = testServerPort(t, server.URL)

	verifier := newHTTPInstallationVerifier(server.Client())
	verifier.maximumPolls = 4
	verifier.wait = func(context.Context, time.Duration) error { return nil }
	if err := verifier.Verify(context.Background(), plan); err != nil {
		t.Fatalf("verify fixed installation flow: %v", err)
	}
	if paasCalls != 2 || auditCalls != 2 {
		t.Fatalf("verification calls PaaS=%d Audit=%d", paasCalls, auditCalls)
	}
}

func TestHTTPInstallationVerifierNormalizesUnavailableProviderOutput(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage verification fixture: %v", err)
	}
	credential := readTestFile(t, plan.Root, layout.InstallationVerifierCredential)
	defer clear(credential)
	native := "native provider failed with " + string(credential) + " at /private/provider/path"
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		calls++
		response.Header().Set("Content-Type", "text/plain")
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = response.Write([]byte(native))
	}))
	defer server.Close()
	plan.Port = testServerPort(t, server.URL)
	verifier := newHTTPInstallationVerifier(server.Client())
	verifier.maximumPolls = 2
	verifier.wait = func(context.Context, time.Duration) error { return nil }
	err := verifier.Verify(context.Background(), plan)
	if !errors.Is(err, platformcommand.ErrEffectUnavailable) || calls != 2 ||
		strings.Contains(err.Error(), native) ||
		bytes.Contains([]byte(err.Error()), credential) ||
		strings.Contains(err.Error(), "/private/provider/path") {
		t.Fatalf("normalized verification error=%v calls=%d", err, calls)
	}
}

func TestHTTPInstallationVerifierRejectsMismatchedPaaSIdentity(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage verification fixture: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(paasv1.InstallationVerification{
			APIVersion: paasv1.APIVersion, Kind: "InstallationVerification",
			InstallationID: plan.InstallationID, ReleaseID: "different-release",
			State: paasv1.InstallationVerificationReady, DeploymentID: "deployment-verification",
			Generation: 1, OperationID: "operation-verification",
			OperationState: paasv1.OperationSucceeded, DeploymentPhase: paasv1.DeploymentReady,
			CheckedAt: verificationTestTime,
		})
	}))
	defer server.Close()
	plan.Port = testServerPort(t, server.URL)
	verifier := newHTTPInstallationVerifier(server.Client())
	verifier.maximumPolls = 1
	if err := verifier.Verify(
		context.Background(), plan,
	); !errors.Is(err, platformcommand.ErrEffectVerification) {
		t.Fatalf("mismatched PaaS verification error=%v", err)
	}
}

func TestEffectsOwnsTheFixedVerificationPhase(t *testing.T) {
	plan := newInstallPlan(t)
	verifier := &recordingInstallationVerifier{}
	effects := &Effects{
		runtime: &imageRuntime{}, entropy: rand.Reader, verifier: verifier,
	}
	if err := effects.ApplyInstallPhase(
		context.Background(), plan, lifecycle.PhaseVerifying,
	); err != nil {
		t.Fatalf("apply fixed verification phase: %v", err)
	}
	if verifier.calls != 1 || verifier.plan.InstallationID != plan.InstallationID {
		t.Fatalf("verification effect calls=%d plan=%#v", verifier.calls, verifier.plan)
	}
	if err := effects.ApplyInstallPhase(
		context.Background(), plan, lifecycle.PhaseReady,
	); !errors.Is(err, platformcommand.ErrEffectVerification) {
		t.Fatalf("unexpected install phase error=%v", err)
	}
}

type recordingInstallationVerifier struct {
	calls int
	plan  platformcommand.InstallPlan
}

func (verifier *recordingInstallationVerifier) Verify(
	_ context.Context,
	plan platformcommand.InstallPlan,
) error {
	verifier.calls++
	verifier.plan = plan
	return nil
}

func testServerPort(t *testing.T, rawURL string) uint16 {
	t.Helper()
	target, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse verification server URL: %v", err)
	}
	_, portText, err := net.SplitHostPort(target.Host)
	if err != nil {
		t.Fatalf("split verification server address: %v", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("parse verification server port: %v", err)
	}
	return uint16(port)
}
