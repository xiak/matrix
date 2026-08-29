package nethttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/nodeexporter"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
)

var nodeIdentity = nodev1.Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"}

const controllerID = "worker-a"

type sourceFunc func(context.Context) (paasv1.ExecutionTargetObservation, error)

func (fn sourceFunc) Current(ctx context.Context) (paasv1.ExecutionTargetObservation, error) {
	return fn(ctx)
}

type deploymentService struct{}

func (deploymentService) Ready(context.Context) error { return nil }

func (deploymentService) ExecuteDeployment(
	context.Context,
	nodev1.DeploymentEffectRequest,
) (paasv1.AdapterResult, error) {
	return paasv1.AdapterResult{}, errors.New("unexpected Deployment effect")
}

func (deploymentService) ObserveDeployment(
	context.Context,
	paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	return paasv1.DeploymentObservation{}, errors.New("unexpected Deployment observation")
}

func (deploymentService) ObserveDeploymentRuntime(
	context.Context,
	paasv1.ObserveDeploymentRuntimeRequest,
) (paasv1.DeploymentRuntimeObservation, error) {
	return paasv1.DeploymentRuntimeObservation{}, errors.New("unexpected Deployment runtime observation")
}

type deploymentServiceFuncs struct {
	ready   func(context.Context) error
	execute func(context.Context, nodev1.DeploymentEffectRequest) (paasv1.AdapterResult, error)
	observe func(context.Context, paasv1.ObserveDeploymentRequest) (paasv1.DeploymentObservation, error)
	runtime func(context.Context, paasv1.ObserveDeploymentRuntimeRequest) (paasv1.DeploymentRuntimeObservation, error)
}

func (service deploymentServiceFuncs) Ready(ctx context.Context) error {
	if service.ready == nil {
		return nil
	}
	return service.ready(ctx)
}

func (service deploymentServiceFuncs) ExecuteDeployment(
	ctx context.Context,
	request nodev1.DeploymentEffectRequest,
) (paasv1.AdapterResult, error) {
	return service.execute(ctx, request)
}

func (service deploymentServiceFuncs) ObserveDeployment(
	ctx context.Context,
	request paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	return service.observe(ctx, request)
}

func (service deploymentServiceFuncs) ObserveDeploymentRuntime(
	ctx context.Context,
	request paasv1.ObserveDeploymentRuntimeRequest,
) (paasv1.DeploymentRuntimeObservation, error) {
	if service.runtime == nil {
		return paasv1.DeploymentRuntimeObservation{}, errors.New("unexpected Deployment runtime observation")
	}
	return service.runtime(ctx, request)
}

type deploymentArtifactResolver struct{}

func (deploymentArtifactResolver) ResolveDeploymentArtifact(
	_ context.Context,
	artifact paasv1.ArtifactRef,
) (nodev1.ResolvedArtifact, error) {
	return nodev1.ResolvedArtifact{
		ArtifactDigest: artifact.Digest,
		LocalImageID:   deploymentTestDigest('d'),
	}, nil
}

type deploymentSecretResolver struct {
	content []byte
}

func (resolver deploymentSecretResolver) ResolveSecret(
	_ context.Context,
	_ paasv1.SecretVersionReference,
) ([]byte, error) {
	return bytes.Clone(resolver.content), nil
}

func observedTarget() paasv1.ExecutionTargetObservation {
	capacity := paasv1.Capacity{CPUMillis: 2000, MemoryBytes: 8000, StorageBytes: 10000, WorkloadSlots: 2}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return paasv1.ExecutionTargetObservation{
		ExecutionTargetID: nodeIdentity.ExecutionTargetID, IdentityFingerprint: "sha256:" + strings.Repeat("a", 64),
		Labels: map[string]string{"matrix-os": "linux"}, Capacity: capacity, Allocatable: capacity,
		Health: paasv1.ExecutionTargetHealthReady, SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		ObservedAt: now,
		Usage: &paasv1.ExecutionTargetUsage{
			ObservedAt: now, ValidUntil: now.Add(nodev1.MaximumObservationAge),
			CPU:    paasv1.CPUUsage{State: paasv1.MeasurementUnavailable},
			Memory: paasv1.MemoryUsage{State: paasv1.MeasurementUnavailable}, FilesystemsState: paasv1.MeasurementUnavailable,
		},
	}
}

func observationCommand() paasv1.AdapterCommandEnvelope {
	return paasv1.AdapterCommandEnvelope{
		OperationID: "operation-a", CommandID: "command-a", Attempt: 1, Action: paasv1.AdapterObserveExecutionTarget,
		Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, ExecutionTargetID: nodeIdentity.ExecutionTargetID,
		RequestDigest: "sha256:" + strings.Repeat("b", 64), BindingRef: "binding-a",
		Deadline: time.Now().UTC().Truncate(time.Microsecond).Add(5 * time.Second),
	}
}

func TestRealMTLSBindsBothPeersAndReturnsOnlyTheSelectedNode(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	var calls atomic.Int32
	server := startNode(t, node, sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		calls.Add(1)
		return observedTarget(), nil
	}), 8)
	client := newClient(t, server.URL, controller.credentials, nodeIdentity, controllerID)
	value, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
	if err != nil || value.ExecutionTargetID != nodeIdentity.ExecutionTargetID || calls.Load() != 1 {
		t.Fatalf("authenticated observation failed: %#v, %v", value, err)
	}
	otherURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, "worker-b")
	other := authority.issue(t, otherURI, x509.ExtKeyUsageClientAuth, false)
	wrongController := newClient(t, server.URL, other.credentials, nodeIdentity, "worker-b")
	if _, err := wrongController.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()}); err == nil {
		t.Fatal("another controller identity passed mTLS")
	}
	wrongNodeIdentity := nodeIdentity
	wrongNodeIdentity.ExecutionTargetID = "target-b"
	wrongNode := newClient(t, server.URL, controller.credentials, wrongNodeIdentity, controllerID)
	command := observationCommand()
	command.ExecutionTargetID = wrongNodeIdentity.ExecutionTargetID
	if _, err := wrongNode.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: command}); err == nil {
		t.Fatal("trusted CA alone admitted another node identity")
	}
	foreign := newAuthority(t).issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	expired := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, true)
	for name, certificate := range map[string]*tls.Certificate{"missing certificate": nil, "untrusted issuer": &foreign.pair, "expired certificate": &expired.pair} {
		t.Run(name, func(t *testing.T) {
			raw := authority.rawClient(certificate)
			defer raw.CloseIdleConnections()
			response, err := raw.Post(server.URL+nodev1.ObservationPath, "application/json", bytes.NewReader(requestBody(t, observationCommand())))
			if response != nil {
				response.Body.Close()
			}
			if err == nil {
				t.Fatal("unauthenticated peer reached the HTTP boundary")
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatalf("rejected peer reached the observation source: %d calls", calls.Load())
	}
}

func TestRealMTLSDeploymentBindsExactTargetMaterialsAndObservation(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	execution := deploymentExecutionFixture(t)
	var effectCalls, observationCalls, runtimeCalls atomic.Int32
	var receivedSecret string
	var receivedSecretBytes []byte
	service := deploymentServiceFuncs{
		execute: func(_ context.Context, request nodev1.DeploymentEffectRequest) (paasv1.AdapterResult, error) {
			effectCalls.Add(1)
			if request.Identity != nodeIdentity || request.Execution.Command.ExecutionTargetID != nodeIdentity.ExecutionTargetID ||
				request.Execution.Command.BindingRef != "binding-a" || len(request.Materials.Artifacts) != 1 ||
				request.Materials.Artifacts[0].LocalImageID != deploymentTestDigest('d') || len(request.Materials.Secrets) != 1 {
				t.Fatal("node service received a retargeted or incomplete effect")
			}
			receivedSecret = string(request.Materials.Secrets[0].Value)
			receivedSecretBytes = request.Materials.Secrets[0].Value
			return paasv1.AdapterResult{
				CommandID: request.Execution.Command.CommandID,
				State:     paasv1.AdapterResultSucceeded, Receipt: "node-receipt",
				ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
			}, nil
		},
		observe: func(_ context.Context, request paasv1.ObserveDeploymentRequest) (paasv1.DeploymentObservation, error) {
			observationCalls.Add(1)
			return deploymentObservationFixture(request), nil
		},
		runtime: func(_ context.Context, request paasv1.ObserveDeploymentRuntimeRequest) (paasv1.DeploymentRuntimeObservation, error) {
			runtimeCalls.Add(1)
			return deploymentRuntimeObservationFixture(request), nil
		},
	}
	handler, err := New(sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		return observedTarget(), nil
	}), service, Config{Identity: nodeIdentity, ControllerID: controllerID, BindingRef: "binding-a"})
	if err != nil {
		t.Fatal(err)
	}
	server := startTLSServer(t, node, handler)
	client := newDeploymentClient(t, server.URL, controller.credentials, nodeIdentity, "binding-a")
	result, err := client.ApplyDeployment(context.Background(), execution)
	if err != nil || result.State != paasv1.AdapterResultSucceeded || effectCalls.Load() != 1 ||
		receivedSecret != "secret-value" {
		t.Fatalf("remote effect failed: %#v, %v", result, err)
	}
	if !bytes.Equal(receivedSecretBytes, make([]byte, len(receivedSecretBytes))) {
		t.Fatal("node handler retained decoded secret bytes after the effect")
	}
	observe := deploymentObserveRequest(execution)
	observation, err := client.ObserveDeployment(context.Background(), observe)
	if err != nil || observation.Phase != paasv1.DeploymentReady || observationCalls.Load() != 1 {
		t.Fatalf("remote observation failed: %#v, %v", observation, err)
	}
	runtimeObservation, err := client.ObserveDeploymentRuntime(
		context.Background(), deploymentRuntimeObserveRequest(execution),
	)
	if err != nil || len(runtimeObservation.Instances) != 1 || runtimeCalls.Load() != 1 ||
		runtimeObservation.Instances[0].ID != "instance-0123456789abcdef0123456789abcdef" {
		t.Fatalf("remote runtime observation failed: %#v, %v", runtimeObservation, err)
	}

	wrong := deploymentExecutionFixture(t)
	wrong.Command.BindingRef = "binding-b"
	wrong.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(wrong)
	wrongClient := newDeploymentClient(t, server.URL, controller.credentials, nodeIdentity, "binding-b")
	_, err = wrongClient.ApplyDeployment(context.Background(), wrong)
	var fault paasv1.AdapterFault
	if !errors.As(err, &fault) || fault.Normalized.Class != paasv1.AdapterErrorPermissionDenied || effectCalls.Load() != 1 {
		t.Fatalf("wrong binding reached the node effect: %v", err)
	}
	_, err = wrongClient.ObserveDeploymentRuntime(
		context.Background(), deploymentRuntimeObserveRequest(execution),
	)
	if !errors.As(err, &fault) || fault.Normalized.Class != paasv1.AdapterErrorPermissionDenied || runtimeCalls.Load() != 1 {
		t.Fatalf("wrong binding reached the node runtime observation: %v", err)
	}
}

func TestLostRemoteEffectResponseBecomesUnknownThenObservesSameTarget(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	execution := deploymentExecutionFixture(t)
	var effects, observations atomic.Int32
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case nodev1.DeploymentEffectPath:
			value, err := nodev1.DecodeDeploymentEffectRequest(request.Body)
			if err != nil || value.Identity != nodeIdentity {
				t.Error("lost-response fixture received invalid effect")
				return
			}
			defer value.Materials.Clear()
			effects.Add(1)
			connection, _, err := response.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		case nodev1.DeploymentObservationPath:
			value, err := nodev1.DecodeDeploymentObservationRequest(request.Body)
			if err != nil || value.Identity != nodeIdentity ||
				value.Request.Command.ExecutionTargetID != execution.Command.ExecutionTargetID {
				t.Error("lost-response recovery observed another target")
				return
			}
			observations.Add(1)
			encoded, _ := json.Marshal(nodev1.DeploymentObservationResponse{
				APIVersion: nodev1.APIVersion, Kind: nodev1.DeploymentObservationResponseKind,
				Identity: nodeIdentity, CommandID: value.Request.Command.CommandID,
				Observation: deploymentObservationFixture(value.Request),
			})
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write(encoded)
		default:
			response.WriteHeader(http.StatusBadRequest)
		}
	})
	server := startTLSServer(t, node, handler)
	client := newDeploymentClient(t, server.URL, controller.credentials, nodeIdentity, "binding-a")
	_, err := client.ApplyDeployment(context.Background(), execution)
	var fault paasv1.AdapterFault
	if !errors.As(err, &fault) || fault.Normalized.Class != paasv1.AdapterErrorUnknownOutcome || effects.Load() != 1 {
		t.Fatalf("lost response was not classified as unknown: %v", err)
	}
	observation, err := client.ObserveDeployment(context.Background(), deploymentObserveRequest(execution))
	if err != nil || observation.Phase != paasv1.DeploymentReady || observations.Load() != 1 || effects.Load() != 1 {
		t.Fatalf("same-target recovery observation failed: %#v, %v", observation, err)
	}
}

func TestDeploymentClientRejectsUncorrelatedEffectResponsesAsUnknown(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	for _, problem := range []string{"identity", "command", "unknown field", "wrong content type", "redirect"} {
		t.Run(problem, func(t *testing.T) {
			handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				value, err := nodev1.DecodeDeploymentEffectRequest(request.Body)
				if err != nil {
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				defer value.Materials.Clear()
				if problem == "redirect" {
					response.Header().Set("Location", "https://127.0.0.1:1/another-target")
					response.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				identity := nodeIdentity
				commandID := value.Execution.Command.CommandID
				if problem == "identity" {
					identity.ExecutionTargetID = "target-b"
				}
				if problem == "command" {
					commandID = "other-command"
				}
				result := paasv1.AdapterResult{
					CommandID: commandID, State: paasv1.AdapterResultSucceeded,
					Receipt: "node-receipt", ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
				}
				encoded, _ := json.Marshal(nodev1.DeploymentEffectResponse{
					APIVersion: nodev1.APIVersion, Kind: nodev1.DeploymentEffectResponseKind,
					Identity: identity, CommandID: commandID, Result: result,
				})
				if problem == "unknown field" {
					encoded = bytes.Replace(encoded, []byte(`"result":`), []byte(`"shell":"/bin/sh","result":`), 1)
				}
				contentType := "application/json"
				if problem == "wrong content type" {
					contentType = "text/plain"
				}
				response.Header().Set("Content-Type", contentType)
				_, _ = response.Write(encoded)
			})
			server := startTLSServer(t, node, handler)
			client := newDeploymentClient(t, server.URL, controller.credentials, nodeIdentity, "binding-a")
			_, err := client.ApplyDeployment(context.Background(), deploymentExecutionFixture(t))
			var fault paasv1.AdapterFault
			if !errors.As(err, &fault) || fault.Normalized.Class != paasv1.AdapterErrorUnknownOutcome {
				t.Fatalf("uncorrelated effect response was accepted: %v", err)
			}
		})
	}
}

func TestAuthenticatedRequestsRejectInvalidInputBeforeReadingTheHost(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	var calls atomic.Int32
	server := startNode(t, node, sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		calls.Add(1)
		return observedTarget(), nil
	}), 8)
	raw := authority.rawClient(&controller.pair)
	defer raw.CloseIdleConnections()
	valid := string(requestBody(t, observationCommand()))
	expired := observationCommand()
	expired.Deadline = time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	distant := observationCommand()
	distant.Deadline = time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
	for name, source := range map[string]string{
		"unknown":            strings.Replace(valid, `"command":`, `"shell":"/bin/sh","command":`, 1),
		"duplicate":          strings.Replace(valid, `"bindingRef":"binding-a"`, `"bindingRef":"binding-a","bindingRef":"binding-a"`, 1),
		"case alias":         strings.Replace(valid, `"bindingRef":`, `"BindingRef":`, 1),
		"wrong binding":      strings.Replace(valid, "binding-a", "binding-b", 1),
		"wrong installation": strings.Replace(valid, "installation-a", "installation-b", 1),
		"tenant identity":    strings.Replace(valid, `"kind":"PLATFORM"`, `"kind":"TENANT","tenantId":"tenant-a"`, 1),
		"expired":            string(requestBody(t, expired)), "distant deadline": string(requestBody(t, distant)),
		"oversize": valid + strings.Repeat(" ", nodev1.MaximumObservationRequestBytes),
		"deep":     `{"command":` + strings.Repeat(`[`, 64) + `0` + strings.Repeat(`]`, 64) + `}`,
		"trailing": valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			response, err := raw.Post(server.URL+nodev1.ObservationPath, "application/json", strings.NewReader(source))
			if err != nil {
				// A size rejection can close the connection before Windows has
				// finished writing the body. Refusal without source access is the
				// contract; successful delivery of an error body is not.
				if name == "oversize" {
					return
				}
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
			if response.StatusCode < 400 || response.StatusCode >= 500 || strings.Contains(string(body), "/bin/sh") {
				t.Fatalf("invalid request not safely denied: %d %s", response.StatusCode, body)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid request read the host: %d calls", calls.Load())
	}
	// A plaintext mount and forwarded certificate headers are not authentication.
	handler, err := New(sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		t.Fatal("plaintext request read the host")
		return paasv1.ExecutionTargetObservation{}, nil
	}), deploymentService{}, Config{Identity: nodeIdentity, ControllerID: controllerID, BindingRef: "binding-a"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, nodev1.ObservationPath, strings.NewReader(valid))
	request.Header.Set("X-Forwarded-Client-Cert", controllerURI)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatal("plaintext handler admitted forwarded identity")
	}
}

func TestSelfReadinessRequiresFreshCollectorButCannotReadControllerSurface(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	var available atomic.Bool
	var calls atomic.Int32
	value := observedTarget()
	value.Usage.CPU = paasv1.CPUUsage{State: paasv1.MeasurementAvailable,
		Value: &paasv1.CPUUsageValue{LogicalCPUs: 2, WindowMillis: 5000}}
	value.Usage.Memory = paasv1.MemoryUsage{State: paasv1.MeasurementAvailable,
		Value: &paasv1.MemoryUsageValue{TotalBytes: 8000, AvailableBytes: 6000, UsedBytes: 2000}}
	value.Usage.FilesystemsState = paasv1.MeasurementAvailable
	value.Usage.Filesystems = []paasv1.FilesystemUsage{{Device: "disk-a", MountPoint: "/", FilesystemType: "ext4",
		State: paasv1.MeasurementAvailable, Value: &paasv1.FilesystemUsageValue{
			TotalBytes: 10000, UsedBytes: 1000, AvailableBytes: 9000, InodesState: paasv1.MeasurementUnsupported}}}
	if err := paasv1.ValidateExecutionTargetObservation(value); err != nil {
		t.Fatal(err)
	}
	server := startNode(t, node, sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		calls.Add(1)
		if available.Load() {
			return value, nil
		}
		return observedTarget(), nil
	}), 2)
	client, err := nodehttps.NewReadinessClient(server.URL, nodeIdentity, value.IdentityFingerprint, node.credentials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if _, err := client.Verify(context.Background()); err == nil {
		t.Fatal("missing collector was reported as a ready installation")
	}
	available.Store(true)
	first, err := client.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Verify(context.Background())
	if err != nil || first != second || first.ObservedAt != value.ObservedAt || first.ValidUntil != value.Usage.ValidUntil {
		t.Fatalf("readiness changed observation freshness: %#v, %#v, %v", first, second, err)
	}
	raw := authority.rawClient(&node.pair)
	defer raw.CloseIdleConnections()
	before := calls.Load()
	response, err := raw.Post(server.URL+nodev1.ObservationPath, "application/json", bytes.NewReader(requestBody(t, observationCommand())))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || calls.Load() != before {
		t.Fatal("self readiness credential gained controller observation authority")
	}
	for _, suffix := range []string{"?", "?command=execute", "/extra"} {
		response, err := raw.Get(server.URL + nodev1.ReadinessPath + suffix)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode < 400 || calls.Load() != before {
			t.Fatal("request-shaped readiness was admitted")
		}
	}
	otherURI, _ := nodev1.NodeURI(nodev1.Identity{InstallationID: nodeIdentity.InstallationID, ExecutionTargetID: "target-b"})
	other := authority.issue(t, otherURI, x509.ExtKeyUsageClientAuth, false)
	wrong := authority.rawClient(&other.pair)
	defer wrong.CloseIdleConnections()
	response, err = wrong.Get(server.URL + nodev1.ReadinessPath)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || calls.Load() != before {
		t.Fatal("another node identity reached self readiness")
	}
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	if _, err := nodehttps.NewReadinessClient(server.URL, nodeIdentity, value.IdentityFingerprint, controller.credentials); err == nil {
		t.Fatal("readiness accepts a controller credential")
	}
}

func TestNodeBoundsConcurrencyAndNeverSerializesProviderErrors(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := startNode(t, node, sourceFunc(func(ctx context.Context) (paasv1.ExecutionTargetObservation, error) {
		entered <- struct{}{}
		select {
		case <-ctx.Done():
			return paasv1.ExecutionTargetObservation{}, ctx.Err()
		case <-release:
			return paasv1.ExecutionTargetObservation{}, errors.New("provider secret=password /private/path")
		}
	}), 1)
	client := newClient(t, server.URL, controller.credentials, nodeIdentity, controllerID)
	first := make(chan error, 1)
	go func() {
		_, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first observation did not start")
	}
	_, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
	var fault paasv1.AdapterFault
	if !errors.As(err, &fault) || fault.Normalized.Code != paasv1.ErrorRateLimited {
		t.Fatalf("concurrency limit error = %v", err)
	}
	close(release)
	select {
	case err := <-first:
		if !errors.As(err, &fault) || fault.Normalized.Code != paasv1.ErrorExecutionTargetUnavailable ||
			strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "/private/path") {
			t.Fatalf("native error escaped: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observation did not finish")
	}
}

func TestNodeObservationFailsClosedWhenDeploymentRuntimeIsUnavailable(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	var hostCalls atomic.Int32
	handler, err := New(sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		hostCalls.Add(1)
		return observedTarget(), nil
	}), deploymentServiceFuncs{
		ready: func(context.Context) error {
			return errors.New("docker socket /private/path password=secret is unavailable")
		},
		execute: func(context.Context, nodev1.DeploymentEffectRequest) (paasv1.AdapterResult, error) {
			return paasv1.AdapterResult{}, errors.New("unexpected effect")
		},
		observe: func(context.Context, paasv1.ObserveDeploymentRequest) (paasv1.DeploymentObservation, error) {
			return paasv1.DeploymentObservation{}, errors.New("unexpected Deployment observation")
		},
	}, Config{Identity: nodeIdentity, ControllerID: controllerID, BindingRef: "binding-a"})
	if err != nil {
		t.Fatal(err)
	}
	server := startTLSServer(t, node, handler)
	client := newClient(t, server.URL, controller.credentials, nodeIdentity, controllerID)
	_, err = client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
	var fault paasv1.AdapterFault
	if !errors.As(err, &fault) || fault.Normalized.Class != paasv1.AdapterErrorUnavailable ||
		hostCalls.Load() != 0 || strings.Contains(err.Error(), "/private/path") || strings.Contains(err.Error(), "password") {
		t.Fatalf("unready executor did not close node admission safely: %v", err)
	}
}

func TestClientRejectsUncorrelatedResponsesAndRedirects(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	for _, problem := range []string{"command", "identity", "fingerprint", "future", "stale", "missing usage", "future usage", "unknown", "oversize", "redirect"} {
		t.Run(problem, func(t *testing.T) {
			handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if problem == "redirect" {
					response.Header().Set("Location", "https://127.0.0.1:1/should-not-be-followed")
					response.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				command, err := nodev1.DecodeObservationRequest(request.Body)
				if err != nil {
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				value := nodev1.ObservationResponse{
					APIVersion: nodev1.APIVersion, Kind: nodev1.ObservationResponseKind,
					Identity: nodeIdentity, CommandID: command.Command.CommandID, Observation: observedTarget(),
				}
				switch problem {
				case "command":
					value.CommandID = "other-command"
				case "identity":
					value.Identity.InstallationID = "installation-b"
				case "fingerprint":
					value.Observation.IdentityFingerprint = "sha256:" + strings.Repeat("c", 64)
				case "future":
					value.Observation.ObservedAt = time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
				case "stale":
					value.Observation.ObservedAt = time.Now().UTC().Add(-nodev1.MaximumObservationAge).Truncate(time.Microsecond)
				case "missing usage":
					value.Observation.Usage = nil
				case "future usage":
					value.Observation.Usage.ObservedAt = time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
					value.Observation.Usage.ValidUntil = value.Observation.Usage.ObservedAt.Add(time.Second)
				}
				body, _ := json.Marshal(value)
				if problem == "unknown" {
					body = append([]byte(`{"privateKey":"secret",`), body[1:]...)
				}
				if problem == "oversize" {
					body = append(body, bytes.Repeat([]byte(" "), nodev1.MaximumObservationResponseBytes)...)
				}
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write(body)
			})
			server := startTLSServer(t, node, handler)
			client := newClient(t, server.URL, controller.credentials, nodeIdentity, controllerID)
			_, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
			var fault paasv1.AdapterFault
			want := paasv1.ErrorAdapterRejected
			if problem == "stale" {
				want = paasv1.ErrorExecutionTargetUnavailable
			}
			if !errors.As(err, &fault) || fault.Normalized.Code != want || strings.Contains(err.Error(), "privateKey") {
				t.Fatalf("untrusted response accepted or leaked: %v", err)
			}
		})
	}
}

func TestEnrollmentAuthenticatesRolesAddressesAndMutualTrustBeforeEffects(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	collectorURI, _ := nodev1.CollectorURI(nodeIdentity)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	collector := authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
	if err := nodehttps.ValidateEnrollment(node.credentials, collector.credentials, nodeIdentity, "127.0.0.1:16443", "127.0.0.1:19100"); err != nil {
		t.Fatal("valid mutually trusted enrollment was rejected")
	}
	for _, test := range []struct {
		name                          string
		node, collector               nodehttps.Credentials
		nodeAddress, collectorAddress string
	}{
		{"untrusted collector", node.credentials, newAuthority(t).issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false).credentials, "127.0.0.1:16443", "127.0.0.1:19100"},
		{"untrusted node", newAuthority(t).issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth).credentials, collector.credentials, "127.0.0.1:16443", "127.0.0.1:19100"},
		{"node lacks client role", authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false).credentials, collector.credentials, "127.0.0.1:16443", "127.0.0.1:19100"},
		{"collector lacks server role", node.credentials, authority.issue(t, collectorURI, x509.ExtKeyUsageClientAuth, false).credentials, "127.0.0.1:16443", "127.0.0.1:19100"},
		{"collector cannot act as node", collector.credentials, collector.credentials, "127.0.0.1:16443", "127.0.0.1:19100"},
		{"node cannot act as collector", node.credentials, node.credentials, "127.0.0.1:16443", "127.0.0.1:19100"},
		{"expired node", authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, true, x509.ExtKeyUsageClientAuth).credentials, collector.credentials, "127.0.0.1:16443", "127.0.0.1:19100"},
		{"expired collector", node.credentials, authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, true).credentials, "127.0.0.1:16443", "127.0.0.1:19100"},
		{"node address not in certificate", node.credentials, collector.credentials, "127.0.0.2:16443", "127.0.0.1:19100"},
		{"collector address not in certificate", node.credentials, collector.credentials, "127.0.0.1:16443", "127.0.0.2:19100"},
		{"DNS listener", node.credentials, collector.credentials, "localhost:16443", "127.0.0.1:19100"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := nodehttps.ValidateEnrollment(test.node, test.collector, nodeIdentity, test.nodeAddress, test.collectorAddress); err == nil {
				t.Fatal("incompatible enrollment was admitted")
			}
		})
	}
}

func TestCollectorTransportRequiresTheExactLocalCollectorAndNodeIdentities(t *testing.T) {
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	collectorURI, _ := nodev1.CollectorURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageClientAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	foreign := newAuthority(t).issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
	for name, certificate := range map[string]issuedCertificate{
		"selected collector": authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false),
		"node role":          authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false),
		"untrusted":          foreign,
		"expired":            authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, true),
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/plain; version=0.0.4")
				_, _ = w.Write([]byte("# TYPE node_scrape_collector_success gauge\nnode_scrape_collector_success{collector=\"cpu\"} 0\n"))
			}))
			server.TLS = &tls.Config{
				MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate.pair},
				ClientCAs: authority.roots, ClientAuth: tls.RequireAndVerifyClientCert,
				VerifyConnection: func(state tls.ConnectionState) error {
					if !nodev1.MatchesIdentity(state.PeerCertificates[0].URIs, nodeURI) {
						return errors.New("wrong node identity")
					}
					return nil
				},
			}
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			collector, err := nodeexporter.New(nodeexporter.Config{Endpoint: server.URL, Identity: nodeIdentity, Credentials: node.credentials})
			if err != nil {
				t.Fatal(err)
			}
			defer collector.Close()
			_, err = collector.ObserveExecutionTargetUsage(context.Background())
			if name == "selected collector" {
				if err != nil || calls.Load() != 1 {
					t.Fatalf("authenticated collector rejected: %v", err)
				}
			} else if err != nodeexporter.ErrUnavailable || calls.Load() != 0 {
				t.Fatal("collector identity was not checked before HTTP")
			}
			if _, err := nodeexporter.New(nodeexporter.Config{Endpoint: server.URL, Identity: nodeIdentity, Credentials: controller.credentials}); err == nil {
				t.Fatal("controller identity can act as a node collector client")
			}
		})
	}
	for _, endpoint := range []string{"http://127.0.0.1:9100", "https://192.168.1.3:9100", "https://localhost:9100", "https://127.0.0.1:9100/metrics", "https://127.0.0.1:9100?target=other"} {
		if _, err := nodeexporter.New(nodeexporter.Config{Endpoint: endpoint, Identity: nodeIdentity, Credentials: node.credentials}); err == nil {
			t.Fatal("collector accepted a nonlocal or request-shaped endpoint")
		}
	}
}

func TestRealMTLSReloadsCredentialsAndRetiresBothOldPeers(t *testing.T) {
	oldAuthority, nextAuthority := newAuthority(t), newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	oldNode := oldAuthority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	nextNode := nextAuthority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	oldController := oldAuthority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	nextController := nextAuthority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	oldSecurity, err := nodehttps.ServerTLS(oldNode.credentials, nodeIdentity, controllerID)
	if err != nil {
		t.Fatal(err)
	}
	nextSecurity, err := nodehttps.ServerTLS(nextNode.credentials, nodeIdentity, controllerID)
	if err != nil {
		t.Fatal(err)
	}
	var activeServer atomic.Pointer[tls.Config]
	activeServer.Store(oldSecurity)
	var calls atomic.Int32
	handler, err := New(sourceFunc(func(context.Context) (paasv1.ExecutionTargetObservation, error) {
		calls.Add(1)
		return observedTarget(), nil
	}), deploymentService{}, Config{Identity: nodeIdentity, ControllerID: controllerID, BindingRef: "binding-a"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = oldSecurity.Clone()
	server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return activeServer.Load(), nil }
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	var current atomic.Pointer[nodehttps.Credentials]
	current.Store(&oldController.credentials)
	client, err := nodehttps.New(nodehttps.Config{Endpoint: server.URL, Identity: nodeIdentity,
		ControllerID: controllerID, BindingRef: "binding-a", ExpectedFingerprint: observedTarget().IdentityFingerprint,
		Credentials: func() (nodehttps.Credentials, error) {
			if value := current.Load(); value != nil {
				return *value, nil
			}
			return nodehttps.Credentials{}, errors.New("private credential path is unavailable")
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	observe := func(allowed bool) {
		t.Helper()
		before := calls.Load()
		_, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: observationCommand()})
		if allowed {
			if err != nil || calls.Load() != before+1 {
				t.Fatalf("current credential did not reach the node: %v", err)
			}
		} else if err == nil || calls.Load() != before || strings.Contains(err.Error(), "private credential") {
			t.Fatal("retired or unavailable credential reached the source or leaked provider input")
		}
	}
	observe(true)
	current.Store(nil)
	observe(false)
	current.Store(&nextController.credentials)
	observe(false) // The old server certificate is no longer trusted.
	activeServer.Store(nextSecurity)
	observe(true) // The existing client adopts the new files without reconstruction.
	retired := oldController.withTrust(t, nextAuthority.pem)
	current.Store(&retired.credentials)
	observe(false) // Server trust is current, but the old client identity is retired.
	current.Store(&nextController.credentials)
	observe(true)
	activeServer.Store(oldSecurity)
	observe(false)
}

func TestCredentialRenewalAndCompleteTrustRetirementAreDistinct(t *testing.T) {
	oldAuthority, nextAuthority := newAuthority(t), newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	collectorURI, _ := nodev1.CollectorURI(nodeIdentity)
	oldNode := oldAuthority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	oldCollector := oldAuthority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
	nextNode := nextAuthority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	nextCollector := nextAuthority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
	renewed := oldAuthority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	validate := func(beforeNode, beforeCollector, node, collector issuedCertificate, revoke bool) error {
		return nodehttps.ValidateCredentialRotation(beforeNode.credentials, beforeCollector.credentials, node.credentials, collector.credentials,
			nodeIdentity, "127.0.0.1:16443", "127.0.0.1:19100", revoke)
	}
	if validate(oldNode, oldCollector, renewed, oldCollector, false) != nil ||
		validate(oldNode, oldCollector, renewed, oldCollector, true) == nil ||
		validate(oldNode, oldCollector, nextNode, nextCollector, true) != nil {
		t.Fatal("renewal was confused with retirement of the complete trust set")
	}
	expiredNode := oldAuthority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, true, x509.ExtKeyUsageClientAuth)
	expiredCollector := oldAuthority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, true)
	if validate(expiredNode, expiredCollector, nextNode, nextCollector, true) != nil {
		t.Fatal("expired sealed predecessor prevented authenticated rotation")
	}
	retainedNodeKey := nextAuthority.issueWithKey(t, oldNode.pair.PrivateKey.(ed25519.PrivateKey), nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	retainedCollectorKey := nextAuthority.issueWithKey(t, oldCollector.pair.PrivateKey.(ed25519.PrivateKey), collectorURI, x509.ExtKeyUsageServerAuth, false)
	swappedNodeKey := nextAuthority.issueWithKey(t, oldCollector.pair.PrivateKey.(ed25519.PrivateKey), nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	swappedCollectorKey := nextAuthority.issueWithKey(t, oldNode.pair.PrivateKey.(ed25519.PrivateKey), collectorURI, x509.ExtKeyUsageServerAuth, false)
	sharedCollectorKey := nextAuthority.issueWithKey(t, nextNode.pair.PrivateKey.(ed25519.PrivateKey), collectorURI, x509.ExtKeyUsageServerAuth, false)
	t.Run("renewal cannot share node and collector keys", func(t *testing.T) {
		if validate(oldNode, oldCollector, nextNode, sharedCollectorKey, false) == nil {
			t.Fatal("the unprivileged collector received the node private key")
		}
	})
	reissuedTemplate := *oldAuthority.certificate
	reissuedTemplate.SerialNumber = big.NewInt(2)
	reissuedDER, err := x509.CreateCertificate(rand.Reader, &reissuedTemplate, &reissuedTemplate, oldAuthority.key.Public(), oldAuthority.key)
	if err != nil {
		t.Fatal(err)
	}
	reissuedCA, err := x509.ParseCertificate(reissuedDER)
	if err != nil {
		t.Fatal(err)
	}
	reissued := testAuthority{certificate: reissuedCA, key: oldAuthority.key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: reissuedDER}), roots: x509.NewCertPool()}
	reissued.roots.AddCert(reissuedCA)
	if bytes.Equal(reissued.pem, oldAuthority.pem) {
		t.Fatal("reissued CA fixture did not change its certificate bytes")
	}
	mixedTrust := append(append([]byte{}, nextAuthority.pem...), oldAuthority.pem...)
	for name, peers := range map[string][2]issuedCertificate{
		"old node key":                    {retainedNodeKey, nextCollector},
		"old collector key":               {nextNode, retainedCollectorKey},
		"old collector key moved to node": {swappedNodeKey, nextCollector},
		"old node key moved to collector": {nextNode, swappedCollectorKey},
		"shared candidate key":            {nextNode, sharedCollectorKey},
		"reissued old CA key": {reissued.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth),
			reissued.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)},
		"retained trust":    {nextNode.withTrust(t, mixedTrust), nextCollector.withTrust(t, mixedTrust)},
		"expired candidate": {nextAuthority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, true, x509.ExtKeyUsageClientAuth), nextCollector},
		"wrong role":        {nextAuthority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth), nextCollector},
	} {
		t.Run(name, func(t *testing.T) {
			if validate(oldNode, oldCollector, peers[0], peers[1], true) == nil {
				t.Fatal("unsafe credential retirement passed admission")
			}
		})
	}
}

func newDeploymentClient(
	t *testing.T,
	endpoint string,
	credentials nodehttps.Credentials,
	identity nodev1.Identity,
	bindingRef string,
) *nodehttps.DeploymentClient {
	t.Helper()
	client, err := nodehttps.NewDeploymentClient(nodehttps.DeploymentConfig{
		Connection: nodehttps.Config{
			Endpoint: endpoint, Identity: identity, ControllerID: controllerID,
			BindingRef: bindingRef, ExpectedFingerprint: observedTarget().IdentityFingerprint,
			Credentials: func() (nodehttps.Credentials, error) { return credentials, nil },
		},
		Artifacts: deploymentArtifactResolver{},
		Secrets:   deploymentSecretResolver{content: []byte("secret-value")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func deploymentExecutionFixture(t *testing.T) paasv1.DeploymentExecutionRequest {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"}
	metadata := func(id string) paasv1.ResourceMetadata {
		return paasv1.ResourceMetadata{
			ID: paasv1.ResourceID(id), Name: id, Scope: scope,
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
		}
	}
	revision := paasv1.ApplicationRevision{
		APIVersion: paasv1.APIVersion, Kind: "ApplicationRevision",
		Metadata: metadata("revision-a"),
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: "application-a", Revision: "revision-1",
			ContentDigest: deploymentTestDigest('b'),
			Components: []paasv1.ApplicationRevisionComponent{{
				Name: "web",
				Artifact: paasv1.ArtifactRef{
					Kind: paasv1.ArtifactOCIImage, Locator: "registry.example.invalid/web",
					Digest: deploymentTestDigest('a'),
				},
				Resources: paasv1.ResourceRequirements{CPUMillis: 100, MemoryBytes: 64 * 1024 * 1024},
				Inputs: []paasv1.ComponentInput{{
					Name: "password", Kind: paasv1.InputSecret,
					Injection: paasv1.InjectionFile, Required: true,
				}},
			}},
		},
	}
	generation := paasv1.DeploymentGeneration{
		APIVersion: paasv1.APIVersion, Kind: "DeploymentGeneration", Scope: scope,
		DeploymentID: "deployment-a", Generation: 1,
		Spec: paasv1.DeploymentSpec{
			ApplicationRevisionID: revision.Metadata.ID, PlacementPolicyID: "policy-a",
			DesiredState: paasv1.DeploymentDesiredRunning,
			Components: []paasv1.DeploymentComponent{{
				Name: "web", Replicas: 1,
				Bindings: []paasv1.ComponentBinding{{
					Name: "password", SecretVersion: &paasv1.SecretVersionReference{
						SecretID: "secret-a", Version: "version-1",
					},
				}},
			}},
		},
		CreatedByOperationID: "operation-a", CreatedAt: now,
	}
	generation.ContentDigest = paasv1.DeploymentSpecContentDigest(generation.Spec)
	placement := paasv1.PlacementDecision{
		APIVersion: paasv1.APIVersion, Kind: "PlacementDecision",
		Metadata: metadata("decision-a"), DeploymentID: generation.DeploymentID,
		DeploymentGeneration: generation.Generation, DeploymentResourceVersion: 1,
		ApplicationRevisionID: revision.Metadata.ID,
		PlacementPolicyID:     generation.Spec.PlacementPolicyID, PolicyResourceVersion: 1,
		RequestedIsolationGuarantee: paasv1.IsolationWorkload,
		Outcome:                     paasv1.PlacementScheduled, ExecutionTargetID: nodeIdentity.ExecutionTargetID,
		ExecutionTargetResourceVersion: 1, GrantedIsolationGuarantee: paasv1.IsolationWorkload,
		CandidateSetDigest: deploymentTestDigest('c'), DecidedAt: now,
	}
	request := paasv1.DeploymentExecutionRequest{
		Command: paasv1.AdapterCommandEnvelope{
			OperationID: "operation-a", CommandID: "command-a", Attempt: 1,
			Action: paasv1.AdapterApplyDeployment, Scope: scope,
			ApplicationID: revision.Spec.ApplicationID, ApplicationRevisionID: revision.Metadata.ID,
			DeploymentID: generation.DeploymentID, ExecutionTargetID: placement.ExecutionTargetID,
			BindingRef: "binding-a", Deadline: now.Add(time.Minute),
		},
		Generation: generation, ApplicationRevision: revision, Placement: placement,
	}
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
	if err := paasv1.ValidateDeploymentExecutionRequest(request); err != nil {
		t.Fatalf("invalid Deployment fixture: %v", err)
	}
	return request
}

func deploymentObserveRequest(
	execution paasv1.DeploymentExecutionRequest,
) paasv1.ObserveDeploymentRequest {
	command := execution.Command
	command.CommandID = "observe-a"
	command.Action = paasv1.AdapterObserveDeployment
	command.Deadline = time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
	request := paasv1.ObserveDeploymentRequest{
		Command: command, Generation: execution.Generation.Generation,
		ExpectedContentDigest: execution.Generation.ContentDigest,
	}
	request.Command.RequestDigest = paasv1.ObserveDeploymentRequestDigest(request)
	return request
}

func deploymentObservationFixture(
	request paasv1.ObserveDeploymentRequest,
) paasv1.DeploymentObservation {
	return paasv1.DeploymentObservation{
		DeploymentID: request.Command.DeploymentID, Generation: request.Generation,
		ApplicationRevisionID: request.Command.ApplicationRevisionID,
		Phase:                 paasv1.DeploymentReady, ReadyComponents: 1,
		ReceiptDigest: deploymentTestDigest('e'),
		ObservedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
}

func deploymentRuntimeObserveRequest(
	execution paasv1.DeploymentExecutionRequest,
) paasv1.ObserveDeploymentRuntimeRequest {
	return paasv1.ObserveDeploymentRuntimeRequest{
		RequestID:             "runtime-observe-a",
		Scope:                 execution.Command.Scope,
		DeploymentID:          execution.Generation.DeploymentID,
		Generation:            execution.Generation.Generation,
		ApplicationRevisionID: execution.ApplicationRevision.Metadata.ID,
		ExecutionTargetID:     execution.Command.ExecutionTargetID,
		ExpectedContentDigest: execution.Generation.ContentDigest,
		Deadline:              time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute),
	}
}

func deploymentRuntimeObservationFixture(
	request paasv1.ObserveDeploymentRuntimeRequest,
) paasv1.DeploymentRuntimeObservation {
	return paasv1.DeploymentRuntimeObservation{
		DeploymentID:          request.DeploymentID,
		Generation:            request.Generation,
		ApplicationRevisionID: request.ApplicationRevisionID,
		ExecutionTargetID:     request.ExecutionTargetID,
		Instances: []paasv1.DeploymentRuntimeInstance{{
			ID:            "instance-0123456789abcdef0123456789abcdef",
			ComponentName: "web",
			State:         paasv1.DeploymentInstanceRunning,
			Health:        paasv1.DeploymentInstanceHealthHealthy,
		}},
		ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
}

func deploymentTestDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

func requestBody(t *testing.T, command paasv1.AdapterCommandEnvelope) []byte {
	t.Helper()
	value, err := json.Marshal(nodev1.ObservationRequest{APIVersion: nodev1.APIVersion, Kind: nodev1.ObservationRequestKind, Identity: nodeIdentity, Command: command})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func startNode(t *testing.T, node issuedCertificate, source ObservationSource, concurrent int) *httptest.Server {
	t.Helper()
	handler, err := New(source, deploymentService{}, Config{Identity: nodeIdentity, ControllerID: controllerID, BindingRef: "binding-a", MaximumConcurrent: concurrent})
	if err != nil {
		t.Fatal(err)
	}
	return startTLSServer(t, node, handler)
}

func startTLSServer(t *testing.T, node issuedCertificate, handler http.Handler) *httptest.Server {
	t.Helper()
	security, err := nodehttps.ServerTLS(node.credentials, nodeIdentity, controllerID)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = security
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newClient(t *testing.T, endpoint string, credentials nodehttps.Credentials, identity nodev1.Identity, controller string) *nodehttps.Client {
	t.Helper()
	client, err := nodehttps.New(nodehttps.Config{
		Endpoint: endpoint, Identity: identity, ControllerID: controller, BindingRef: "binding-a",
		ExpectedFingerprint: observedTarget().IdentityFingerprint,
		Credentials:         func() (nodehttps.Credentials, error) { return credentials, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

type testAuthority struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	pem         []byte
	roots       *x509.CertPool
}
type issuedCertificate struct {
	credentials nodehttps.Credentials
	pair        tls.Certificate
}

func newAuthority(t *testing.T) testAuthority {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return testAuthority{certificate: certificate, key: key, pem: encoded, roots: roots}
}

func (authority testAuthority) issue(t *testing.T, identity string, purpose x509.ExtKeyUsage, expired bool, additionalPurposes ...x509.ExtKeyUsage) issuedCertificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return authority.issueWithKey(t, key, identity, purpose, expired, additionalPurposes...)
}

func (authority testAuthority) issueWithKey(t *testing.T, key ed25519.PrivateKey, identity string, purpose x509.ExtKeyUsage, expired bool, additionalPurposes ...x509.ExtKeyUsage) issuedCertificate {
	t.Helper()
	public := key.Public()
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{purpose}, URIs: []*url.URL{uri},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificate.ExtKeyUsage = append(certificate.ExtKeyUsage, additionalPurposes...)
	if expired {
		certificate.NotAfter = time.Now().Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, authority.certificate, public, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	credentials, err := nodehttps.NewCredentials(encoded, keyPEM, authority.pem)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(encoded, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return issuedCertificate{credentials: credentials, pair: pair}
}

func (certificate issuedCertificate) withTrust(t *testing.T, trust []byte) issuedCertificate {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	defer clear(keyPEM)
	defer clear(key)
	var chain []byte
	for _, der := range certificate.pair.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	credentials, err := nodehttps.NewCredentials(chain, keyPEM, trust)
	if err != nil {
		t.Fatal(err)
	}
	return issuedCertificate{credentials: credentials, pair: certificate.pair}
}

func (authority testAuthority) rawClient(certificate *tls.Certificate) *http.Client {
	security := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: authority.roots}
	if certificate != nil {
		security.Certificates = []tls.Certificate{*certificate}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: security, DisableKeepAlives: true}, Timeout: 5 * time.Second}
}
