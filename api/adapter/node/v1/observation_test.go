package nodev1

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestObservationContractRejectsForeignOrAmbiguousInput(t *testing.T) {
	request := ObservationRequest{
		APIVersion: APIVersion, Kind: ObservationRequestKind,
		Identity: Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"},
		Command: paasv1.AdapterCommandEnvelope{
			OperationID: "operation-a", CommandID: "command-a", Attempt: 1,
			Action: paasv1.AdapterObserveExecutionTarget, Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
			ExecutionTargetID: "target-a", BindingRef: "binding-a", RequestDigest: "sha256:" + strings.Repeat("a", 64),
			Deadline: time.Now().UTC().Truncate(time.Microsecond).Add(time.Second),
		},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeObservationRequest(strings.NewReader(string(encoded)))
	if err != nil || decoded.Identity != request.Identity || decoded.Command != request.Command {
		t.Fatalf("observation round trip: %#v, %v", decoded, err)
	}
	for name, source := range map[string]string{
		"unknown":          strings.Replace(string(encoded), `"command":`, `"shell":"/bin/sh","command":`, 1),
		"duplicate":        strings.Replace(string(encoded), `"bindingRef":"binding-a"`, `"bindingRef":"binding-b","bindingRef":"binding-a"`, 1),
		"case alias":       strings.Replace(string(encoded), `"bindingRef":"binding-a"`, `"BindingRef":"binding-b","bindingRef":"binding-a"`, 1),
		"tenant scope":     strings.Replace(string(encoded), `"kind":"PLATFORM"`, `"kind":"TENANT","tenantId":"tenant-a"`, 1),
		"target mismatch":  strings.Replace(string(encoded), `"executionTargetId":"target-a"`, `"executionTargetId":"target-b"`, 1),
		"different action": strings.Replace(string(encoded), `"OBSERVE_EXECUTION_TARGET"`, `"APPLY_DEPLOYMENT"`, 1),
		"trailing":         string(encoded) + `{}`,
		"size":             string(encoded) + strings.Repeat(" ", MaximumObservationRequestBytes),
		"version":          strings.Replace(string(encoded), APIVersion, "node.adapter.matrix.xiak.com/v2", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeObservationRequest(strings.NewReader(source)); err != ErrInvalidObservation {
				t.Fatalf("invalid node request error = %v", err)
			}
		})
	}
}

func TestCertificateIdentityIsExactAndRoleBound(t *testing.T) {
	identity := Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"}
	nodeURI, err := NodeURI(identity)
	if err != nil {
		t.Fatal(err)
	}
	controllerURI, err := ControllerURI(identity.InstallationID, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	node, _ := url.Parse(nodeURI)
	controller, _ := url.Parse(controllerURI)
	if !MatchesIdentity([]*url.URL{node}, nodeURI) || MatchesIdentity([]*url.URL{controller}, nodeURI) ||
		MatchesIdentity([]*url.URL{node, controller}, nodeURI) || MatchesIdentity([]*url.URL{nil}, nodeURI) {
		t.Fatal("certificate identity admitted an alternate role or URI")
	}
	identity.InstallationID = "installation-a/../installation-b"
	if _, err := NodeURI(identity); err == nil {
		t.Fatal("path-shaped identity accepted")
	}
}

func TestReadinessIsBoundedAndCannotCarryCommands(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	value := Readiness{APIVersion: APIVersion, Kind: ReadinessResponseKind,
		Identity:            Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"},
		IdentityFingerprint: "sha256:" + strings.Repeat("a", 64), ObservedAt: now, ValidUntil: now.Add(MaximumObservationAge)}
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReadiness(strings.NewReader(string(content)))
	if err != nil || decoded != value {
		t.Fatalf("readiness round trip: %#v, %v", decoded, err)
	}
	for _, invalid := range []string{
		strings.Replace(string(content), `"kind":`, `"command":"execute","kind":`, 1),
		strings.Replace(string(content), `"kind":`, `"kind":"NodeReadiness","kind":`, 1),
		strings.Replace(string(content), `"identity":`, `"Identity":`, 1),
		string(content) + `{}`, string(content) + strings.Repeat(" ", MaximumReadinessResponseBytes),
		strings.Replace(string(content), value.ValidUntil.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano), 1),
	} {
		if _, err := DecodeReadiness(strings.NewReader(invalid)); err == nil {
			t.Fatal("invalid readiness was admitted")
		}
	}
}
