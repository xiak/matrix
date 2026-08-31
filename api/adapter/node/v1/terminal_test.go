package nodev1

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestTerminalOpenProtocolReusesExactCurrentRuntimeProof(t *testing.T) {
	request := terminalOpenFixture()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTerminalOpenRequest(bytes.NewReader(encoded))
	if err != nil || decoded.TerminalSessionID != request.TerminalSessionID {
		t.Fatalf("terminal open round trip = %#v / %v", decoded, err)
	}

	for name, mutate := range map[string]func(*TerminalOpenRequest){
		"wrong node": func(value *TerminalOpenRequest) { value.Identity.ExecutionTargetID = "target-b" },
		"wrong session request": func(value *TerminalOpenRequest) {
			value.Request.RequestID = "terminal-session-ffffffffffffffffffffffffffffffff"
		},
		"provider id": func(value *TerminalOpenRequest) { value.InstanceID = "container-deadbeef" },
		"platform scope": func(value *TerminalOpenRequest) {
			value.Request.Scope = paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}
		},
		"stale lifetime": func(value *TerminalOpenRequest) { value.ExpiresAt = value.Request.Deadline },
		"excess lifetime": func(value *TerminalOpenRequest) {
			value.ExpiresAt = value.Request.Deadline.Add(paasv1.MaximumTerminalSessionDuration + time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := terminalOpenFixture()
			mutate(&candidate)
			if ValidateTerminalOpenRequest(candidate) == nil {
				t.Fatal("invalid terminal proof was accepted")
			}
		})
	}

	for name, document := range map[string][]byte{
		"unknown provider selector": bytes.Replace(encoded, []byte(`"instanceId":`), []byte(`"containerId":"provider-id","instanceId":`), 1),
		"duplicate session":         bytes.Replace(encoded, []byte(`"terminalSessionId":`), []byte(`"terminalSessionId":"terminal-session-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","terminalSessionId":`), 1),
		"trailing":                  append(append([]byte{}, encoded...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTerminalOpenRequest(bytes.NewReader(document)); err == nil {
				t.Fatal("non-closed terminal proof was accepted")
			}
		})
	}
}

func TestTerminalControlFramesAreClosedAndBounded(t *testing.T) {
	size := paasv1.TerminalSize{Columns: 100, Rows: 40}
	for _, value := range []TerminalClientControl{
		{Type: TerminalClientResize, Size: &size},
		{Type: TerminalClientClose},
	} {
		encoded, _ := json.Marshal(value)
		if _, err := DecodeTerminalClientControl(bytes.NewReader(encoded)); err != nil {
			t.Fatalf("valid client control rejected: %v", err)
		}
	}
	exitCode := int32(0)
	for _, value := range []TerminalServerControl{
		{Type: TerminalServerReady},
		{Type: TerminalServerExit, ExitCode: &exitCode},
		{Type: TerminalServerError, Error: TerminalErrorUnsupported},
	} {
		encoded, _ := json.Marshal(value)
		if _, err := DecodeTerminalServerControl(bytes.NewReader(encoded)); err != nil {
			t.Fatalf("valid server control rejected: %v", err)
		}
	}

	for _, invalid := range []TerminalClientControl{
		{Type: TerminalClientResize},
		{Type: TerminalClientClose, Size: &size},
		{Type: "EXEC"},
	} {
		if ValidateTerminalClientControl(invalid) == nil {
			t.Fatal("invalid client control accepted")
		}
	}
	for _, invalid := range []TerminalServerControl{
		{Type: TerminalServerReady, ExitCode: &exitCode},
		{Type: TerminalServerExit},
		{Type: TerminalServerError, Error: "PROVIDER_ERROR"},
	} {
		if ValidateTerminalServerControl(invalid) == nil {
			t.Fatal("invalid server control accepted")
		}
	}
}

func terminalOpenFixture() TerminalOpenRequest {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	sessionID := paasv1.ResourceID("terminal-session-0123456789abcdef0123456789abcdef")
	return TerminalOpenRequest{
		APIVersion: APIVersion, Kind: TerminalOpenRequestKind,
		Identity:   Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"},
		BindingRef: "binding-a", TerminalSessionID: sessionID,
		Request: paasv1.ObserveDeploymentRuntimeRequest{
			RequestID:    paasv1.CommandID(sessionID),
			Scope:        paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"},
			DeploymentID: "deployment-a", Generation: 2,
			ApplicationRevisionID: "application-revision-a", ExecutionTargetID: "target-a",
			ExpectedContentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Deadline:              now.Add(paasv1.TerminalSessionConnectTimeout),
		},
		InstanceID: "instance-0123456789abcdef0123456789abcdef",
		Size:       paasv1.TerminalSize{Columns: 80, Rows: 24},
		ExpiresAt:  now.Add(paasv1.MaximumTerminalSessionDuration),
	}
}
