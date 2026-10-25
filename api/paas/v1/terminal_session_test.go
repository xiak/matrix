package paasv1

import (
	"strings"
	"testing"
	"time"
)

func TestTerminalSessionContractBindsOneOpaqueCurrentInstance(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 11, 12, 123000000, time.UTC)
	value := terminalSessionFixture(now)
	if err := ValidateTerminalSession(value); err != nil {
		t.Fatalf("valid terminal session rejected: %v", err)
	}
	if err := ValidateCreateTerminalSessionRequest(CreateTerminalSessionRequest{
		InstanceID: value.InstanceID,
		Size:       value.Size,
	}); err != nil {
		t.Fatalf("valid terminal request rejected: %v", err)
	}

	connectedAt := now.Add(time.Second)
	value.State, value.ConnectedAt = TerminalSessionActive, &connectedAt
	if err := ValidateTerminalSession(value); err != nil {
		t.Fatalf("valid active terminal session rejected: %v", err)
	}
	endedAt := connectedAt.Add(time.Minute)
	value.State, value.Outcome, value.EndedAt = TerminalSessionEnded, TerminalSessionCompleted, &endedAt
	if err := ValidateTerminalSession(value); err != nil {
		t.Fatalf("valid ended terminal session rejected: %v", err)
	}
}

func TestTerminalSessionContractRejectsProviderSelectorsAndAmbiguousLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 11, 12, 123000000, time.UTC)
	for name, mutate := range map[string]func(*TerminalSession){
		"provider id":     func(value *TerminalSession) { value.InstanceID = ResourceID(strings.Repeat("b", 64)) },
		"platform scope":  func(value *TerminalSession) { value.Scope = ResourceScope{Kind: AuthorityPlatform} },
		"zero generation": func(value *TerminalSession) { value.Generation = 0 },
		"long ticket": func(value *TerminalSession) {
			value.ConnectBefore = value.CreatedAt.Add(TerminalSessionConnectTimeout + time.Microsecond)
		},
		"long lifetime": func(value *TerminalSession) {
			value.ExpiresAt = value.CreatedAt.Add(MaximumTerminalSessionDuration + time.Microsecond)
		},
		"pending outcome": func(value *TerminalSession) { value.Outcome = TerminalSessionFailed },
		"active no start": func(value *TerminalSession) { value.State = TerminalSessionActive },
		"ended no outcome": func(value *TerminalSession) {
			ended := value.CreatedAt.Add(time.Second)
			value.State, value.EndedAt = TerminalSessionEnded, &ended
		},
		"unknown outcome": func(value *TerminalSession) {
			ended := value.CreatedAt.Add(time.Second)
			value.State, value.Outcome, value.EndedAt = TerminalSessionEnded, "UNKNOWN", &ended
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := terminalSessionFixture(now)
			mutate(&value)
			if ValidateTerminalSession(value) == nil {
				t.Fatal("invalid terminal session was accepted")
			}
		})
	}
	if ValidateCreateTerminalSessionRequest(CreateTerminalSessionRequest{
		InstanceID: "container-provider-id",
		Size:       TerminalSize{Columns: 80, Rows: 24},
	}) == nil {
		t.Fatal("provider-native selector was accepted")
	}
}

func terminalSessionFixture(now time.Time) TerminalSession {
	return TerminalSession{
		APIVersion: APIVersion,
		Kind:       "TerminalSession",
		ID:         "terminal-session-0123456789abcdef0123456789abcdef",
		Scope: ResourceScope{
			Kind:     AuthorityTenant,
			TenantID: "tenant-a",
		},
		DeploymentID:          "deployment-a",
		Generation:            2,
		ApplicationRevisionID: "application-revision-a",
		InstanceID:            "instance-0123456789abcdef0123456789abcdef",
		Size:                  TerminalSize{Columns: 80, Rows: 24},
		State:                 TerminalSessionPending,
		CreatedAt:             now,
		ConnectBefore:         now.Add(TerminalSessionConnectTimeout),
		ExpiresAt:             now.Add(MaximumTerminalSessionDuration),
	}
}
