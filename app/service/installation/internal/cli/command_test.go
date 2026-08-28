package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
)

func TestPlatformCommandSurfaceBuildsExactRequests(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Request
	}{
		{"install", []string{"platform", "install", "--bundle", "/media/release", "--root", "/srv/matrix", "--trust-key", "/media/trust.json"}, Request{Action: lifecycle.ActionInstall, Root: "/srv/matrix", Bundle: "/media/release", TrustKey: "/media/trust.json"}},
		{"verify", []string{"platform", "verify", "--root", "/srv/matrix"}, Request{Action: lifecycle.ActionVerify, Root: "/srv/matrix"}},
		{"status", []string{"platform", "status", "--root", "/srv/matrix"}, Request{Action: lifecycle.ActionStatus, Root: "/srv/matrix"}},
		{"backup", []string{"platform", "backup", "--root", "/srv/matrix"}, Request{Action: lifecycle.ActionBackup, Root: "/srv/matrix"}},
		{"upgrade", []string{"platform", "upgrade", "--bundle", "/media/release-b", "--root", "/srv/matrix"}, Request{Action: lifecycle.ActionUpgrade, Root: "/srv/matrix", Bundle: "/media/release-b"}},
		{"rollback", []string{"platform", "rollback", "--root", "/srv/matrix"}, Request{Action: lifecycle.ActionRollback, Root: "/srv/matrix"}},
		{"recover", []string{"platform", "recover", "--root", "/srv/matrix", "--backup", "backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Request{Action: lifecycle.ActionRecover, Root: "/srv/matrix", BackupID: "backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{"recover-credentials", []string{"platform", "recover-credentials", "--root", "/srv/matrix", "--recovery-input", "/private/recovery.json"}, Request{Action: lifecycle.ActionRecoverCredentials, Root: "/srv/matrix", RecoveryInput: "/private/recovery.json"}},
		{"configure-nodes", []string{"platform", "configure-nodes", "--root", "/srv/matrix", "--configuration", "/private/nodes.json", "--expected-configuration-digest", "sha256:" + strings.Repeat("a", 64)}, Request{Action: lifecycle.ActionConfigureNodes, Root: "/srv/matrix", Configuration: "/private/nodes.json", ExpectedConfigurationDigest: "sha256:" + strings.Repeat("a", 64)}},
		{"support", []string{"platform", "support", "--root", "/srv/matrix", "--output", "/safe/support.json"}, Request{Action: lifecycle.ActionSupport, Root: "/srv/matrix", SupportOutput: "/safe/support.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.want.Subject = SubjectPlatform
			var got Request
			backend := backendFunc(func(_ context.Context, request Request) (Result, error) {
				got = request
				return Result{State: "READY", ReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa"}, nil
			})
			var out, errOut bytes.Buffer
			command, err := NewCommand(Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backend)
			if err != nil {
				t.Fatalf("construct command: %v", err)
			}
			command.SetArgs(test.args)
			if err := command.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("execute command: %v", err)
			}
			if got != test.want {
				t.Fatalf("backend request = %#v, want %#v", got, test.want)
			}
			if errOut.Len() != 0 || !strings.HasPrefix(out.String(), strings.ReplaceAll(strings.ToUpper(test.name), "-", "_")+" SUCCEEDED") {
				t.Fatalf("command output = %q / %q", out.String(), errOut.String())
			}
		})
	}
}

func TestPlatformCommandNamesHaveNoCompatibilityAliases(t *testing.T) {
	command, err := NewCommand(
		Streams{In: strings.NewReader(""), Out: io.Discard, ErrOut: io.Discard},
		backendFunc(func(context.Context, Request) (Result, error) { return Result{State: "READY"}, nil }),
	)
	if err != nil {
		t.Fatalf("construct command: %v", err)
	}
	platform, _, err := command.Find([]string{"platform"})
	if err != nil {
		t.Fatalf("find platform command: %v", err)
	}
	got := make([]string, 0, len(platform.Commands()))
	for _, child := range platform.Commands() {
		if len(child.Aliases) != 0 {
			t.Fatalf("command %q has compatibility aliases %v", child.Name(), child.Aliases)
		}
		got = append(got, child.Name())
	}
	slices.Sort(got)
	want := []string{"backup", "configure-nodes", "install", "recover", "recover-credentials", "rollback", "status", "support", "upgrade", "verify"}
	if !slices.Equal(got, want) {
		t.Fatalf("platform command surface = %v, want %v", got, want)
	}
	if command.PersistentFlags().Lookup("output") != nil || command.PersistentFlags().Lookup("format") == nil {
		t.Fatal("global output contract must use --format and not support's --output")
	}
}

func TestPlatformCredentialRecoveryHasExplicitResumeAndNoAuthoritySelectors(t *testing.T) {
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{"--format", "json", "platform", "recover-credentials", "--root", "/srv/platform", "--resume"},
		Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
		backendFunc(func(_ context.Context, request Request) (Result, error) {
			if request.Subject != SubjectPlatform || request.Action != lifecycle.ActionRecoverCredentials ||
				!request.Resume || request.RecoveryInput != "" {
				t.Fatal("credential recovery resume lost its closed intent")
			}
			return Result{State: "PASSWORD_CHANGE_REQUIRED", CorrelationID: "cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
		}))
	if exit != ExitSuccess || !strings.Contains(out.String(), `"action":"RECOVER_CREDENTIALS"`) ||
		strings.Contains(out.String(), "/srv/") || errOut.Len() != 0 {
		t.Fatal("credential recovery did not return a sanitized platform result")
	}
	for _, extra := range [][]string{
		nil,
		{"--recovery-input", " "},
		{"--resume", "--recovery-input", "/private/recovery.json"},
		{"--password", "raw-secret-value"},
		{"--recovery-input", "/private/recovery.json", "--principal-id", "principal-other"},
		{"--recovery-input", "/private/recovery.json", "--organization-id", "organization-other"},
		{"--recovery-input", "/private/recovery.json", "--database-dsn", "postgres://secret@wrong-host/foreign"},
		{"--recovery-input", "/private/recovery.json", "--backup", "backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"--recovery-input", "/private/recovery.json", "--force"},
	} {
		out.Reset()
		errOut.Reset()
		args := append([]string{"--format", "json", "platform", "recover-credentials", "--root", "/srv/platform"}, extra...)
		exit := Run(context.Background(), args, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
			backendFunc(func(context.Context, Request) (Result, error) {
				t.Fatal("invalid recovery input reached the backend")
				return Result{}, nil
			}))
		if exit != ExitInvalidInput || out.Len() != 0 || strings.Contains(errOut.String(), "raw-secret-value") ||
			strings.Contains(errOut.String(), "wrong-host") || strings.Contains(errOut.String(), "/private/") {
			t.Fatal("credential recovery accepted an unrelated authority selector or exposed raw input")
		}
	}
	for _, args := range [][]string{
		{"node", "recover-credentials", "--root", "/srv/node", "--resume"},
		{"platform", "recover", "--root", "/srv/platform", "--recovery-input", "/private/recovery.json"},
		{"platform", "status", "--root", "/srv/platform", "--resume"},
	} {
		out.Reset()
		errOut.Reset()
		if Run(context.Background(), args, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
			backendFunc(func(context.Context, Request) (Result, error) {
				t.Fatal("credential recovery crossed a command purpose")
				return Result{}, nil
			})) != ExitInvalidInput {
			t.Fatal("credential recovery entered a different command purpose")
		}
	}
}

func TestNodeCommandsStaySeparateAndRequireProtectedEnrollment(t *testing.T) {
	for _, action := range []string{"install", "start", "verify", "status", "rotate-credentials", "upgrade", "rollback", "support"} {
		t.Run(action, func(t *testing.T) {
			var request Request
			backend := backendFunc(func(_ context.Context, value Request) (Result, error) {
				request = value
				return Result{State: "READY", ExecutionTargetID: "target-a"}, nil
			})
			args := []string{"--format", "json", "node", action, "--root", "/srv/node"}
			if action == "install" {
				args = append(args, "--bundle", "/media/node", "--trust-key", "/media/trust.json", "--configuration", "/private/enrollment.json")
			}
			if action == "rotate-credentials" {
				args = append(args, "--configuration", "/private/enrollment.json", "--expected-configuration-digest", "sha256:"+strings.Repeat("a", 64))
			}
			if action == "upgrade" {
				args = append(args, "--bundle", "/media/node-successor")
			}
			if action == "support" {
				args = append(args, "--output", "/srv/node/support/snapshot.json")
			}
			var out, errOut bytes.Buffer
			exit := Run(context.Background(), args, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backend)
			if exit != ExitSuccess || request.Subject != SubjectNode || request.Action != lifecycle.Action(strings.ReplaceAll(strings.ToUpper(action), "-", "_")) {
				t.Fatalf("node request not routed: %d / %#v / %s", exit, request, errOut.String())
			}
			if action == "rotate-credentials" && !request.RevokePreviousCredentials {
				t.Fatal("node rotation defaulted to retaining the previous trust set")
			}
			if action == "support" && request.SupportOutput != "/srv/node/support/snapshot.json" {
				t.Fatal("node support lost its explicit evidence destination")
			}
			var result successEnvelope
			if json.Unmarshal(out.Bytes(), &result) != nil || result.Kind != "NodeCommandResult" || result.Result.ExecutionTargetID != "target-a" {
				t.Fatal("node result lost its scope")
			}
		})
	}
	for _, args := range [][]string{
		{"node", "install", "--root", "/srv/node", "--bundle", "/media/node", "--trust-key", "/media/trust.json"},
		{"node", "backup", "--root", "/srv/node"},
		{"node", "recover", "--root", "/srv/node"},
		{"node", "start", "--root", "/srv/node", "--configuration", "/private/other.json"},
		{"platform", "install", "--root", "/srv/platform", "--configuration", "/private/enrollment.json"},
		{"platform", "rotate-credentials", "--root", "/srv/platform"},
		{"node", "rotate-credentials", "--root", "/srv/node", "--configuration", "/private/enrollment.json"},
		{"node", "rotate-credentials", "--root", "/srv/node", "--configuration", "/private/enrollment.json", "--expected-configuration-digest", "../credentials"},
		{"node", "upgrade", "--root", "/srv/node"},
		{"node", "upgrade", "--root", "/srv/node", "--bundle", "/media/node", "--resume"},
		{"node", "upgrade", "--root", "/srv/node", "--bundle", "/media/node", "--configuration", "/private/enrollment.json"},
		{"node", "upgrade", "--root", "/srv/node", "--bundle", "/media/node", "--trust-key", "/private/other-trust"},
		{"node", "rollback", "--root", "/srv/node", "--bundle", "/media/node"},
		{"node", "rollback", "--root", "/srv/node", "--backup", "backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"node", "rollback", "--root", "/srv/node", "--force"},
		{"node", "support", "--root", "/srv/node"},
		{"node", "support", "--root", "/srv/node", "--output", "/srv/node/support/snapshot.json", "--configuration", "/private/other.json"},
		{"node", "support", "--root", "/srv/node", "--output", "/srv/node/support/snapshot.json", "--bundle", "/media/other"},
		{"node", "support", "--root", "/srv/node", "--output", "/srv/node/support/snapshot.json", "--force"},
	} {
		var out, errOut bytes.Buffer
		exit := Run(context.Background(), append([]string{"--format", "json"}, args...), Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
			backendFunc(func(context.Context, Request) (Result, error) {
				t.Fatal("invalid command reached backend")
				return Result{}, nil
			}))
		if exit != ExitInvalidInput || out.Len() != 0 {
			t.Fatalf("invalid node input accepted: %v", args)
		}
	}
}

func TestNodeUpgradeResumeUsesOnlyItsSealedIntent(t *testing.T) {
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{"node", "upgrade", "--root", "/srv/node", "--resume"},
		Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
		backendFunc(func(_ context.Context, request Request) (Result, error) {
			if request != (Request{Subject: SubjectNode, Action: lifecycle.ActionUpgrade, Root: "/srv/node", Resume: true}) {
				t.Fatal("node upgrade resume accepted another release selector")
			}
			return Result{State: "READY"}, nil
		}))
	if exit != ExitSuccess || errOut.Len() != 0 {
		t.Fatal("node upgrade resume did not reach its purpose-bound backend")
	}
}

func TestNodeSameTrustRenewalRequiresExplicitOptOut(t *testing.T) {
	var out, errOut bytes.Buffer
	expected := "sha256:" + strings.Repeat("a", 64)
	exit := Run(context.Background(), []string{"node", "rotate-credentials", "--root", "/srv/node",
		"--configuration", "/private/enrollment.json", "--expected-configuration-digest", expected, "--revoke-previous=false"},
		Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
		backendFunc(func(_ context.Context, request Request) (Result, error) {
			if request.Action != lifecycle.ActionRotateCredentials || request.RevokePreviousCredentials || request.ExpectedConfigurationDigest != expected {
				t.Fatal("explicit renewal policy was lost")
			}
			return Result{State: "READY", ConfigurationDigest: expected}, nil
		}))
	if exit != ExitSuccess || !strings.Contains(out.String(), expected) || strings.Contains(out.String(), "/private/") {
		t.Fatal("node result omitted its usable commitment or exposed an input path")
	}
}

func TestPlatformNodeConfigurationHasExplicitPurposeBoundResume(t *testing.T) {
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{"platform", "configure-nodes", "--root", "/srv/platform", "--resume"}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backendFunc(func(_ context.Context, request Request) (Result, error) {
		if request.Subject != SubjectPlatform || request.Action != lifecycle.ActionConfigureNodes || !request.Resume || request.Configuration != "" || request.ExpectedConfigurationDigest != "" {
			t.Fatal("node configuration resume changed purpose")
		}
		return Result{State: "READY"}, nil
	}))
	if exit != ExitSuccess {
		t.Fatal("valid resume rejected")
	}
	for _, args := range [][]string{
		{"platform", "configure-nodes", "--root", "/srv/platform"},
		{"platform", "configure-nodes", "--root", "/srv/platform", "--configuration", "/private/nodes.json"},
		{"platform", "configure-nodes", "--root", "/srv/platform", "--resume", "--configuration", "/private/nodes.json"},
		{"platform", "configure-nodes", "--root", "/srv/platform", "--resume", "--endpoint", "https://127.0.0.1:1"},
		{"platform", "configure-nodes", "--root", "/srv/platform", "--resume", "--principal-id", "caller"},
		{"node", "configure-nodes", "--root", "/srv/node", "--resume"},
	} {
		out.Reset()
		errOut.Reset()
		if Run(context.Background(), args, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backendFunc(func(context.Context, Request) (Result, error) {
			t.Fatal("unsafe node input reached backend")
			return Result{}, nil
		})) != ExitInvalidInput {
			t.Fatal("ambiguous node configuration input accepted")
		}
	}
}

func TestRunWritesVersionedStableJSON(t *testing.T) {
	backend := backendFunc(func(_ context.Context, request Request) (Result, error) {
		if request.Action != lifecycle.ActionInstall {
			t.Fatalf("backend action = %s", request.Action)
		}
		return Result{
			State: "READY", ReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa", Changed: true,
			CorrelationID: "cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}, nil
	})
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{
		"--format", "json", "platform", "install", "--bundle", "/media/release",
		"--root", "/srv/matrix", "--trust-key", "/media/trust.json",
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backend)
	if exit != ExitSuccess || errOut.Len() != 0 {
		t.Fatalf("run exit/output = %d / %q", exit, errOut.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("decode JSON output: %v", err)
	}
	if envelope["apiVersion"] != OutputAPIVersion || envelope["kind"] != "PlatformCommandResult" ||
		envelope["action"] != "INSTALL" || envelope["status"] != "SUCCEEDED" {
		t.Fatalf("success envelope = %#v", envelope)
	}
	result := envelope["result"].(map[string]any)
	if result["state"] != "READY" || result["releaseId"] != "matrix-v0.1.0-aaaaaaaaaaaa" ||
		result["changed"] != true {
		t.Fatalf("success result = %#v", result)
	}
}

func TestRunMapsFaultsToStableExitClassesWithoutNativeLeakage(t *testing.T) {
	tests := []struct {
		class FaultClass
		exit  int
	}{
		{FaultInvalidArgument, ExitInvalidInput},
		{FaultPrecondition, ExitPrecondition},
		{FaultConflict, ExitConflict},
		{FaultVerification, ExitVerification},
		{FaultUnavailable, ExitUnavailable},
		{FaultInternal, ExitInternal},
	}
	for _, test := range tests {
		t.Run(string(test.class), func(t *testing.T) {
			fault, err := NewFault(test.class, "PLATFORM_TEST_FAILURE")
			if err != nil {
				t.Fatalf("construct fault: %v", err)
			}
			backend := backendFunc(func(context.Context, Request) (Result, error) { return Result{}, fault })
			var out, errOut bytes.Buffer
			exit := Run(context.Background(), []string{
				"--format", "json", "platform", "verify", "--root", "/srv/matrix",
			}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backend)
			if exit != test.exit || out.Len() != 0 {
				t.Fatalf("fault exit/output = %d / %q", exit, out.String())
			}
			var envelope failureEnvelope
			if err := json.Unmarshal(errOut.Bytes(), &envelope); err != nil {
				t.Fatalf("decode failure envelope: %v", err)
			}
			if envelope.APIVersion != OutputAPIVersion || envelope.Action != lifecycle.ActionVerify ||
				envelope.Error.Class != test.class || envelope.Error.Code != "PLATFORM_TEST_FAILURE" {
				t.Fatalf("failure envelope = %#v", envelope)
			}
		})
	}

	backend := backendFunc(func(context.Context, Request) (Result, error) {
		return Result{}, errors.New("secret-value /customer/private/path: native Docker payload")
	})
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{
		"--format", "json", "platform", "verify", "--root", "/srv/matrix",
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backend)
	if exit != ExitInternal || strings.Contains(errOut.String(), "secret-value") ||
		strings.Contains(errOut.String(), "/customer") || strings.Contains(errOut.String(), "Docker") {
		t.Fatalf("native backend failure leaked: exit=%d output=%q", exit, errOut.String())
	}
}

func TestRunClassifiesUsageAndCancellation(t *testing.T) {
	backendCalled := false
	backend := backendFunc(func(context.Context, Request) (Result, error) {
		backendCalled = true
		return Result{State: "READY"}, nil
	})
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{
		"--format", "json", "platform", "install", "--root", "/srv/matrix",
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backend)
	if exit != ExitInvalidInput || backendCalled || !strings.Contains(errOut.String(), "INVALID_COMMAND_INPUT") {
		t.Fatalf("usage result = exit %d called %t output %q", exit, backendCalled, errOut.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend = backendFunc(func(ctx context.Context, _ Request) (Result, error) {
		return Result{}, ctx.Err()
	})
	out.Reset()
	errOut.Reset()
	exit = Run(ctx, []string{
		"--format", "json", "platform", "status", "--root", "/srv/matrix",
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backend)
	if exit != ExitInterrupted || !strings.Contains(errOut.String(), "COMMAND_INTERRUPTED") {
		t.Fatalf("cancellation result = exit %d output %q", exit, errOut.String())
	}
}

type backendFunc func(context.Context, Request) (Result, error)

func (function backendFunc) Run(ctx context.Context, request Request) (Result, error) {
	return function(ctx, request)
}
