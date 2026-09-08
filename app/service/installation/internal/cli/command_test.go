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

	"github.com/xiak/matrix/app/service/devops/sourcecredential"
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
		{"support", []string{"platform", "support", "--root", "/srv/matrix", "--output", "/safe/support.json"}, Request{Action: lifecycle.ActionSupport, Root: "/srv/matrix", SupportOutput: "/safe/support.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got Request
			backend := backendFunc(func(_ context.Context, request Request) (Result, error) {
				got = request
				return Result{State: "READY", ReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa"}, nil
			})
			var out, errOut bytes.Buffer
			command, err := NewCommand(
				Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
				testBackends(backend),
			)
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
			if errOut.Len() != 0 || !strings.HasPrefix(out.String(), strings.ToUpper(test.name)+" SUCCEEDED") {
				t.Fatalf("command output = %q / %q", out.String(), errOut.String())
			}
		})
	}
}

func TestPlatformCommandNamesHaveNoCompatibilityAliases(t *testing.T) {
	command, err := NewCommand(
		Streams{In: strings.NewReader(""), Out: io.Discard, ErrOut: io.Discard},
		testBackends(backendFunc(func(context.Context, Request) (Result, error) {
			return Result{State: "READY"}, nil
		})),
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
	want := []string{"backup", "install", "recover", "rollback", "status", "support", "upgrade", "verify"}
	if !slices.Equal(got, want) {
		t.Fatalf("platform command surface = %v, want %v", got, want)
	}
	if command.PersistentFlags().Lookup("output") != nil || command.PersistentFlags().Lookup("format") == nil {
		t.Fatal("global output contract must use --format and not support's --output")
	}
}

func TestSourceCredentialCommandSurfaceBuildsExactRequests(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want SourceCredentialRequest
	}{
		{
			name: "apply webhook",
			args: []string{
				"devops", "source-credential", "apply", "--root", "/srv/matrix",
				"--tenant", "tenant:one", "--purpose", "WEBHOOK",
				"--reference", "webhook:v1", "--from-file", "/secure/webhook",
			},
			want: SourceCredentialRequest{
				Operation: SourceCredentialApply, Root: "/srv/matrix", TenantID: "tenant:one",
				Purpose: sourcecredential.PurposeWebhook, Reference: "webhook:v1",
				FromFile: "/secure/webhook",
			},
		},
		{
			name: "apply fetch",
			args: []string{
				"devops", "source-credential", "apply", "--root", "/srv/matrix",
				"--tenant", "tenant-one", "--purpose", "FETCH",
				"--reference", "fetch.v1", "--from-file", "/secure/fetch",
			},
			want: SourceCredentialRequest{
				Operation: SourceCredentialApply, Root: "/srv/matrix", TenantID: "tenant-one",
				Purpose: sourcecredential.PurposeFetch, Reference: "fetch.v1",
				FromFile: "/secure/fetch",
			},
		},
		{
			name: "retire previous",
			args: []string{
				"devops", "source-credential", "retire-previous", "--root", "/srv/matrix",
				"--tenant", "tenant-one", "--purpose", "WEBHOOK",
				"--reference", "webhook.v1",
			},
			want: SourceCredentialRequest{
				Operation: SourceCredentialRetirePrevious, Root: "/srv/matrix",
				TenantID: "tenant-one", Purpose: sourcecredential.PurposeWebhook,
				Reference: "webhook.v1",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got SourceCredentialRequest
			sourceBackend := sourceCredentialBackendFunc(func(
				_ context.Context,
				request SourceCredentialRequest,
			) (SourceCredentialResult, error) {
				got = request
				state := "APPLIED"
				if request.Operation == SourceCredentialRetirePrevious {
					state = "PREVIOUS_RETIRED"
				}
				return sourceCredentialResult(request, state), nil
			})
			var out, errOut bytes.Buffer
			command, err := NewCommand(
				Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
				Backends{Platform: noopPlatformBackend(), SourceCredential: sourceBackend, RunnerNode: noopRunnerNodeBackend()},
			)
			if err != nil {
				t.Fatal(err)
			}
			command.SetArgs(test.args)
			if err := command.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("execute source credential command: %v", err)
			}
			if got != test.want {
				t.Fatalf("source credential request=%#v want=%#v", got, test.want)
			}
			if errOut.Len() != 0 || !strings.Contains(out.String(), "tenant="+test.want.TenantID) ||
				test.want.FromFile != "" && strings.Contains(out.String(), test.want.FromFile) {
				t.Fatalf("source credential output=%q / %q", out.String(), errOut.String())
			}
		})
	}
}

func TestSourceCredentialCommandsHaveNoAliasesOrSecretArgument(t *testing.T) {
	command, err := NewCommand(
		Streams{In: strings.NewReader(""), Out: io.Discard, ErrOut: io.Discard},
		testBackends(noopPlatformBackend()),
	)
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := command.Find([]string{"devops", "source-credential"})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(source.Commands()))
	for _, child := range source.Commands() {
		if len(child.Aliases) != 0 || child.Flags().Lookup("value") != nil ||
			child.Flags().Lookup("secret") != nil {
			t.Fatalf("unsafe source credential surface on %q", child.Name())
		}
		got = append(got, child.Name())
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"apply", "retire-previous"}) {
		t.Fatalf("source credential commands=%v", got)
	}
}

func TestSourceCredentialJSONAndFailureNeverExposeNativeMaterial(t *testing.T) {
	requestArgs := []string{
		"--format", "json", "devops", "source-credential", "apply",
		"--root", "/srv/matrix", "--tenant", "tenant-one", "--purpose", "REPORT",
		"--reference", "report.v1", "--from-file", "/secure/report-token",
	}
	sourceBackend := sourceCredentialBackendFunc(func(
		_ context.Context,
		request SourceCredentialRequest,
	) (SourceCredentialResult, error) {
		return sourceCredentialResult(request, "UNCHANGED"), nil
	})
	var out, errOut bytes.Buffer
	exit := Run(
		context.Background(), requestArgs,
		Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
		Backends{Platform: noopPlatformBackend(), SourceCredential: sourceBackend, RunnerNode: noopRunnerNodeBackend()},
	)
	if exit != ExitSuccess || errOut.Len() != 0 ||
		strings.Contains(out.String(), "/secure/report-token") {
		t.Fatalf("source credential success exit=%d output=%q / %q", exit, out.String(), errOut.String())
	}
	var envelope sourceCredentialSuccessEnvelope
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Kind != "SourceCredentialCommandResult" ||
		envelope.Action != actionSourceCredentialApply || envelope.Result.State != "UNCHANGED" ||
		envelope.Result.Purpose != sourcecredential.PurposeReport {
		t.Fatalf("source credential envelope=%#v", envelope)
	}

	sourceBackend = sourceCredentialBackendFunc(func(
		context.Context, SourceCredentialRequest,
	) (SourceCredentialResult, error) {
		return SourceCredentialResult{}, errors.New(
			"report-secret-value /secure/report-token: native filesystem failure",
		)
	})
	out.Reset()
	errOut.Reset()
	exit = Run(
		context.Background(), requestArgs,
		Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
		Backends{Platform: noopPlatformBackend(), SourceCredential: sourceBackend, RunnerNode: noopRunnerNodeBackend()},
	)
	if exit != ExitInternal || out.Len() != 0 ||
		strings.Contains(errOut.String(), "report-secret-value") ||
		strings.Contains(errOut.String(), "/secure") ||
		strings.Contains(errOut.String(), "filesystem") {
		t.Fatalf("native source credential failure leaked: exit=%d output=%q", exit, errOut.String())
	}
}

func TestSourceCredentialUsageFailsBeforeBackend(t *testing.T) {
	called := false
	sourceBackend := sourceCredentialBackendFunc(func(
		context.Context, SourceCredentialRequest,
	) (SourceCredentialResult, error) {
		called = true
		return SourceCredentialResult{}, nil
	})
	for name, args := range map[string][]string{
		"apply missing file": {
			"devops", "source-credential", "apply", "--root", "/srv/matrix",
			"--tenant", "tenant-one", "--purpose", "WEBHOOK", "--reference", "webhook.v1",
		},
		"retire fetch": {
			"devops", "source-credential", "retire-previous", "--root", "/srv/matrix",
			"--tenant", "tenant-one", "--purpose", "FETCH", "--reference", "fetch.v1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			exit := Run(
				context.Background(), args,
				Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut},
				Backends{Platform: noopPlatformBackend(), SourceCredential: sourceBackend, RunnerNode: noopRunnerNodeBackend()},
			)
			if exit != ExitInvalidInput || out.Len() != 0 ||
				!strings.Contains(errOut.String(), "INVALID_COMMAND_INPUT") {
				t.Fatalf("usage exit=%d output=%q / %q", exit, out.String(), errOut.String())
			}
		})
	}
	if called {
		t.Fatal("source credential backend was called for invalid usage")
	}
}

func TestRunnerNodeCommandsBuildClosedRequests(t *testing.T) {
	serverCAPin := "sha256:" + strings.Repeat("a", 64)
	runnerCAPin := "sha256:" + strings.Repeat("b", 64)
	tests := []struct {
		name string
		args []string
		want RunnerNodeRequest
	}{
		{
			name: "export",
			args: []string{"devops", "runner-node", "export-release", "--root", "/srv/matrix", "--output", "/media/runner-release"},
			want: RunnerNodeRequest{Operation: RunnerNodeExportRelease, Root: "/srv/matrix", Output: "/media/runner-release"},
		},
		{
			name: "request",
			args: []string{
				"devops", "runner-node", "request", "--root", "/srv/matrix-runner",
				"--release", "/media/runner-release", "--trust-key", "/media/release-trust.json",
				"--installation", "mxi-11111111111111111111111111111111",
				"--node", "runner-one", "--slots", "4",
				"--gateway-origin", "https://192.0.2.10:8444",
				"--server-ca-fingerprint", serverCAPin,
				"--runner-ca-fingerprint", runnerCAPin,
			},
			want: RunnerNodeRequest{
				Operation: RunnerNodeCreateRequest, Root: "/srv/matrix-runner",
				Release: "/media/runner-release", TrustKey: "/media/release-trust.json",
				InstallationID: "mxi-11111111111111111111111111111111",
				NodeID:         "runner-one", Slots: 4, GatewayOrigin: "https://192.0.2.10:8444",
				ServerCAPin: serverCAPin, RunnerCAPin: runnerCAPin,
			},
		},
		{
			name: "enroll",
			args: []string{
				"devops", "runner-node", "enroll", "--root", "/srv/matrix",
				"--request", "/media/enrollment-request.json",
				"--output", "/media/enrollment.json",
			},
			want: RunnerNodeRequest{
				Operation: RunnerNodeEnroll, Root: "/srv/matrix",
				RequestFile: "/media/enrollment-request.json", Output: "/media/enrollment.json",
			},
		},
		{
			name: "install",
			args: []string{
				"devops", "runner-node", "install", "--root", "/srv/matrix-runner",
				"--release", "/media/runner-release", "--trust-key", "/media/release-trust.json",
				"--enrollment", "/media/enrollment.json",
			},
			want: RunnerNodeRequest{
				Operation: RunnerNodeInstall, Root: "/srv/matrix-runner",
				Release: "/media/runner-release", TrustKey: "/media/release-trust.json",
				EnrollmentFile: "/media/enrollment.json",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got RunnerNodeRequest
			backend := runnerNodeBackendFunc(func(
				_ context.Context, request RunnerNodeRequest,
			) (RunnerNodeResult, error) {
				got = request
				result := RunnerNodeResult{
					State: "EXPORTED", ReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa",
					ServerCAPin: serverCAPin, RunnerCAPin: runnerCAPin,
				}
				if request.Operation != RunnerNodeExportRelease {
					result.ServerCAPin = ""
					result.RunnerCAPin = ""
					result.State = "ENROLLED"
					if request.Operation == RunnerNodeCreateRequest {
						result.State = "REQUESTED"
					} else if request.Operation == RunnerNodeInstall {
						result.State = "INSTALLED"
					}
					result.InstallationID = "mxi-11111111111111111111111111111111"
					result.NodeID = "runner-one"
					result.Slots = 4
					result.RequestDigest = "sha256:" + strings.Repeat("a", 64)
				}
				return result, nil
			})
			backends := testBackends(noopPlatformBackend())
			backends.RunnerNode = backend
			var out, errOut bytes.Buffer
			exit := Run(
				context.Background(), test.args,
				Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backends,
			)
			if exit != ExitSuccess || got != test.want || errOut.Len() != 0 {
				t.Fatalf("runner command exit=%d request=%#v output=%q", exit, got, errOut.String())
			}
			for _, secretPath := range []string{
				test.want.TrustKey, test.want.RequestFile, test.want.EnrollmentFile, test.want.Output,
			} {
				if secretPath != "" && strings.Contains(out.String(), secretPath) {
					t.Fatalf("runner command disclosed native path %q", secretPath)
				}
			}
		})
	}
}

func TestRunnerNodeUsageRejectsFifthSlotBeforeBackend(t *testing.T) {
	called := false
	backends := testBackends(noopPlatformBackend())
	backends.RunnerNode = runnerNodeBackendFunc(func(
		context.Context, RunnerNodeRequest,
	) (RunnerNodeResult, error) {
		called = true
		return RunnerNodeResult{}, nil
	})
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{
		"devops", "runner-node", "request", "--root", "/srv/runner",
		"--release", "/media/release", "--trust-key", "/media/trust",
		"--installation", "mxi-11111111111111111111111111111111",
		"--node", "runner-one", "--slots", "5",
		"--gateway-origin", "https://192.0.2.10:8444",
		"--server-ca-fingerprint", "sha256:" + strings.Repeat("a", 64),
		"--runner-ca-fingerprint", "sha256:" + strings.Repeat("b", 64),
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, backends)
	if exit != ExitInvalidInput || called || out.Len() != 0 ||
		!strings.Contains(errOut.String(), "INVALID_COMMAND_INPUT") {
		t.Fatalf("invalid runner slots exit=%d called=%t output=%q", exit, called, errOut.String())
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
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, testBackends(backend))
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
			}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, testBackends(backend))
			if exit != test.exit || out.Len() != 0 {
				t.Fatalf("fault exit/output = %d / %q", exit, out.String())
			}
			var envelope failureEnvelope
			if err := json.Unmarshal(errOut.Bytes(), &envelope); err != nil {
				t.Fatalf("decode failure envelope: %v", err)
			}
			if envelope.APIVersion != OutputAPIVersion || envelope.Action != commandAction(lifecycle.ActionVerify) ||
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
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, testBackends(backend))
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
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, testBackends(backend))
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
	}, Streams{In: strings.NewReader(""), Out: &out, ErrOut: &errOut}, testBackends(backend))
	if exit != ExitInterrupted || !strings.Contains(errOut.String(), "COMMAND_INTERRUPTED") {
		t.Fatalf("cancellation result = exit %d output %q", exit, errOut.String())
	}
}

type backendFunc func(context.Context, Request) (Result, error)

func (function backendFunc) Run(ctx context.Context, request Request) (Result, error) {
	return function(ctx, request)
}

type sourceCredentialBackendFunc func(
	context.Context,
	SourceCredentialRequest,
) (SourceCredentialResult, error)

func (function sourceCredentialBackendFunc) RunSourceCredential(
	ctx context.Context,
	request SourceCredentialRequest,
) (SourceCredentialResult, error) {
	return function(ctx, request)
}

type runnerNodeBackendFunc func(
	context.Context,
	RunnerNodeRequest,
) (RunnerNodeResult, error)

func (function runnerNodeBackendFunc) RunRunnerNode(
	ctx context.Context,
	request RunnerNodeRequest,
) (RunnerNodeResult, error) {
	return function(ctx, request)
}

func noopPlatformBackend() backendFunc {
	return backendFunc(func(context.Context, Request) (Result, error) {
		return Result{State: "READY"}, nil
	})
}

func noopRunnerNodeBackend() runnerNodeBackendFunc {
	return runnerNodeBackendFunc(func(
		context.Context,
		RunnerNodeRequest,
	) (RunnerNodeResult, error) {
		return RunnerNodeResult{State: "EXPORTED", ReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa"}, nil
	})
}

func testBackends(platform PlatformBackend) Backends {
	return Backends{
		Platform: platform,
		SourceCredential: sourceCredentialBackendFunc(func(
			_ context.Context,
			request SourceCredentialRequest,
		) (SourceCredentialResult, error) {
			return sourceCredentialResult(request, "UNCHANGED"), nil
		}),
		RunnerNode: noopRunnerNodeBackend(),
	}
}

func sourceCredentialResult(
	request SourceCredentialRequest,
	state string,
) SourceCredentialResult {
	return SourceCredentialResult{
		State: state, Purpose: request.Purpose, TenantID: request.TenantID,
		Reference: request.Reference,
	}
}
