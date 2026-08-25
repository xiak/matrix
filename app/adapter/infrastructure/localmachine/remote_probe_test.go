package localmachine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type fakeRemoteProbeExecutor struct {
	results map[RemoteProbeID]remoteProbeResult
	err     error
	probes  []RemoteProbeID
	calls   int
}

func (executor *fakeRemoteProbeExecutor) Execute(
	_ context.Context,
	_ MachineBinding,
	_ SSHCredential,
	probes []RemoteProbeID,
) (map[RemoteProbeID]remoteProbeResult, error) {
	executor.calls++
	executor.probes = append([]RemoteProbeID(nil), probes...)
	return executor.results, executor.err
}

type fakeRemoteHostProbe struct {
	facts HostFacts
	err   error
	calls int
}

func (probe *fakeRemoteHostProbe) Inspect(
	_ context.Context,
	_ MachineBinding,
) (HostFacts, error) {
	probe.calls++
	return probe.facts, probe.err
}

func TestSSHHostProbeNormalizesFixedRemoteFacts(t *testing.T) {
	if _, err := parseRemoteHostFacts(validRemoteProbeResults()); err != nil {
		t.Fatalf("valid remote probe fixture is invalid: %v", err)
	}
	credential := mustParsedSSHCredential(t, "matrix")
	resolver, err := NewStaticSSHCredentialResolver(NamedSSHCredential{
		Ref:        "credential-node-1",
		Credential: credential,
	})
	if err != nil {
		t.Fatalf("NewStaticSSHCredentialResolver() error = %v", err)
	}
	executor := &fakeRemoteProbeExecutor{results: validRemoteProbeResults()}
	probe, err := newSSHHostProbe(resolver, executor)
	if err != nil {
		t.Fatalf("newSSHHostProbe() error = %v", err)
	}
	facts, err := probe.Inspect(
		context.Background(),
		mustSSHBinding(t, "127.0.0.1:2222", pinnedTestHostKey(), "/var/lib/matrix"),
	)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if executor.calls != 1 || !reflect.DeepEqual(executor.probes, remoteProbeSequence) {
		t.Fatalf("executor probes = %v after %d calls", executor.probes, executor.calls)
	}
	if facts.MachineID != "0123456789abcdef0123456789abcdef" ||
		facts.OperatingSystem != "linux" ||
		facts.Architecture != "amd64" ||
		facts.LogicalCPUs != 4 ||
		facts.MemoryTotalBytes != 8192*1024 ||
		facts.MemoryAvailableBytes != 4096*1024 ||
		facts.StorageTotalBytes != 16384*1024 ||
		facts.StorageAvailableBytes != 8192*1024 ||
		!facts.DockerEngineReady ||
		!facts.ComposePluginReady {
		t.Fatalf("normalized remote facts = %+v", facts)
	}
}

func TestSSHHostProbeRejectsMalformedOrIncompleteOutput(t *testing.T) {
	tests := map[string]func(map[RemoteProbeID]remoteProbeResult){
		"missing required result": func(values map[RemoteProbeID]remoteProbeResult) {
			delete(values, RemoteProbeCPU)
		},
		"failed required result": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeStorage] = remoteProbeResult{succeeded: false}
		},
		"invalid machine id": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeMachineID] = successfulRemoteResult("not-a-machine-id")
		},
		"unsupported operating system": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeOS] = successfulRemoteResult("Darwin")
		},
		"unsupported architecture": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeArch] = successfulRemoteResult("mips64")
		},
		"zero CPU": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeCPU] = successfulRemoteResult("0")
		},
		"incomplete memory": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeMemory] = successfulRemoteResult("8192")
		},
		"integer overflow": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeMemory] = successfulRemoteResult(
				"9007199254740992 1",
			)
		},
		"impossible storage": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeStorage] = successfulRemoteResult("100 101")
		},
		"sensitive external text": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeOS] = successfulRemoteResult("Linux password=must-not-leak")
		},
		"control character": func(values map[RemoteProbeID]remoteProbeResult) {
			values[RemoteProbeOS] = successfulRemoteResult("Linux\x00")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			results := validRemoteProbeResults()
			mutate(results)
			executor := &fakeRemoteProbeExecutor{results: results}
			probe := mustTestSSHHostProbe(t, executor)
			_, err := probe.Inspect(
				context.Background(),
				mustSSHBinding(t, "127.0.0.1:2222", pinnedTestHostKey(), "/"),
			)
			var failure ProbeFailure
			if !errors.As(err, &failure) ||
				failure.Kind != ProbeFailureValidation ||
				failure.ID != "ssh-output" {
				t.Fatalf("Inspect() error = %v, want ssh-output validation failure", err)
			}
			if strings.Contains(err.Error(), "must-not-leak") {
				t.Fatalf("normalized failure leaked remote output: %q", err)
			}
		})
	}
}

func TestSSHHostProbeNormalizesCredentialAndExecutorFailures(t *testing.T) {
	emptyResolver, err := NewStaticSSHCredentialResolver()
	if err != nil {
		t.Fatalf("NewStaticSSHCredentialResolver() error = %v", err)
	}
	executor := &fakeRemoteProbeExecutor{results: validRemoteProbeResults()}
	probe, err := newSSHHostProbe(emptyResolver, executor)
	if err != nil {
		t.Fatalf("newSSHHostProbe() error = %v", err)
	}
	binding := mustSSHBinding(
		t,
		"127.0.0.1:2222",
		pinnedTestHostKey(),
		"/",
	)
	if _, err := probe.Inspect(context.Background(), binding); err == nil {
		t.Fatal("missing credential must fail")
	} else {
		var failure ProbeFailure
		if !errors.As(err, &failure) ||
			failure.Kind != ProbeFailurePermission ||
			failure.ID != "ssh-credential" {
			t.Fatalf("missing credential error = %v", err)
		}
	}
	if executor.calls != 0 {
		t.Fatalf("executor called %d times without a credential", executor.calls)
	}

	nativeExecutor := &fakeRemoteProbeExecutor{
		err: errors.New("endpoint=10.0.0.8 password=must-not-leak"),
	}
	probe = mustTestSSHHostProbe(t, nativeExecutor)
	_, err = probe.Inspect(context.Background(), binding)
	var failure ProbeFailure
	if !errors.As(err, &failure) ||
		failure.Kind != ProbeFailureInternal ||
		failure.ID != "ssh" {
		t.Fatalf("native executor error = %v, want normalized internal failure", err)
	}
	if strings.Contains(err.Error(), "must-not-leak") ||
		strings.Contains(err.Error(), "10.0.0.8") {
		t.Fatalf("normalized executor failure leaked native detail: %q", err)
	}
}

func TestRemoteProbeCommandsAreClosedAndStoragePathIsQuotedByValidation(t *testing.T) {
	rootCommand, err := remoteProbeCommand(RemoteProbeStorage, "/")
	if err != nil {
		t.Fatalf("root storage command error = %v", err)
	}
	pathCommand, err := remoteProbeCommand(RemoteProbeStorage, "/var/lib/matrix")
	if err != nil {
		t.Fatalf("path storage command error = %v", err)
	}
	if !strings.Contains(rootCommand, "'/'") ||
		!strings.Contains(pathCommand, "'/var/lib/matrix'") {
		t.Fatalf("storage commands do not contain their validated literal path: %q / %q",
			rootCommand, pathCommand)
	}
	for _, unsafe := range []string{
		"/var/lib/matrix;id",
		"/var/lib/matrix path",
		"/var/lib/'matrix'",
		"../matrix",
		"/" + strings.Repeat("a", 4096),
	} {
		if _, err := remoteProbeCommand(RemoteProbeStorage, unsafe); err == nil {
			t.Fatalf("unsafe storage path %q must be rejected", unsafe)
		}
	}
	if _, err := remoteProbeCommand(RemoteProbeID("caller-command"), "/"); err == nil {
		t.Fatal("unknown remote probe identifier must be rejected")
	}
}

func TestAdapterUsesRemoteProbeAndNormalizesRemoteFailures(t *testing.T) {
	binding := mustSSHBinding(
		t,
		"127.0.0.1:2222",
		pinnedTestHostKey(),
		"/",
	)
	success := &fakeRemoteHostProbe{facts: validHostFacts()}
	adapter := mustRemoteAdapter(t, binding, success)
	request := validInspectExecutionTargetRequest()
	request.Command.BindingRef = binding.ID()
	observation, err := adapter.InspectExecutionTarget(context.Background(), request)
	if err != nil {
		t.Fatalf("remote InspectExecutionTarget() error = %v", err)
	}
	if success.calls != 1 || observation.Health != paasv1.ExecutionTargetHealthReady {
		t.Fatalf("remote observation = %+v after %d calls", observation, success.calls)
	}

	tests := map[ProbeFailureKind]struct {
		class paasv1.AdapterErrorClass
		code  paasv1.ErrorCode
	}{
		ProbeFailureHostKey: {
			class: paasv1.AdapterErrorPermissionDenied,
			code:  paasv1.ErrorAdapterRejected,
		},
		ProbeFailurePermission: {
			class: paasv1.AdapterErrorPermissionDenied,
			code:  paasv1.ErrorPermissionDenied,
		},
		ProbeFailureValidation: {
			class: paasv1.AdapterErrorValidation,
			code:  paasv1.ErrorAdapterRejected,
		},
	}
	for kind, want := range tests {
		t.Run(string(kind), func(t *testing.T) {
			failing := mustRemoteAdapter(t, binding, &fakeRemoteHostProbe{
				err: ProbeFailure{Kind: kind, ID: "secret-native-probe"},
			})
			_, err := failing.InspectExecutionTarget(context.Background(), request)
			fault := requireAdapterFault(t, err)
			if fault.Normalized.Class != want.class ||
				fault.Normalized.Code != want.code ||
				fault.Normalized.Retryable {
				t.Fatalf("normalized remote fault = %+v", fault.Normalized)
			}
			if strings.Contains(fault.Error(), "secret-native-probe") {
				t.Fatalf("adapter fault leaked native probe ID: %q", fault.Error())
			}
		})
	}
}

func validRemoteProbeResults() map[RemoteProbeID]remoteProbeResult {
	return map[RemoteProbeID]remoteProbeResult{
		RemoteProbeMachineID: successfulRemoteResult("0123456789abcdef0123456789abcdef\n"),
		RemoteProbeOS:        successfulRemoteResult("Linux\n"),
		RemoteProbeArch:      successfulRemoteResult("x86_64\n"),
		RemoteProbeCPU:       successfulRemoteResult("4\n"),
		RemoteProbeMemory:    successfulRemoteResult("8192 4096\n"),
		RemoteProbeStorage:   successfulRemoteResult("16384 8192\n"),
		RemoteProbeDocker:    successfulRemoteResult(""),
		RemoteProbeCompose:   successfulRemoteResult(""),
	}
}

func successfulRemoteResult(value string) remoteProbeResult {
	return remoteProbeResult{output: []byte(value), succeeded: true}
}

func pinnedTestHostKey() string {
	return "SHA256:" + strings.Repeat("A", 43)
}

func mustSSHBinding(
	t *testing.T,
	endpoint string,
	hostKeyFingerprint string,
	storagePath string,
) MachineBinding {
	t.Helper()
	binding, err := NewMachineBinding(MachineBindingSpec{
		ID:            "remote-linux",
		Kind:          BindingSSH,
		Endpoint:      endpoint,
		CredentialRef: "credential-node-1",
		HostKeySHA256: hostKeyFingerprint,
		Labels:        map[string]string{"location": "remote"},
		AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{
			paasv1.IsolationWorkload,
		},
		StoragePath: storagePath,
	})
	if err != nil {
		t.Fatalf("NewMachineBinding(SSH) error = %v", err)
	}
	return binding
}

func mustParsedSSHCredential(t *testing.T, username string) SSHCredential {
	t.Helper()
	_, privateKeyPEM := mustSSHSignerAndPEM(t)
	credential, err := NewSSHCredential(SSHCredentialSpec{
		Username:      username,
		PrivateKeyPEM: privateKeyPEM,
	})
	if err != nil {
		t.Fatalf("NewSSHCredential() error = %v", err)
	}
	return credential
}

func mustTestSSHHostProbe(
	t *testing.T,
	executor remoteProbeExecutor,
) *SSHHostProbe {
	t.Helper()
	credential := mustParsedSSHCredential(t, "matrix")
	resolver, err := NewStaticSSHCredentialResolver(NamedSSHCredential{
		Ref:        "credential-node-1",
		Credential: credential,
	})
	if err != nil {
		t.Fatalf("NewStaticSSHCredentialResolver() error = %v", err)
	}
	probe, err := newSSHHostProbe(resolver, executor)
	if err != nil {
		t.Fatalf("newSSHHostProbe() error = %v", err)
	}
	return probe
}

func mustRemoteAdapter(
	t *testing.T,
	binding MachineBinding,
	probe RemoteHostProbe,
) *Adapter {
	t.Helper()
	resolver, err := NewStaticBindingResolver(binding)
	if err != nil {
		t.Fatalf("NewStaticBindingResolver() error = %v", err)
	}
	localProbe := &fakeHostProbe{facts: validHostFacts()}
	adapter, err := New(Config{
		Bindings:    resolver,
		LocalProbe:  localProbe,
		RemoteProbe: probe,
		Clock:       fixedClock,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return adapter
}
