package localmachine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	paasv1 "matrix/api/paas/v1"
)

func TestNewMachineBindingCanonicalizesAndOwnsCollections(t *testing.T) {
	labels := map[string]string{"location": "local"}
	isolation := []paasv1.IsolationClass{
		paasv1.IsolationSharedCompose,
		paasv1.IsolationDedicatedCompose,
	}
	binding, err := NewMachineBinding(MachineBindingSpec{
		ID:                      "local",
		Kind:                    BindingLocal,
		Labels:                  labels,
		AllowedIsolationClasses: isolation,
	})
	if err != nil {
		t.Fatalf("NewMachineBinding() error = %v", err)
	}
	labels["location"] = "mutated"
	isolation[0] = paasv1.IsolationPhysicalHost

	if got := binding.Labels()["location"]; got != "local" {
		t.Fatalf("binding label = %q, want local", got)
	}
	if got := binding.AllowedIsolationClasses(); !reflect.DeepEqual(got, []paasv1.IsolationClass{
		paasv1.IsolationDedicatedCompose,
		paasv1.IsolationSharedCompose,
	}) {
		t.Fatalf("canonical isolation classes = %v", got)
	}

	clonedLabels := binding.Labels()
	clonedLabels["location"] = "changed-again"
	if got := binding.Labels()["location"]; got != "local" {
		t.Fatalf("binding leaked its label map: %q", got)
	}
}

func TestLocalBindingRejectsMixedOrUnsafeConfiguration(t *testing.T) {
	tests := map[string]MachineBindingSpec{
		"ssh fields": {
			ID:                      "local",
			Kind:                    BindingLocal,
			Endpoint:                "example.internal:22",
			AllowedIsolationClasses: []paasv1.IsolationClass{paasv1.IsolationSharedCompose},
		},
		"relative storage": {
			ID:                      "local",
			Kind:                    BindingLocal,
			StoragePath:             "relative",
			AllowedIsolationClasses: []paasv1.IsolationClass{paasv1.IsolationSharedCompose},
		},
		"reserved label": {
			ID:                      "local",
			Kind:                    BindingLocal,
			Labels:                  map[string]string{"matrix-os": "forged"},
			AllowedIsolationClasses: []paasv1.IsolationClass{paasv1.IsolationSharedCompose},
		},
		"sensitive label": {
			ID:                      "local",
			Kind:                    BindingLocal,
			Labels:                  map[string]string{"note": "access_token=not-allowed"},
			AllowedIsolationClasses: []paasv1.IsolationClass{paasv1.IsolationSharedCompose},
		},
		"control character": {
			ID:                      "local",
			Kind:                    BindingLocal,
			Labels:                  map[string]string{"note": "line1\nline2"},
			AllowedIsolationClasses: []paasv1.IsolationClass{paasv1.IsolationSharedCompose},
		},
		"unsupported isolation": {
			ID:                      "local",
			Kind:                    BindingLocal,
			AllowedIsolationClasses: []paasv1.IsolationClass{paasv1.IsolationPhysicalHost},
		},
		"empty isolation": {
			ID:   "local",
			Kind: BindingLocal,
		},
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewMachineBinding(spec); err == nil {
				t.Fatal("unsafe binding must be rejected")
			}
		})
	}
}

func TestSSHBindingRequiresPinnedReferenceOnlyConfiguration(t *testing.T) {
	valid := MachineBindingSpec{
		ID:                      "remote-linux",
		Kind:                    BindingSSH,
		Endpoint:                "node-1.example.internal:22",
		CredentialRef:           "credential-ssh-node-1",
		HostKeySHA256:           "SHA256:" + strings.Repeat("A", 43),
		StoragePath:             "/var/lib/matrix",
		AllowedIsolationClasses: []paasv1.IsolationClass{paasv1.IsolationDedicatedCompose},
	}
	if _, err := NewMachineBinding(valid); err != nil {
		t.Fatalf("valid pinned SSH binding rejected: %v", err)
	}

	tests := map[string]func(*MachineBindingSpec){
		"missing endpoint": func(value *MachineBindingSpec) {
			value.Endpoint = ""
		},
		"userinfo endpoint": func(value *MachineBindingSpec) {
			value.Endpoint = "root@node-1.example.internal:22"
		},
		"missing credential ref": func(value *MachineBindingSpec) {
			value.CredentialRef = ""
		},
		"missing pin": func(value *MachineBindingSpec) {
			value.HostKeySHA256 = ""
		},
		"invalid pin": func(value *MachineBindingSpec) {
			value.HostKeySHA256 = "SHA256:not-a-pin"
		},
		"relative remote storage": func(value *MachineBindingSpec) {
			value.StoragePath = "var/lib/matrix"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewMachineBinding(candidate); err == nil {
				t.Fatal("unsafe SSH binding must be rejected")
			}
		})
	}
}

func TestStaticBindingResolverIsImmutableAndFailClosed(t *testing.T) {
	binding := mustLocalBinding(t, "")
	resolver, err := NewStaticBindingResolver(binding)
	if err != nil {
		t.Fatalf("NewStaticBindingResolver() error = %v", err)
	}
	first, err := resolver.Resolve(context.Background(), "local")
	if err != nil {
		t.Fatalf("Resolve(local) error = %v", err)
	}
	first.labels["location"] = "mutated"
	second, err := resolver.Resolve(context.Background(), "local")
	if err != nil {
		t.Fatalf("Resolve(local) second error = %v", err)
	}
	if got := second.labels["location"]; got != "local" {
		t.Fatalf("resolver leaked mutable binding state: %q", got)
	}
	if _, err := resolver.Resolve(context.Background(), "missing"); !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("Resolve(missing) error = %v, want ErrBindingNotFound", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.Resolve(cancelled, "local"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestStaticBindingResolverRejectsDuplicateIDs(t *testing.T) {
	binding := mustLocalBinding(t, "")
	if _, err := NewStaticBindingResolver(binding, binding); err == nil {
		t.Fatal("duplicate binding IDs must be rejected")
	}
}

func mustLocalBinding(t *testing.T, expectedFingerprint string) MachineBinding {
	t.Helper()
	binding, err := NewMachineBinding(MachineBindingSpec{
		ID:                         "local",
		Kind:                       BindingLocal,
		ExpectedMachineFingerprint: expectedFingerprint,
		Labels:                     map[string]string{"location": "local"},
		AllowedIsolationClasses: []paasv1.IsolationClass{
			paasv1.IsolationSharedCompose,
			paasv1.IsolationDedicatedCompose,
		},
	})
	if err != nil {
		t.Fatalf("NewMachineBinding(local) error = %v", err)
	}
	return binding
}
