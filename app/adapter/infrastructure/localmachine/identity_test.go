package localmachine

import (
	"strings"
	"testing"
)

func TestDeriveMachineFingerprintIsStableAndVersioned(t *testing.T) {
	facts := validHostFacts()
	first, err := DeriveMachineFingerprint(facts)
	if err != nil {
		t.Fatalf("DeriveMachineFingerprint() error = %v", err)
	}
	second, err := DeriveMachineFingerprint(facts)
	if err != nil {
		t.Fatalf("DeriveMachineFingerprint() second error = %v", err)
	}
	if first != second {
		t.Fatalf("machine fingerprints differ: %q and %q", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("machine fingerprint %q is not a contract digest", first)
	}
}

func TestDeriveMachineFingerprintChangesForIdentityFactsOnly(t *testing.T) {
	base := validHostFacts()
	baseFingerprint, err := DeriveMachineFingerprint(base)
	if err != nil {
		t.Fatalf("DeriveMachineFingerprint(base) error = %v", err)
	}
	tests := map[string]func(*HostFacts){
		"machine id": func(value *HostFacts) {
			value.MachineID = "machine-002"
		},
		"operating system": func(value *HostFacts) {
			value.OperatingSystem = "darwin"
		},
		"architecture": func(value *HostFacts) {
			value.Architecture = "arm64"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			got, err := DeriveMachineFingerprint(candidate)
			if err != nil {
				t.Fatalf("DeriveMachineFingerprint() error = %v", err)
			}
			if got == baseFingerprint {
				t.Fatalf("changing %s did not change identity", name)
			}
		})
	}

	capacityChanged := base
	capacityChanged.MemoryAvailableBytes--
	capacityChanged.DockerEngineReady = !capacityChanged.DockerEngineReady
	got, err := DeriveMachineFingerprint(capacityChanged)
	if err != nil {
		t.Fatalf("DeriveMachineFingerprint(capacity) error = %v", err)
	}
	if got != baseFingerprint {
		t.Fatal("capacity or capability changes must not rewrite machine identity")
	}
}

func TestDeriveMachineFingerprintRejectsIncompleteOrSensitiveFacts(t *testing.T) {
	tests := map[string]func(*HostFacts){
		"missing machine id": func(value *HostFacts) {
			value.MachineID = ""
		},
		"sensitive machine id": func(value *HostFacts) {
			value.MachineID = "access_token=leak"
		},
		"zero cpu": func(value *HostFacts) {
			value.LogicalCPUs = 0
		},
		"memory overflow": func(value *HostFacts) {
			value.MemoryAvailableBytes = value.MemoryTotalBytes + 1
		},
		"storage overflow": func(value *HostFacts) {
			value.StorageAvailableBytes = value.StorageTotalBytes + 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := validHostFacts()
			mutate(&candidate)
			if _, err := DeriveMachineFingerprint(candidate); err == nil {
				t.Fatal("invalid host facts must be rejected")
			}
		})
	}
}

func validHostFacts() HostFacts {
	return HostFacts{
		MachineID:             "machine-001",
		OperatingSystem:       "windows",
		Architecture:          "amd64",
		LogicalCPUs:           8,
		MemoryTotalBytes:      16 * 1024 * 1024 * 1024,
		MemoryAvailableBytes:  12 * 1024 * 1024 * 1024,
		StorageTotalBytes:     512 * 1024 * 1024 * 1024,
		StorageAvailableBytes: 400 * 1024 * 1024 * 1024,
		DockerEngineReady:     true,
		ComposePluginReady:    true,
	}
}
