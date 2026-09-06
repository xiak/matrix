package phase1e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

// The same gate binary probes each independently booted guest before loading
// images or enrolling a node. No HTTP/debug endpoint or caller host selector.
func TestOfflineNativeHostProbe(t *testing.T) {
	phase := os.Getenv("MATRIX_PHASE1_NATIVE_HOST_PROBE")
	if phase != "1" && phase != "runtime" && phase != "after-restart" {
		t.Skip("native offline companion only")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Fatal("native probe requires Linux/amd64 root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixtureRoot := os.Getenv(nativeFixtureRootEnvironment)
	if validateNativeFixtureRoot(fixtureRoot) != nil {
		t.Fatal("native fixture root is not an isolated task path")
	}
	installationRoot := filepath.Join(fixtureRoot, "installation")
	networkErr := assertNoExternalConnectivity()
	if phase == "1" {
		networkErr = assertNoExternalRoute()
	}
	if networkErr != nil || phase == "1" && assertEmptyDocker(ctx) != nil {
		t.Fatal("native companion is not empty and offline")
	}
	if _, err := os.Stat(installationRoot); (phase == "1" || phase == "runtime") && !os.IsNotExist(err) || phase == "after-restart" && err != nil {
		t.Fatal("native installation root already exists")
	}
	facts, err := localmachine.NewLocalHostProbe().Inspect(ctx, fixtureRoot)
	if err != nil || !facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatal("real native host prerequisites unavailable")
	}
	fingerprint, err := localmachine.DeriveMachineFingerprint(facts)
	if err != nil {
		t.Fatal("native fingerprint unavailable")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal("native boot identity unavailable")
	}
	engine, err := docker(ctx, "info", "--format", "{{.ID}}")
	if err != nil {
		t.Fatal("native engine identity unavailable")
	}
	result := nativeHostFacts{Fingerprint: fingerprint, BootID: strings.TrimSpace(string(boot)), EngineID: strings.TrimSpace(string(engine)), CPUs: int64(facts.LogicalCPUs), MemoryBytes: int64(facts.MemoryTotalBytes), StorageBytes: int64(facts.StorageTotalBytes)}
	if !validNativeFacts(result) {
		t.Fatal("native host facts invalid")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	name := "facts.json"
	if phase == "after-restart" {
		name = "facts-after-restart.json"
	}
	if _, err = privateFixtureFile(fixtureRoot, name, encoded); err != nil {
		t.Fatal(err)
	}
}

func TestNativeBootEvidenceRequiresNewKernelAndSameIdentity(t *testing.T) {
	before := nativeHostFacts{Fingerprint: "sha256:" + strings.Repeat("a", 64), BootID: "00000000-0000-0000-0000-000000000001", EngineID: "engine-1", CPUs: 2, MemoryBytes: 2 << 30, StorageBytes: 20 << 30}
	after := before
	after.BootID = "00000000-0000-0000-0000-000000000002"
	if !sameNativeHostAfterBoot(before, after) || sameNativeHostAfterBoot(before, before) {
		t.Fatal("kernel boot evidence not distinguished")
	}
	for _, change := range []func(*nativeHostFacts){func(v *nativeHostFacts) { v.MemoryBytes -= 4096 }, func(v *nativeHostFacts) { v.StorageBytes += 4096 }, func(v *nativeHostFacts) { v.CPUs++ }} {
		candidate := after
		change(&candidate)
		if !sameNativeHostAfterBoot(before, candidate) {
			t.Fatal("current capacity was mistaken for immutable host identity")
		}
	}
	for _, change := range []func(*nativeHostFacts){func(v *nativeHostFacts) { v.Fingerprint = "sha256:" + strings.Repeat("b", 64) }, func(v *nativeHostFacts) { v.EngineID = "engine-2" }, func(v *nativeHostFacts) { v.BootID = "" }, func(v *nativeHostFacts) { v.MemoryBytes = 0 }, func(v *nativeHostFacts) { v.StorageBytes = 0 }, func(v *nativeHostFacts) { v.CPUs = 0 }} {
		candidate := after
		change(&candidate)
		if sameNativeHostAfterBoot(before, candidate) {
			t.Fatal("replacement host or invalid physical facts accepted as retained boot")
		}
	}
}

func TestNativeRestartReceiptUsesTheAuthenticatedControllerTarget(t *testing.T) {
	now := time.Date(2026, 9, 2, 1, 2, 3, 0, time.UTC)
	terminal := now
	installationID := "mxi-" + strings.Repeat("a", 32)
	targetID := paasv1.ResourceID("a-runtime-native-1")
	input := nativeNodeInput{Endpoint: "https://172.17.0.1:16443"}
	fingerprint := "sha256:" + strings.Repeat("b", 64)
	connection := nodeconfig.Connection{
		BindingRef:          "a-runtime-native-1-connection",
		TargetID:            targetID,
		Endpoint:            input.Endpoint,
		IdentityFingerprint: fingerprint,
	}
	saved := nativeRetainedNode{
		Facts: nativeHostFacts{
			Fingerprint:  fingerprint,
			BootID:       "00000000-0000-0000-0000-000000000001",
			EngineID:     "engine-1",
			CPUs:         2,
			MemoryBytes:  2 << 30,
			StorageBytes: 20 << 30,
		},
		Digest:     "sha256:" + strings.Repeat("c", 64),
		AuditHash:  "sha256:" + strings.Repeat("d", 64),
		ObservedAt: now,
		Operation: paasv1.Operation{
			APIVersion:             paasv1.APIVersion,
			Kind:                   "Operation",
			ID:                     "operation-register-runtime-native-1",
			Scope:                  paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
			InstallationID:         installationID,
			Action:                 paasv1.OperationRegisterExecutionTarget,
			Target:                 paasv1.ResourceRef{Kind: "ExecutionTarget", ID: targetID},
			RequestedBy:            paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "principal-admin"},
			IdempotencyFingerprint: "sha256:" + strings.Repeat("e", 64),
			RequestDigest:          "sha256:" + strings.Repeat("f", 64),
			State:                  paasv1.OperationSucceeded,
			Attempt:                1,
			CreatedAt:              now,
			UpdatedAt:              now,
			TerminalAt:             &terminal,
		},
	}

	actual, valid := nativeRestartConnection(input, saved, installationID, []nodeconfig.Connection{connection}, true)
	if !valid || actual.TargetID != targetID || actual.BindingRef != connection.BindingRef {
		t.Fatal("authenticated P3-4 runtime target was not restored from the controller")
	}
	if _, accepted := nativeRestartConnection(input, saved, installationID, []nodeconfig.Connection{connection}, false); accepted {
		t.Fatal("missing non-runtime workload receipt was accepted")
	}
	standalone := saved
	standalone.Workload = nativeWorkload{ID: strings.Repeat("2", 64), StartedAt: now.Format(time.RFC3339Nano), Running: true}
	if _, accepted := nativeRestartConnection(input, standalone, installationID, []nodeconfig.Connection{connection}, false); !accepted {
		t.Fatal("complete non-runtime workload receipt was rejected")
	}

	for _, scenario := range []struct {
		name   string
		change func(*nativeNodeInput, *nativeRetainedNode, *[]nodeconfig.Connection)
	}{
		{"stale ordinal target", func(_ *nativeNodeInput, value *nativeRetainedNode, _ *[]nodeconfig.Connection) {
			value.Operation.Target.ID = "offline-native-1"
		}},
		{"wrong operation", func(_ *nativeNodeInput, value *nativeRetainedNode, _ *[]nodeconfig.Connection) {
			value.Operation.Action = paasv1.OperationDrainExecutionTarget
		}},
		{"unfinished operation", func(_ *nativeNodeInput, value *nativeRetainedNode, _ *[]nodeconfig.Connection) {
			value.Operation.State = paasv1.OperationExecuting
			value.Operation.TerminalAt = nil
		}},
		{"replaced host", func(_ *nativeNodeInput, value *nativeRetainedNode, _ *[]nodeconfig.Connection) {
			value.Facts.Fingerprint = "sha256:" + strings.Repeat("1", 64)
		}},
		{"wrong endpoint", func(value *nativeNodeInput, _ *nativeRetainedNode, _ *[]nodeconfig.Connection) {
			value.Endpoint = "https://172.17.0.1:16444"
		}},
		{"ambiguous endpoint", func(_ *nativeNodeInput, _ *nativeRetainedNode, values *[]nodeconfig.Connection) {
			*values = append(*values, connection)
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			candidateInput, candidateSaved := input, saved
			connections := []nodeconfig.Connection{connection}
			scenario.change(&candidateInput, &candidateSaved, &connections)
			if _, accepted := nativeRestartConnection(candidateInput, candidateSaved, installationID, connections, true); accepted {
				t.Fatal("forged or stale restart receipt was accepted")
			}
		})
	}
}

func TestNativeRetentionPreservesDeploymentRuntimeAcrossBoot(t *testing.T) {
	encoded, err := json.Marshal(nativeRetention{DeploymentRuntime: true})
	if err != nil {
		t.Fatal(err)
	}
	var decoded nativeRetention
	if decodeOne(encoded, &decoded) != nil || !decoded.DeploymentRuntime {
		t.Fatal("deployment-runtime validation mode was lost across the reboot receipt")
	}
}

func TestNativeSSHTransportPinsAndReusesConnections(t *testing.T) {
	fixture := nativeNodes{input: nativeFixtureInput{
		IdentityFile:   "/data/xiak/private/id_ed25519",
		KnownHostsFile: "/data/xiak/private/known_hosts",
	}}
	joined := "\n" + strings.Join(fixture.sshArguments(0), "\n") + "\n"
	for _, required := range []string{
		"BatchMode=yes",
		"IdentitiesOnly=yes",
		"StrictHostKeyChecking=yes",
		"GlobalKnownHostsFile=/dev/null",
		"UserKnownHostsFile=/data/xiak/private/known_hosts",
		"ConnectionAttempts=3",
		"ControlMaster=auto",
		"ControlPersist=30s",
		"ControlPath=" + nativeSSHControlPath,
	} {
		if !strings.Contains(joined, "\n"+required+"\n") {
			t.Fatalf("required SSH boundary %q is absent", required)
		}
	}
	for _, forbidden := range []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "PasswordAuthentication=yes"} {
		if strings.Contains(joined, "\n"+forbidden+"\n") {
			t.Fatalf("unsafe SSH option %q is present", forbidden)
		}
	}
}

func TestNativeReadinessRetryAccommodatesAuthenticatedObservation(t *testing.T) {
	if nativeReadinessTimeout != 2*time.Minute || nativeReadinessAttemptTimeout != 2*nodev1.MaximumObservationAge ||
		nativeReadinessInitialDelay != 2*time.Second ||
		nativeReadinessMaximumDelay <= nodev1.MaximumObservationAge/2 ||
		nativeReadinessTimeout < 3*nativeReadinessAttemptTimeout {
		t.Fatal("native readiness retry no longer accommodates bounded release authentication and fresh sampling")
	}
	delay := nativeReadinessInitialDelay
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}
	for index, expected := range want {
		if delay != expected {
			t.Fatalf("native readiness delay %d = %s, want %s", index, delay, expected)
		}
		delay = nextNativeReadinessDelay(delay)
	}
}

func TestNativeControlPlaneAddressIsOneCanonicalPrivateIPv4Address(t *testing.T) {
	for _, value := range []string{"10.0.0.1", "172.16.0.1", "192.168.255.254"} {
		if !validNativeControlPlaneAddress(value) {
			t.Fatalf("private control-plane address %q was rejected", value)
		}
	}
	for _, value := range []string{
		"", "8.8.8.8", "127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1",
		"::1", "192.168.50.1:8443", "matrix.internal", "192.168.050.001",
	} {
		if validNativeControlPlaneAddress(value) {
			t.Fatalf("external, ambiguous or non-canonical control-plane address %q was accepted", value)
		}
	}
}

func TestNativeEnrollmentTargetIdentityProtectsFirstFitOrdering(t *testing.T) {
	for _, value := range []paasv1.ResourceID{
		"execution-target-00000000000000000000000000000000",
		"execution-target-abcdef0123456789abcdef0123456789",
	} {
		if !validNativeEnrollmentTargetID(value) {
			t.Fatalf("generated enrollment target %q was rejected", value)
		}
	}
	for _, value := range []paasv1.ResourceID{
		"execution-target-local",
		"execution-target-ABCDEF0123456789ABCDEF0123456789",
		"execution-target-abcdef",
		"execution-target-gggggggggggggggggggggggggggggggg",
		"target-abcdef0123456789abcdef0123456789",
	} {
		if validNativeEnrollmentTargetID(value) {
			t.Fatalf("ambiguous enrollment target %q was accepted", value)
		}
	}
}

func TestNativeFixtureRejectsAmbiguousOrExternalTargets(t *testing.T) {
	directory := t.TempDir()
	valid := nativeFixtureInput{ReleaseA: filepath.Join(directory, "a"), ReleaseB: filepath.Join(directory, "b"), IdentityFile: filepath.Join(directory, "client"), KnownHostsFile: filepath.Join(directory, "known_hosts"), FixtureRoot: "/data/xiak/matrix-native-gate-1", ControlPlaneAddress: "192.168.50.1", Nodes: []nativeNodeInput{{Port: 2201, Endpoint: "https://192.168.50.10:16443"}, {Port: 2202, Endpoint: "https://192.168.50.11:16443"}}}
	for _, scenario := range []struct {
		name   string
		change func(*nativeFixtureInput)
	}{
		{"one host", func(v *nativeFixtureInput) { v.Nodes = v.Nodes[:1] }},
		{"same SSH forward", func(v *nativeFixtureInput) { v.Nodes[1].Port = v.Nodes[0].Port }},
		{"same node endpoint", func(v *nativeFixtureInput) { v.Nodes[1].Endpoint = v.Nodes[0].Endpoint }},
		{"public endpoint", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint = "https://8.8.8.8:16443" }},
		{"DNS endpoint", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint = "https://node.invalid:16443" }},
		{"HTTP endpoint", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint = "http://172.17.0.1:16443" }},
		{"endpoint credentials", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint = "https://user@172.17.0.1:16443" }},
		{"query", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint += "?" }},
		{"public listen address", func(v *nativeFixtureInput) { v.Nodes[0].ListenAddress = "8.8.8.8:16443" }},
		{"DNS listen address", func(v *nativeFixtureInput) { v.Nodes[0].ListenAddress = "node.invalid:16443" }},
		{"missing listen port", func(v *nativeFixtureInput) { v.Nodes[0].ListenAddress = "172.17.0.1" }},
		{"privileged collector", func(v *nativeFixtureInput) { v.Nodes[0].CollectorPort = 443 }},
		{"shared node and collector port", func(v *nativeFixtureInput) { v.Nodes[0].CollectorPort = 16443 }},
		{"relative signer", func(v *nativeFixtureInput) { v.IdentityFile = "client" }},
		{"missing fixture root", func(v *nativeFixtureInput) { v.FixtureRoot = "" }},
		{"broad fixture root", func(v *nativeFixtureInput) { v.FixtureRoot = "/data/xiak" }},
		{"outside task area", func(v *nativeFixtureInput) { v.FixtureRoot = "/var/lib/matrix" }},
		{"unclean fixture root", func(v *nativeFixtureInput) { v.FixtureRoot += "/../other" }},
		{"public control plane", func(v *nativeFixtureInput) { v.ControlPlaneAddress = "8.8.8.8" }},
		{"loopback control plane", func(v *nativeFixtureInput) { v.ControlPlaneAddress = "127.0.0.1" }},
		{"control-plane port", func(v *nativeFixtureInput) { v.ControlPlaneAddress = "192.168.50.1:8443" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input := valid
			input.Nodes = append([]nativeNodeInput(nil), valid.Nodes...)
			scenario.change(&input)
			if validateNativeFixture(input) == nil {
				t.Fatal("unsafe or ambiguous native fixture accepted")
			}
		})
	}
	if validateNativeFixture(valid) != nil {
		t.Fatal("valid isolated native fixture rejected")
	}
	legacy := valid
	legacy.ControlPlaneAddress = ""
	if validateNativeFixture(legacy) != nil {
		t.Fatal("accepted pre-enrollment native fixture was rejected")
	}
}

func TestNativeEnrollmentFixtureRequiresThreeIndependentFixedPrivateListeners(t *testing.T) {
	valid := nativeFixtureInput{
		ControlPlaneAddress: "192.168.50.1",
		Nodes: []nativeNodeInput{
			{Port: 2201, Endpoint: "https://192.168.50.10:16443"},
			{Port: 2202, Endpoint: "https://192.168.50.11:16443"},
		},
	}
	if validateNativeEnrollmentFixture(valid) != nil {
		t.Fatal("independent control plane and fixed node listeners were rejected")
	}
	for _, scenario := range []struct {
		name   string
		change func(*nativeFixtureInput)
	}{
		{"missing control plane", func(value *nativeFixtureInput) { value.ControlPlaneAddress = "" }},
		{"node is control plane", func(value *nativeFixtureInput) {
			value.ControlPlaneAddress = "192.168.50.10"
		}},
		{"same node address", func(value *nativeFixtureInput) {
			value.Nodes[1].Endpoint = value.Nodes[0].Endpoint
		}},
		{"legacy forwarded port", func(value *nativeFixtureInput) {
			value.Nodes[1].Endpoint = "https://192.168.50.10:16444"
		}},
		{"custom management port", func(value *nativeFixtureInput) {
			value.Nodes[0].Endpoint = "https://192.168.50.10:16444"
		}},
		{"public node address", func(value *nativeFixtureInput) {
			value.Nodes[0].Endpoint = "https://8.8.8.8:16443"
		}},
		{"operator listen address", func(value *nativeFixtureInput) {
			value.Nodes[0].ListenAddress = "192.168.50.10:16443"
		}},
		{"operator collector port", func(value *nativeFixtureInput) {
			value.Nodes[0].CollectorPort = 19100
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			candidate := valid
			candidate.Nodes = append([]nativeNodeInput(nil), valid.Nodes...)
			scenario.change(&candidate)
			if validateNativeEnrollmentFixture(candidate) == nil {
				t.Fatal("legacy forwarding or operator-selected listener input was accepted")
			}
		})
	}
}

func TestNativeReleasePairRequiresTheExplicitDeploymentRuntimePredecessor(t *testing.T) {
	fixtures, err := releasetest.WriteNodeRuntimeSequence(
		t.TempDir(),
		nodeconfig.DeploymentRuntimePredecessorRevision,
		nodeconfig.RuntimeRevision,
	)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(fixtures[0].TrustPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := release.VerifyDirectory(fixtures[0].Root, trust)
	if err != nil {
		t.Fatal(err)
	}
	b, err := release.VerifyDirectory(fixtures[1].Root, trust)
	if err != nil {
		t.Fatal(err)
	}
	if validateNativeReleasePair(a, b) != nil {
		t.Fatal("authenticated deployment-runtime predecessor pair was rejected")
	}

	for _, scenario := range []struct {
		name   string
		change func(*release.VerifiedBundle, *release.VerifiedBundle)
	}{
		{"current release as predecessor", func(a, _ *release.VerifiedBundle) {
			a.Manifest.Node.RuntimeRevision = nodeconfig.RuntimeRevision
			a.Manifest.TopologyDigest = nodeconfig.ContractDigest()
		}},
		{"predecessor release as target", func(_, b *release.VerifiedBundle) {
			b.Manifest.Node.RuntimeRevision = nodeconfig.DeploymentRuntimePredecessorRevision
			b.Manifest.TopologyDigest = nodeconfig.DeploymentRuntimePredecessorContractDigest()
		}},
		{"non-root predecessor", func(a, _ *release.VerifiedBundle) {
			a.Manifest.Release.PreviousID = "another-release"
			a.Manifest.Release.PreviousVersion = "v0.0.1"
		}},
		{"non-adjacent target", func(_, b *release.VerifiedBundle) {
			b.Manifest.Release.PreviousID = "another-release"
		}},
		{"same source", func(a, b *release.VerifiedBundle) {
			b.Manifest.Release.SourceCommit = a.Manifest.Release.SourceCommit
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			candidateA, candidateB := a, b
			scenario.change(&candidateA, &candidateB)
			if validateNativeReleasePair(candidateA, candidateB) == nil {
				t.Fatal("unsupported or ambiguous native release pair was accepted")
			}
		})
	}
}

func TestNativeEnrollmentReleasePairRequiresTwoAdjacentCurrentReleases(t *testing.T) {
	fixtures, err := releasetest.WriteNodeRuntimeSequence(
		t.TempDir(), nodeconfig.RuntimeRevision, nodeconfig.RuntimeRevision,
	)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(fixtures[0].TrustPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := release.VerifyDirectory(fixtures[0].Root, trust)
	if err != nil {
		t.Fatal(err)
	}
	b, err := release.VerifyDirectory(fixtures[1].Root, trust)
	if err != nil {
		t.Fatal(err)
	}
	if validateNativeEnrollmentReleasePair(a, b) != nil {
		t.Fatal("adjacent current enrollment releases were rejected")
	}

	for _, scenario := range []struct {
		name   string
		change func(*release.VerifiedBundle, *release.VerifiedBundle)
	}{
		{"predecessor runtime as source", func(a, _ *release.VerifiedBundle) {
			a.Manifest.Node.RuntimeRevision = nodeconfig.DeploymentRuntimePredecessorRevision
			a.Manifest.TopologyDigest = nodeconfig.DeploymentRuntimePredecessorContractDigest()
		}},
		{"predecessor runtime as successor", func(_, b *release.VerifiedBundle) {
			b.Manifest.Node.RuntimeRevision = nodeconfig.DeploymentRuntimePredecessorRevision
			b.Manifest.TopologyDigest = nodeconfig.DeploymentRuntimePredecessorContractDigest()
		}},
		{"non-root source", func(a, _ *release.VerifiedBundle) {
			a.Manifest.Release.PreviousID = "another-release"
			a.Manifest.Release.PreviousVersion = "v0.0.1"
		}},
		{"non-adjacent successor", func(_, b *release.VerifiedBundle) {
			b.Manifest.Release.PreviousID = "another-release"
		}},
		{"same source commit", func(a, b *release.VerifiedBundle) {
			b.Manifest.Release.SourceCommit = a.Manifest.Release.SourceCommit
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			candidateA, candidateB := a, b
			scenario.change(&candidateA, &candidateB)
			if validateNativeEnrollmentReleasePair(candidateA, candidateB) == nil {
				t.Fatal("unsupported or ambiguous current enrollment pair was accepted")
			}
		})
	}
}

func TestNativeJoinSourceDecryptsOnlyTheBoundCreationEnvelope(t *testing.T) {
	wrappingKey, _, err := nativeWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	creation, credential, issuerPrivate := nativeJoinCreationFixture(t, wrappingKey)
	defer clear(credential)
	defer clear(issuerPrivate)

	source, decrypted, err := nativeJoinSource(creation, wrappingKey)
	if err != nil {
		t.Fatal("valid enrollment creation envelope was rejected")
	}
	defer clear(source)
	defer clear(decrypted)
	decoded, err := nodeconfig.DecodeJoinFile(source)
	if err != nil {
		t.Fatal("assembled join file did not satisfy the installer contract")
	}
	defer decoded.Clear()
	if !bytes.Equal(decrypted, credential) || decoded.Join != creation.Join ||
		decoded.Credential != base64.RawURLEncoding.EncodeToString(credential) ||
		!bytes.HasSuffix(source, []byte{'\n'}) ||
		bytes.Contains(source, []byte(creation.WrappedCredential.Ciphertext)) {
		t.Fatal("join source did not preserve exactly the signed metadata and decrypted credential")
	}

	reject := func(t *testing.T, candidate paasv1.CreateNodeEnrollmentResponse, key *rsa.PrivateKey) {
		t.Helper()
		candidateSource, candidateCredential, candidateErr := nativeJoinSource(candidate, key)
		defer clear(candidateSource)
		defer clear(candidateCredential)
		if candidateErr == nil || len(candidateSource) != 0 || len(candidateCredential) != 0 {
			t.Fatal("unbound or undecryptable enrollment creation envelope was accepted")
		}
	}

	t.Run("credential digest mismatch", func(t *testing.T) {
		candidate := creation
		other := sha256.Sum256([]byte("different enrollment credential"))
		candidate.Join.CredentialDigest = "sha256:" + hex.EncodeToString(other[:])
		resignNativeJoin(t, &candidate.Join, issuerPrivate)
		if paasv1.ValidateCreateNodeEnrollmentResponse(candidate) != nil {
			t.Fatal("digest-mismatch fixture did not retain a valid signed creation envelope")
		}
		reject(t, candidate, wrappingKey)
	})

	t.Run("cross-enrollment wrapping label", func(t *testing.T) {
		candidate := creation
		ciphertext, err := rsa.EncryptOAEP(
			sha256.New(), rand.Reader, &wrappingKey.PublicKey, credential, nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(ciphertext)
		candidate.WrappedCredential.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
		if paasv1.ValidateCreateNodeEnrollmentResponse(candidate) != nil {
			t.Fatal("wrong-label fixture did not retain a valid public creation envelope")
		}
		reject(t, candidate, wrappingKey)
	})

	t.Run("different wrapping private key", func(t *testing.T) {
		other, _, err := nativeWrappingKey()
		if err != nil {
			t.Fatal(err)
		}
		reject(t, creation, other)
	})

	t.Run("missing wrapping private key", func(t *testing.T) {
		reject(t, creation, nil)
	})
}

func nativeJoinCreationFixture(
	t *testing.T,
	wrappingKey *rsa.PrivateKey,
) (paasv1.CreateNodeEnrollmentResponse, []byte, ed25519.PrivateKey) {
	t.Helper()
	now := time.Date(2026, 9, 8, 8, 0, 0, 0, time.UTC)
	expiresAt := now.Add(20 * time.Minute)
	installationID := "mxi-" + strings.Repeat("a", 32)
	enrollmentID := paasv1.ResourceID("node-enrollment-" + strings.Repeat("b", 32))
	targetID := paasv1.ResourceID("execution-target-" + strings.Repeat("c", 32))
	credential := make([]byte, 32)
	for index := range credential {
		credential[index] = byte(index + 1)
	}
	digest := sha256.Sum256(credential)

	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "matrix-enrollment-issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		URIs:     []*url.URL{issuerURI},
	}
	issuerDER, err := x509.CreateCertificate(
		rand.Reader, issuerTemplate, issuerTemplate, issuerPublic, issuerPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	join := paasv1.NodeEnrollmentJoin{
		APIVersion: paasv1.NodeEnrollmentJoinAPIVersion, Kind: paasv1.NodeEnrollmentJoinKind,
		EnrollmentID: enrollmentID, InstallationID: installationID, ExecutionTargetID: targetID,
		ControlPlaneURL: "https://192.168.50.1:8443/api/paas/v1/node-enrollments/" +
			string(enrollmentID) + "/exchange",
		CredentialDigest: "sha256:" + hex.EncodeToString(digest[:]), ExpiresAt: expiresAt,
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(issuerDER),
		SignatureAlgorithm: paasv1.NodeJoinSignatureEd25519,
	}
	resignNativeJoin(t, &join, issuerPrivate)
	label, err := paasv1.NodeEnrollmentCredentialWrappingLabel(
		join.InstallationID, join.EnrollmentID,
	)
	if err != nil {
		clear(credential)
		t.Fatal(err)
	}
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(), rand.Reader, &wrappingKey.PublicKey, credential, label,
	)
	clear(label)
	if err != nil {
		clear(credential)
		t.Fatal(err)
	}
	defer clear(ciphertext)
	creation := paasv1.CreateNodeEnrollmentResponse{
		Enrollment: paasv1.NodeEnrollment{
			APIVersion: paasv1.APIVersion, Kind: "NodeEnrollment",
			Metadata: paasv1.ResourceMetadata{
				ID: enrollmentID, Name: "runtime-native-1",
				Scope:           paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
				Labels:          map[string]string{nativeRuntimeProfileLabel: nativeRuntimeProfile},
				ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
			},
			ExecutionTargetID: targetID, ExecutionPoolID: nativeRuntimePool,
			OperationID: "operation-enroll-runtime-native-1",
			State:       paasv1.NodeEnrollmentWaitingInstall, ExpiresAt: expiresAt,
		},
		Join: join,
		WrappedCredential: paasv1.WrappedJoinCredential{
			Algorithm:  paasv1.JoinCredentialRSAOAEP256,
			Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		},
	}
	if paasv1.ValidateCreateNodeEnrollmentResponse(creation) != nil {
		clear(credential)
		t.Fatal("native join creation fixture is invalid")
	}
	return creation, credential, issuerPrivate
}

func resignNativeJoin(t *testing.T, join *paasv1.NodeEnrollmentJoin, key ed25519.PrivateKey) {
	t.Helper()
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(*join)
	if err != nil {
		t.Fatal(err)
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, commitment))
}

func TestNativeDeploymentRuntimeRequiresExactAdvancingProviderNeutralProof(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	deployment := paasv1.Deployment{
		Metadata:   paasv1.ResourceMetadata{ID: "deployment-a", Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"}},
		Generation: 1,
		Spec:       paasv1.DeploymentSpec{ApplicationRevisionID: "revision-a"},
	}
	snapshot := paasv1.DeploymentRuntimeSnapshot{
		APIVersion: paasv1.APIVersion,
		Kind:       "DeploymentRuntimeSnapshot",
		Scope:      deployment.Metadata.Scope,
		State:      paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentRuntimeValue{
			Observation: paasv1.DeploymentRuntimeObservation{
				DeploymentID:          deployment.Metadata.ID,
				Generation:            deployment.Generation,
				ApplicationRevisionID: deployment.Spec.ApplicationRevisionID,
				ExecutionTargetID:     "target-a",
				Instances: []paasv1.DeploymentRuntimeInstance{{
					ID: "instance-0123456789abcdef0123456789abcdef", ComponentName: "web",
					State: paasv1.DeploymentInstanceRunning, Health: paasv1.DeploymentInstanceHealthNone,
				}},
				ObservedAt: now,
			},
			ValidUntil: now.Add(15 * time.Second),
		},
		Resources: paasv1.DeploymentResourceSnapshot{
			State: paasv1.MeasurementAvailable,
			Value: &paasv1.DeploymentResourceValue{
				Observation: paasv1.DeploymentResourceObservation{
					DeploymentID:          deployment.Metadata.ID,
					Generation:            deployment.Generation,
					ApplicationRevisionID: deployment.Spec.ApplicationRevisionID,
					ExecutionTargetID:     "target-a",
					Instances: []paasv1.DeploymentResourceInstance{{
						ID: "instance-0123456789abcdef0123456789abcdef",
						CPU: paasv1.DeploymentInstanceCPUUsage{
							State: paasv1.MeasurementAvailable,
							Value: &paasv1.DeploymentInstanceCPUUsageValue{
								WindowMillis: 1000, UsedCores: 0.1, LimitCPUMillis: 100,
							},
						},
						Memory: paasv1.DeploymentInstanceMemoryUsage{
							State: paasv1.MeasurementAvailable,
							Value: &paasv1.DeploymentInstanceMemoryUsageValue{
								UsedBytes: 8 << 20, LimitBytes: 32 << 20,
							},
						},
						Network: paasv1.DeploymentInstanceNetworkUsage{
							State: paasv1.MeasurementAvailable,
							Value: &paasv1.DeploymentInstanceNetworkUsageValue{},
						},
						BlockIO: paasv1.DeploymentInstanceBlockIOUsage{State: paasv1.MeasurementUnsupported},
						Storage: paasv1.DeploymentInstanceStorageUsage{
							State: paasv1.MeasurementAvailable,
							Value: &paasv1.DeploymentInstanceStorageUsageValue{
								ObservedAt: now.Add(-10 * time.Second), ValidUntil: now.Add(80 * time.Second),
								ImageTotalBytes: 10, ImageSharedBytes: 4, ImageUniqueBytes: 6,
								VolumesState: paasv1.MeasurementAvailable,
								Volumes:      &paasv1.DeploymentInstanceVolumeUsage{},
							},
						},
					}},
					ObservedAt: now,
				},
				ValidUntil: now.Add(15 * time.Second),
			},
		},
	}
	if !validNativeDeploymentRuntime(snapshot, deployment, "target-a", now.Add(-time.Second), now.Add(time.Second)) {
		t.Fatal("exact advancing runtime proof rejected")
	}
	advanced := snapshot.Snapshot(now)
	advanced.Value.Observation.ObservedAt = now.Add(time.Second)
	advanced.Value.ValidUntil = now.Add(16 * time.Second)
	advanced.Resources.Value.Observation.ObservedAt = now.Add(time.Second)
	advanced.Resources.Value.ValidUntil = now.Add(16 * time.Second)
	if !sameNativeRuntimeInstance(snapshot, advanced) {
		t.Fatal("same opaque instance was not retained across refreshed runtime proof")
	}
	replaced := advanced.Snapshot(now)
	replaced.Value.Observation.Instances[0].ID = "instance-fedcba9876543210fedcba9876543210"
	if sameNativeRuntimeInstance(snapshot, replaced) {
		t.Fatal("replacement instance was accepted as the refreshed terminal authority")
	}
	for _, change := range []func(*paasv1.DeploymentRuntimeSnapshot){
		func(value *paasv1.DeploymentRuntimeSnapshot) { value.Value.Observation.ExecutionTargetID = "target-b" },
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Value.Observation.ObservedAt = now.Add(-2 * time.Second)
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Value.Observation.Instances[0].Health = paasv1.DeploymentInstanceHealthUnhealthy
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Value.Observation.Instances[0].Health = paasv1.DeploymentInstanceHealthStarting
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) { value.Value.ValidUntil = now },
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.ExecutionTargetID = "target-b"
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.ObservedAt = now.Add(-2 * time.Second)
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].CPU.State = paasv1.MeasurementUnsupported
			value.Resources.Value.Observation.Instances[0].CPU.Value = nil
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].Storage.State = paasv1.MeasurementUnavailable
			value.Resources.Value.Observation.Instances[0].Storage.Value = nil
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].ID = "instance-fedcba9876543210fedcba9876543210"
		},
	} {
		candidate := snapshot.Snapshot(now)
		change(&candidate)
		if validNativeDeploymentRuntime(candidate, deployment, "target-a", now.Add(-time.Second), now.Add(time.Second)) {
			t.Fatal("stale, unready or wrong-target runtime proof accepted")
		}
	}
}

func TestNativeRetentionRequiresSameRunningContainerAndStart(t *testing.T) {
	baseline := nativeWorkload{ID: strings.Repeat("a", 64), StartedAt: "2026-08-28T00:00:00Z", Running: true}
	if !sameNativeWorkload(baseline, baseline) {
		t.Fatal("unchanged runtime rejected")
	}
	for _, scenario := range []struct {
		name   string
		change func(*nativeWorkload)
	}{
		{"replacement", func(v *nativeWorkload) { v.ID = strings.Repeat("b", 64) }},
		{"restart", func(v *nativeWorkload) { v.StartedAt = "2026-08-28T00:01:00Z" }},
		{"restart counter", func(v *nativeWorkload) { v.RestartCount++ }},
		{"stopped", func(v *nativeWorkload) { v.Running = false }},
		{"missing start", func(v *nativeWorkload) { v.StartedAt = "" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			current := baseline
			scenario.change(&current)
			if sameNativeWorkload(baseline, current) {
				t.Fatal("runtime replacement or downtime accepted as retention")
			}
		})
	}
}

func TestNativeEnrollmentPreservesEveryRunningPlatformContainer(t *testing.T) {
	baseline := func() []containerInspection {
		result := make([]containerInspection, 0, 3)
		for _, role := range []string{"paas-api", "paas-worker", "postgres"} {
			var container containerInspection
			container.ID = role + "-container"
			container.Config.Image = "sha256:" + strings.Repeat(string(role[0]), 64)
			container.Config.Labels = map[string]string{
				"com.xiak.matrix.installation": "installation-test",
				"com.xiak.matrix.role":         role,
			}
			container.State.Running = true
			container.State.StartedAt = "2026-09-08T00:00:00Z"
			result = append(result, container)
		}
		return result
	}
	before := baseline()
	after := baseline()
	after[0], after[2] = after[2], after[0]
	if !preservesNativeEnrollmentRuntime(before, after) {
		t.Fatal("unchanged running platform was rejected after enrollment observation")
	}

	for _, scenario := range []struct {
		name   string
		change func([]containerInspection) []containerInspection
	}{
		{"replacement", func(value []containerInspection) []containerInspection {
			value[0].ID = "replacement"
			return value
		}},
		{"restart", func(value []containerInspection) []containerInspection {
			value[0].State.StartedAt = "2026-09-08T00:01:00Z"
			return value
		}},
		{"restart counter", func(value []containerInspection) []containerInspection {
			value[0].RestartCount++
			return value
		}},
		{"image replacement", func(value []containerInspection) []containerInspection {
			value[0].Config.Image = "sha256:" + strings.Repeat("f", 64)
			return value
		}},
		{"label mutation", func(value []containerInspection) []containerInspection {
			value[0].Config.Labels["unexpected"] = "true"
			return value
		}},
		{"stopped", func(value []containerInspection) []containerInspection {
			value[0].State.Running = false
			return value
		}},
		{"missing", func(value []containerInspection) []containerInspection {
			return value[:len(value)-1]
		}},
		{"additional", func(value []containerInspection) []containerInspection {
			return append(value, value[0])
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			candidate := baseline()
			candidate = scenario.change(candidate)
			if preservesNativeEnrollmentRuntime(before, candidate) {
				t.Fatal("platform replacement, restart or inventory change was accepted")
			}
		})
	}
}

func TestNativeRotationAllowsOnlyTheOwnedAPIReplacement(t *testing.T) {
	var before []containerInspection
	for _, name := range []string{"paas-api", "paas-worker", "postgres", "workload"} {
		var container containerInspection
		container.ID = name + "-before"
		container.Config.Image = "sha256:" + strings.Repeat("a", 64)
		container.Config.Labels = map[string]string{"com.xiak.matrix.installation": "installation-test", "com.xiak.matrix.role": name}
		container.State.Running = true
		container.State.StartedAt = "2026-08-28T00:00:00Z"
		before = append(before, container)
	}
	for _, scenario := range []struct {
		name    string
		mutate  func([]containerInspection) []containerInspection
		allowed bool
	}{
		{"API only", func(v []containerInspection) []containerInspection { return v }, true},
		{"worker replacement", func(v []containerInspection) []containerInspection { v[1].ID = "new-worker"; return v }, false},
		{"database restart", func(v []containerInspection) []containerInspection {
			v[2].State.StartedAt = "2026-08-28T00:01:00Z"
			return v
		}, false},
		{"workload restart counter", func(v []containerInspection) []containerInspection { v[3].RestartCount++; return v }, false},
		{"database stopped", func(v []containerInspection) []containerInspection { v[2].State.Running = false; return v }, false},
		{"API foreign installation", func(v []containerInspection) []containerInspection {
			v[0].Config.Labels = map[string]string{"com.xiak.matrix.installation": "foreign", "com.xiak.matrix.role": "paas-api"}
			return v
		}, false},
		{"API wrong image", func(v []containerInspection) []containerInspection { v[0].Config.Image = "other-image"; return v }, false},
		{"additional runtime", func(v []containerInspection) []containerInspection { return append(v, v[2]) }, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			after := append([]containerInspection(nil), before...)
			after[0].ID = "new-api"
			after[0].State.StartedAt = "2026-08-28T00:01:00Z"
			after = scenario.mutate(after)
			if preservesNativeRotationRuntime(before, after, "installation-test") != scenario.allowed {
				t.Fatal("API-only replacement boundary misclassified")
			}
		})
	}
}
