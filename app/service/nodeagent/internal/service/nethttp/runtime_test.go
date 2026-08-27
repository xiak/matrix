//go:build linux

package nethttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

// This extends the existing process gate with the real mx lifecycle, signed
// native payloads, systemd ownership and self-readiness. It never installs a
// package or changes an existing Docker object or system service.
func TestLinuxSignedNodeStartup(t *testing.T) {
	if os.Getenv("MATRIX_NODE_INSTALLATION_REAL_RUNTIME") != "1" {
		t.Skip("set MATRIX_NODE_INSTALLATION_REAL_RUNTIME=1 on an isolated native systemd host")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" {
		t.Fatal("signed node gate requires native Linux/amd64 root")
	}
	bundle, releaseTrust := os.Getenv("MATRIX_NODE_RELEASE_BUNDLE"), os.Getenv("MATRIX_NODE_RELEASE_TRUST")
	for _, path := range []string{bundle, releaseTrust} {
		if !filepath.IsAbs(path) {
			t.Fatal("signed node gate requires a release-builder bundle and its trust root")
		}
	}
	trustBytes, _, err := release.ReadTrustRootFile(releaseTrust)
	if err != nil {
		t.Fatal("signed node trust root is unavailable")
	}
	verified, err := release.VerifyDirectory(bundle, trustBytes)
	if err != nil || verified.Manifest.Kind != release.NodeManifestKind {
		t.Fatal("node gate release did not authenticate")
	}
	installer := filepath.Join(bundle, "bin", "mx")
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	base := t.TempDir()
	root := filepath.Join(base, "installation")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	facts, err := localmachine.NewLocalHostProbe().Inspect(ctx, base)
	cancel()
	if err != nil || !facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatal("node gate host prerequisites unavailable")
	}
	fingerprint, err := localmachine.DeriveMachineFingerprint(facts)
	if err != nil {
		t.Fatal(err)
	}
	var identityEntropy [16]byte
	if _, err := rand.Read(identityEntropy[:]); err != nil {
		t.Fatal(err)
	}
	identity := nodev1.Identity{InstallationID: "mxi-" + hex.EncodeToString(identityEntropy[:]), ExecutionTargetID: nodeIdentity.ExecutionTargetID}
	collectorUnit, _ := nodeconfig.ServiceName(identity, true)
	nodeUnit, _ := nodeconfig.ServiceName(identity, false)
	units := []string{nodeUnit, collectorUnit}
	for _, unit := range units {
		load := nativeUnitProperty(t, unit, "LoadState")
		if load != "not-found" {
			t.Fatal("node gate unit identity already exists")
		}
	}
	t.Cleanup(func() {
		for _, unit := range units {
			description := nativeUnitProperty(t, unit, "Description")
			if description == unit || description == "" {
				continue
			}
			if !strings.HasPrefix(description, "Matrix node ") && !strings.HasPrefix(description, "Matrix collector ") {
				t.Error("node gate refuses to clean a foreign service")
				continue
			}
			nativeSystemctl(t, "stop", unit)
			// A successful stop may have already garbage-collected the unit.
			if nativeUnitProperty(t, unit, "LoadState") == "loaded" {
				nativeSystemctl(t, "reset-failed", unit)
			}
		}
	})
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(identity)
	collectorURI, _ := nodev1.CollectorURI(identity)
	controllerURI, _ := nodev1.ControllerURI(identity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	collector := authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	certificateFile, keyFile := nativeCertificateFiles(t, base, "node", node)
	collectorCertificate, collectorKey := nativeCertificateFiles(t, base, "collector", collector)
	trustFile := filepath.Join(base, "trust.pem")
	if err := os.WriteFile(trustFile, authority.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	config := nodeconfig.Configuration{
		APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.ConfigurationKind, Identity: identity,
		ControllerID: controllerID, BindingRef: "binding-a", ExpectedFingerprint: fingerprint,
		ListenAddress: unusedLoopbackAddress(t), CollectorEndpoint: "https://" + unusedLoopbackAddress(t),
		StoragePath: filepath.Join(root, "runtime", "executor"), CertificateFile: certificateFile, PrivateKeyFile: keyFile, TrustFile: trustFile,
		SystemReserve: paasv1.Capacity{MemoryBytes: 256 * 1024 * 1024},
	}
	enrollment := nodeconfig.Enrollment{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.EnrollmentKind,
		Node: config, CollectorCertificateFile: collectorCertificate, CollectorPrivateKeyFile: collectorKey}
	enrollmentBytes, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentFile := filepath.Join(base, "enrollment.json")
	if err := os.WriteFile(enrollmentFile, enrollmentBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	diagnosticContext, stopDiagnostic := context.WithCancel(context.Background())
	defer stopDiagnostic()
	diagnostic := make(chan string, 1)
	go func() {
		select {
		case <-diagnosticContext.Done():
			return
		case <-time.After(10 * time.Second):
		}
		var summary strings.Builder
		for _, unit := range units {
			ctx, cancel := context.WithTimeout(diagnosticContext, 3*time.Second)
			output, _ := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState,SubState,MainPID,ExecMainCode,ExecMainStatus,NRestarts", unit).Output()
			cancel()
			if len(output) < 4096 {
				summary.WriteString(string(output))
			}
		}
		client, err := nodehttps.New(nodehttps.Config{Endpoint: "https://" + config.ListenAddress, Identity: identity,
			ControllerID: controllerID, BindingRef: config.BindingRef, ExpectedFingerprint: fingerprint, Credentials: controller.credentials})
		if err == nil {
			defer client.Close()
			ctx, cancel := context.WithTimeout(diagnosticContext, 3*time.Second)
			defer cancel()
			command := observationCommand()
			command.Deadline = time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
			value, err := client.ObserveExecutionTarget(ctx, paasv1.ObserveExecutionTargetRequest{Command: command})
			fmt.Fprintf(&summary, "health=%s usage=%t error=%v", value.Health, value.Usage != nil, err)
			if value.Usage != nil {
				fmt.Fprintf(&summary, " cpu=%s memory=%s filesystems=%s", value.Usage.CPU.State, value.Usage.Memory.State, value.Usage.FilesystemsState)
			}
		}
		diagnostic <- summary.String()
	}()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		select {
		case summary := <-diagnostic:
			t.Logf("startup snapshot: %s", summary)
		default:
		}
		client, err := nodehttps.New(nodehttps.Config{Endpoint: "https://" + config.ListenAddress, Identity: identity,
			ControllerID: controllerID, BindingRef: config.BindingRef, ExpectedFingerprint: fingerprint, Credentials: controller.credentials})
		if err != nil {
			return
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		command := observationCommand()
		command.Deadline = time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
		value, err := client.ObserveExecutionTarget(ctx, paasv1.ObserveExecutionTargetRequest{Command: command})
		t.Logf("node observation diagnostic: health=%s usage=%t error=%v", value.Health, value.Usage != nil, err)
		if value.Usage != nil {
			t.Logf("node measurement states: cpu=%s memory=%s filesystems=%s", value.Usage.CPU.State, value.Usage.Memory.State, value.Usage.FilesystemsState)
		}
	})
	installArgs := []string{"node", "install", "--root", root, "--bundle", bundle, "--trust-key", releaseTrust, "--configuration", enrollmentFile}
	// A role substitution fails before creating a root or touching services.
	wrong := enrollment
	wrong.Node.PrivateKeyFile = collectorKey
	wrongBytes, _ := json.Marshal(wrong)
	if err := os.WriteFile(enrollmentFile, wrongBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	nativeMX(t, installer, false, installArgs...)
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("invalid enrollment created an installation root")
	}
	if err := os.WriteFile(enrollmentFile, enrollmentBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	installed := nativeMX(t, installer, true, installArgs...)
	if installed.State != "READY" || !installed.Changed || installed.ExecutionTargetID != string(identity.ExecutionTargetID) ||
		installed.ReleaseID != verified.Manifest.Release.ID {
		t.Fatal("signed node install did not commit real readiness")
	}
	journalPath := filepath.Join(root, "state", "journal.json")
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	firstPID := nativeUnitProperty(t, nodeUnit, "MainPID")
	collectorPID := nativeUnitProperty(t, collectorUnit, "MainPID")
	if firstPID == "" || firstPID == "0" || collectorPID == "" || collectorPID == "0" || nativeUnitProperty(t, collectorUnit, "DynamicUser") != "yes" {
		t.Fatal("native supervision or separate collector UID absent")
	}
	collectorProcess, err := os.Stat("/proc/" + collectorPID)
	if err != nil || collectorProcess.Sys().(*syscall.Stat_t).Uid == 0 {
		t.Fatal("collector is privileged")
	}
	uid := collectorProcess.Sys().(*syscall.Stat_t).Uid
	denied := exec.Command("/usr/bin/test", "-r", filepath.Join(root, "secrets", "node", "node-key.pem"))
	denied.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	if denied.Run() == nil {
		t.Fatal("collector UID can read node credentials")
	}
	denied = exec.Command("/usr/bin/test", "-w", "/var/run/docker.sock")
	denied.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	if denied.Run() == nil {
		t.Fatal("collector UID can access Docker")
	}
	replayed := nativeMX(t, installer, true, installArgs...)
	if replayed.Changed || nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID {
		t.Fatal("install replay replaced a running node")
	}
	nativeMX(t, installer, false, "platform", "status", "--root", root)
	after, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("install replay or platform directory misuse changed sealed state")
	}
	client, err := nodehttps.New(nodehttps.Config{Endpoint: "https://" + config.ListenAddress, Identity: identity,
		ControllerID: controllerID, BindingRef: config.BindingRef, ExpectedFingerprint: fingerprint, Credentials: controller.credentials})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first := awaitObservation(t, client, time.Time{}, paasv1.MeasurementAvailable)
	if first.Capacity.MemoryBytes != int64(facts.MemoryTotalBytes) || first.Usage.CPU.Value == nil {
		t.Fatal("signed node is not observing the real host")
	}
	storageUsage(t, first, config.StoragePath)
	// No UI reader or mx poll is needed for the next source sample.
	<-time.After(6 * time.Second)
	second := awaitObservation(t, client, first.ObservedAt, paasv1.MeasurementAvailable)
	if !second.Usage.ObservedAt.After(first.Usage.ObservedAt) {
		t.Fatal("signed node observations did not advance without readers")
	}
	// A changed staged executable is rejected before process replacement.
	staged := filepath.Join(root, "releases", installed.ReleaseID, "bin", "matrix-node-agent")
	original, err := os.ReadFile(staged)
	if err != nil || len(original) == 0 {
		t.Fatal("read owned staged payload")
	}
	original[0] ^= 0xff
	if os.WriteFile(staged+".tamper", original, 0o700) != nil || os.Rename(staged+".tamper", staged) != nil {
		t.Fatal("replace gate-owned staged payload")
	}
	nativeMX(t, installer, false, "node", "start", "--root", root)
	if nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID {
		t.Fatal("tampered release changed the running node")
	}
	original[0] ^= 0xff
	if os.WriteFile(staged+".tamper", original, 0o700) != nil || os.Rename(staged+".tamper", staged) != nil {
		t.Fatal("restore gate-owned staged payload")
	}
	clear(original)
	// A same-name service with changed policy is not installation-owned merely
	// because its process is still healthy. Reject it before replacement/stop.
	memoryLimit := nativeUnitProperty(t, collectorUnit, "MemoryMax")
	nativeSystemctl(t, "set-property", "--runtime", collectorUnit, "MemoryMax=67108864")
	nativeMX(t, installer, false, "node", "start", "--root", root)
	if nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID || nativeUnitProperty(t, collectorUnit, "MainPID") != collectorPID {
		t.Fatal("changed service ownership partially replaced or stopped the node")
	}
	nativeSystemctl(t, "set-property", "--runtime", collectorUnit, "MemoryMax="+memoryLimit)
	// A stopped collector makes readiness false without affecting reservations
	// or pretending the old source sample has a new timestamp.
	nativeSystemctl(t, "stop", collectorUnit)
	status := nativeMX(t, installer, true, "node", "status", "--root", root)
	if status.State != "NOT_READY" {
		t.Fatal("stopped collector reported ready")
	}
	started := nativeMX(t, installer, true, "node", "start", "--root", root)
	if started.State != "READY" || nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID {
		t.Fatal("collector reconciliation replaced the healthy node")
	}
	// Supervision, not mx polling, restarts a crashed resident process.
	nativeSystemctl(t, "kill", "--kill-who=main", "--signal=KILL", nodeUnit)
	deadline := time.Now().Add(15 * time.Second)
	for nativeUnitProperty(t, nodeUnit, "MainPID") == firstPID || nativeUnitProperty(t, nodeUnit, "MainPID") == "0" {
		if time.Now().After(deadline) {
			t.Fatal("systemd did not restart the owned node")
		}
		<-time.After(200 * time.Millisecond)
	}
	nativeMX(t, installer, true, "node", "verify", "--root", root)
	// Simulate loss of both resident processes, retaining the sealed root.
	for _, unit := range units {
		nativeSystemctl(t, "stop", unit)
	}
	// Hold collector readiness while the real mx process is interrupted. The
	// systemd-owned services must survive and a fresh mx must resume the exact
	// durable command, not start a new operation or replace either process.
	startContext, cancelStart := context.WithTimeout(context.Background(), 90*time.Second)
	interrupted := exec.CommandContext(startContext, installer, "--format", "json", "node", "start", "--root", root)
	var interruptionOutput bytes.Buffer
	interrupted.Stdout, interrupted.Stderr = &interruptionOutput, &interruptionOutput
	if err := interrupted.Start(); err != nil {
		cancelStart()
		t.Fatal("start interruptible node command")
	}
	done := make(chan struct{})
	var interruptedErr error
	go func() {
		interruptedErr = interrupted.Wait()
		close(done)
	}()
	defer func() {
		cancelStart()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("interrupted mx did not exit")
		}
	}()
	deadline = time.Now().Add(15 * time.Second)
	for {
		if pid := nativeUnitProperty(t, collectorUnit, "MainPID"); pid != "" && pid != "0" {
			break
		}
		select {
		case <-done:
			t.Fatal("mx exited before starting the collector")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("collector was not started before interruption")
		}
		<-time.After(100 * time.Millisecond)
	}
	for {
		if pid := nativeUnitProperty(t, nodeUnit, "MainPID"); pid != "" && pid != "0" {
			break
		}
		select {
		case <-done:
			if interruptionOutput.Len() <= 4096 {
				t.Logf("interruption startup result: %s", interruptionOutput.Bytes())
			}
			t.Fatal("mx exited before starting the node")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("node was not started before interruption")
		}
		<-time.After(100 * time.Millisecond)
	}
	// MainPID can be assigned before a Type=exec service has exec'd. Wait for
	// both services before pausing collection, so this does not stall systemd's
	// own startup job instead of exercising the installer's readiness phase.
	nativeSystemctl(t, "kill", "--kill-who=main", "--signal=STOP", collectorUnit)
	paused := true
	defer func() {
		if paused {
			nativeSystemctl(t, "kill", "--kill-who=main", "--signal=CONT", collectorUnit)
		}
	}()
	retainedNodePID, retainedCollectorPID := nativeUnitProperty(t, nodeUnit, "MainPID"), nativeUnitProperty(t, collectorUnit, "MainPID")
	if err := interrupted.Process.Kill(); err != nil {
		t.Fatal("mx completed before the interruption gate")
	}
	<-done
	if interruptedErr == nil {
		t.Fatal("interrupted mx reported successful completion")
	}
	pending := nativeMX(t, installer, true, "node", "status", "--root", root)
	if (pending.State != "STARTING" && pending.State != "VERIFYING") || pending.CorrelationID == "" {
		t.Fatal("interruption did not retain the in-flight command")
	}
	nativeSystemctl(t, "kill", "--kill-who=main", "--signal=CONT", collectorUnit)
	paused = false
	started = nativeMX(t, installer, true, "node", "start", "--root", root)
	if started.State != "READY" || started.ReleaseID != installed.ReleaseID || started.CorrelationID != pending.CorrelationID ||
		nativeUnitProperty(t, nodeUnit, "MainPID") != retainedNodePID || nativeUnitProperty(t, collectorUnit, "MainPID") != retainedCollectorPID {
		t.Fatal("node replay lost its command, committed release or running processes")
	}
}

type nativeMXResult struct {
	State             string `json:"state"`
	CorrelationID     string `json:"correlationId"`
	ReleaseID         string `json:"releaseId"`
	ExecutionTargetID string `json:"executionTargetId"`
	Changed           bool   `json:"changed"`
}

func nativeMX(t *testing.T, binary string, success bool, arguments ...string) nativeMXResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, append([]string{"--format", "json"}, arguments...)...)
	output, err := command.CombinedOutput()
	if (err == nil) != success || len(output) > 4096 {
		t.Fatalf("native mx %s failed: %s / %v", arguments[1], output, err)
	}
	var envelope struct {
		Kind   string         `json:"kind"`
		Status string         `json:"status"`
		Result nativeMXResult `json:"result"`
	}
	if json.Unmarshal(output, &envelope) != nil {
		t.Fatal("native mx output is not a bounded contract")
	}
	if success && (envelope.Kind != "NodeCommandResult" || envelope.Status != "SUCCEEDED") {
		t.Fatal("native mx did not return node success")
	}
	if !success && envelope.Status != "FAILED" {
		t.Fatal("native mx did not report failure")
	}
	return envelope.Result
}

func nativeSystemctl(t *testing.T, arguments ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "systemctl", arguments...)
	if command.Run() != nil {
		t.Error("fixture-owned systemd operation failed")
	}
}

func nativeUnitProperty(t *testing.T, unit, property string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemctl", "show", "--value", "--property="+property, unit).Output()
	if err != nil || len(output) > 4096 {
		t.Fatal("cannot read fixture unit property")
	}
	return strings.TrimSpace(string(output))
}

func nativeCertificateFiles(t *testing.T, root, name string, certificate issuedCertificate) (string, string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(certificate.pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(key)
	certificatePath, keyPath := filepath.Join(root, name+".pem"), filepath.Join(root, name+"-key.pem")
	if os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.pair.Certificate[0]}), 0o600) != nil ||
		os.WriteFile(keyPath, key, 0o600) != nil {
		t.Fatal("write native gate certificate")
	}
	return certificatePath, keyPath
}

// This opt-in gate uses an actual Linux host, Docker/Compose and the built
// node executable. Unit tests never start or modify a caller's Docker engine.
func TestLinuxNodeProcessObservation(t *testing.T) {
	if os.Getenv("MATRIX_NODE_AGENT_REAL_RUNTIME") != "1" {
		t.Skip("set MATRIX_NODE_AGENT_REAL_RUNTIME=1 on an isolated Linux Docker/Compose host")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("node runtime gate requires Linux/amd64")
	}
	if os.Geteuid() != 0 {
		t.Fatal("node runtime gate requires root on an isolated host to exercise a separate unprivileged collector UID")
	}
	binary := os.Getenv("MATRIX_NODE_AGENT_BINARY")
	collectorBinary := os.Getenv("MATRIX_NODE_EXPORTER_BINARY")
	if !filepath.IsAbs(binary) || !filepath.IsAbs(collectorBinary) {
		t.Fatal("MATRIX_NODE_AGENT_BINARY and MATRIX_NODE_EXPORTER_BINARY must select the verified Linux executables")
	}
	// The prerequisite probe must inspect the same local engine as the node,
	// regardless of the caller's inherited Docker endpoint or CLI context.
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	facts, err := localmachine.NewLocalHostProbe().Inspect(ctx, root)
	cancel()
	if err != nil || !facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatalf("real node prerequisites unavailable: docker=%t compose=%t error=%v", facts.DockerEngineReady, facts.ComposePluginReady, err)
	}
	fingerprint, err := localmachine.DeriveMachineFingerprint(facts)
	if err != nil {
		t.Fatal(err)
	}
	authority := newAuthority(t)
	nodeURI, _ := nodev1.NodeURI(nodeIdentity)
	controllerURI, _ := nodev1.ControllerURI(nodeIdentity.InstallationID, controllerID)
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	collectorURI, _ := nodev1.CollectorURI(nodeIdentity)
	collectorCertificate := authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
	collectorDirectory, err := os.MkdirTemp("", "matrix-node-collector-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(collectorDirectory) })
	collectorAddress := unusedLoopbackAddress(t)
	provisionCollector(t, collectorDirectory, collectorBinary, collectorCertificate, authority.pem, nodeURI)
	stopCollector := startCollectorProcess(t, collectorAddress, collectorDirectory, root)
	certificatePath := filepath.Join(root, "node.crt")
	keyPath := filepath.Join(root, "node.key")
	trustPath := filepath.Join(root, "trust.crt")
	keyDER, err := x509.MarshalPKCS8PrivateKey(node.pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	for path, content := range map[string][]byte{
		certificatePath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.pair.Certificate[0]}),
		keyPath:         keyPEM, trustPath: authority.pem,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	address := unusedLoopbackAddress(t)
	systemReserve := paasv1.Capacity{MemoryBytes: 256 * 1024 * 1024}
	configuration, err := json.Marshal(map[string]any{
		"apiVersion": "node.installation.matrix.xiak.com/v1", "kind": "NodeConfiguration",
		"identity": nodeIdentity, "controllerId": controllerID, "bindingRef": "binding-a",
		"expectedFingerprint": fingerprint, "listenAddress": address, "storagePath": root,
		"collectorEndpoint": "https://" + collectorAddress,
		"certificateFile":   certificatePath, "privateKeyFile": keyPath, "trustFile": trustPath,
		"systemReserve": systemReserve,
	})
	if err != nil {
		t.Fatal(err)
	}
	configurationPath := filepath.Join(root, "node.json")
	if err := os.WriteFile(configurationPath, configuration, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := nodehttps.New(nodehttps.Config{
		Endpoint: "https://" + address, Identity: nodeIdentity, ControllerID: controllerID,
		BindingRef: "binding-a", ExpectedFingerprint: fingerprint, Credentials: controller.credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stop := startAgentProcess(t, binary, configurationPath)
	first := awaitObservation(t, client, time.Time{}, paasv1.MeasurementAvailable)
	if first.Health != paasv1.ExecutionTargetHealthReady || first.Capacity.MemoryBytes != int64(facts.MemoryTotalBytes) ||
		first.Allocatable.MemoryBytes != first.Capacity.MemoryBytes-systemReserve.MemoryBytes {
		t.Fatal("real node did not report its OS capacity and installation reserve")
	}
	// No observer is connected during this interval; the resident sampler must
	// still advance. This is not an on-demand SSH probe disguised as streaming.
	timer := time.NewTimer(6 * time.Second)
	<-timer.C
	second := awaitObservation(t, client, first.ObservedAt, paasv1.MeasurementAvailable)
	storage := storageUsage(t, second, root)
	if second.Usage.CPU.State != paasv1.MeasurementAvailable || second.Usage.CPU.Value.LogicalCPUs != int64(facts.LogicalCPUs) ||
		second.Usage.Memory.Value.TotalBytes != int64(facts.MemoryTotalBytes) ||
		storage.TotalBytes <= 0 {
		t.Fatal("real collector did not report current CPU, memory and filesystem usage")
	}
	// Exercise the real collector's filesystem view using only a bounded file
	// owned by this gate. No workload, Docker object or unrelated file is touched.
	activityPath := filepath.Join(root, "filesystem-activity")
	activity, err := os.OpenFile(activityPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 1024*1024)
	for index := 0; index < 32; index++ {
		// Incompressible data exercises allocated space on compressed filesystems
		// as well as ext4; repeated zero blocks need not occupy physical space.
		if _, err := rand.Read(block); err != nil {
			_ = activity.Close()
			t.Fatal(err)
		}
		if _, err := activity.Write(block); err != nil {
			_ = activity.Close()
			t.Fatal(err)
		}
	}
	if err := activity.Sync(); err != nil {
		_ = activity.Close()
		t.Fatal(err)
	}
	if err := activity.Close(); err != nil {
		t.Fatal(err)
	}
	// One bounded CPU worker, not an unbounded host stress test. Its lifetime
	// overlaps a complete sampling window and cannot outlive the test.
	cpuDeadline := time.Now().Add(6 * time.Second)
	cpuDone := make(chan struct{})
	go func() {
		defer close(cpuDone)
		var digest [32]byte
		for time.Now().Before(cpuDeadline) {
			digest = sha256.Sum256(digest[:])
		}
	}()
	<-cpuDone
	activityAt := time.Now().UTC()
	activitySample := awaitObservation(t, client, activityAt, paasv1.MeasurementAvailable)
	if storageUsage(t, activitySample, root).UsedBytes <= storage.UsedBytes {
		t.Fatal("real filesystem measurement did not respond to the gate's file activity")
	}
	if activitySample.Usage.CPU.Value == nil || activitySample.Usage.CPU.Value.UtilizationRatio <= 0 ||
		math.Abs(activitySample.Usage.CPU.Value.UtilizationRatio-second.Usage.CPU.Value.UtilizationRatio) < 1e-9 {
		t.Fatal("CPU measurement did not change across real activity")
	}
	stopCollector()
	unavailable := awaitObservation(t, client, activitySample.ObservedAt, paasv1.MeasurementUnavailable)
	// Shared storage pools can change reported capacity between observations.
	// The invariant is reserve policy against this sample, not a frozen capacity.
	expectedAllocatable := unavailable.Capacity
	expectedAllocatable.MemoryBytes -= systemReserve.MemoryBytes
	if unavailable.Health != paasv1.ExecutionTargetHealthReady || unavailable.Allocatable != expectedAllocatable ||
		unavailable.Usage.Memory.Value != nil || unavailable.Usage.CPU.Value != nil {
		t.Fatalf("collector outage: health=%s capacity=%+v allocatable=%+v expected=%+v cpu=%s/%t memory=%s/%t",
			unavailable.Health, unavailable.Capacity, unavailable.Allocatable, expectedAllocatable,
			unavailable.Usage.CPU.State, unavailable.Usage.CPU.Value != nil,
			unavailable.Usage.Memory.State, unavailable.Usage.Memory.Value != nil)
	}
	stopCollector = startCollectorProcess(t, collectorAddress, collectorDirectory, root)
	recovered := awaitObservation(t, client, unavailable.ObservedAt, paasv1.MeasurementAvailable)
	stop()
	command := observationCommand()
	command.Deadline = time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
	if _, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: command}); err == nil {
		t.Fatal("stopped node remained available")
	}
	stop = startAgentProcess(t, binary, configurationPath)
	restarted := awaitObservation(t, client, recovered.ObservedAt, paasv1.MeasurementAvailable)
	if restarted.IdentityFingerprint != fingerprint {
		t.Fatal("restart changed the enrolled host identity")
	}
	stop()
	stopCollector()
	t.Log("authenticated Linux node and separate-UID collector continuously measured CPU/memory/filesystem usage, observed file activity and recovered from collector/node restarts")
}

func startAgentProcess(t *testing.T, binary, configurationPath string) func() {
	t.Helper()
	command := exec.Command(binary)
	command.Env = append(os.Environ(),
		"MATRIX_NODE_CONFIGURATION_FILE="+configurationPath,
		"DOCKER_HOST=tcp://127.0.0.1:1", "DOCKER_CONTEXT=must-not-select-another-engine")
	return startRuntimeProcess(t, command, false)
}

func startRuntimeProcess(t *testing.T, command *exec.Cmd, acceptsSignal bool) func() {
	t.Helper()
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal("node executable could not start")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-done:
				if err != nil && !(acceptsSignal && command.ProcessState.Sys().(syscall.WaitStatus).Signal() == syscall.SIGTERM) {
					t.Error("node process did not stop cleanly")
				}
			case <-time.After(5 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Error("node process did not honor shutdown")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func unusedLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func provisionCollector(t *testing.T, directory, binary string, certificate issuedCertificate, trust []byte, nodeURI string) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	defer clear(keyPEM)
	configuration := fmt.Sprintf("tls_server_config:\n  cert_file: %q\n  key_file: %q\n  client_ca_file: %q\n  client_auth_type: RequireAndVerifyClientCert\n  client_allowed_sans:\n    - %q\n  min_version: TLS13\nhttp_server_config:\n  http2: false\n",
		filepath.Join(directory, "collector.crt"), filepath.Join(directory, "collector.key"), filepath.Join(directory, "trust.crt"), nodeURI)
	for name, content := range map[string][]byte{
		"collector.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.pair.Certificate[0]}),
		"collector.key": keyPEM, "trust.crt": trust, "web.yml": []byte(configuration),
	} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	// The verified source artifact may live below a root-only build directory.
	// Copy it into this fixture without granting the collector write access to
	// its executable or loosening any existing directory's permissions.
	source, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	executable, err := os.OpenFile(filepath.Join(directory, "node_exporter"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o555)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(executable, source)
	modeErr := executable.Chmod(0o555)
	closeErr := executable.Close()
	if copyErr != nil || modeErr != nil || closeErr != nil {
		t.Fatal("collector fixture could not be copied")
	}
	if err := os.Chmod(directory, 0o711); err != nil {
		t.Fatal(err)
	}
}

func startCollectorProcess(t *testing.T, address, directory, storagePath string) func() {
	t.Helper()
	var parents []string
	for path := storagePath; ; path = filepath.Dir(path) {
		parents = append(parents, regexp.QuoteMeta(path))
		if path == "/" {
			break
		}
	}
	command := exec.Command(filepath.Join(directory, "node_exporter"),
		"--web.listen-address="+address, "--web.config.file="+filepath.Join(directory, "web.yml"),
		"--web.disable-exporter-metrics", "--web.max-requests=2", "--collector.disable-defaults",
		"--collector.cpu", "--collector.loadavg", "--collector.meminfo", "--collector.filesystem",
		"--collector.filesystem.mount-points-include=^("+strings.Join(parents, "|")+")$", "--collector.filesystem.fs-types-exclude=^$",
		"--collector.filesystem.mount-timeout=1s")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	return startRuntimeProcess(t, command, true)
}

func storageUsage(t *testing.T, observation paasv1.ExecutionTargetObservation, path string) paasv1.FilesystemUsageValue {
	t.Helper()
	var selected *paasv1.FilesystemUsage
	for index := range observation.Usage.Filesystems {
		filesystem := &observation.Usage.Filesystems[index]
		prefix := strings.TrimSuffix(filesystem.MountPoint, "/") + "/"
		if (path == filesystem.MountPoint || strings.HasPrefix(path, prefix)) &&
			(selected == nil || len(filesystem.MountPoint) > len(selected.MountPoint)) {
			selected = filesystem
		}
	}
	if observation.Usage.FilesystemsState != paasv1.MeasurementAvailable || selected == nil ||
		selected.State != paasv1.MeasurementAvailable || selected.Value == nil {
		t.Fatal("collector did not report the experiment's actual storage filesystem")
	}
	return *selected.Value
}

func awaitObservation(t *testing.T, client *nodehttps.Client, after time.Time, memoryState paasv1.MeasurementState) paasv1.ExecutionTargetObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		command := observationCommand()
		command.Deadline = time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
		value, err := client.ObserveExecutionTarget(ctx, paasv1.ObserveExecutionTargetRequest{Command: command})
		if err == nil && value.ObservedAt.After(after) && value.Usage != nil && value.Usage.Memory.State == memoryState {
			return value
		}
		select {
		case <-ctx.Done():
			t.Fatal("real node did not produce a new authenticated observation")
		case <-ticker.C:
		}
	}
}
