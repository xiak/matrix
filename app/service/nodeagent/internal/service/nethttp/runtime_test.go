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
	"sync/atomic"
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
	bootPhase, bootRoot := os.Getenv("MATRIX_NODE_BOOT_PHASE"), os.Getenv("MATRIX_NODE_BOOT_ROOT")
	if bootPhase != "" {
		if (bootPhase != "prepare" && bootPhase != "verify") || !filepath.IsAbs(bootRoot) ||
			filepath.Clean(bootRoot) != bootRoot || !strings.HasPrefix(filepath.Base(bootRoot), "matrix-node-boot-") {
			t.Fatal("boot gate needs a dedicated absolute fixture root and prepare/verify phase")
		}
		if bootPhase == "verify" {
			verifyNativeBoot(t, installer, bootRoot, verified.Manifest.Release.ID)
			return
		}
	}
	var base string
	if bootPhase == "prepare" {
		base = bootRoot
		if err := os.Mkdir(base, 0o700); err != nil {
			t.Fatal("boot gate root already exists or cannot be created")
		}
	} else {
		base = t.TempDir()
	}
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
	startupUnit, _ := nodeconfig.StartupServiceName(identity)
	units := []string{nodeUnit, collectorUnit}
	keepForBoot := false
	var collectorRuntimeDirectory string
	for _, unit := range append([]string{startupUnit}, units...) {
		load := nativeUnitProperty(t, unit, "LoadState")
		if load != "not-found" {
			t.Fatal("node gate unit identity already exists")
		}
	}
	t.Cleanup(func() {
		if keepForBoot {
			return
		}
		source := filepath.Join(root, "config", "native", startupUnit)
		changed := false
		for _, path := range []string{filepath.Join("/etc/systemd/system/multi-user.target.wants", startupUnit), filepath.Join("/etc/systemd/system", startupUnit)} {
			target, err := os.Readlink(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || target != source {
				t.Error("node gate refuses to remove foreign boot registration")
				continue
			}
			if !changed && nativeUnitProperty(t, startupUnit, "LoadState") == "loaded" {
				if nativeUnitProperty(t, startupUnit, "FragmentPath") != filepath.Join("/etc/systemd/system", startupUnit) {
					t.Fatal("node gate refuses to stop foreign boot service")
				}
				nativeSystemctl(t, "stop", startupUnit)
			}
			if err := os.Remove(path); err != nil {
				t.Error("remove owned boot registration")
			}
			changed = true
		}
		if changed {
			nativeSystemctl(t, "daemon-reload")
		}
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
		if collectorRuntimeDirectory != "" {
			if _, err := os.Lstat(collectorRuntimeDirectory); !os.IsNotExist(err) {
				t.Error("stopped collector left a native runtime directory")
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
			ControllerID: controllerID, BindingRef: config.BindingRef, ExpectedFingerprint: fingerprint,
			Credentials: func() (nodehttps.Credentials, error) { return controller.credentials, nil }})
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
		for _, unit := range append([]string{startupUnit}, units...) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			output, _ := exec.CommandContext(ctx, "systemctl", "show", "--property=Id,LoadState,FragmentPath,DropInPaths,NeedDaemonReload,Transient,Type,ActiveState,ExecStartEx,Environment,ReadWritePaths,LoadCredential,BindReadOnlyPaths,RuntimeDirectory,MemoryMax,TasksMax,Restart,RemainAfterExit", unit).Output()
			cancel()
			if len(output) <= 12288 {
				t.Logf("owned unit snapshot: %s", output)
			}
		}
		select {
		case summary := <-diagnostic:
			t.Logf("startup snapshot: %s", summary)
		default:
		}
		client, err := nodehttps.New(nodehttps.Config{Endpoint: "https://" + config.ListenAddress, Identity: identity,
			ControllerID: controllerID, BindingRef: config.BindingRef, ExpectedFingerprint: fingerprint,
			Credentials: func() (nodehttps.Credentials, error) { return controller.credentials, nil }})
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
	for _, suffix := range []string{"unsupported space", "unsupported:binding", "unsupported%specifier", "unsupported$dollar"} {
		unsupportedRoot := filepath.Join(base, suffix)
		unsupported := enrollment
		unsupported.Node.StoragePath = filepath.Join(unsupportedRoot, "runtime", "executor")
		encoded, _ := json.Marshal(unsupported)
		if err := os.WriteFile(enrollmentFile, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		nativeMX(t, installer, false, "node", "install", "--root", unsupportedRoot, "--bundle", bundle, "--trust-key", releaseTrust, "--configuration", enrollmentFile)
		if _, err := os.Lstat(unsupportedRoot); !os.IsNotExist(err) {
			t.Fatal("unsupported native path created installation state")
		}
	}
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
	if nativeUnitProperty(t, startupUnit, "UnitFileState") != "enabled" || nativeUnitProperty(t, startupUnit, "Transient") != "no" {
		t.Fatal("signed installation is not persistently registered for boot")
	}
	// The boot entry point must work under its actual service sandbox too.
	nativeSystemctl(t, "start", "--no-block", startupUnit)
	awaitNativeStartup(t, startupUnit)
	if nativeUnitProperty(t, startupUnit, "ActiveState") != "active" || nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID ||
		nativeUnitProperty(t, collectorUnit, "MainPID") != collectorPID {
		t.Fatal("boot entry point failed or replaced healthy services")
	}
	// Starting the boot entry point records a start command; exact install
	// replay below must leave this new journal unchanged.
	before, err = os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if firstPID == "" || firstPID == "0" || collectorPID == "" || collectorPID == "0" || nativeUnitProperty(t, collectorUnit, "DynamicUser") != "yes" {
		t.Fatal("native supervision or separate collector UID absent")
	}
	collectorProcess, err := os.Stat("/proc/" + collectorPID)
	if err != nil || collectorProcess.Sys().(*syscall.Stat_t).Uid == 0 {
		t.Fatal("collector is privileged")
	}
	uid := collectorProcess.Sys().(*syscall.Stat_t).Uid
	runtimeDirectoryName := nativeUnitProperty(t, collectorUnit, "RuntimeDirectory")
	if runtimeDirectoryName == "" || filepath.Base(runtimeDirectoryName) != runtimeDirectoryName {
		t.Fatal("collector runtime directory is not supervised")
	}
	collectorRuntimeDirectory = filepath.Join("/run", runtimeDirectoryName)
	if directory, err := os.Stat(collectorRuntimeDirectory); err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 {
		t.Fatal("collector runtime directory is not private")
	}
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
		ControllerID: controllerID, BindingRef: config.BindingRef, ExpectedFingerprint: fingerprint,
		Credentials: func() (nodehttps.Credentials, error) { return controller.credentials, nil }})
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
	// A pending drop-in is rejected even before a manager reload could make
	// its hooks effective. No unrelated service or global drop-in is changed.
	dropin := filepath.Join("/etc/systemd/system", startupUnit+".d")
	if err := os.Mkdir(dropin, 0o700); err != nil {
		t.Fatal("create fixture-owned startup override")
	}
	dropinFile := filepath.Join(dropin, "gate.conf")
	t.Cleanup(func() {
		if _, err := os.Lstat(dropinFile); err == nil {
			if err := os.Remove(dropinFile); err != nil {
				t.Error("remove fixture-owned boot override")
			}
		}
		if _, err := os.Lstat(dropin); err == nil {
			if err := os.Remove(dropin); err != nil {
				t.Error("remove empty fixture-owned override directory")
			}
		}
	})
	if err := os.WriteFile(dropinFile, []byte("[Service]\nExecStartPost=/usr/bin/false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nativeMX(t, installer, false, "node", "start", "--root", root)
	if nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID || nativeUnitProperty(t, collectorUnit, "MainPID") != collectorPID {
		t.Fatal("pending boot override changed healthy processes")
	}
	if os.Remove(dropinFile) != nil || os.Remove(dropin) != nil {
		t.Fatal("remove exact fixture-owned startup override")
	}
	// Loading an altered execution flag must not be hidden by restoring the
	// source file without reloading it. Never execute the altered command.
	func() {
		source := filepath.Join(root, "config", "native", startupUnit)
		original, err := os.ReadFile(source)
		if err != nil || bytes.Count(original, []byte("ExecStart=:")) != 1 {
			t.Fatal("read fixture startup source")
		}
		defer func() {
			if os.WriteFile(source, original, 0o600) != nil {
				t.Error("restore fixture startup source")
			}
			nativeSystemctl(t, "daemon-reload")
		}()
		altered := bytes.Replace(original, []byte("ExecStart=:"), []byte("ExecStart=+:"), 1)
		if os.WriteFile(source, altered, 0o600) != nil {
			t.Fatal("alter fixture startup execution flag")
		}
		nativeSystemctl(t, "daemon-reload")
		if os.WriteFile(source, original, 0o600) != nil {
			t.Fatal("restore fixture startup source without reload")
		}
		nativeMX(t, installer, false, "node", "start", "--root", root)
		if nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID || nativeUnitProperty(t, collectorUnit, "MainPID") != collectorPID {
			t.Fatal("altered execution flag changed healthy processes")
		}
	}()
	// Partial registration can be replayed without restarting resident work.
	wantedLink := filepath.Join("/etc/systemd/system/multi-user.target.wants", startupUnit)
	if err := os.Remove(wantedLink); err != nil {
		t.Fatal(err)
	}
	if result := nativeMX(t, installer, true, "node", "status", "--root", root); result.State != "NOT_READY" {
		t.Fatal("missing persistent registration was reported ready")
	}
	nativeMX(t, installer, true, "node", "start", "--root", root)
	if nativeUnitProperty(t, nodeUnit, "MainPID") != firstPID || nativeUnitProperty(t, collectorUnit, "MainPID") != collectorPID {
		t.Fatal("partial boot registration replay replaced healthy services")
	}
	// Routine manager reload must retain the exact service policy and mount
	// bindings, not just keep the previous processes temporarily alive.
	nativeSystemctl(t, "daemon-reload")
	nativeMX(t, installer, true, "node", "verify", "--root", root)
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
	if _, err := os.Lstat(collectorRuntimeDirectory); !os.IsNotExist(err) {
		t.Fatal("collector stop retained its transient mount destination")
	}
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
	interruption := interruptNativeCommand(t, installer, root, units, "node", "start", "--root", root)
	pending := interruption.result
	retainedNodePID, retainedCollectorPID := interruption.nodePID, interruption.collectorPID
	if bootPhase == "prepare" {
		// Leave the actual interrupted command for the next guest boot. The
		// deferred CONT only releases the fixture's pause; it does not run mx.
		retainNativeBoot(t, base, root, identity, installed.ReleaseID, pending.CorrelationID)
		keepForBoot = true
		return
	}
	interruption.resume()
	started = nativeMX(t, installer, true, "node", "start", "--root", root)
	if started.State != "READY" || started.ReleaseID != installed.ReleaseID || started.CorrelationID != pending.CorrelationID ||
		nativeUnitProperty(t, nodeUnit, "MainPID") != retainedNodePID || nativeUnitProperty(t, collectorUnit, "MainPID") != retainedCollectorPID {
		t.Fatal("node replay lost its command, committed release or running processes")
	}
	t.Run("credential lifecycle retains a running workload", func(t *testing.T) {
		checkWorkload := nativeRetainedWorkload(t, base, identity.InstallationID)
		marker := "runtime/executor/credential-retained-receipt"
		if err := os.WriteFile(filepath.Join(root, marker), []byte("accepted-node-effect"), 0o600); err != nil {
			t.Fatal(err)
		}
		retained := map[string][]byte{}
		for _, relative := range []string{"config/node.json", "config/release-trust.json", "config/native/" + startupUnit, marker} {
			data, err := os.ReadFile(filepath.Join(root, relative))
			if err != nil {
				t.Fatal(err)
			}
			retained[relative] = data
		}
		writeEnrollment := func(name string, node, collector issuedCertificate, trust []byte) (string, []string) {
			t.Helper()
			candidate := enrollment
			candidate.Node.CertificateFile, candidate.Node.PrivateKeyFile = nativeCertificateFiles(t, base, name+"-node", node)
			candidate.CollectorCertificateFile, candidate.CollectorPrivateKeyFile = nativeCertificateFiles(t, base, name+"-collector", collector)
			candidate.Node.TrustFile = filepath.Join(base, name+"-trust.pem")
			path := filepath.Join(base, name+".json")
			encoded, err := json.Marshal(candidate)
			if err != nil || os.WriteFile(candidate.Node.TrustFile, trust, 0o600) != nil || os.WriteFile(path, encoded, 0o600) != nil {
				t.Fatal("write protected rotation input")
			}
			return path, []string{path, candidate.Node.CertificateFile, candidate.Node.PrivateKeyFile, candidate.Node.TrustFile,
				candidate.CollectorCertificateFile, candidate.CollectorPrivateKeyFile}
		}
		var current atomic.Pointer[nodehttps.Credentials]
		current.Store(&controller.credentials)
		rotatingClient, err := nodehttps.New(nodehttps.Config{Endpoint: "https://" + config.ListenAddress, Identity: identity,
			ControllerID: controllerID, BindingRef: config.BindingRef, ExpectedFingerprint: fingerprint,
			Credentials: func() (nodehttps.Credentials, error) { return *current.Load(), nil }})
		if err != nil {
			t.Fatal(err)
		}
		defer rotatingClient.Close()
		status := nativeMX(t, installer, true, "node", "status", "--root", root)
		if paasv1.ValidateDigest("configurationDigest", status.ConfigurationDigest) != nil {
			t.Fatal("current credential commitment is unavailable")
		}
		renewedNode := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
		renewedCollector := authority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
		renewalFile, _ := writeEnrollment("renewal", renewedNode, renewedCollector, authority.pem)
		renewalArgs := []string{"node", "rotate-credentials", "--root", root, "--configuration", renewalFile,
			"--expected-configuration-digest", status.ConfigurationDigest}
		before, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		nodePID, collectorPID := nativeUnitProperty(t, nodeUnit, "MainPID"), nativeUnitProperty(t, collectorUnit, "MainPID")
		nativeMX(t, installer, false, renewalArgs...)
		after, err := os.ReadFile(journalPath)
		if err != nil || !bytes.Equal(before, after) || nativeUnitProperty(t, nodeUnit, "MainPID") != nodePID ||
			nativeUnitProperty(t, collectorUnit, "MainPID") != collectorPID {
			t.Fatal("default retirement accepted old trust or caused partial effects")
		}
		renewed := nativeMX(t, installer, true, append(renewalArgs, "--revoke-previous=false")...)
		if !renewed.Changed || renewed.State != "READY" || renewed.ConfigurationDigest == status.ConfigurationDigest {
			t.Fatal("explicit same-trust renewal did not commit")
		}
		awaitObservation(t, rotatingClient, time.Time{}, paasv1.MeasurementAvailable)
		checkWorkload()

		nextAuthority := newAuthority(t)
		nextNode := nextAuthority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false, x509.ExtKeyUsageClientAuth)
		nextCollector := nextAuthority.issue(t, collectorURI, x509.ExtKeyUsageServerAuth, false)
		nextController := nextAuthority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
		rotationFile, externalInputs := writeEnrollment("retirement", nextNode, nextCollector, nextAuthority.pem)
		rotationArgs := []string{"node", "rotate-credentials", "--root", root, "--configuration", rotationFile,
			"--expected-configuration-digest", renewed.ConfigurationDigest}
		interrupted := interruptNativeCommand(t, installer, root, units, rotationArgs...)
		for _, path := range externalInputs {
			if err := os.Remove(path); err != nil {
				t.Fatal("remove exact fixture-owned external rotation input")
			}
		}
		interrupted.resume()
		rotated := nativeMX(t, installer, true, "node", "start", "--root", root)
		if rotated.State != "READY" || rotated.CorrelationID != interrupted.result.CorrelationID ||
			rotated.ReleaseID != installed.ReleaseID || rotated.ExecutionTargetID != string(identity.ExecutionTargetID) ||
			rotated.ConfigurationDigest == renewed.ConfigurationDigest || paasv1.ValidateDigest("configurationDigest", rotated.ConfigurationDigest) != nil ||
			nativeUnitProperty(t, nodeUnit, "MainPID") != interrupted.nodePID || nativeUnitProperty(t, collectorUnit, "MainPID") != interrupted.collectorPID {
			t.Fatal("interrupted rotation lost sealed intent or replaced already activated processes")
		}
		current.Store(&nextController.credentials)
		awaitObservation(t, rotatingClient, time.Time{}, paasv1.MeasurementAvailable)
		assertRetired := func() {
			t.Helper()
			for _, peer := range []issuedCertificate{controller, node, renewedNode} {
				for _, endpoint := range []string{"https://" + config.ListenAddress + nodev1.ReadinessPath, config.CollectorEndpoint + "/metrics"} {
					retiredClient := nextAuthority.rawClient(&peer.pair)
					response, err := retiredClient.Get(endpoint)
					if response != nil {
						response.Body.Close()
					}
					retiredClient.CloseIdleConnections()
					if err == nil {
						t.Fatal("retired credential passed real mutual TLS after the trust switch")
					}
				}
			}
		}
		assertRetired()
		checkWorkload()
		for _, unit := range units {
			nativeSystemctl(t, "stop", unit)
		}
		restarted := nativeMX(t, installer, true, "node", "start", "--root", root)
		if restarted.State != "READY" || restarted.ConfigurationDigest != rotated.ConfigurationDigest {
			t.Fatal("resident restart did not retain the committed credential set")
		}
		awaitObservation(t, rotatingClient, time.Time{}, paasv1.MeasurementAvailable)
		assertRetired()
		checkWorkload()
		writeEnrollment("retirement", nextNode, nextCollector, nextAuthority.pem)
		replayed := nativeMX(t, installer, true, rotationArgs...)
		if replayed.Changed || replayed.ConfigurationDigest != rotated.ConfigurationDigest || replayed.CorrelationID != rotated.CorrelationID {
			t.Fatal("rotation replay after restart lost its original receipt")
		}
		for relative, expected := range retained {
			actual, err := os.ReadFile(filepath.Join(root, relative))
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatal("credential rotation changed retained configuration, release trust, boot ownership or executor receipt")
			}
		}
		entries, err := os.ReadDir(filepath.Join(root, "secrets", "node-rotations"))
		if err != nil || len(entries) != 0 {
			t.Fatal("committed rotation retained obsolete private-key snapshots")
		}
		if data, err := os.ReadFile(enrollmentFile); err != nil || !bytes.Equal(data, enrollmentBytes) {
			t.Fatal("rotation altered operator-owned original enrollment")
		}
	})
}

type nativeInterruptedCommand struct {
	result                nativeMXResult
	nodePID, collectorPID string
	resume                func()
}

// Pause only the owned collector after both Type=exec services have started,
// so the real installer can be killed during readiness, not systemd startup.
func interruptNativeCommand(t *testing.T, installer, root string, units []string, arguments ...string) nativeInterruptedCommand {
	t.Helper()
	if len(units) != 2 {
		t.Fatal("interruption gate requires the exact node and collector")
	}
	previous := []string{nativeUnitProperty(t, units[0], "MainPID"), nativeUnitProperty(t, units[1], "MainPID")}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	command := exec.CommandContext(ctx, installer, append([]string{"--format", "json"}, arguments...)...)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal("start interruptible node command")
	}
	done := make(chan struct{})
	var commandErr error
	go func() { commandErr = command.Wait(); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("interrupted mx did not exit")
		}
	})
	for {
		running := true
		for index, unit := range units {
			pid := nativeUnitProperty(t, unit, "MainPID")
			if pid == "" || pid == "0" || pid == previous[index] || nativeUnitProperty(t, unit, "ActiveState") != "active" {
				running = false
			}
		}
		if running {
			break
		}
		select {
		case <-done:
			if output.Len() <= 4096 {
				t.Logf("interruption startup result: %s", output.Bytes())
			}
			t.Fatal("mx exited before both replacement services were running")
		case <-ctx.Done():
			t.Fatal("resident services did not start before the interruption deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
	nativeSystemctl(t, "kill", "--kill-who=main", "--signal=STOP", units[1])
	var resumeOnce sync.Once
	resume := func() {
		resumeOnce.Do(func() { nativeSystemctl(t, "kill", "--kill-who=main", "--signal=CONT", units[1]) })
	}
	t.Cleanup(resume)
	nodePID, collectorPID := nativeUnitProperty(t, units[0], "MainPID"), nativeUnitProperty(t, units[1], "MainPID")
	if command.Process.Kill() != nil {
		t.Fatal("mx completed before the interruption gate")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("interrupted mx did not stop")
	}
	if commandErr == nil {
		t.Fatal("interrupted mx reported successful completion")
	}
	pending := nativeMX(t, installer, true, "node", "status", "--root", root)
	if (pending.State != "STARTING" && pending.State != "VERIFYING") || pending.CorrelationID == "" {
		t.Fatal("interruption did not retain the in-flight command")
	}
	return nativeInterruptedCommand{result: pending, nodePID: nodePID, collectorPID: collectorPID, resume: resume}
}

// This one network-disabled, bounded fixture proves credential replacement
// does not restart a workload or lose data; it is not a PaaS placement gate.
func nativeRetainedWorkload(t *testing.T, base, installationID string) func() {
	t.Helper()
	const image = "postgres@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a"
	const label = "com.xiak.matrix.fixture"
	const inspect = `{{.Id}}|{{.State.StartedAt}}|{{.RestartCount}}|{{.State.Running}}|{{index .Config.Labels "com.xiak.matrix.fixture"}}`
	docker := func(arguments ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput()
		if len(output) > 4096 {
			return "", fmt.Errorf("fixture Docker output exceeded its bound")
		}
		return strings.TrimSpace(string(output)), err
	}
	name := "matrix-node-credentials-" + strings.TrimPrefix(installationID, "mxi-")
	if _, err := docker("inspect", "--type", "container", "--format", "{{.Id}}", name); err == nil {
		t.Fatal("workload fixture identity already exists")
	}
	data := filepath.Join(base, "credential-workload-data")
	// PG18 creates its private versioned PGDATA below this bind root, then
	// drops UID. The mount root must remain traversable inside the container;
	// the test's outer base is still owner-only on the native host.
	if err := os.Mkdir(data, 0o711); err != nil {
		t.Fatal("create owned workload fixture data")
	}
	id, err := docker("run", "--pull=never", "--detach", "--name", name, "--label", label+"="+installationID,
		"--cpus=0.5", "--memory=384m", "--pids-limit=128", "--network=none",
		"--mount", "type=bind,src="+data+",dst=/var/lib/postgresql", "--env", "POSTGRES_PASSWORD="+installationID,
		image, "postgres", "-c", "max_connections=10", "-c", "shared_buffers=32MB", "-c", "max_worker_processes=2")
	if err != nil || len(id) != 64 {
		t.Fatal("start bounded workload using the preloaded pinned image")
	}
	t.Cleanup(func() {
		owned, err := docker("inspect", "--type", "container", "--format", `{{.Id}}|{{index .Config.Labels "com.xiak.matrix.fixture"}}`, id)
		if err != nil || owned != id+"|"+installationID {
			t.Error("refuse to remove an unauthenticated workload fixture")
			return
		}
		if _, err := docker("rm", "--force", id); err != nil {
			t.Error("remove exact owned workload fixture")
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := docker("exec", id, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			state, _ := docker("inspect", "--type", "container", "--format", `{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}`, id)
			diagnostic, _ := docker("logs", "--tail=12", id)
			t.Logf("owned workload prerequisite: %s\n%s", state, diagnostic)
			t.Fatal("bounded workload fixture did not become ready")
		}
		<-time.After(200 * time.Millisecond)
	}
	if _, err := docker("exec", id, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c",
		"CREATE TABLE retained_marker(value text NOT NULL); INSERT INTO retained_marker VALUES ('credential-rotation-retained');"); err != nil {
		t.Fatal("seed real workload marker")
	}
	before, err := docker("inspect", "--type", "container", "--format", inspect, id)
	if err != nil || !strings.HasPrefix(before, id+"|") || !strings.HasSuffix(before, "|0|true|"+installationID) {
		t.Fatal("workload identity or running state is unavailable")
	}
	return func() {
		t.Helper()
		after, err := docker("inspect", "--type", "container", "--format", inspect, id)
		if err != nil || after != before {
			t.Fatal("node lifecycle changed the running workload identity or startup time")
		}
		marker, err := docker("exec", id, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-Atc", "SELECT value FROM retained_marker")
		if err != nil || marker != "credential-rotation-retained" {
			t.Fatal("node lifecycle lost real retained workload data")
		}
	}
}

// The operator reboots only the dedicated local guest between these phases.
// The gate never issues a machine or shared-engine restart itself.
type nativeBootEvidence struct {
	Identity      nodev1.Identity   `json:"identity"`
	Root          string            `json:"root"`
	ReleaseID     string            `json:"releaseId"`
	CorrelationID string            `json:"correlationId"`
	BootID        string            `json:"bootId"`
	Files         map[string]string `json:"files"`
}

func retainNativeBoot(t *testing.T, base, root string, identity nodev1.Identity, releaseID, correlationID string) {
	t.Helper()
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	marker := "runtime/executor/boot-retained-receipt"
	if err := os.WriteFile(filepath.Join(root, marker), []byte("accepted-node-effect"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence := nativeBootEvidence{Identity: identity, Root: root, ReleaseID: releaseID, CorrelationID: correlationID, BootID: strings.TrimSpace(string(bootID)), Files: map[string]string{}}
	for _, relative := range []string{"config/node.json", "config/release-trust.json", "secrets/node/node.pem", "secrets/node/node-key.pem",
		"secrets/node/trust.pem", "secrets/node/collector.pem", "secrets/node/collector-key.pem", marker} {
		source, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(source)
		clear(source)
		evidence.Files[relative] = hex.EncodeToString(digest[:])
	}
	source, err := json.Marshal(evidence)
	if err != nil || os.WriteFile(filepath.Join(base, "boot-evidence.json"), source, 0o600) != nil {
		t.Fatal("retain owned boot evidence")
	}
}

func verifyNativeBoot(t *testing.T, installer, base, releaseID string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(base, "boot-evidence.json"))
	var evidence nativeBootEvidence
	if err != nil || json.Unmarshal(source, &evidence) != nil || nodev1.ValidateIdentity(evidence.Identity) != nil ||
		evidence.Root != filepath.Join(base, "installation") || evidence.ReleaseID != releaseID || evidence.CorrelationID == "" || len(evidence.Files) != 8 {
		t.Fatal("boot fixture evidence is missing or inconsistent")
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(bootID)) == evidence.BootID || evidence.BootID == "" {
		t.Fatal("a process restart is not evidence of a guest kernel boot")
	}
	startupUnit, _ := nodeconfig.StartupServiceName(evidence.Identity)
	awaitNativeStartup(t, startupUnit)
	for _, collector := range []bool{false, true} {
		unit, _ := nodeconfig.ServiceName(evidence.Identity, collector)
		if nativeUnitProperty(t, unit, "ActiveState") != "active" || nativeUnitProperty(t, unit, "MainPID") == "0" {
			t.Fatal("resident service was not running before any mx command")
		}
	}
	for relative, expected := range evidence.Files {
		if filepath.IsAbs(relative) || strings.Contains(relative, "..") {
			t.Fatal("boot evidence escaped its fixture root")
		}
		source, err := os.ReadFile(filepath.Join(evidence.Root, relative))
		digest := sha256.Sum256(source)
		clear(source)
		if err != nil || hex.EncodeToString(digest[:]) != expected {
			t.Fatal("guest boot changed retained configuration, credentials or receipts")
		}
	}
	// Process startup and fresh observations are distinct. Status must remain
	// read-only while a bounded wait obtains a current sample after boot load.
	deadline := time.Now().Add(30 * time.Second)
	for {
		status := nativeMX(t, installer, true, "node", "status", "--root", evidence.Root)
		if status.ReleaseID != releaseID || status.CorrelationID != evidence.CorrelationID ||
			status.ExecutionTargetID != string(evidence.Identity.ExecutionTargetID) || status.Changed {
			t.Fatal("guest boot did not preserve authenticated identity and original command")
		}
		if status.State == "READY" {
			return
		}
		if status.State != "NOT_READY" || time.Now().After(deadline) {
			t.Fatalf("guest boot did not obtain fresh readiness: %s", status.State)
		}
		<-time.After(time.Second)
	}
}

func awaitNativeStartup(t *testing.T, unit string) {
	t.Helper()
	deadline := time.Now().Add(time.Duration(nodeconfig.StartupPolicy().TimeoutStartMicros) * time.Microsecond)
	for {
		state := nativeUnitProperty(t, unit, "ActiveState")
		if state == "active" {
			return
		}
		if state == "failed" || time.Now().After(deadline) {
			t.Fatal("registered startup did not finish within its service deadline")
		}
		<-time.After(time.Second)
	}
}

type nativeMXResult struct {
	State               string `json:"state"`
	CorrelationID       string `json:"correlationId"`
	ReleaseID           string `json:"releaseId"`
	ExecutionTargetID   string `json:"executionTargetId"`
	Changed             bool   `json:"changed"`
	ConfigurationDigest string `json:"configurationDigest"`
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
		BindingRef: "binding-a", ExpectedFingerprint: fingerprint,
		Credentials: func() (nodehttps.Credentials, error) { return controller.credentials, nil },
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
