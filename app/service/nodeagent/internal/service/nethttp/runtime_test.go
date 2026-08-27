//go:build linux

package nethttp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
)

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
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	facts, err := localmachine.NewLocalHostProbe().Inspect(ctx, root)
	cancel()
	if err != nil || !facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatalf("real node prerequisites unavailable: %v", err)
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
	configuration, err := json.Marshal(map[string]any{
		"apiVersion": "node.installation.matrix.xiak.com/v1", "kind": "NodeConfiguration",
		"identity": nodeIdentity, "controllerId": controllerID, "bindingRef": "binding-a",
		"expectedFingerprint": fingerprint, "listenAddress": address, "storagePath": root,
		"collectorEndpoint": "https://" + collectorAddress,
		"certificateFile":   certificatePath, "privateKeyFile": keyPath, "trustFile": trustPath,
		"systemReserve": paasv1.Capacity{MemoryBytes: 256 * 1024 * 1024},
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
		first.Allocatable.MemoryBytes != first.Capacity.MemoryBytes-256*1024*1024 {
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
		storage.TotalBytes != int64(facts.StorageTotalBytes) {
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
	if unavailable.Health != paasv1.ExecutionTargetHealthReady || unavailable.Allocatable != second.Allocatable ||
		unavailable.Usage.Memory.Value != nil || unavailable.Usage.CPU.Value != nil {
		t.Fatal("collector failure changed placement capacity or fabricated usage")
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
	closeErr := executable.Close()
	if copyErr != nil || closeErr != nil {
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
