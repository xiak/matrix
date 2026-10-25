//go:build linux

package authorityprocess

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
)

// Reuse the complete authority gate with real node/collector processes, not a
// second copy of tenant, host admission, revocation or Audit assertions.
func TestLinuxNodeAuthorityProcesses(t *testing.T) {
	const variable = "MATRIX_NODE_AUTHORITY_PROCESS_POSTGRES_TEST_DSN"
	if os.Getenv(variable) == "" {
		t.Skipf("set %s on an isolated Linux/amd64 Docker/Compose host", variable)
	}
	if runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Fatal("real node authority gate requires Linux/amd64 root for the separate collector UID")
	}
	runAuthorityProcesses(t, variable, newLinuxProcessNode)
}

func newLinuxProcessNode(t *testing.T, directory, installationID string) *processNodeFixture {
	t.Helper()
	nodeBinary, collectorBinary := os.Getenv("MATRIX_NODE_AGENT_BINARY"), os.Getenv("MATRIX_NODE_EXPORTER_BINARY")
	for _, binary := range []string{nodeBinary, collectorBinary} {
		info, err := os.Lstat(binary)
		if !filepath.IsAbs(binary) || err != nil || !info.Mode().IsRegular() {
			t.Fatal("real node gate requires exact, verified node and collector executables")
		}
	}
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	facts, err := localmachine.NewLocalHostProbe().Inspect(ctx, directory)
	cancel()
	if err != nil || !facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatal("real local Docker/Compose host prerequisites are unavailable")
	}
	fingerprint, err := localmachine.DeriveMachineFingerprint(facts)
	if err != nil {
		t.Fatal(err)
	}
	identity := nodev1.Identity{InstallationID: installationID, ExecutionTargetID: processHostTarget}
	wrongIdentity := nodev1.Identity{InstallationID: installationID, ExecutionTargetID: "another-process-node"}
	nodeURI, _ := nodev1.NodeURI(identity)
	wrongURI, _ := nodev1.NodeURI(wrongIdentity)
	controllerURI, _ := nodev1.ControllerURI(installationID, processHostController)
	collectorURI, _ := nodev1.CollectorURI(identity)
	trust, issue := newProcessNodeAuthority(t)
	nodeCertificate, nodeKey := issue(2, nodeURI, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	controllerCertificate, controllerKey := issue(3, controllerURI, x509.ExtKeyUsageClientAuth)
	collectorCertificate, collectorKey := issue(4, collectorURI, x509.ExtKeyUsageServerAuth)
	wrongCertificate, wrongKey := issue(5, wrongURI, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	defer clear(nodeKey)
	defer clear(controllerKey)
	defer clear(collectorKey)
	defer clear(wrongKey)
	controller, err := nodehttps.NewCredentials(controllerCertificate, controllerKey, trust)
	if err != nil {
		t.Fatal(err)
	}
	collectorAddress := freeAddress(t)
	startAuthorityCollector(t, collectorBinary, collectorAddress, directory, nodeURI, collectorCertificate, collectorKey, trust)
	nodeAddress := freeAddress(t)
	nodeCertificatePath := writeProtectedFile(t, directory, "linux-node.crt", nodeCertificate)
	nodeKeyPath := writeProtectedFile(t, directory, "linux-node.key", nodeKey)
	wrongCertificatePath := writeProtectedFile(t, directory, "wrong-node.crt", wrongCertificate)
	wrongKeyPath := writeProtectedFile(t, directory, "wrong-node.key", wrongKey)
	trustPath := writeProtectedFile(t, directory, "linux-node-trust.crt", trust)
	var child *childProcess
	startNode := func(wrong bool) {
		child.stop()
		selected, certificatePath, keyPath := identity, nodeCertificatePath, nodeKeyPath
		if wrong {
			selected, certificatePath, keyPath = wrongIdentity, wrongCertificatePath, wrongKeyPath
		}
		document, err := json.Marshal(map[string]any{
			"apiVersion": "node.installation.matrix.xiak.com/v1", "kind": "NodeConfiguration",
			"identity": selected, "controllerId": processHostController, "bindingRef": processHostBinding,
			"expectedFingerprint": fingerprint, "listenAddress": nodeAddress, "storagePath": directory,
			"collectorEndpoint": "https://" + collectorAddress, "certificateFile": certificatePath,
			"privateKeyFile": keyPath, "trustFile": trustPath, "systemReserve": paasv1.Capacity{MemoryBytes: 256 << 20},
		})
		if err != nil {
			t.Fatal(err)
		}
		configurationPath := writeProtectedFile(t, directory, "linux-node.json", document)
		child = startChild(t, directory, nodeBinary, []string{"MATRIX_NODE_CONFIGURATION_FILE=" + configurationPath})
		client, err := nodehttps.New(nodehttps.Config{Endpoint: "https://" + nodeAddress, Identity: selected,
			ControllerID: processHostController, BindingRef: processHostBinding, ExpectedFingerprint: fingerprint,
			Credentials: func() (nodehttps.Credentials, error) { return controller, nil }})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		awaitProcessNode(t, child, client, selected, !wrong)
	}
	startNode(false)
	fixture := &processNodeFixture{
		configurationPath: writeProcessNodeConnection(t, directory, installationID, "https://"+nodeAddress, fingerprint, controllerCertificate, controllerKey, trust),
		setWrongIdentity:  startNode,
		setUnavailable: func(unavailable bool) {
			if unavailable {
				child.stop()
			} else {
				startNode(false)
			}
		},
		assertTarget: func(target paasv1.ExecutionTarget) {
			usage := target.Status.Usage
			if target.Metadata.Labels["matrix-machine-fingerprint"] != fingerprint || target.Status.Capacity.MemoryBytes != int64(facts.MemoryTotalBytes) ||
				target.Status.Allocatable.MemoryBytes != target.Status.Capacity.MemoryBytes-(256<<20) ||
				usage == nil || usage.CPU.Value == nil || usage.CPU.Value.LogicalCPUs != int64(facts.LogicalCPUs) ||
				usage.Memory.Value == nil || usage.Memory.Value.TotalBytes != int64(facts.MemoryTotalBytes) {
				t.Fatal("control plane did not receive the real node's identity, OS memory, CPU or reserve")
			}
			for _, filesystem := range usage.Filesystems {
				if filesystem.State == paasv1.MeasurementAvailable && filesystem.Value != nil && filesystem.Value.TotalBytes > 0 &&
					(directory == filesystem.MountPoint || strings.HasPrefix(directory, strings.TrimSuffix(filesystem.MountPoint, "/")+"/")) {
					return
				}
			}
			t.Fatal("control plane did not receive the real node's storage filesystem measurement")
		},
	}
	return fixture
}

func awaitProcessNode(t *testing.T, child *childProcess, client *nodehttps.Client, identity nodev1.Identity, requireMetrics bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if exited, _ := child.poll(); exited {
			t.Fatal("real node process exited before an authenticated observation")
		}
		request := paasv1.ObserveExecutionTargetRequest{Command: paasv1.AdapterCommandEnvelope{
			OperationID: "operation-node-process", CommandID: "command-node-process", Attempt: 1, Action: paasv1.AdapterObserveExecutionTarget,
			Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, ExecutionTargetID: identity.ExecutionTargetID,
			RequestDigest: "sha256:" + strings.Repeat("b", 64), BindingRef: processHostBinding,
			Deadline: time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Second),
		}}
		observation, err := client.ObserveExecutionTarget(ctx, request)
		if err == nil && observation.Health == paasv1.ExecutionTargetHealthReady && (!requireMetrics ||
			(observation.Usage != nil && observation.Usage.CPU.State == paasv1.MeasurementAvailable &&
				observation.Usage.Memory.State == paasv1.MeasurementAvailable && observation.Usage.FilesystemsState == paasv1.MeasurementAvailable)) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("real node did not become ready with the required authenticated measurements")
		case <-ticker.C:
		}
	}
}

func startAuthorityCollector(t *testing.T, binary, address, storagePath, nodeURI string, certificate, key, trust []byte) {
	t.Helper()
	directory, err := os.MkdirTemp("", "matrix-authority-collector-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	configuration := fmt.Sprintf("tls_server_config:\n  cert_file: %q\n  key_file: %q\n  client_ca_file: %q\n  client_auth_type: RequireAndVerifyClientCert\n  client_allowed_sans:\n    - %q\n  min_version: TLS13\nhttp_server_config:\n  http2: false\n",
		filepath.Join(directory, "collector.crt"), filepath.Join(directory, "collector.key"), filepath.Join(directory, "trust.crt"), nodeURI)
	for name, content := range map[string][]byte{"collector.crt": certificate, "collector.key": key, "trust.crt": trust, "web.yml": []byte(configuration)} {
		path := writeProtectedFile(t, directory, name, content)
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	executablePath := filepath.Join(directory, "node_exporter")
	executable, err := os.OpenFile(executablePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o555)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(executable, io.LimitReader(source, 64<<20))
	modeErr := executable.Chmod(0o555)
	closeErr := executable.Close()
	if copyErr != nil || modeErr != nil || closeErr != nil || os.Chmod(directory, 0o711) != nil {
		t.Fatal("could not provision the isolated collector executable")
	}
	var mounts []string
	for path := storagePath; ; path = filepath.Dir(path) {
		mounts = append(mounts, regexp.QuoteMeta(path))
		if path == "/" {
			break
		}
	}
	command := exec.Command(executablePath, "--web.listen-address="+address, "--web.config.file="+filepath.Join(directory, "web.yml"),
		"--web.disable-exporter-metrics", "--web.max-requests=2", "--collector.disable-defaults", "--collector.cpu", "--collector.loadavg", "--collector.meminfo", "--collector.filesystem",
		"--collector.filesystem.mount-points-include=^("+strings.Join(mounts, "|")+")$", "--collector.filesystem.fs-types-exclude=^$", "--collector.filesystem.mount-timeout=1s")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	startChildCommand(t, command)
}
