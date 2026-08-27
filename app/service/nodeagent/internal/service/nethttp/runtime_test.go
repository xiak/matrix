package nethttp

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	binary := os.Getenv("MATRIX_NODE_AGENT_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("MATRIX_NODE_AGENT_BINARY must select the built node executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	facts, err := localmachine.NewLocalHostProbe().Inspect(ctx, "/")
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
	node := authority.issue(t, nodeURI, x509.ExtKeyUsageServerAuth, false)
	controller := authority.issue(t, controllerURI, x509.ExtKeyUsageClientAuth, false)
	root := t.TempDir()
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	configuration, err := json.Marshal(map[string]any{
		"apiVersion": "node.installation.matrix.xiak.com/v1", "kind": "NodeConfiguration",
		"identity": nodeIdentity, "controllerId": controllerID, "bindingRef": "binding-a",
		"expectedFingerprint": fingerprint, "listenAddress": address, "storagePath": "/",
		"certificateFile": certificatePath, "privateKeyFile": keyPath, "trustFile": trustPath,
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
	first := awaitObservation(t, client, time.Time{})
	if first.Health != paasv1.ExecutionTargetHealthReady || first.Capacity.MemoryBytes != int64(facts.MemoryTotalBytes) ||
		first.Allocatable.MemoryBytes != first.Capacity.MemoryBytes-256*1024*1024 {
		t.Fatal("real node did not report its OS capacity and installation reserve")
	}
	// No observer is connected during this interval; the resident sampler must
	// still advance. This is not an on-demand SSH probe disguised as streaming.
	timer := time.NewTimer(6 * time.Second)
	<-timer.C
	second := awaitObservation(t, client, first.ObservedAt)
	stop()
	command := observationCommand()
	command.Deadline = time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
	if _, err := client.ObserveExecutionTarget(context.Background(), paasv1.ObserveExecutionTargetRequest{Command: command}); err == nil {
		t.Fatal("stopped node remained available")
	}
	stop = startAgentProcess(t, binary, configurationPath)
	restarted := awaitObservation(t, client, second.ObservedAt)
	if restarted.IdentityFingerprint != fingerprint {
		t.Fatal("restart changed the enrolled host identity")
	}
	stop()
	t.Log("authenticated Linux agent refreshed in the background, disconnected and restarted with its persisted identity pin")
}

func startAgentProcess(t *testing.T, binary, configurationPath string) func() {
	t.Helper()
	command := exec.Command(binary)
	command.Env = append(os.Environ(),
		"MATRIX_NODE_CONFIGURATION_FILE="+configurationPath,
		"DOCKER_HOST=tcp://127.0.0.1:1", "DOCKER_CONTEXT=must-not-select-another-engine")
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
				if err != nil {
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

func awaitObservation(t *testing.T, client *nodehttps.Client, after time.Time) paasv1.ExecutionTargetObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		command := observationCommand()
		command.Deadline = time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
		value, err := client.ObserveExecutionTarget(ctx, paasv1.ObserveExecutionTargetRequest{Command: command})
		if err == nil && value.ObservedAt.After(after) {
			return value
		}
		select {
		case <-ctx.Done():
			t.Fatal("real node did not produce a new authenticated observation")
		case <-ticker.C:
		}
	}
}
