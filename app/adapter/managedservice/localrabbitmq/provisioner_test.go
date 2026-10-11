package localrabbitmq

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontaineradapter "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

func TestEnsureCreatesRealRabbitMQShapeWithoutEmbeddingCredentials(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	secret := []byte("managed-rabbitmq-secret-material-00000000000000000000000000")
	secretCalls := 0
	imageID := "sha256:" + strings.Repeat("f", 64)
	root := t.TempDir()
	provisioner, err := New(Config{
		Root: root, ImageID: imageID, Runtime: runtime,
		NewSecret: func() ([]byte, error) {
			secretCalls++
			return append([]byte(nil), secret...), nil
		},
	})
	if err != nil {
		t.Fatalf("new RabbitMQ provisioner: %v", err)
	}
	request := testProvisionRequest()
	result, err := provisioner.Ensure(context.Background(), request)
	if err != nil {
		t.Fatalf("ensure RabbitMQ: %v", err)
	}
	defer runtime.close()
	document, err := os.ReadFile(runtime.project.EffectDocument)
	if err != nil {
		t.Fatal(err)
	}
	var effect struct {
		Services map[string]struct {
			Image       string            `json:"image"`
			PullPolicy  string            `json:"pull_policy"`
			Environment map[string]string `json:"environment"`
			Command     []string          `json:"command"`
			Volumes     []struct {
				Target   string `json:"target"`
				ReadOnly bool   `json:"read_only"`
			} `json:"volumes"`
		} `json:"services"`
	}
	if err := json.Unmarshal(document, &effect); err != nil {
		t.Fatal(err)
	}
	service := effect.Services[rabbitMQServiceName]
	if service.Image != imageID || service.PullPolicy != "never" ||
		service.Environment["RABBITMQ_DEFAULT_USER"] != "matrix_service" ||
		service.Environment["RABBITMQ_DEFAULT_VHOST"] != "matrix" ||
		service.Environment["RABBITMQ_DEFAULT_PASS"] != "" ||
		len(service.Command) != 3 || !strings.Contains(service.Command[2], "/run/secrets/rabbitmq-password") ||
		strings.Contains(string(document), string(secret)) ||
		!strings.HasPrefix(result.Endpoint, "amqp://127.0.0.1:") ||
		!strings.HasSuffix(result.Endpoint, "/matrix") ||
		!strings.HasPrefix(result.CredentialReference, "credential-") {
		t.Fatalf("invalid RabbitMQ effect=%s result=%#v", document, result)
	}
	mounted := false
	for _, volume := range service.Volumes {
		if volume.Target == "/run/secrets/rabbitmq-password" && volume.ReadOnly {
			mounted = true
		}
	}
	if !mounted {
		t.Fatal("RabbitMQ credential is not mounted read-only")
	}
	second, err := provisioner.Ensure(context.Background(), request)
	if err != nil || second != result || runtime.applyCalls != 1 || secretCalls != 1 {
		t.Fatalf("equal ensure=%#v err=%v apply=%d secrets=%d", second, err, runtime.applyCalls, secretCalls)
	}
	deprovision := managedserviceadapterv1.DeprovisionRequest{
		TenantID: request.TenantID, InstallationID: request.InstallationID,
		OperationID: "operation-delete", OfferingID: request.OfferingID,
		EngineVersion: request.EngineVersion, RegionID: request.RegionID,
	}
	if err := provisioner.Delete(context.Background(), deprovision); err != nil ||
		runtime.stopCalls != 1 || runtime.purgeCalls != 1 {
		t.Fatalf("delete RabbitMQ err=%v stop=%d purge=%d", err, runtime.stopCalls, runtime.purgeCalls)
	}
	directory := filepath.Join(root, localcontaineradapter.ProjectName(request.TenantID, request.InstallationID))
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("RabbitMQ data and credentials still exist: %v", err)
	}
}

func TestEnsureRejectsAnotherOfferingBeforeRuntime(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	provisioner, err := New(Config{Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("1", 64), Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	request := testProvisionRequest()
	request.OfferingID = managedservicev1.PostgreSQLOfferingID
	request.EngineVersion = "18"
	if _, err := provisioner.Ensure(context.Background(), request); err == nil || runtime.applyCalls != 0 {
		t.Fatal("another offering reached the RabbitMQ runtime")
	}
}

func testProvisionRequest() managedserviceadapterv1.ProvisionRequest {
	return managedserviceadapterv1.ProvisionRequest{
		TenantID: "organization-test", InstallationID: "rabbitmq-primary",
		OperationID: "operation-test", OfferingID: managedservicev1.RabbitMQOfferingID,
		EngineVersion: "4.1.8", RegionID: "local-primary",
		QuotaShape: managedservicev1.QuotaShape{
			ID: "rabbitmq-small", DisplayName: "开发型",
			CPUMillicores: 500, MemoryMiB: 768, StorageGiB: 10,
		},
	}
}

type fakeRuntime struct {
	t          *testing.T
	project    composeadapter.RuntimeProject
	listener   net.Listener
	applyCalls int
	stopCalls  int
	purgeCalls int
}

func (runtime *fakeRuntime) Ready(context.Context) error { return nil }

func (runtime *fakeRuntime) Apply(_ context.Context, project composeadapter.RuntimeProject) error {
	runtime.applyCalls++
	runtime.project = project
	content, err := os.ReadFile(project.EffectDocument)
	if err != nil {
		runtime.t.Fatal(err)
	}
	var document struct {
		Services map[string]struct {
			Ports []string `json:"ports"`
		} `json:"services"`
	}
	if json.Unmarshal(content, &document) != nil || len(document.Services[rabbitMQServiceName].Ports) != 1 {
		runtime.t.Fatalf("invalid RabbitMQ effect document: %s", content)
	}
	published := strings.Split(document.Services[rabbitMQServiceName].Ports[0], ":")
	runtime.listener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", published[1]))
	if err != nil {
		runtime.t.Fatal(err)
	}
	return nil
}

func (runtime *fakeRuntime) Observe(_ context.Context, project composeadapter.RuntimeProject) ([]composeadapter.RuntimeContainer, error) {
	if runtime.listener == nil {
		return []composeadapter.RuntimeContainer{}, nil
	}
	return []composeadapter.RuntimeContainer{{
		Project: project.Name, Service: rabbitMQServiceName,
		State: "running", Health: "healthy", PublishedPorts: 1,
		Labels: map[string]string{
			"com.xiak.matrix.managed":                     "true",
			"com.xiak.matrix.managedservice.installation": "rabbitmq-primary",
			"com.xiak.matrix.managedservice.offering":     managedservicev1.RabbitMQOfferingID,
			"com.xiak.matrix.managedservice.region":       "local-primary",
		},
	}}, nil
}

func (runtime *fakeRuntime) Stop(context.Context, composeadapter.RuntimeProject) error {
	runtime.stopCalls++
	if runtime.listener != nil {
		_ = runtime.listener.Close()
		runtime.listener = nil
	}
	return nil
}

func (runtime *fakeRuntime) PurgeData(context.Context, composeadapter.RuntimeProject, string) error {
	runtime.purgeCalls++
	return nil
}

func (runtime *fakeRuntime) close() {
	if runtime.listener != nil {
		_ = runtime.listener.Close()
	}
}
