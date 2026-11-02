package localmysql

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

func TestEnsureCreatesRealMySQLShapeWithoutEmbeddingCredentials(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	secrets := [][]byte{
		[]byte("managed-mysql-user-secret-material-000000000000000000000000"),
		[]byte("managed-mysql-root-secret-material-000000000000000000000000"),
	}
	secretIndex := 0
	imageID := "sha256:" + strings.Repeat("b", 64)
	root := t.TempDir()
	provisioner, err := New(Config{
		Root: root, ImageID: imageID, EndpointImageID: "sha256:" + strings.Repeat("d", 64), Runtime: runtime,
		NewSecret: func() ([]byte, error) {
			result := append([]byte(nil), secrets[secretIndex]...)
			secretIndex++
			return result, nil
		},
	})
	if err != nil {
		t.Fatalf("new MySQL provisioner: %v", err)
	}
	request := testProvisionRequest()
	result, err := provisioner.Ensure(context.Background(), request)
	if err != nil {
		t.Fatalf("ensure MySQL: %v", err)
	}
	defer runtime.close()
	if runtime.applyCalls != 1 || result.Endpoint == "" ||
		!strings.HasPrefix(result.CredentialReference, "credential-") {
		t.Fatalf("result=%#v applyCalls=%d", result, runtime.applyCalls)
	}
	document, err := os.ReadFile(runtime.project.EffectDocument)
	if err != nil {
		t.Fatalf("read Compose document: %v", err)
	}
	var effect struct {
		Services map[string]struct {
			Image       string            `json:"image"`
			PullPolicy  string            `json:"pull_policy"`
			Environment map[string]string `json:"environment"`
			Networks    []string          `json:"networks"`
			Ports       []string          `json:"ports"`
			User        string            `json:"user"`
			ReadOnly    bool              `json:"read_only"`
			CapDrop     []string          `json:"cap_drop"`
			Sysctls     map[string]string `json:"sysctls"`
			Volumes     []struct {
				Source   string `json:"source"`
				Target   string `json:"target"`
				ReadOnly bool   `json:"read_only"`
			} `json:"volumes"`
		} `json:"services"`
		Networks map[string]struct {
			Internal      bool              `json:"internal"`
			DriverOptions map[string]string `json:"driver_opts"`
		} `json:"networks"`
	}
	if err := json.Unmarshal(document, &effect); err != nil {
		t.Fatal("decode MySQL Compose document", err)
	}
	service, exists := effect.Services[mysqlServiceName]
	if !exists || service.Image != imageID || service.PullPolicy != "never" ||
		service.Environment["MYSQL_PASSWORD_FILE"] != "/run/secrets/mysql-password" ||
		service.Environment["MYSQL_ROOT_PASSWORD_FILE"] != "/run/secrets/mysql-root-password" {
		t.Fatalf("invalid MySQL Compose service: %#v", service)
	}
	if len(service.Ports) != 0 || len(service.Networks) != 1 || service.Networks[0] != "private" ||
		!effect.Networks["private"].Internal || effect.Networks["private"].DriverOptions["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" {
		t.Fatal("MySQL backend has a public port, host gateway or external network")
	}
	endpoint, exists := effect.Services[endpointServiceName]
	if !exists || len(endpoint.Ports) != 1 || len(endpoint.Networks) != 2 ||
		len(endpoint.Volumes) != 0 || endpoint.Environment["MYSQL_PASSWORD_FILE"] != "" ||
		endpoint.User != "65532:65532" || !endpoint.ReadOnly ||
		len(endpoint.CapDrop) != 1 || endpoint.CapDrop[0] != "ALL" ||
		endpoint.Sysctls["net.ipv4.ip_forward"] != "0" || endpoint.Sysctls["net.ipv6.conf.all.forwarding"] != "0" {
		t.Fatal("MySQL ingress is not bounded, credential-free and non-routing")
	}
	for _, secret := range secrets {
		if strings.Contains(string(document), string(secret)) {
			t.Fatal("MySQL Compose document contains a generated credential")
		}
	}
	wantMounts := map[string]bool{
		"/run/secrets/mysql-password":      false,
		"/run/secrets/mysql-root-password": false,
	}
	for _, volume := range service.Volumes {
		if _, expected := wantMounts[volume.Target]; expected && volume.Source != "" && volume.ReadOnly {
			wantMounts[volume.Target] = true
		}
	}
	for target, mounted := range wantMounts {
		if !mounted {
			t.Fatalf("MySQL credential is not mounted read-only: %s", target)
		}
	}
	second, err := provisioner.Ensure(context.Background(), request)
	if err != nil || second != result || runtime.applyCalls != 1 || secretIndex != 2 {
		t.Fatalf("equal ensure=%#v err=%v applyCalls=%d secrets=%d", second, err, runtime.applyCalls, secretIndex)
	}
	deprovision := managedserviceadapterv1.DeprovisionRequest{
		TenantID: request.TenantID, InstallationID: request.InstallationID,
		OperationID: "operation-delete", OfferingID: request.OfferingID,
		EngineVersion: request.EngineVersion, RegionID: request.RegionID,
	}
	if err := provisioner.Delete(context.Background(), deprovision); err != nil ||
		runtime.stopCalls != 1 || runtime.purgeCalls != 1 {
		t.Fatalf("delete MySQL err=%v stopCalls=%d purgeCalls=%d", err, runtime.stopCalls, runtime.purgeCalls)
	}
	projectDirectory := filepath.Join(root, localcontaineradapter.ProjectName(request.TenantID, request.InstallationID))
	if _, err := os.Lstat(projectDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("MySQL data and credentials still exist: %v", err)
	}
	if err := provisioner.Delete(context.Background(), deprovision); err != nil ||
		runtime.stopCalls != 1 || runtime.purgeCalls != 1 {
		t.Fatalf("equal delete replay err=%v stopCalls=%d purgeCalls=%d", err, runtime.stopCalls, runtime.purgeCalls)
	}
}

func TestEnsureRejectsAnotherOfferingBeforeRuntime(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	provisioner, err := New(Config{
		Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("c", 64), EndpointImageID: "sha256:" + strings.Repeat("d", 64), Runtime: runtime,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := testProvisionRequest()
	request.OfferingID = managedservicev1.PostgreSQLOfferingID
	request.EngineVersion = "18"
	if _, err := provisioner.Ensure(context.Background(), request); err == nil || runtime.applyCalls != 0 {
		t.Fatal("another offering reached the MySQL runtime")
	}
}

func testProvisionRequest() managedserviceadapterv1.ProvisionRequest {
	return managedserviceadapterv1.ProvisionRequest{
		TenantID: "organization-test", InstallationID: "mysql-primary",
		OperationID: "operation-test", OfferingID: managedservicev1.MySQLOfferingID,
		EngineVersion: "8.4", RegionID: "local-primary",
		QuotaShape: managedservicev1.QuotaShape{
			ID: "mysql-small", DisplayName: "开发型",
			CPUMillicores: 500, MemoryMiB: 1024, StorageGiB: 10,
		},
	}
}

type fakeRuntime struct {
	t           *testing.T
	project     composeadapter.RuntimeProject
	listener    net.Listener
	applyCalls  int
	stopCalls   int
	purgeCalls  int
	observed    func([]composeadapter.RuntimeContainer) []composeadapter.RuntimeContainer
	beforeApply func() error
}

func (runtime *fakeRuntime) Ready(context.Context) error { return nil }

func (runtime *fakeRuntime) Apply(_ context.Context, project composeadapter.RuntimeProject) error {
	runtime.applyCalls++
	if runtime.beforeApply != nil {
		if err := runtime.beforeApply(); err != nil {
			return err
		}
	}
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
	if json.Unmarshal(content, &document) != nil || len(document.Services[endpointServiceName].Ports) != 1 {
		runtime.t.Fatalf("invalid MySQL effect document: %s", content)
	}
	published := strings.Split(document.Services[endpointServiceName].Ports[0], ":")
	if len(published) != 3 {
		runtime.t.Fatalf("invalid published port: %#v", published)
	}
	if runtime.listener != nil {
		_ = runtime.listener.Close()
	}
	runtime.listener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", published[1]))
	if err != nil {
		runtime.t.Fatal(err)
	}
	return nil
}

func (runtime *fakeRuntime) Observe(
	_ context.Context,
	project composeadapter.RuntimeProject,
) ([]composeadapter.RuntimeContainer, error) {
	if runtime.listener == nil {
		return []composeadapter.RuntimeContainer{}, nil
	}
	backend := composeadapter.RuntimeContainer{
		Project: project.Name, Service: mysqlServiceName,
		State: "running", Health: "healthy", PublishedPorts: 0,
		Labels: map[string]string{
			"com.xiak.matrix.managed":                     "true",
			"com.xiak.matrix.managedservice.installation": "mysql-primary",
			"com.xiak.matrix.managedservice.offering":     managedservicev1.MySQLOfferingID,
			"com.xiak.matrix.managedservice.region":       "local-primary",
		},
	}
	endpoint := backend
	endpoint.Service, endpoint.PublishedPorts = endpointServiceName, 1
	containers := []composeadapter.RuntimeContainer{backend, endpoint}
	if runtime.observed != nil {
		containers = runtime.observed(containers)
	}
	return containers, nil
}

func TestEnsureRequiresBothOwnedServicesAndPrivateBackend(t *testing.T) {
	for _, mutation := range []struct {
		name   string
		change func([]composeadapter.RuntimeContainer) []composeadapter.RuntimeContainer
	}{
		{"missing ingress", func(c []composeadapter.RuntimeContainer) []composeadapter.RuntimeContainer { return c[:1] }},
		{"published backend", func(c []composeadapter.RuntimeContainer) []composeadapter.RuntimeContainer {
			c[0].PublishedPorts = 1
			return c
		}},
		{"unhealthy ingress", func(c []composeadapter.RuntimeContainer) []composeadapter.RuntimeContainer {
			c[1].Health = "unhealthy"
			return c
		}},
		{"duplicate backend", func(c []composeadapter.RuntimeContainer) []composeadapter.RuntimeContainer {
			return []composeadapter.RuntimeContainer{c[0], c[0]}
		}},
		{"foreign ingress", func(c []composeadapter.RuntimeContainer) []composeadapter.RuntimeContainer {
			c[1].Project = "foreign"
			return c
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			runtime := &fakeRuntime{t: t, observed: mutation.change}
			defer runtime.close()
			provider, err := New(Config{Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("b", 64), EndpointImageID: "sha256:" + strings.Repeat("d", 64), Runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Ensure(t.Context(), testProvisionRequest()); err == nil {
				t.Fatal("invalid network boundary reported ready")
			}
		})
	}
}

func TestEndpointImageMustBePinned(t *testing.T) {
	for _, image := range []string{"", "matrix-paas:latest", "sha256:invalid"} {
		if _, err := New(Config{Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("b", 64), EndpointImageID: image, Runtime: &fakeRuntime{t: t}}); err == nil {
			t.Fatal("untrusted endpoint identity accepted")
		}
	}
}

func (runtime *fakeRuntime) Stop(context.Context, composeadapter.RuntimeProject) error {
	runtime.stopCalls++
	if runtime.listener != nil {
		if err := runtime.listener.Close(); err != nil {
			return err
		}
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
