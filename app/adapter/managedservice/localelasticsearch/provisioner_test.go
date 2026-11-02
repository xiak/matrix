package localelasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontaineradapter "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

func TestEnsureCreatesRealElasticsearchShapeWithoutEmbeddingCredentials(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	secret := []byte("managed-elasticsearch-secret-material-000000000000000000000")
	secretCalls := 0
	imageID := "sha256:" + strings.Repeat("d", 64)
	root := t.TempDir()
	provisioner, err := New(Config{
		Root: root, ImageID: imageID, EndpointImageID: "sha256:" + strings.Repeat("f", 64), Runtime: runtime,
		NewSecret: func() ([]byte, error) {
			secretCalls++
			return append([]byte(nil), secret...), nil
		},
	})
	if err != nil {
		t.Fatalf("new Elasticsearch provisioner: %v", err)
	}
	request := testProvisionRequest()
	result, err := provisioner.Ensure(context.Background(), request)
	if err != nil {
		t.Fatalf("ensure Elasticsearch: %v", err)
	}
	defer runtime.close()
	document, err := os.ReadFile(runtime.project.EffectDocument)
	if err != nil {
		t.Fatal(err)
	}
	var effect struct {
		Networks map[string]struct {
			Internal      bool              `json:"internal"`
			DriverOptions map[string]string `json:"driver_opts"`
		} `json:"networks"`
		Services map[string]struct {
			Networks    []string          `json:"networks"`
			Ports       []string          `json:"ports"`
			User        string            `json:"user"`
			Image       string            `json:"image"`
			PullPolicy  string            `json:"pull_policy"`
			GroupAdd    []string          `json:"group_add"`
			Environment map[string]string `json:"environment"`
			Volumes     []struct {
				Target   string `json:"target"`
				ReadOnly bool   `json:"read_only"`
			} `json:"volumes"`
		} `json:"services"`
	}
	if err := json.Unmarshal(document, &effect); err != nil {
		t.Fatal(err)
	}
	service := effect.Services[elasticsearchServiceName]
	endpoint := effect.Services[endpointServiceName]
	if len(effect.Services) != 2 || len(service.Ports) != 0 || !reflect.DeepEqual(service.Networks, []string{"private"}) ||
		!effect.Networks["private"].Internal || effect.Networks["private"].DriverOptions["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" ||
		endpoint.User != "65532:65532" || len(endpoint.Ports) != 1 || !strings.HasPrefix(endpoint.Ports[0], "127.0.0.1:") ||
		!reflect.DeepEqual(endpoint.Networks, []string{"private", "default"}) {
		t.Fatal("Elasticsearch network boundary is invalid")
	}
	if service.Image != imageID || service.PullPolicy != "never" ||
		service.Environment["ELASTIC_PASSWORD_FILE"] != "/tmp/matrix-elasticsearch-password" ||
		service.Environment["xpack.security.enabled"] != "true" ||
		service.Environment["xpack.security.http.ssl.enabled"] != "false" ||
		strings.Contains(string(document), string(secret)) ||
		!strings.HasPrefix(result.Endpoint, "http://127.0.0.1:") ||
		!strings.HasPrefix(result.CredentialReference, "credential-") {
		t.Fatalf("invalid Elasticsearch effect=%s result=%#v", document, result)
	}
	if goruntime.GOOS == "linux" {
		credentialPath := filepath.Join(root, localcontaineradapter.ProjectName(request.TenantID, request.InstallationID), "elasticsearch-password")
		groupID, available, groupErr := credentialFileGroupIDForTest(credentialPath)
		if groupErr != nil || !available || len(service.GroupAdd) != 1 ||
			service.GroupAdd[0] != strconv.FormatUint(groupID, 10) {
			t.Fatalf("Elasticsearch credential group_add=%v group=%d available=%t err=%v", service.GroupAdd, groupID, available, groupErr)
		}
	} else if len(service.GroupAdd) != 0 {
		t.Fatalf("unsupported host invented Elasticsearch supplemental groups: %v", service.GroupAdd)
	}
	mounted := false
	for _, volume := range service.Volumes {
		if volume.Target == "/run/secrets/elasticsearch-password-source" && volume.ReadOnly {
			mounted = true
		}
	}
	if !mounted {
		t.Fatal("Elasticsearch credential is not mounted read-only")
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
		t.Fatalf("delete Elasticsearch err=%v stop=%d purge=%d", err, runtime.stopCalls, runtime.purgeCalls)
	}
	directory := filepath.Join(root, localcontaineradapter.ProjectName(request.TenantID, request.InstallationID))
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Elasticsearch data and credentials still exist: %v", err)
	}
}

func credentialFileGroupIDForTest(path string) (uint64, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, false, err
	}
	value := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !value.IsValid() {
		return 0, false, nil
	}
	field := value.FieldByName("Gid")
	if !field.IsValid() {
		return 0, false, nil
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint(), true, nil
	default:
		return 0, false, nil
	}
}

func TestEnsureRejectsAnotherOfferingBeforeRuntime(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	provisioner, err := New(Config{Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("e", 64), EndpointImageID: "sha256:" + strings.Repeat("f", 64), Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	request := testProvisionRequest()
	request.OfferingID = managedservicev1.MySQLOfferingID
	request.EngineVersion = "8.4"
	if _, err := provisioner.Ensure(context.Background(), request); err == nil || runtime.applyCalls != 0 {
		t.Fatal("another offering reached the Elasticsearch runtime")
	}
}

func TestElasticsearchVirtualMemoryRequirement(t *testing.T) {
	for name, fixture := range map[string]struct {
		value string
		valid bool
	}{
		"production minimum": {value: "1048576\n", valid: true},
		"above minimum":      {value: "1048577", valid: true},
		"bootstrap minimum":  {value: "262144", valid: false},
		"invalid":            {value: "unknown", valid: false},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateVirtualMemoryMapCount([]byte(fixture.value))
			if (err == nil) != fixture.valid {
				t.Fatalf("validate vm.max_map_count=%q err=%v", fixture.value, err)
			}
		})
	}
}

func testProvisionRequest() managedserviceadapterv1.ProvisionRequest {
	return managedserviceadapterv1.ProvisionRequest{
		TenantID: "organization-test", InstallationID: "elasticsearch-primary",
		OperationID: "operation-test", OfferingID: managedservicev1.ElasticsearchOfferingID,
		EngineVersion: "8.19.23", RegionID: "local-primary",
		QuotaShape: managedservicev1.QuotaShape{
			ID: "elasticsearch-small", DisplayName: "开发型",
			CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10,
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
		runtime.t.Fatalf("invalid Elasticsearch effect document: %s", content)
	}
	published := strings.Split(document.Services[endpointServiceName].Ports[0], ":")
	if runtime.listener != nil {
		_ = runtime.listener.Close()
	}
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
	backend := composeadapter.RuntimeContainer{
		Project: project.Name, Service: elasticsearchServiceName,
		State: "running", Health: "healthy", PublishedPorts: 0,
		Labels: map[string]string{
			"com.xiak.matrix.managed":                     "true",
			"com.xiak.matrix.managedservice.installation": "elasticsearch-primary",
			"com.xiak.matrix.managedservice.offering":     managedservicev1.ElasticsearchOfferingID,
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
