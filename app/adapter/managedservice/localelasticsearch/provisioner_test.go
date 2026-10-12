package localelasticsearch

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

func TestEnsureCreatesRealElasticsearchShapeWithoutEmbeddingCredentials(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	secret := []byte("managed-elasticsearch-secret-material-000000000000000000000")
	secretCalls := 0
	imageID := "sha256:" + strings.Repeat("d", 64)
	root := t.TempDir()
	provisioner, err := New(Config{
		Root: root, ImageID: imageID, Runtime: runtime,
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
		Services map[string]struct {
			Image       string            `json:"image"`
			PullPolicy  string            `json:"pull_policy"`
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
	if service.Image != imageID || service.PullPolicy != "never" ||
		service.Environment["ELASTIC_PASSWORD_FILE"] != "/tmp/matrix-elasticsearch-password" ||
		service.Environment["xpack.security.enabled"] != "true" ||
		service.Environment["xpack.security.http.ssl.enabled"] != "false" ||
		strings.Contains(string(document), string(secret)) ||
		!strings.HasPrefix(result.Endpoint, "http://127.0.0.1:") ||
		!strings.HasPrefix(result.CredentialReference, "credential-") {
		t.Fatalf("invalid Elasticsearch effect=%s result=%#v", document, result)
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

func TestEnsureRejectsAnotherOfferingBeforeRuntime(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	provisioner, err := New(Config{Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("e", 64), Runtime: runtime})
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
	if json.Unmarshal(content, &document) != nil || len(document.Services[elasticsearchServiceName].Ports) != 1 {
		runtime.t.Fatalf("invalid Elasticsearch effect document: %s", content)
	}
	published := strings.Split(document.Services[elasticsearchServiceName].Ports[0], ":")
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
		Project: project.Name, Service: elasticsearchServiceName,
		State: "running", Health: "healthy", PublishedPorts: 1,
		Labels: map[string]string{
			"com.xiak.matrix.managed":                     "true",
			"com.xiak.matrix.managedservice.installation": "elasticsearch-primary",
			"com.xiak.matrix.managedservice.offering":     managedservicev1.ElasticsearchOfferingID,
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
