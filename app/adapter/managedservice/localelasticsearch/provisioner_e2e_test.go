package localelasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontaineradapter "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const localElasticsearchE2EImage = "MATRIX_LOCAL_ELASTICSEARCH_E2E_IMAGE_ID"

func TestLocalElasticsearchRealRuntime(t *testing.T) {
	imageID := os.Getenv(localElasticsearchE2EImage)
	if imageID == "" {
		t.Skipf("set %s to an already loaded, immutable Elasticsearch 8.19.23 image ID", localElasticsearchE2EImage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	runtime := composeadapter.NewLocalRuntime()
	root := t.TempDir()
	provisioner, err := New(Config{Root: root, ImageID: imageID, Runtime: runtime})
	if err != nil {
		t.Fatalf("new real Elasticsearch provisioner: %v", err)
	}
	request := testProvisionRequest()
	projectName := localcontaineradapter.ProjectName(request.TenantID, request.InstallationID)
	directory := filepath.Join(root, projectName)
	project := composeadapter.RuntimeProject{
		Name: projectName, Directory: directory,
		EffectDocument:      filepath.Join(directory, "compose.json"),
		ObservationDocument: filepath.Join(directory, "observe.json"),
		TimeoutSeconds:      120,
	}
	defer func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		if _, err := os.Stat(project.ObservationDocument); err == nil {
			_ = runtime.Stop(cleanup, project)
		}
	}()
	result, err := provisioner.Ensure(ctx, request)
	if err != nil {
		configuration, _ := exec.CommandContext(context.Background(), "docker", "compose",
			"--project-name", projectName, "--project-directory", directory,
			"--file", project.EffectDocument, "config").CombinedOutput()
		logs, _ := exec.CommandContext(context.Background(), "docker", "compose",
			"--project-name", projectName, "--project-directory", directory,
			"--file", project.ObservationDocument, "logs", "--no-color", "--tail", "80").CombinedOutput()
		t.Fatalf("ensure real Elasticsearch: %v; Compose configuration: %s; logs: %s", err, configuration, logs)
	}
	password, err := os.ReadFile(filepath.Join(directory, "elasticsearch-password"))
	if err != nil {
		t.Fatal("read generated Elasticsearch credential")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	var rootResponse struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	elasticsearchJSON(t, ctx, client, http.MethodGet, result.Endpoint+"/", password, nil, http.StatusOK, &rootResponse)
	if rootResponse.Version.Number != "8.19.23" {
		t.Fatalf("Elasticsearch version=%q", rootResponse.Version.Number)
	}
	elasticsearchJSON(t, ctx, client, http.MethodPut, result.Endpoint+"/matrix-probe", password,
		[]byte(`{"settings":{"number_of_shards":1,"number_of_replicas":0}}`), http.StatusOK, nil)
	elasticsearchJSON(t, ctx, client, http.MethodPut,
		result.Endpoint+"/matrix-probe/_doc/preserved?refresh=wait_for", password,
		[]byte(`{"value":"preserved"}`), http.StatusCreated, nil)
	client.CloseIdleConnections()
	if err := runtime.Stop(ctx, project); err != nil {
		t.Fatalf("stop Elasticsearch before persistence replay: %v", err)
	}
	replayed, err := provisioner.Ensure(ctx, request)
	if err != nil || replayed != result {
		t.Fatalf("reconcile real Elasticsearch=%#v err=%v", replayed, err)
	}
	var document struct {
		Found  bool `json:"found"`
		Source struct {
			Value string `json:"value"`
		} `json:"_source"`
	}
	elasticsearchJSON(t, ctx, client, http.MethodGet,
		result.Endpoint+"/matrix-probe/_doc/preserved", password, nil, http.StatusOK, &document)
	if !document.Found || document.Source.Value != "preserved" {
		t.Fatalf("Elasticsearch persistence probe=%#v", document)
	}
	client.CloseIdleConnections()
	deprovision := managedserviceadapterv1.DeprovisionRequest{
		TenantID: request.TenantID, InstallationID: request.InstallationID,
		OperationID: "operation-real-delete", OfferingID: request.OfferingID,
		EngineVersion: request.EngineVersion, RegionID: request.RegionID,
	}
	if err := provisioner.Delete(ctx, deprovision); err != nil {
		t.Fatalf("delete real Elasticsearch: %v", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("real Elasticsearch data or credentials remain: %v", err)
	}
	endpoint, _ := url.Parse(result.Endpoint)
	if connection, err := net.DialTimeout("tcp", endpoint.Host, time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("terminated Elasticsearch endpoint still accepts connections")
	}
	if err := provisioner.Delete(ctx, deprovision); err != nil {
		t.Fatalf("equal real Elasticsearch delete replay: %v", err)
	}
}

func elasticsearchJSON(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	method string,
	endpoint string,
	password []byte,
	body []byte,
	wantStatus int,
	result any,
) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("elastic", string(password))
	response, err := client.Do(request)
	if err != nil {
		container := exec.CommandContext(context.Background(), "docker", "container", "ls", "--all",
			"--filter", "label=com.xiak.matrix.managedservice.offering=elasticsearch-8.19", "--format", "{{.ID}}")
		containerBytes, _ := container.Output()
		identities := bytes.Fields(containerBytes)
		logs := []byte(nil)
		if len(identities) == 1 {
			logs, _ = exec.CommandContext(context.Background(), "docker", "container", "logs", "--tail", "120", string(identities[0])).CombinedOutput()
		}
		t.Fatalf("Elasticsearch %s %s: %v; logs: %s", method, endpoint, err, logs)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil || response.StatusCode != wantStatus {
		t.Fatalf("Elasticsearch %s %s status=%d body=%s err=%v", method, endpoint, response.StatusCode, content, err)
	}
	if result != nil && json.Unmarshal(content, result) != nil {
		t.Fatalf("decode Elasticsearch response: %s", content)
	}
}
