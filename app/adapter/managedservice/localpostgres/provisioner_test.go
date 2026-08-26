package localpostgres

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
)

func TestEnsureUsesOnlyFixedArtifactAndFileCredential(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	secret := []byte("managed-postgres-secret-material-0000000000000000000000000000")
	provisioner, err := New(Config{
		Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("a", 64), Runtime: runtime,
		NewSecret: func() ([]byte, error) { return append([]byte(nil), secret...), nil },
	})
	if err != nil {
		t.Fatalf("new provisioner: %v", err)
	}
	result, err := provisioner.Ensure(context.Background(), testProvisionRequest())
	if err != nil {
		t.Fatalf("ensure PostgreSQL: %v", err)
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
	if strings.Contains(string(document), string(secret)) || strings.Contains(string(document), "postgres:latest") ||
		!strings.Contains(string(document), `"pull_policy":"never"`) ||
		!strings.Contains(string(document), `"image":"sha256:`+strings.Repeat("a", 64)+`"`) {
		t.Fatalf("Compose document crossed the fixed artifact or credential boundary: %s", document)
	}
	passwordPath := strings.TrimSuffix(runtime.project.EffectDocument, "compose.json") + "postgres-password"
	password, err := os.ReadFile(passwordPath)
	if err != nil || string(password) != string(secret) {
		t.Fatalf("credential file does not contain the generated secret: err=%v", err)
	}
	if os.PathSeparator == '/' {
		dataPath := strings.TrimSuffix(runtime.project.EffectDocument, "compose.json") + "data"
		info, statErr := os.Stat(dataPath)
		if statErr != nil {
			t.Fatalf("inspect PostgreSQL 18 data mount: %v", statErr)
		}
		if info.Mode().Perm() != 0o777 || info.Mode()&os.ModeSticky == 0 {
			t.Fatalf("PostgreSQL 18 data mount mode=%v", info.Mode())
		}
	}
	second, err := provisioner.Ensure(context.Background(), testProvisionRequest())
	if err != nil || second != result || runtime.applyCalls != 1 {
		t.Fatalf("equal ensure=%#v err=%v applyCalls=%d", second, err, runtime.applyCalls)
	}
}

func TestEnsureRejectsUnsupportedOfferingBeforeRuntime(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	provisioner, err := New(Config{
		Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("b", 64), Runtime: runtime,
	})
	if err != nil {
		t.Fatalf("new provisioner: %v", err)
	}
	request := testProvisionRequest()
	request.OfferingID = "mysql-9"
	if _, err := provisioner.Ensure(context.Background(), request); err == nil || runtime.applyCalls != 0 {
		t.Fatalf("unsupported offering err=%v applyCalls=%d", err, runtime.applyCalls)
	}
}

func testProvisionRequest() managedserviceadapterv1.ProvisionRequest {
	return managedserviceadapterv1.ProvisionRequest{
		TenantID: "organization-test", InstallationID: "postgres-primary",
		OperationID: "operation-test", OfferingID: managedservicev1.PostgreSQLOfferingID,
		EngineVersion: "18", RegionID: "local-primary",
		QuotaShape: managedservicev1.QuotaShape{
			ID: "pg-small", DisplayName: "开发型",
			CPUMillicores: 500, MemoryMiB: 1024, StorageGiB: 10,
		},
	}
}

type fakeRuntime struct {
	t          *testing.T
	project    composeadapter.RuntimeProject
	listener   net.Listener
	applyCalls int
}

func (runtime *fakeRuntime) Ready(context.Context) error { return nil }

func (runtime *fakeRuntime) Apply(_ context.Context, project composeadapter.RuntimeProject) error {
	runtime.applyCalls++
	runtime.project = project
	content, err := os.ReadFile(project.EffectDocument)
	if err != nil {
		runtime.t.Fatalf("read effect document: %v", err)
	}
	var document struct {
		Services map[string]struct {
			Ports []string `json:"ports"`
		} `json:"services"`
	}
	if json.Unmarshal(content, &document) != nil || len(document.Services[postgresServiceName].Ports) != 1 {
		runtime.t.Fatalf("invalid effect document: %s", content)
	}
	published := strings.Split(document.Services[postgresServiceName].Ports[0], ":")
	if len(published) != 3 {
		runtime.t.Fatalf("invalid published port: %#v", published)
	}
	runtime.listener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", published[1]))
	if err != nil {
		runtime.t.Fatalf("listen on planned endpoint: %v", err)
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
	return []composeadapter.RuntimeContainer{{
		Project: project.Name, Service: postgresServiceName,
		State: "running", Health: "healthy", PublishedPorts: 1,
		Labels: map[string]string{
			"com.xiak.matrix.managed":                     "true",
			"com.xiak.matrix.managedservice.installation": "postgres-primary",
		},
	}}, nil
}

func (runtime *fakeRuntime) Stop(context.Context, composeadapter.RuntimeProject) error {
	return nil
}

func (runtime *fakeRuntime) close() {
	if runtime.listener != nil {
		_ = runtime.listener.Close()
	}
}
