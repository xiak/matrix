package localmysql

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

func TestEnsureCreatesRealMySQLShapeWithoutEmbeddingCredentials(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	secrets := [][]byte{
		[]byte("managed-mysql-user-secret-material-000000000000000000000000"),
		[]byte("managed-mysql-root-secret-material-000000000000000000000000"),
	}
	secretIndex := 0
	imageID := "sha256:" + strings.Repeat("b", 64)
	provisioner, err := New(Config{
		Root: t.TempDir(), ImageID: imageID, Runtime: runtime,
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
			Volumes     []struct {
				Source   string `json:"source"`
				Target   string `json:"target"`
				ReadOnly bool   `json:"read_only"`
			} `json:"volumes"`
		} `json:"services"`
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
}

func TestEnsureRejectsAnotherOfferingBeforeRuntime(t *testing.T) {
	runtime := &fakeRuntime{t: t}
	provisioner, err := New(Config{
		Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("c", 64), Runtime: runtime,
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
		runtime.t.Fatal(err)
	}
	var document struct {
		Services map[string]struct {
			Ports []string `json:"ports"`
		} `json:"services"`
	}
	if json.Unmarshal(content, &document) != nil || len(document.Services[mysqlServiceName].Ports) != 1 {
		runtime.t.Fatalf("invalid MySQL effect document: %s", content)
	}
	published := strings.Split(document.Services[mysqlServiceName].Ports[0], ":")
	if len(published) != 3 {
		runtime.t.Fatalf("invalid published port: %#v", published)
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
	return []composeadapter.RuntimeContainer{{
		Project: project.Name, Service: mysqlServiceName,
		State: "running", Health: "healthy", PublishedPorts: 1,
		Labels: map[string]string{
			"com.xiak.matrix.managed":                     "true",
			"com.xiak.matrix.managedservice.installation": "mysql-primary",
			"com.xiak.matrix.managedservice.offering":     managedservicev1.MySQLOfferingID,
			"com.xiak.matrix.managedservice.region":       "local-primary",
		},
	}}, nil
}

func (runtime *fakeRuntime) Stop(context.Context, composeadapter.RuntimeProject) error { return nil }

func (runtime *fakeRuntime) close() {
	if runtime.listener != nil {
		_ = runtime.listener.Close()
	}
}
