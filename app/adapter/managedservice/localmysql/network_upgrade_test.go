package localmysql

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
)

func TestInstalledNetworkUpgradePreservesStateAndRecoversInterruptedEffect(t *testing.T) {
	for _, mode := range []string{"running", "stopped", "failed-effect", "foreign-runtime"} {
		t.Run(mode, func(t *testing.T) {
			runtime := &fakeRuntime{t: t}
			defer runtime.close()
			provider, err := New(Config{Root: t.TempDir(), ImageID: "sha256:" + strings.Repeat("b", 64), EndpointImageID: "sha256:" + strings.Repeat("d", 64), Runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			result, err := provider.Ensure(t.Context(), testProvisionRequest())
			if err != nil {
				t.Fatal(err)
			}
			directory := runtime.project.Directory
			credential, err := os.ReadFile(filepath.Join(directory, "mysql-password"))
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(directory, "data", "durable-row")
			if err := os.WriteFile(marker, []byte("existing data"), 0o600); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(runtime.project.EffectDocument)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if json.Unmarshal(content, &document) != nil {
				t.Fatal("decode test deployment")
			}
			services := document["services"].(map[string]any)
			delete(services, endpointServiceName)
			delete(document, "networks")
			backend := services[mysqlServiceName].(map[string]any)
			delete(backend, "networks")
			_, port, _ := net.SplitHostPort(result.Endpoint)
			backend["ports"] = []string{"127.0.0.1:" + port + ":3306/tcp"}
			old, _ := json.Marshal(document)
			for _, file := range []string{runtime.project.EffectDocument, runtime.project.ObservationDocument} {
				if os.WriteFile(file, old, 0o600) != nil {
					t.Fatal("write installed deployment")
				}
			}
			legacy := true
			runtime.observed = func(c []composeadapter.RuntimeContainer) []composeadapter.RuntimeContainer {
				if !legacy {
					return c
				}
				c = c[:1]
				c[0].PublishedPorts = 1
				if mode == "stopped" {
					c[0].State = "exited"
				}
				if mode == "foreign-runtime" {
					c[0].Project = "foreign-project"
				}
				return c
			}
			fail := mode == "failed-effect"
			runtime.beforeApply = func() error {
				if fail {
					return errors.New("unavailable")
				}
				legacy = false
				return nil
			}
			err = provider.UpgradeNetwork(t.Context())
			if mode == "foreign-runtime" {
				if err == nil || runtime.applyCalls != 1 || runtime.stopCalls != 0 {
					t.Fatal("foreign deployment reached migration")
				}
				after, _ := os.ReadFile(runtime.project.EffectDocument)
				if !bytes.Equal(old, after) {
					t.Fatal("foreign deployment document changed")
				}
				return
			}
			if fail {
				if err == nil || runtime.purgeCalls != 0 {
					t.Fatal("migration failure purged state or claimed success")
				}
				fail = false
				err = provider.UpgradeNetwork(t.Context())
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "stopped" && (runtime.applyCalls != 1 || runtime.stopCalls != 1) {
				t.Fatal("stopped instance was started")
			}
			for _, file := range []string{runtime.project.EffectDocument, runtime.project.ObservationDocument} {
				content, _ := os.ReadFile(file)
				if json.Unmarshal(content, &document) != nil {
					t.Fatal("decode migrated deployment")
				}
				services = document["services"].(map[string]any)
				if services[mysqlServiceName].(map[string]any)["ports"] != nil || services[endpointServiceName] == nil {
					t.Fatal("direct published port survived migration")
				}
			}
			after, _ := os.ReadFile(filepath.Join(directory, "mysql-password"))
			data, _ := os.ReadFile(marker)
			if !bytes.Equal(credential, after) || string(data) != "existing data" || runtime.purgeCalls != 0 {
				t.Fatal("migration changed credentials or data")
			}
			calls, stops := runtime.applyCalls, runtime.stopCalls
			if provider.UpgradeNetwork(t.Context()) != nil || runtime.applyCalls != calls || runtime.stopCalls != stops {
				t.Fatal("completed migration was not idempotent")
			}
		})
	}
}
