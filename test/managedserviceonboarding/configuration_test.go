package managedserviceonboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
)

func requestFor(service string) adapterv1.ProvisionRequest {
	return adapterv1.ProvisionRequest{
		TenantID: "onboarding-account", InstallationID: service + "-example", OperationID: "operation-create",
		OfferingID: service + "-8.19-onboarding", EngineVersion: Version,
		RegionID: "local-primary", QuotaShape: Shape(service),
	}
}

func deletionFor(request adapterv1.ProvisionRequest) adapterv1.DeprovisionRequest {
	return adapterv1.DeprovisionRequest{TenantID: request.TenantID, InstallationID: request.InstallationID,
		OperationID: "operation-delete", OfferingID: request.OfferingID,
		EngineVersion: request.EngineVersion, RegionID: request.RegionID}
}

func TestProductContractIdentityReplayAndSecrets(t *testing.T) {
	for _, service := range []string{"logstash", "kibana"} {
		t.Run(service, func(t *testing.T) {
			runtime := &recordingRuntime{containers: make(map[string]compose.RuntimeContainer)}
			config := InstallationConfig{Root: filepath.Join(t.TempDir(), "provider"),
				ImageID: "sha256:" + strings.Repeat("a", 64), Runtime: runtime, Request: requestFor(service)}
			dependency := testDependency(t, config.Request.TenantID)
			construct := func() (adapterv1.Provisioner, error) {
				if service == "logstash" {
					return NewLogstash(config)
				}
				return NewKibana(config, dependency)
			}
			provider, err := construct()
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.Ready(context.Background()); err != nil || runtime.applies != 0 {
				t.Fatal("provider readiness created an installation")
			}
			for name, change := range map[string]func(*adapterv1.ProvisionRequest){
				"tenant":   func(r *adapterv1.ProvisionRequest) { r.TenantID = "other-account" },
				"instance": func(r *adapterv1.ProvisionRequest) { r.InstallationID = "other-instance" },
				"offering": func(r *adapterv1.ProvisionRequest) { r.OfferingID = "unreleased" },
				"version":  func(r *adapterv1.ProvisionRequest) { r.EngineVersion = "8.18.0" },
				"quota":    func(r *adapterv1.ProvisionRequest) { r.QuotaShape.MemoryMiB++ },
				"region":   func(r *adapterv1.ProvisionRequest) { r.RegionID = "another-region" },
			} {
				r := config.Request
				change(&r)
				if _, err := provider.Ensure(context.Background(), r); err == nil || runtime.applies != 0 {
					t.Fatalf("%s reached runtime effects", name)
				}
			}
			first, err := provider.Ensure(context.Background(), config.Request)
			if err != nil || adapterv1.ValidateProvisionResult(first) != nil {
				t.Fatalf("ensure: %v", err)
			}
			provider, err = construct() // New process-side object, same durable state.
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := provider.Ensure(context.Background(), config.Request)
			if err != nil || first != replayed || runtime.applies != 1 {
				t.Fatal("equal replay did not preserve the installation")
			}
			content, err := os.ReadFile(runtime.project.EffectDocument)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := os.ReadFile(filepath.Join(runtime.project.Directory, service+"-secret"))
			if err != nil {
				t.Fatal(err)
			}
			defer clear(secret)
			password, err := os.ReadFile(dependency.PasswordFile)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(content, secret) || bytes.Contains(content, password) || strings.Contains(first.Endpoint, string(secret)) {
				t.Fatal("credential escaped its protected file")
			}
			changed := config
			changed.ImageID = "sha256:" + strings.Repeat("b", 64)
			var drifted adapterv1.Provisioner
			if service == "logstash" {
				drifted, err = NewLogstash(changed)
			} else {
				drifted, err = NewKibana(changed, dependency)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := drifted.Ensure(context.Background(), config.Request); err == nil || runtime.applies != 1 {
				t.Fatal("immutable image/configuration drift was applied")
			}
			badDelete := deletionFor(config.Request)
			badDelete.TenantID = "other-account"
			if err := provider.Delete(context.Background(), badDelete); err == nil || runtime.stops != 0 {
				t.Fatal("cross-tenant deletion reached runtime")
			}
			if err := provider.Delete(context.Background(), deletionFor(config.Request)); err != nil {
				t.Fatal(err)
			}
			if err := provider.Delete(context.Background(), deletionFor(config.Request)); err != nil || runtime.stops != 1 || runtime.purges != 1 {
				t.Fatal("equal deletion was not convergent")
			}
		})
	}
}

func TestKibanaDependencyIsBoundBeforeEffects(t *testing.T) {
	config := InstallationConfig{Root: filepath.Join(t.TempDir(), "provider"),
		ImageID: "sha256:" + strings.Repeat("a", 64), Runtime: &recordingRuntime{}, Request: requestFor("kibana")}
	valid := testDependency(t, config.Request.TenantID)
	for name, change := range map[string]func(*ElasticsearchDependency){
		"tenant":             func(d *ElasticsearchDependency) { d.TenantID = "other-account" },
		"version":            func(d *ElasticsearchDependency) { d.EngineVersion = "8.18.0" },
		"revision":           func(d *ElasticsearchDependency) { d.Revision++ },
		"endpoint":           func(d *ElasticsearchDependency) { d.Endpoint = "http://example.com:9200" },
		"network":            func(d *ElasticsearchDependency) { d.Network = "host" },
		"missing credential": func(d *ElasticsearchDependency) { d.PasswordFile += ".absent" },
	} {
		d := valid
		change(&d)
		if _, err := NewKibana(config, d); err == nil {
			t.Fatalf("accepted invalid %s", name)
		}
	}
}

func TestConfigurationRejectsReplacementAndSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configuration")
	if err := writeImmutable(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeImmutable(path, []byte("changed"), 0o600); err == nil {
		t.Fatal("replaced immutable configuration")
	}
	content, _ := os.ReadFile(path)
	if string(content) != "original" {
		t.Fatal("changed existing configuration")
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symlink creation unavailable on this host")
	}
	if err := writeImmutable(link, []byte("original"), 0o600); err == nil {
		t.Fatal("accepted a symlink")
	}
}

func testDependency(t *testing.T, tenant string) ElasticsearchDependency {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(strings.Repeat("fixture", 8)), 0o600); err != nil {
		t.Fatal(err)
	}
	return ElasticsearchDependency{TenantID: tenant, InstallationID: "dependency-es", EngineVersion: Version,
		Revision: 1, Network: "matrix-onboarding-unit", Endpoint: "http://elasticsearch:9200", PasswordFile: path}
}

type recordingRuntime struct {
	containers             map[string]compose.RuntimeContainer
	project                compose.RuntimeProject
	applies, stops, purges int
}

func (*recordingRuntime) Ready(context.Context) error { return nil }
func (r *recordingRuntime) Apply(_ context.Context, p compose.RuntimeProject) error {
	content, err := os.ReadFile(p.EffectDocument)
	if err != nil {
		return err
	}
	var doc struct {
		Services map[string]struct {
			Labels map[string]string `json:"labels"`
		} `json:"services"`
	}
	if json.Unmarshal(content, &doc) != nil || len(doc.Services) != 1 {
		return errors.New("invalid fixture document")
	}
	for service, value := range doc.Services {
		r.containers[p.Name] = compose.RuntimeContainer{ID: p.Name, Project: p.Name, Service: service,
			State: "running", Health: "healthy", PublishedPorts: 1, Labels: value.Labels}
	}
	r.project = p
	r.applies++
	return nil
}
func (r *recordingRuntime) Observe(_ context.Context, p compose.RuntimeProject) ([]compose.RuntimeContainer, error) {
	if c, ok := r.containers[p.Name]; ok {
		return []compose.RuntimeContainer{c}, nil
	}
	return nil, nil
}
func (r *recordingRuntime) Stop(_ context.Context, p compose.RuntimeProject) error {
	delete(r.containers, p.Name)
	r.stops++
	return nil
}
func (r *recordingRuntime) PurgeData(context.Context, compose.RuntimeProject, string) error {
	r.purges++
	return nil
}
