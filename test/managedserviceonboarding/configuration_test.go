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
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	locallogstash "github.com/xiak/matrix/app/adapter/managedservice/locallogstash"
)

// InstallationConfig is trusted test composition, never a tenant body.
type InstallationConfig struct {
	Root, ImageID, EndpointImageID string
	Runtime                        compose.Runtime
	Request                        adapterv1.ProvisionRequest
}

func requestFor(service string) adapterv1.ProvisionRequest {
	request := adapterv1.ProvisionRequest{
		TenantID: "onboarding-account", InstallationID: service + "-example", OperationID: "operation-create",
		OfferingID: service + "-8.19", EngineVersion: Version, RegionID: "local-primary",
		QuotaShape: managedv1.QuotaShape{ID: service + "-small", DisplayName: "开发型", CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10},
	}
	if service == "kibana" {
		request.Elasticsearch = &adapterv1.ElasticsearchDependency{InstallationID: "dependency-es", ResourceVersion: 3, EngineVersion: Version, RegionID: "local-primary"}
	}
	return request
}

func newLogstash(config InstallationConfig) (adapterv1.Provisioner, error) {
	return locallogstash.New(locallogstash.Config{Root: config.Root, ImageID: config.ImageID, EndpointImageID: config.EndpointImageID, Runtime: config.Runtime})
}

func deletionFor(request adapterv1.ProvisionRequest) adapterv1.DeprovisionRequest {
	return adapterv1.DeprovisionRequest{TenantID: request.TenantID, InstallationID: request.InstallationID,
		OperationID: "operation-delete", OfferingID: request.OfferingID,
		EngineVersion: request.EngineVersion, RegionID: request.RegionID, Elasticsearch: request.Elasticsearch}
}

func TestLogstashContractIdentityReplayAndSecrets(t *testing.T) {
	const service = "logstash"
	runtime := &recordingRuntime{containers: make(map[string][]compose.RuntimeContainer)}
	config := InstallationConfig{Root: filepath.Join(t.TempDir(), "provider"),
		ImageID: "sha256:" + strings.Repeat("a", 64), EndpointImageID: "sha256:" + strings.Repeat("e", 64), Runtime: runtime, Request: requestFor(service)}
	construct := func() (adapterv1.Provisioner, error) { return newLogstash(config) }
	provider, err := construct()
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Ready(context.Background()); err != nil || runtime.applies != 0 {
		t.Fatal("provider readiness created an installation")
	}
	for _, change := range []func(*adapterv1.DeprovisionRequest){
		func(r *adapterv1.DeprovisionRequest) { r.OfferingID = "another-product" },
		func(r *adapterv1.DeprovisionRequest) { r.EngineVersion = "8.18.0" },
		func(r *adapterv1.DeprovisionRequest) { r.RegionID = "another-region" },
	} {
		request := deletionFor(config.Request)
		change(&request)
		if err := provider.Delete(context.Background(), request); err == nil || runtime.stops != 0 {
			t.Fatal("another product's deletion profile was accepted")
		}
	}
	for name, change := range map[string]func(*adapterv1.ProvisionRequest){
		"tenant":   func(r *adapterv1.ProvisionRequest) { r.TenantID = "" },
		"instance": func(r *adapterv1.ProvisionRequest) { r.InstallationID = "" },
		"offering": func(r *adapterv1.ProvisionRequest) { r.OfferingID = "unreleased" },
		"version":  func(r *adapterv1.ProvisionRequest) { r.EngineVersion = "8.18.0" },
		"quota":    func(r *adapterv1.ProvisionRequest) { r.QuotaShape.MemoryMiB++ },
		"region":   func(r *adapterv1.ProvisionRequest) { r.RegionID = "another-region" },
		"unexpected dependency": func(r *adapterv1.ProvisionRequest) {
			r.Elasticsearch = requestFor("kibana").Elasticsearch
		},
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
	{
		request := config.Request
		request.OperationID = "operation-observe-again"
		request.QuotaShape.DisplayName = "A translated label"
		if observed, err := provider.Ensure(context.Background(), request); err != nil || observed != first || runtime.applies != 1 {
			t.Fatal("presentation metadata changed the deployed configuration")
		}
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
	binding, err := os.ReadFile(filepath.Join(runtime.project.Directory, "product-configuration.json"))
	if err != nil || bytes.Contains(binding, []byte("\"elasticsearch\"")) {
		t.Fatal("new optional dependency changed the existing Logstash binding shape")
	}
	if bytes.Contains(content, secret) || strings.Contains(first.Endpoint, string(secret)) {
		t.Fatal("credential escaped its protected file")
	}
	changed := config
	changed.ImageID = "sha256:" + strings.Repeat("b", 64)
	drifted, err := newLogstash(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drifted.Ensure(context.Background(), config.Request); err == nil || runtime.applies != 1 {
		t.Fatal("immutable image/configuration drift was applied")
	}
	badDelete := deletionFor(config.Request)
	badDelete.TenantID = "other-account"
	if err := provider.Delete(context.Background(), badDelete); err != nil || runtime.stops != 0 {
		t.Fatal("cross-tenant deletion reached runtime")
	}
	if err := provider.Delete(context.Background(), deletionFor(config.Request)); err != nil {
		t.Fatal(err)
	}
	if err := provider.Delete(context.Background(), deletionFor(config.Request)); err != nil || runtime.stops != 1 || runtime.purges != 1 {
		t.Fatal("equal deletion was not convergent")
	}
}

type recordingRuntime struct {
	containers             map[string][]compose.RuntimeContainer
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
			Ports  []string          `json:"ports"`
		} `json:"services"`
	}
	if json.Unmarshal(content, &doc) != nil || len(doc.Services) == 0 {
		return errors.New("invalid fixture document")
	}
	r.containers[p.Name] = nil
	for service, value := range doc.Services {
		r.containers[p.Name] = append(r.containers[p.Name], compose.RuntimeContainer{ID: p.Name + "-" + service, Project: p.Name, Service: service, State: "running", Health: "healthy", PublishedPorts: uint32(len(value.Ports)), Labels: value.Labels})
	}
	r.project = p
	r.applies++
	return nil
}
func (r *recordingRuntime) Observe(_ context.Context, p compose.RuntimeProject) ([]compose.RuntimeContainer, error) {
	if c, ok := r.containers[p.Name]; ok {
		return c, nil
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
