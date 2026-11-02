// Package locallogstash owns the closed HTTP JSON to durable-file product.
// Lifecycle, ownership, credentials and recovery use the shared Docker adapter.
package locallogstash

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const Version = "8.19.23"
const ConfigurationRevision = "http-json-file-v1"

type Config struct {
	Root            string
	ImageID         string
	EndpointImageID string
	Runtime         compose.Runtime
	NewSecret       func() ([]byte, error)
}

func New(config Config) (adapterv1.Provisioner, error) {
	if !regexp.MustCompile("^sha256:[0-9a-f]{64}$").MatchString(config.EndpointImageID) {
		return nil, errors.New("Logstash requires an immutable endpoint image")
	}
	return localcontainer.New(localcontainer.Config{
		Root: config.Root, ImageID: config.ImageID, ServiceName: "logstash", EndpointServiceName: "logstash-endpoint",
		CredentialFiles:   []localcontainer.CredentialFile{{Name: "logstash-secret", Mode: 0o640}},
		DataDirectoryMode: os.ModeSticky | 0o777, Runtime: config.Runtime, NewSecret: config.NewSecret,
		ValidateRequest: validateRequest, ValidateDeletion: validateDeletion,
		CompileDocument: func(input localcontainer.DocumentInput) ([]byte, error) {
			return compileDocument(input, config.EndpointImageID)
		},
		Endpoint: func(port int) string { return fmt.Sprintf("http://127.0.0.1:%d", port) },
	})
}

func compileDocument(input localcontainer.DocumentInput, endpointImageID string) ([]byte, error) {
	if err := bindConfiguration(input); err != nil {
		return nil, err
	}
	secret, err := localcontainer.ReadProtectedSecret(input.CredentialPaths["logstash-secret"])
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	pipeline := []byte(fmt.Sprintf(`input { http { host => "0.0.0.0" port => 8080 user => "matrix" password => %q codec => json } }
filter { mutate { remove_field => ["headers"] add_field => { "matrix_profile" => "http-json-file-v1" } } }
output { file { path => "/usr/share/logstash/data/events.jsonl" codec => json_lines flush_interval => 0 } }
`, secret))
	defer clear(pipeline)
	pipelinePath := filepath.Join(filepath.Dir(input.DataDirectory), "logstash.conf")
	if err := localcontainer.WriteImmutable(pipelinePath, pipeline, 0o640); err != nil {
		return nil, err
	}
	settings := []byte("api.http.host: 127.0.0.1\napi.http.port: 9600\nxpack.monitoring.enabled: false\npipeline.workers: 1\npipeline.batch.size: 16\npipeline.ecs_compatibility: disabled\npath.data: /usr/share/logstash/data\n")
	settingsPath := filepath.Join(filepath.Dir(input.DataDirectory), "logstash.yml")
	if err := localcontainer.WriteImmutable(settingsPath, settings, 0o640); err != nil {
		return nil, err
	}
	service := productService(input)
	service["environment"] = map[string]string{"LS_JAVA_OPTS": "-Xms512m -Xmx512m"}
	service["volumes"] = []map[string]any{
		mount(pipelinePath, "/usr/share/logstash/pipeline/logstash.conf", true),
		mount(settingsPath, "/usr/share/logstash/config/logstash.yml", true),
		mount(input.DataDirectory, "/usr/share/logstash/data", false),
	}
	service["healthcheck"] = map[string]any{
		// Pipeline metadata appears before the HTTP input has necessarily
		// bound its socket. Readiness also proves the protected input is
		// serving an authentication rejection, without producing an event.
		"test":     []string{"CMD-SHELL", `curl --max-time 1 --silent --fail http://127.0.0.1:9600/_node/pipelines/main >/dev/null && test "$(curl --max-time 1 --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8080/)" = 401`},
		"interval": "5s", "timeout": "3s", "retries": 30, "start_period": "30s",
	}
	encoded, err := json.Marshal(map[string]any{
		"name": input.ProjectName, "networks": localcontainer.PrivateNetworks(),
		"services": map[string]any{
			"logstash": service,
			"logstash-endpoint": localcontainer.EndpointService(
				endpointImageID, input.PublishedPort, "logstash", 8080, ownershipLabels(input.Request),
			),
		},
	})
	if err != nil {
		return nil, errors.New("Logstash deployment cannot be encoded")
	}
	return encoded, nil
}

func validateRequest(request adapterv1.ProvisionRequest) error {
	if request.OfferingID != managedv1.LogstashOfferingID || request.EngineVersion != Version || request.RegionID != "local-primary" {
		return errors.New("Logstash profile is invalid")
	}
	shape := request.QuotaShape
	small := shape.ID == "logstash-small" && shape.CPUMillicores == 1000 && shape.MemoryMiB == 1536 && shape.StorageGiB == 10
	medium := shape.ID == "logstash-medium" && shape.CPUMillicores == 2000 && shape.MemoryMiB == 3072 && shape.StorageGiB == 20
	if small || medium {
		return nil
	}
	return errors.New("Logstash quota shape is invalid")
}

func validateDeletion(request adapterv1.DeprovisionRequest) error {
	if request.OfferingID != managedv1.LogstashOfferingID || request.EngineVersion != Version || request.RegionID != "local-primary" {
		return errors.New("Logstash deletion profile is invalid")
	}
	return nil
}

func bindConfiguration(input localcontainer.DocumentInput) error {
	request := input.Request
	request.OperationID = ""
	request.QuotaShape.DisplayName = "" // Presentation does not change a deployed configuration.
	content, err := json.Marshal(struct {
		Revision, ImageID string
		Request           adapterv1.ProvisionRequest
	}{ConfigurationRevision, input.ImageID, request})
	if err != nil {
		return errors.New("Logstash configuration cannot be encoded")
	}
	return localcontainer.WriteImmutable(filepath.Join(filepath.Dir(input.DataDirectory), "product-configuration.json"), content, 0o600)
}

func ownershipLabels(request adapterv1.ProvisionRequest) map[string]string {
	return map[string]string{
		"com.xiak.matrix.managed":                     "true",
		"com.xiak.matrix.managedservice.installation": request.InstallationID,
		"com.xiak.matrix.managedservice.offering":     request.OfferingID,
		"com.xiak.matrix.managedservice.region":       request.RegionID,
	}
}

func productService(input localcontainer.DocumentInput) map[string]any {
	return map[string]any{
		"image": input.ImageID, "pull_policy": "never", "restart": "unless-stopped", "networks": []string{"private"},
		"mem_limit": fmt.Sprintf("%dm", input.Request.QuotaShape.MemoryMiB), "cpus": localcontainer.FormatCPUs(input.Request.QuotaShape.CPUMillicores),
		"pids_limit": 512, "cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"},
		"group_add": []string{fmt.Sprint(input.CredentialGroupIDs["logstash-secret"])}, "labels": ownershipLabels(input.Request),
	}
}

func mount(source, target string, readOnly bool) map[string]any {
	return map[string]any{"type": "bind", "source": source, "target": target, "read_only": readOnly}
}
