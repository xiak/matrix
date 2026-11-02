package managedserviceonboarding

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

// NewLogstash implements the closed http-json-file-v1 example. It accepts
// no caller Pipeline DSL, filesystem destination, plugin or command.
func NewLogstash(config InstallationConfig) (adapterv1.Provisioner, error) {
	return newInstallation(config, "logstash", func(input localcontainer.DocumentInput) ([]byte, error) {
		if err := commitConfiguration(input, "http-json-file-v1", nil); err != nil {
			return nil, err
		}
		secret, err := readProtectedSecret(input.CredentialPaths["logstash-secret"])
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
		if err := writeImmutable(pipelinePath, pipeline, 0o640); err != nil {
			return nil, err
		}
		settings := []byte("api.http.host: 127.0.0.1\napi.http.port: 9600\nxpack.monitoring.enabled: false\npipeline.workers: 1\npipeline.batch.size: 16\npipeline.ecs_compatibility: disabled\npath.data: /usr/share/logstash/data\n")
		settingsPath := filepath.Join(filepath.Dir(input.DataDirectory), "logstash.yml")
		if err := writeImmutable(settingsPath, settings, 0o640); err != nil {
			return nil, err
		}
		service := serviceDocument(input, "logstash", 8080)
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
		encoded, err := json.Marshal(map[string]any{"name": input.ProjectName, "services": map[string]any{"logstash": service}})
		if err != nil {
			return nil, errors.New("Logstash deployment cannot be encoded")
		}
		return encoded, nil
	})
}
