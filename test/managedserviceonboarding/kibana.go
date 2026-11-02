package managedserviceonboarding

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

// ElasticsearchDependency is resolved by trusted test composition. A production
// integration must resolve an authorized current object and immutable credential
// reference; this structure is not a tenant-facing API or an IAM decision.
type ElasticsearchDependency struct {
	TenantID       string
	InstallationID string
	EngineVersion  string
	Revision       uint64
	Network        string
	Endpoint       string
	PasswordFile   string
}

var fixtureNetwork = regexp.MustCompile(`^matrix-onboarding-[a-z0-9-]{1,48}$`)

// NewKibana implements elasticsearch-ui-v1 with one immutable same-tenant
// dependency. It never uses the Elasticsearch administrator as its server user.
func NewKibana(config InstallationConfig, dependency ElasticsearchDependency) (adapterv1.Provisioner, error) {
	if dependency.TenantID != config.Request.TenantID ||
		managedv1.ValidateInstallationID(dependency.InstallationID) != nil ||
		dependency.EngineVersion != Version || dependency.Revision != 1 ||
		!fixtureNetwork.MatchString(dependency.Network) || dependency.Endpoint != "http://elasticsearch:9200" {
		return nil, errors.New("Kibana dependency binding is invalid")
	}
	credential, err := localcontainer.ReadProtectedSecret(dependency.PasswordFile)
	clear(credential)
	if err != nil {
		return nil, err
	}
	return newInstallation(config, "kibana", func(input localcontainer.DocumentInput) ([]byte, error) {
		if err := commitConfiguration(input, "elasticsearch-ui-v1", dependency); err != nil {
			return nil, err
		}
		password, err := localcontainer.ReadProtectedSecret(dependency.PasswordFile)
		if err != nil {
			return nil, err
		}
		defer clear(password)
		encryptionKey, err := localcontainer.ReadProtectedSecret(input.CredentialPaths["kibana-secret"])
		if err != nil {
			return nil, err
		}
		defer clear(encryptionKey)
		settings, err := json.Marshal(map[string]any{
			"server.host": "0.0.0.0", "server.port": 5601,
			"elasticsearch.hosts":    []string{dependency.Endpoint},
			"elasticsearch.username": "kibana_system", "elasticsearch.password": string(password),
			"xpack.security.encryptionKey":              string(encryptionKey),
			"xpack.encryptedSavedObjects.encryptionKey": string(encryptionKey),
			"xpack.reporting.encryptionKey":             string(encryptionKey),
			"telemetry.enabled":                         false, "newsfeed.enabled": false,
			"xpack.fleet.isAirGapped": true, "xpack.fleet.registryUrl": "http://127.0.0.1:1",
			"status.allowAnonymous": true,
		})
		if err != nil {
			return nil, errors.New("Kibana settings cannot be encoded")
		}
		defer clear(settings)
		settingsPath := filepath.Join(filepath.Dir(input.DataDirectory), "kibana.yml")
		if err := localcontainer.WriteImmutable(settingsPath, settings, 0o640); err != nil {
			return nil, err
		}
		service := serviceDocument(input, "kibana", 5601)
		service["environment"] = map[string]string{"NODE_OPTIONS": "--max-old-space-size=1024"}
		service["volumes"] = []map[string]any{
			mount(settingsPath, "/usr/share/kibana/config/kibana.yml", true),
			mount(input.DataDirectory, "/usr/share/kibana/data", false),
		}
		// Docker suppresses host publication for an internal-only network.
		// Keep the product's own network for the loopback endpoint and attach
		// the existing internal dependency network without taking ownership.
		service["networks"] = []string{"default", "dependency"}
		service["healthcheck"] = map[string]any{
			"test": []string{"CMD", "/usr/share/kibana/node/glibc-217/bin/node", "-e",
				`const http=require('http');const req=http.get('http://127.0.0.1:5601/api/status?v8format=true',r=>{let b='';r.on('data',d=>{b+=d;if(b.length>1048576)req.destroy()});r.on('end',()=>{try{process.exit(r.statusCode===200&&JSON.parse(b).status.overall.level==='available'?0:1)}catch{process.exit(1)}})});req.on('error',()=>process.exit(1));req.setTimeout(2000,()=>{req.destroy();process.exit(1)});`},
			"interval": "5s", "timeout": "3s", "retries": 40, "start_period": "30s",
		}
		encoded, err := json.Marshal(map[string]any{
			"name": input.ProjectName, "services": map[string]any{"kibana": service},
			"networks": map[string]any{"default": map[string]any{}, "dependency": map[string]any{"external": true, "name": dependency.Network}},
		})
		if err != nil {
			return nil, errors.New("Kibana deployment cannot be encoded")
		}
		return encoded, nil
	})
}
