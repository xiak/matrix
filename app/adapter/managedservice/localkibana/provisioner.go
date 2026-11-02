// Package localkibana owns the closed Elasticsearch UI product. The authority
// supplies a typed dependency; this adapter owns its private route and custody.
package localkibana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"time"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const Version = "8.19.23"
const ConfigurationRevision = "elasticsearch-ui-v1"
const dependencyService = "kibana-elasticsearch-endpoint"

var imageIdentity = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
var errDependency = errors.New("Kibana dependency or protected custody is unavailable")

type Config struct {
	Root, ImageID, EndpointImageID          string
	ElasticsearchRoot, ElasticsearchImageID string
	Runtime                                 compose.Runtime
	// HTTPClient is a trusted test seam for the native dependency API. It is
	// never selected by the tenant request.
	HTTPClient *http.Client
	NewSecret  func() ([]byte, error)
}

type Provisioner struct {
	config   Config
	provider *localcontainer.Provisioner
}

func New(config Config) (*Provisioner, error) {
	if !imageIdentity.MatchString(config.ImageID) || !imageIdentity.MatchString(config.EndpointImageID) ||
		!imageIdentity.MatchString(config.ElasticsearchImageID) || config.Runtime == nil ||
		!filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || filepath.Base(config.Root) != "managed-kibana" ||
		!filepath.IsAbs(config.ElasticsearchRoot) || filepath.Clean(config.ElasticsearchRoot) != config.ElasticsearchRoot ||
		filepath.Base(config.ElasticsearchRoot) != "managed-elasticsearch" || filepath.Dir(config.Root) != filepath.Dir(config.ElasticsearchRoot) {
		return nil, errors.New("Kibana local dependency configuration is invalid")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if protectedDirectory(filepath.Dir(config.Root)) != nil || protectedDirectory(config.ElasticsearchRoot) != nil {
		return nil, errDependency
	}
	p := &Provisioner{config: config}
	provider, err := localcontainer.New(localcontainer.Config{
		Root: config.Root, ImageID: config.ImageID, Runtime: config.Runtime,
		ServiceName: "kibana", EndpointServiceName: "kibana-endpoint", DependencyServiceName: dependencyService,
		CredentialFiles:   []localcontainer.CredentialFile{{Name: "kibana-session-key", Mode: 0o640}},
		DataDirectoryMode: os.ModeSticky | 0o777, NewSecret: config.NewSecret,
		ValidateRequest: validateRequest, ValidateDeletion: validateDeletion,
		CompileDocument: p.compileDocument, PrepareConfiguration: p.prepareConfiguration, ReleaseDependencies: p.releaseDependency,
		Endpoint: func(port int) string { return fmt.Sprintf("http://127.0.0.1:%d", port) },
	})
	if err != nil {
		return nil, err
	}
	p.provider = provider
	return p, nil
}

func (p *Provisioner) Ready(ctx context.Context) error {
	if p == nil || p.provider == nil {
		return errors.New("Kibana provider is unavailable")
	}
	if err := protectedDirectory(p.config.ElasticsearchRoot); err != nil {
		return err
	}
	return p.provider.Ready(ctx)
}

func (p *Provisioner) Ensure(ctx context.Context, request adapterv1.ProvisionRequest) (adapterv1.ProvisionResult, error) {
	if p == nil || adapterv1.ValidateProvisionRequest(request) != nil || validateRequest(request) != nil {
		return adapterv1.ProvisionResult{}, errors.New("Kibana provisioning identity is invalid")
	}
	lock, err := compose.AcquireProjectLock(ctx, filepath.Dir(p.config.Root), localcontainer.ProjectName(request.TenantID, request.InstallationID))
	if err != nil {
		return adapterv1.ProvisionResult{}, errors.New("Kibana project custody is unavailable")
	}
	defer lock.Close()
	return p.provider.Ensure(ctx, request)
}

func (p *Provisioner) Delete(ctx context.Context, request adapterv1.DeprovisionRequest) error {
	if p == nil || adapterv1.ValidateDeprovisionRequest(request) != nil || validateDeletion(request) != nil {
		return errors.New("Kibana deletion identity is invalid")
	}
	lock, err := compose.AcquireProjectLock(ctx, filepath.Dir(p.config.Root), localcontainer.ProjectName(request.TenantID, request.InstallationID))
	if err != nil {
		return errors.New("Kibana project custody is unavailable")
	}
	defer lock.Close()
	if err := p.validateBoundDeletion(request); err != nil {
		return err
	}
	return p.provider.Delete(ctx, request)
}

func (p *Provisioner) validateBoundDeletion(request adapterv1.DeprovisionRequest) error {
	directory := filepath.Join(p.config.Root, localcontainer.ProjectName(request.TenantID, request.InstallationID))
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if protectedDirectory(directory) != nil {
		return errDependency
	}
	content, err := readPrivate(filepath.Join(directory, "product-configuration.json"), 0o600, 65536)
	if err != nil {
		return err
	}
	var binding struct {
		Revision, ImageID, ElasticsearchImageID string
		Request                                 adapterv1.ProvisionRequest
	}
	if json.Unmarshal(content, &binding) != nil || binding.Revision != ConfigurationRevision || binding.ImageID != p.config.ImageID ||
		binding.ElasticsearchImageID != p.config.ElasticsearchImageID || binding.Request.Elasticsearch == nil || request.Elasticsearch == nil ||
		binding.Request.TenantID != request.TenantID || binding.Request.InstallationID != request.InstallationID ||
		binding.Request.OfferingID != request.OfferingID || binding.Request.EngineVersion != request.EngineVersion || binding.Request.RegionID != request.RegionID ||
		*binding.Request.Elasticsearch != *request.Elasticsearch {
		return errDependency
	}
	return nil
}

func validateRequest(request adapterv1.ProvisionRequest) error {
	if request.OfferingID != managedv1.KibanaOfferingID || request.EngineVersion != Version || request.RegionID != "local-primary" || request.Elasticsearch == nil {
		return errors.New("Kibana product profile is invalid")
	}
	shape := request.QuotaShape
	small := shape.ID == "kibana-small" && shape.CPUMillicores == 1000 && shape.MemoryMiB == 1536 && shape.StorageGiB == 10
	medium := shape.ID == "kibana-medium" && shape.CPUMillicores == 2000 && shape.MemoryMiB == 3072 && shape.StorageGiB == 20
	if !small && !medium {
		return errors.New("Kibana quota shape is invalid")
	}
	return nil
}

func validateDeletion(request adapterv1.DeprovisionRequest) error {
	if request.OfferingID != managedv1.KibanaOfferingID || request.EngineVersion != Version || request.RegionID != "local-primary" || request.Elasticsearch == nil {
		return errors.New("Kibana deletion profile is invalid")
	}
	return nil
}

func (p *Provisioner) compileDocument(input localcontainer.DocumentInput) ([]byte, error) {
	if err := p.bindConfiguration(input); err != nil {
		return nil, err
	}
	group, available := input.CredentialGroupIDs["kibana-session-key"]
	if runtime.GOOS == "linux" && !available {
		return nil, errors.New("Kibana credential group is unavailable")
	}
	groups := []string{}
	if available {
		groups = append(groups, strconv.FormatUint(uint64(group), 10))
	}
	labels := ownershipLabels(input.Request)
	relay := localcontainer.EndpointService(p.config.EndpointImageID, input.PublishedPort, "elasticsearch", 9200, labels)
	delete(relay, "ports")
	delete(relay, "depends_on")
	relay["networks"] = []string{"private", "dependency"}
	networks := localcontainer.PrivateNetworks()
	networks["dependency"] = map[string]any{"external": true, "name": localcontainer.ProjectName(input.Request.TenantID, input.Request.Elasticsearch.InstallationID) + "_private"}
	service := map[string]any{
		"image": input.ImageID, "pull_policy": "never", "restart": "unless-stopped",
		"read_only": false, "init": false, "pids_limit": 512, "cap_drop": []string{"ALL"},
		"security_opt": []string{"no-new-privileges:true"}, "group_add": groups,
		"networks": []string{"private"}, "environment": map[string]string{"NODE_OPTIONS": "--max-old-space-size=1024"},
		"depends_on": map[string]any{dependencyService: map[string]string{"condition": "service_healthy"}},
		"volumes": []map[string]any{
			{"type": "bind", "source": filepath.Join(filepath.Dir(input.DataDirectory), "kibana.yml"), "target": "/usr/share/kibana/config/kibana.yml", "read_only": true},
			{"type": "bind", "source": input.DataDirectory, "target": "/usr/share/kibana/data"},
		},
		"healthcheck": map[string]any{
			"test": []string{"CMD", "/usr/share/kibana/node/glibc-217/bin/node", "-e",
				"const http=require('http');const req=http.get('http://127.0.0.1:5601/api/status?v8format=true',r=>{let b='';r.on('data',d=>{b+=d;if(b.length>1048576)req.destroy()});r.on('end',()=>{try{process.exit(r.statusCode===200&&JSON.parse(b).status.overall.level==='available'?0:1)}catch{process.exit(1)}})});req.on('error',()=>process.exit(1));req.setTimeout(2000,()=>{req.destroy();process.exit(1)});"},
			"interval": "5s", "timeout": "3s", "retries": 40, "start_period": "30s",
		},
		"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{
			"cpus":   localcontainer.FormatCPUs(input.Request.QuotaShape.CPUMillicores),
			"memory": strconv.FormatUint(uint64(input.Request.QuotaShape.MemoryMiB), 10) + "M", "pids": 512,
		}}},
		"labels": labels,
	}
	return json.Marshal(map[string]any{"name": input.ProjectName, "networks": networks, "services": map[string]any{
		"kibana": service, dependencyService: relay,
		"kibana-endpoint": localcontainer.EndpointService(p.config.EndpointImageID, input.PublishedPort, "kibana", 5601, labels),
	}})
}

func (p *Provisioner) bindConfiguration(input localcontainer.DocumentInput) error {
	request := input.Request
	request.OperationID = ""
	request.QuotaShape.DisplayName = ""
	content, err := json.Marshal(struct {
		Revision, ImageID, ElasticsearchImageID string
		Request                                 adapterv1.ProvisionRequest
	}{ConfigurationRevision, input.ImageID, p.config.ElasticsearchImageID, request})
	if err != nil {
		return errors.New("Kibana binding cannot be encoded")
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

func protectedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
		return errDependency
	}
	return nil
}
