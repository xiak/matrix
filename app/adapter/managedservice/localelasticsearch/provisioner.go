// Package localelasticsearch installs the closed Elasticsearch offering on
// the local Docker host without accepting provider-native caller input.
package localelasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontaineradapter "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const elasticsearchServiceName = "elasticsearch"
const endpointServiceName = "elasticsearch-endpoint"

const minimumVirtualMemoryMapCount uint64 = 1048576

type Config struct {
	Root            string
	ImageID         string
	EndpointImageID string
	Runtime         composeadapter.Runtime
	NewSecret       func() ([]byte, error)
}

type Provisioner struct {
	provider *localcontaineradapter.Provisioner
	config   Config
}

func New(config Config) (*Provisioner, error) {
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(config.EndpointImageID) {
		return nil, errors.New("local Elasticsearch requires an immutable endpoint image")
	}
	provider, err := localcontaineradapter.New(localcontaineradapter.Config{
		Root: config.Root, ImageID: config.ImageID,
		ServiceName:         elasticsearchServiceName,
		EndpointServiceName: endpointServiceName,
		CredentialFiles: []localcontaineradapter.CredentialFile{
			// The upstream image runs as uid 1000, gid 0. The owning project
			// directory remains 0700 while this one bind-mounted source is
			// group-readable by that fixed container identity.
			{Name: "elasticsearch-password", Mode: 0o640},
		},
		DataDirectoryMode: os.ModeSticky | 0o777,
		Runtime:           config.Runtime, ValidateRequest: validateRequest,
		CompileDocument: func(input localcontaineradapter.DocumentInput) ([]byte, error) {
			return compileDocument(input, config.EndpointImageID)
		},
		Endpoint: func(port int) string {
			return "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		},
		NewSecret: config.NewSecret,
	})
	if err != nil {
		return nil, errors.New("local Elasticsearch provisioner configuration is invalid")
	}
	return &Provisioner{provider: provider, config: config}, nil
}

func (provisioner *Provisioner) Ready(ctx context.Context) error {
	if provisioner == nil || provisioner.provider == nil {
		return errors.New("local Elasticsearch provisioner is unavailable")
	}
	if err := provisioner.provider.Ready(ctx); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("local Elasticsearch host is unsupported")
	}
	content, err := os.ReadFile("/proc/sys/vm/max_map_count")
	if err != nil || validateVirtualMemoryMapCount(content) != nil {
		return errors.New("local Elasticsearch host virtual memory limit is unavailable")
	}
	return nil
}

func validateVirtualMemoryMapCount(content []byte) error {
	value, err := strconv.ParseUint(strings.TrimSpace(string(content)), 10, 64)
	if err != nil || value < minimumVirtualMemoryMapCount {
		return errors.New("Elasticsearch virtual memory map count is too low")
	}
	return nil
}

func (provisioner *Provisioner) Ensure(
	ctx context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	if provisioner == nil || provisioner.provider == nil {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local Elasticsearch provisioner is unavailable")
	}
	return provisioner.provider.Ensure(ctx, request)
}

func (provisioner *Provisioner) Delete(
	ctx context.Context,
	request managedserviceadapterv1.DeprovisionRequest,
) error {
	if provisioner == nil || provisioner.provider == nil ||
		request.OfferingID != managedservicev1.ElasticsearchOfferingID ||
		request.EngineVersion != "8.19.23" || request.RegionID != "local-primary" {
		return errors.New("local Elasticsearch deletion profile is invalid")
	}
	return provisioner.provider.Delete(ctx, request)
}

// UpgradeNetwork preserves installed Elasticsearch state while moving its
// direct-port predecessor behind a private per-instance network.
func (provisioner *Provisioner) UpgradeNetwork(ctx context.Context) error {
	if provisioner == nil {
		return errors.New("local Elasticsearch provisioner is unavailable")
	}
	config := provisioner.config
	return localcontaineradapter.UpgradeNetwork(ctx, localcontaineradapter.NetworkUpgrade{
		Root: config.Root, Runtime: config.Runtime,
		ServiceName: elasticsearchServiceName, EndpointServiceName: endpointServiceName,
		OfferingID: managedservicev1.ElasticsearchOfferingID, TargetPort: 9200,
		Mounts: map[string]string{"/usr/share/elasticsearch/data": "data", "/run/secrets/elasticsearch-password-source": "elasticsearch-password"},
		Endpoint: func(port int, labels map[string]string) map[string]any {
			return localcontaineradapter.EndpointService(config.EndpointImageID, port, elasticsearchServiceName, 9200, labels)
		},
	})
}

func compileDocument(input localcontaineradapter.DocumentInput, endpointImageID string) ([]byte, error) {
	request := input.Request
	credentialGroupID, hasCredentialGroup := input.CredentialGroupIDs["elasticsearch-password"]
	if runtime.GOOS == "linux" && !hasCredentialGroup {
		return nil, errors.New("local Elasticsearch credential group is unavailable")
	}
	groupAdd := make([]string, 0, 1)
	if hasCredentialGroup {
		groupAdd = []string{strconv.FormatUint(uint64(credentialGroupID), 10)}
	}
	document := map[string]any{
		"name":     input.ProjectName,
		"networks": localcontaineradapter.PrivateNetworks(),
		"services": map[string]any{
			endpointServiceName: localcontaineradapter.EndpointService(endpointImageID, input.PublishedPort, elasticsearchServiceName, 9200, map[string]string{
				"com.xiak.matrix.managed":                     "true",
				"com.xiak.matrix.managedservice.installation": request.InstallationID,
				"com.xiak.matrix.managedservice.offering":     request.OfferingID,
				"com.xiak.matrix.managedservice.region":       request.RegionID,
			}),
			elasticsearchServiceName: map[string]any{
				"image": input.ImageID, "pull_policy": "never", "restart": "unless-stopped",
				"read_only": false, "init": false, "pids_limit": 384,
				"group_add": groupAdd,
				"environment": map[string]string{
					"discovery.type":                                        "single-node",
					"xpack.security.enabled":                                "true",
					"xpack.security.enrollment.enabled":                     "false",
					"xpack.security.http.ssl.enabled":                       "false",
					"xpack.ml.enabled":                                      "false",
					"cluster.routing.allocation.disk.watermark.low":         "5gb",
					"cluster.routing.allocation.disk.watermark.high":        "3gb",
					"cluster.routing.allocation.disk.watermark.flood_stage": "2gb",
					"ELASTIC_PASSWORD_FILE":                                 "/tmp/matrix-elasticsearch-password",
				},
				"command": []string{
					"bash", "-ec",
					`cp /run/secrets/elasticsearch-password-source /tmp/matrix-elasticsearch-password; chmod 600 /tmp/matrix-elasticsearch-password; exec /usr/local/bin/docker-entrypoint.sh eswrapper`,
				},
				"networks": []string{"private"},
				"volumes": []map[string]any{
					{"type": "bind", "source": input.DataDirectory, "target": "/usr/share/elasticsearch/data"},
					{"type": "bind", "source": input.CredentialPaths["elasticsearch-password"], "target": "/run/secrets/elasticsearch-password-source", "read_only": true},
				},
				"tmpfs":        []string{"/tmp:rw,nosuid,size=128m"},
				"security_opt": []string{"no-new-privileges:true"},
				"cap_drop":     []string{"ALL"},
				"healthcheck": map[string]any{
					"test":     []string{"CMD-SHELL", `response="$$(curl --fail --silent --user "elastic:$$(cat /tmp/matrix-elasticsearch-password)" "http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=2s")"; printf '%s' "$${response}" | grep -q '"timed_out":false'`},
					"interval": "2s", "timeout": "3s", "retries": 90, "start_period": "30s",
				},
				"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{
					"cpus":   localcontaineradapter.FormatCPUs(request.QuotaShape.CPUMillicores),
					"memory": strconv.FormatUint(uint64(request.QuotaShape.MemoryMiB), 10) + "M",
					"pids":   384,
				}}},
				"labels": map[string]string{
					"com.xiak.matrix.managed":                     "true",
					"com.xiak.matrix.role":                        "managed-elasticsearch",
					"com.xiak.matrix.managedservice.installation": request.InstallationID,
					"com.xiak.matrix.managedservice.offering":     request.OfferingID,
					"com.xiak.matrix.managedservice.region":       request.RegionID,
					"com.xiak.matrix.managedservice.storage-gib":  strconv.FormatUint(uint64(request.QuotaShape.StorageGiB), 10),
				},
			},
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("local Elasticsearch Compose document cannot be encoded")
	}
	return encoded, nil
}

func validateRequest(request managedserviceadapterv1.ProvisionRequest) error {
	if request.OfferingID != managedservicev1.ElasticsearchOfferingID ||
		request.EngineVersion != "8.19.23" || request.RegionID != "local-primary" {
		return errors.New("local Elasticsearch installation profile is invalid")
	}
	return nil
}
