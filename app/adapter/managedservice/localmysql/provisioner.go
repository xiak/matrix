// Package localmysql installs the closed MySQL LTS offering on the local
// Docker host without accepting provider-native caller input.
package localmysql

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"strconv"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontaineradapter "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const mysqlServiceName = "mysql"
const endpointServiceName = "mysql-endpoint"
const endpointBinary = "/matrix/bin/matrix-mysql-endpoint"

type Config struct {
	Root            string
	ImageID         string
	EndpointImageID string
	Runtime         composeadapter.Runtime
	NewSecret       func() ([]byte, error)
}

type Provisioner struct {
	provider        *localcontaineradapter.Provisioner
	root            string
	endpointImageID string
	runtime         composeadapter.Runtime
}

func New(config Config) (*Provisioner, error) {
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(config.EndpointImageID) {
		return nil, errors.New("local MySQL requires an immutable trusted endpoint image")
	}
	provider, err := localcontaineradapter.New(localcontaineradapter.Config{
		Root: config.Root, ImageID: config.ImageID,
		ServiceName:         mysqlServiceName,
		EndpointServiceName: endpointServiceName,
		CredentialFiles: []localcontaineradapter.CredentialFile{
			{Name: "mysql-password", Mode: 0o600},
			{Name: "mysql-root-password", Mode: 0o600},
		},
		DataDirectoryMode: os.ModeSticky | 0o777,
		Runtime:           config.Runtime, ValidateRequest: validateRequest,
		CompileDocument: func(input localcontaineradapter.DocumentInput) ([]byte, error) {
			return compileDocument(input, config.EndpointImageID)
		},
		Endpoint: func(port int) string {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		},
		NewSecret: config.NewSecret,
	})
	if err != nil {
		return nil, errors.New("local MySQL provisioner configuration is invalid")
	}
	return &Provisioner{provider: provider, root: config.Root, endpointImageID: config.EndpointImageID, runtime: config.Runtime}, nil
}

func (provisioner *Provisioner) Ready(ctx context.Context) error {
	if provisioner == nil || provisioner.provider == nil {
		return errors.New("local MySQL provisioner is unavailable")
	}
	return provisioner.provider.Ready(ctx)
}

func (provisioner *Provisioner) Ensure(
	ctx context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	if provisioner == nil || provisioner.provider == nil {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local MySQL provisioner is unavailable")
	}
	return provisioner.provider.Ensure(ctx, request)
}

func (provisioner *Provisioner) Delete(
	ctx context.Context,
	request managedserviceadapterv1.DeprovisionRequest,
) error {
	if provisioner == nil || provisioner.provider == nil ||
		request.OfferingID != managedservicev1.MySQLOfferingID ||
		request.EngineVersion != "8.4" || request.RegionID != "local-primary" {
		return errors.New("local MySQL deletion profile is invalid")
	}
	return provisioner.provider.Delete(ctx, request)
}

func compileDocument(input localcontaineradapter.DocumentInput, endpointImageID string) ([]byte, error) {
	request := input.Request
	labels := map[string]string{
		"com.xiak.matrix.managed":                     "true",
		"com.xiak.matrix.managedservice.installation": request.InstallationID,
		"com.xiak.matrix.managedservice.offering":     request.OfferingID,
		"com.xiak.matrix.managedservice.region":       request.RegionID,
	}
	endpoint := endpointService(endpointImageID, input.PublishedPort, labels)
	document := map[string]any{
		"name":     input.ProjectName,
		"networks": localcontaineradapter.PrivateNetworks(),
		"services": map[string]any{
			endpointServiceName: endpoint,
			mysqlServiceName: map[string]any{
				"image": input.ImageID, "pull_policy": "never", "restart": "unless-stopped",
				"read_only": false, "init": false, "pids_limit": 192,
				"environment": map[string]string{
					"MYSQL_DATABASE":           "service",
					"MYSQL_USER":               "matrix_service",
					"MYSQL_PASSWORD_FILE":      "/run/secrets/mysql-password",
					"MYSQL_ROOT_PASSWORD_FILE": "/run/secrets/mysql-root-password",
					"MYSQL_LOG_CONSOLE":        "true",
				},
				"networks": []string{"private"},
				"volumes": []map[string]any{
					{"type": "bind", "source": input.DataDirectory, "target": "/var/lib/mysql"},
					{"type": "bind", "source": input.CredentialPaths["mysql-password"], "target": "/run/secrets/mysql-password", "read_only": true},
					{"type": "bind", "source": input.CredentialPaths["mysql-root-password"], "target": "/run/secrets/mysql-root-password", "read_only": true},
				},
				"tmpfs":        []string{"/tmp:rw,noexec,nosuid,size=64m", "/var/run/mysqld:rw,nosuid,size=16m"},
				"security_opt": []string{"no-new-privileges:true"},
				"cap_drop":     []string{"ALL"},
				"cap_add":      []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"},
				"healthcheck": map[string]any{
					"test":     []string{"CMD-SHELL", `mysqladmin ping -h 127.0.0.1 -u matrix_service --password="$$(cat /run/secrets/mysql-password)" --silent`},
					"interval": "2s", "timeout": "3s", "retries": 60, "start_period": "20s",
				},
				"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{
					"cpus":   localcontaineradapter.FormatCPUs(request.QuotaShape.CPUMillicores),
					"memory": strconv.FormatUint(uint64(request.QuotaShape.MemoryMiB), 10) + "M",
					"pids":   192,
				}}},
				"labels": map[string]string{
					"com.xiak.matrix.managed":                     "true",
					"com.xiak.matrix.role":                        "managed-mysql",
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
		return nil, errors.New("local MySQL Compose document cannot be encoded")
	}
	return encoded, nil
}

func validateRequest(request managedserviceadapterv1.ProvisionRequest) error {
	if request.OfferingID != managedservicev1.MySQLOfferingID ||
		request.EngineVersion != "8.4" || request.RegionID != "local-primary" {
		return errors.New("local MySQL installation profile is invalid")
	}
	return nil
}

func endpointService(imageID string, port int, labels map[string]string) map[string]any {
	// Existing installed releases carry this entrypoint. Keep the authenticated
	// MySQL deployment document stable while sharing the endpoint implementation.
	endpoint := localcontaineradapter.EndpointService(imageID, port, mysqlServiceName, 3306, labels)
	endpoint["entrypoint"] = []string{endpointBinary}
	endpoint["command"] = []string{}
	endpoint["healthcheck"].(map[string]any)["test"] = []string{"CMD", endpointBinary, "--check"}
	return endpoint
}
