// Package localmysql installs the closed MySQL LTS offering on the local
// Docker host without accepting provider-native caller input.
package localmysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	document := map[string]any{
		"name":     input.ProjectName,
		"networks": privateNetworks(),
		"services": map[string]any{
			endpointServiceName: endpointService(endpointImageID, input.PublishedPort, labels),
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

func privateNetworks() map[string]any {
	return map[string]any{
		"private": map[string]any{
			"internal": true, "driver": "bridge", "enable_ipv6": false,
			"driver_opts": map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
		},
		// Keep Compose's implicit bridge configuration. Explicitly adding the
		// same driver changes its network hash; Compose would try to remove
		// the still-attached predecessor network before recreating MySQL.
		"default": map[string]any{},
	}
}

func endpointService(imageID string, port int, labels map[string]string) map[string]any {
	return map[string]any{
		"image": imageID, "pull_policy": "never", "restart": "unless-stopped",
		"entrypoint": []string{endpointBinary}, "command": []string{},
		"user": "65532:65532", "read_only": true, "pids_limit": 32,
		// The signed PaaS image inherits a Docker data VOLUME. Override it
		// with bounded tmpfs so this socket-free process creates no volume.
		"tmpfs":    []string{"/var/lib/docker:rw,noexec,nosuid,nodev,size=1m"},
		"networks": []string{"private", "default"},
		"ports":    []string{fmt.Sprintf("127.0.0.1:%d:13306/tcp", port)},
		"cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"},
		"sysctls":     map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"},
		"environment": map[string]string{"GOMAXPROCS": "1", "GOMEMLIMIT": "48MiB"},
		"depends_on":  map[string]any{mysqlServiceName: map[string]string{"condition": "service_healthy"}},
		"healthcheck": map[string]any{
			"test":     []string{"CMD", endpointBinary, "--check"},
			"interval": "5s", "timeout": "4s", "retries": 6,
		},
		"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{"cpus": "0.25", "memory": "64M", "pids": 32}}},
		"labels": labels,
	}
}

func validateRequest(request managedserviceadapterv1.ProvisionRequest) error {
	if request.OfferingID != managedservicev1.MySQLOfferingID ||
		request.EngineVersion != "8.4" || request.RegionID != "local-primary" {
		return errors.New("local MySQL installation profile is invalid")
	}
	return nil
}
