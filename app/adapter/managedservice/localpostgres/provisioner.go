// Package localpostgres installs the one closed PostgreSQL offering on the
// local Docker host without accepting provider-native caller input.
package localpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontaineradapter "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const postgresServiceName = "postgres"

type Config struct {
	Root      string
	ImageID   string
	Runtime   composeadapter.Runtime
	NewSecret func() ([]byte, error)
}

type Provisioner struct {
	provider *localcontaineradapter.Provisioner
}

func New(config Config) (*Provisioner, error) {
	provider, err := localcontaineradapter.New(localcontaineradapter.Config{
		Root: config.Root, ImageID: config.ImageID,
		ServiceName: postgresServiceName,
		CredentialFiles: []localcontaineradapter.CredentialFile{
			{Name: "postgres-password", Mode: 0o600},
		},
		DataDirectoryMode: os.ModeSticky | 0o777,
		Runtime:           config.Runtime, ValidateRequest: validateRequest,
		CompileDocument: compileDocument,
		Endpoint: func(port int) string {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		},
		NewSecret: config.NewSecret,
	})
	if err != nil {
		return nil, errors.New("local PostgreSQL provisioner configuration is invalid")
	}
	return &Provisioner{provider: provider}, nil
}

func (provisioner *Provisioner) Ready(ctx context.Context) error {
	if provisioner == nil || provisioner.provider == nil {
		return errors.New("local PostgreSQL provisioner is unavailable")
	}
	return provisioner.provider.Ready(ctx)
}

func (provisioner *Provisioner) Ensure(
	ctx context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	if provisioner == nil || provisioner.provider == nil {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local PostgreSQL provisioner is unavailable")
	}
	return provisioner.provider.Ensure(ctx, request)
}

func compileDocument(input localcontaineradapter.DocumentInput) ([]byte, error) {
	request := input.Request
	document := map[string]any{
		"name": input.ProjectName,
		"services": map[string]any{
			postgresServiceName: map[string]any{
				"image": input.ImageID, "pull_policy": "never", "restart": "unless-stopped",
				"read_only": false, "init": false, "pids_limit": 192,
				"environment": map[string]string{
					"POSTGRES_DB": "service", "POSTGRES_USER": "matrix_service",
					"POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
				},
				"ports": []string{fmt.Sprintf("127.0.0.1:%d:5432/tcp", input.PublishedPort)},
				"volumes": []map[string]any{
					{"type": "bind", "source": input.DataDirectory, "target": "/var/lib/postgresql"},
					{"type": "bind", "source": input.CredentialPaths["postgres-password"], "target": "/run/secrets/postgres-password", "read_only": true},
				},
				"tmpfs":        []string{"/tmp:rw,noexec,nosuid,size=64m", "/var/run/postgresql:rw,nosuid,size=16m"},
				"security_opt": []string{"no-new-privileges:true"},
				"cap_drop":     []string{"ALL"},
				"cap_add":      []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"},
				"healthcheck": map[string]any{
					"test":     []string{"CMD", "pg_isready", "-h", "127.0.0.1", "-U", "matrix_service", "-d", "service"},
					"interval": "2s", "timeout": "2s", "retries": 30, "start_period": "5s",
				},
				"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{
					"cpus":   localcontaineradapter.FormatCPUs(request.QuotaShape.CPUMillicores),
					"memory": strconv.FormatUint(uint64(request.QuotaShape.MemoryMiB), 10) + "M",
					"pids":   192,
				}}},
				"labels": map[string]string{
					"com.xiak.matrix.managed":                     "true",
					"com.xiak.matrix.role":                        "managed-postgresql",
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
		return nil, errors.New("local PostgreSQL Compose document cannot be encoded")
	}
	return encoded, nil
}

func validateRequest(request managedserviceadapterv1.ProvisionRequest) error {
	if request.OfferingID != managedservicev1.PostgreSQLOfferingID ||
		request.EngineVersion != "18" || request.RegionID != "local-primary" {
		return errors.New("local PostgreSQL installation profile is invalid")
	}
	return nil
}

func projectName(tenantID, installationID string) string {
	return localcontaineradapter.ProjectName(tenantID, installationID)
}
