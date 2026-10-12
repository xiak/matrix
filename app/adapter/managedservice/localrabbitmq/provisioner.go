// Package localrabbitmq installs the closed RabbitMQ offering on the local
// Docker host without accepting provider-native caller input.
package localrabbitmq

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

const rabbitMQServiceName = "rabbitmq"

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
		ServiceName: rabbitMQServiceName,
		CredentialFiles: []localcontaineradapter.CredentialFile{
			{Name: "rabbitmq-password", Mode: 0o600},
		},
		DataDirectoryMode: os.ModeSticky | 0o777,
		Runtime:           config.Runtime, ValidateRequest: validateRequest,
		CompileDocument: compileDocument,
		Endpoint: func(port int) string {
			return "amqp://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/matrix"
		},
		NewSecret: config.NewSecret,
	})
	if err != nil {
		return nil, errors.New("local RabbitMQ provisioner configuration is invalid")
	}
	return &Provisioner{provider: provider}, nil
}

func (provisioner *Provisioner) Ready(ctx context.Context) error {
	if provisioner == nil || provisioner.provider == nil {
		return errors.New("local RabbitMQ provisioner is unavailable")
	}
	return provisioner.provider.Ready(ctx)
}

func (provisioner *Provisioner) Ensure(
	ctx context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	if provisioner == nil || provisioner.provider == nil {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local RabbitMQ provisioner is unavailable")
	}
	return provisioner.provider.Ensure(ctx, request)
}

func (provisioner *Provisioner) Delete(
	ctx context.Context,
	request managedserviceadapterv1.DeprovisionRequest,
) error {
	if provisioner == nil || provisioner.provider == nil ||
		request.OfferingID != managedservicev1.RabbitMQOfferingID ||
		request.EngineVersion != "4.1.8" || request.RegionID != "local-primary" {
		return errors.New("local RabbitMQ deletion profile is invalid")
	}
	return provisioner.provider.Delete(ctx, request)
}

func compileDocument(input localcontaineradapter.DocumentInput) ([]byte, error) {
	request := input.Request
	document := map[string]any{
		"name": input.ProjectName,
		"services": map[string]any{
			rabbitMQServiceName: map[string]any{
				"image": input.ImageID, "pull_policy": "never", "restart": "unless-stopped",
				"hostname":  input.ProjectName,
				"read_only": false, "init": false, "pids_limit": 256,
				"environment": map[string]string{
					"RABBITMQ_DEFAULT_USER":               "matrix_service",
					"RABBITMQ_DEFAULT_VHOST":              "matrix",
					"RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS": "+S 2:2",
				},
				"command": []string{
					"sh", "-ec",
					`export RABBITMQ_DEFAULT_PASS="$$(cat /run/secrets/rabbitmq-password)"; exec docker-entrypoint.sh rabbitmq-server`,
				},
				"ports": []string{fmt.Sprintf("127.0.0.1:%d:5672/tcp", input.PublishedPort)},
				"volumes": []map[string]any{
					{"type": "bind", "source": input.DataDirectory, "target": "/var/lib/rabbitmq"},
					{"type": "bind", "source": input.CredentialPaths["rabbitmq-password"], "target": "/run/secrets/rabbitmq-password", "read_only": true},
				},
				"tmpfs":        []string{"/tmp:rw,noexec,nosuid,size=64m"},
				"security_opt": []string{"no-new-privileges:true"},
				"cap_drop":     []string{"ALL"},
				"cap_add":      []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"},
				"healthcheck": map[string]any{
					"test": []string{
						"CMD-SHELL",
						// A readiness probe must not start another Erlang VM under the
						// product's 0.5 CPU shape. The protocol gate below the provider
						// still proves authenticated AMQP publish and consume semantics.
						"bash -ec 'exec 3<>/dev/tcp/127.0.0.1/5672; exec 3>&-; exec 3<&-'",
					},
					"interval": "2s", "timeout": "5s", "retries": 60, "start_period": "20s",
				},
				"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{
					"cpus":   localcontaineradapter.FormatCPUs(request.QuotaShape.CPUMillicores),
					"memory": strconv.FormatUint(uint64(request.QuotaShape.MemoryMiB), 10) + "M",
					"pids":   256,
				}}},
				"labels": map[string]string{
					"com.xiak.matrix.managed":                     "true",
					"com.xiak.matrix.role":                        "managed-rabbitmq",
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
		return nil, errors.New("local RabbitMQ Compose document cannot be encoded")
	}
	return encoded, nil
}

func validateRequest(request managedserviceadapterv1.ProvisionRequest) error {
	if request.OfferingID != managedservicev1.RabbitMQOfferingID ||
		request.EngineVersion != "4.1.8" || request.RegionID != "local-primary" {
		return errors.New("local RabbitMQ installation profile is invalid")
	}
	return nil
}
