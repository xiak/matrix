// Package localredis owns the fixed authenticated Redis/AOF product.
// Shared container effects retain identity, credentials, data and exact cleanup.
package localredis

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const Version = "8.2.11"
const ConfigurationRevision = "authenticated-aof-v1"
const BusinessUser = "matrix"

// Config is trusted worker composition, never a tenant request.
type Config struct {
	Root            string
	ImageID         string
	EndpointImageID string
	Runtime         compose.Runtime
	NewSecret       func() ([]byte, error)
}

func New(config Config) (adapterv1.Provisioner, error) {
	if !regexp.MustCompile("^sha256:[0-9a-f]{64}$").MatchString(config.EndpointImageID) {
		return nil, errors.New("Redis requires an immutable endpoint image")
	}
	return localcontainer.New(localcontainer.Config{
		Root: config.Root, ImageID: config.ImageID, ServiceName: "redis", EndpointServiceName: "redis-endpoint",
		CredentialFiles:   []localcontainer.CredentialFile{{Name: "redis-password", Mode: 0o640}},
		DataDirectoryMode: os.ModeSticky | 0o777, Runtime: config.Runtime, NewSecret: config.NewSecret,
		ValidateRequest: validateRequest, ValidateDeletion: validateDeletion,
		CompileDocument: func(input localcontainer.DocumentInput) ([]byte, error) {
			return compileDocument(input, config.EndpointImageID)
		},
		Endpoint: func(port int) string { return fmt.Sprintf("redis://127.0.0.1:%d", port) },
	})
}

func validateRequest(request adapterv1.ProvisionRequest) error {
	if request.OfferingID != managedv1.RedisOfferingID || request.EngineVersion != Version || request.RegionID != "local-primary" {
		return errors.New("Redis profile is invalid")
	}
	shape := request.QuotaShape
	small := shape.ID == "redis-small" && shape.CPUMillicores == 500 && shape.MemoryMiB == 512 && shape.StorageGiB == 10
	medium := shape.ID == "redis-medium" && shape.CPUMillicores == 1000 && shape.MemoryMiB == 1024 && shape.StorageGiB == 20
	if small || medium {
		return nil
	}
	return errors.New("Redis quota shape is invalid")
}

func validateDeletion(request adapterv1.DeprovisionRequest) error {
	if request.OfferingID != managedv1.RedisOfferingID || request.EngineVersion != Version || request.RegionID != "local-primary" {
		return errors.New("Redis deletion profile is invalid")
	}
	return nil
}

func compileDocument(input localcontainer.DocumentInput, endpointImageID string) ([]byte, error) {
	directory := filepath.Dir(input.DataDirectory)
	request := input.Request
	request.OperationID = ""
	request.QuotaShape.DisplayName = ""
	binding, err := json.Marshal(struct {
		Revision, ImageID, EndpointImageID string
		Request                            adapterv1.ProvisionRequest
	}{ConfigurationRevision, input.ImageID, endpointImageID, request})
	if err != nil {
		return nil, errors.New("Redis configuration cannot be encoded")
	}
	if err := localcontainer.WriteImmutable(filepath.Join(directory, "product-configuration.json"), binding, 0o600); err != nil {
		return nil, err
	}
	credentialPath := input.CredentialPaths["redis-password"]
	credential, err := localcontainer.ReadProtectedSecret(credentialPath)
	if err != nil {
		return nil, err
	}
	defer clear(credential)
	groupID, present := input.CredentialGroupIDs["redis-password"]
	if !present && runtime.GOOS != "windows" {
		return nil, errors.New("Redis credential group is unavailable")
	}
	passwordDigest := sha256.Sum256(credential)
	acl := []byte(fmt.Sprintf("user default off\nuser %s reset on #%x ~* &* -@all +@read +@write +@connection +@transaction +@pubsub -@admin -@dangerous -@scripting +ping +info +waitaof\n", BusinessUser, passwordDigest))
	defer clear(acl)
	aclPath := filepath.Join(directory, "users.acl")
	if err := localcontainer.WriteImmutable(aclPath, acl, 0o640); err != nil {
		return nil, err
	}
	configuration := []byte(fmt.Sprintf("bind 0.0.0.0\nport 6379\nprotected-mode yes\ndaemonize no\npidfile \"\"\ndir /data\naclfile /run/matrix/users.acl\nappendonly yes\nappendfsync everysec\naof-load-truncated no\nsave \"\"\nmaxmemory %dmb\nmaxmemory-policy noeviction\nmaxclients 128\nlogfile \"\"\nenable-protected-configs no\nenable-debug-command no\nenable-module-command no\n", request.QuotaShape.MemoryMiB/2))
	configPath := filepath.Join(directory, "redis.conf")
	if err := localcontainer.WriteImmutable(configPath, configuration, 0o640); err != nil {
		return nil, err
	}
	labels := map[string]string{
		"com.xiak.matrix.managed":                     "true",
		"com.xiak.matrix.managedservice.installation": request.InstallationID,
		"com.xiak.matrix.managedservice.offering":     request.OfferingID,
		"com.xiak.matrix.managedservice.region":       request.RegionID,
	}
	mount := func(source, target string) map[string]any {
		return map[string]any{"type": "bind", "source": source, "target": target, "read_only": true}
	}
	encoded, err := json.Marshal(map[string]any{
		"name": input.ProjectName, "networks": localcontainer.PrivateNetworks(),
		"services": map[string]any{
			"redis-endpoint": localcontainer.EndpointService(endpointImageID, input.PublishedPort, "redis", 6379, labels),
			"redis": map[string]any{
				"image": input.ImageID, "pull_policy": "never", "restart": "unless-stopped",
				"user": "999:999", "group_add": []string{fmt.Sprint(groupID)},
				"read_only": true, "init": true, "networks": []string{"private"},
				"command":  []string{"redis-server", "/run/matrix/redis.conf"},
				"cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"},
				"mem_limit": fmt.Sprintf("%dm", request.QuotaShape.MemoryMiB), "cpus": localcontainer.FormatCPUs(request.QuotaShape.CPUMillicores),
				"pids_limit": 128, "tmpfs": []string{"/tmp:rw,noexec,nosuid,size=16m"},
				"volumes": []map[string]any{
					{"type": "bind", "source": input.DataDirectory, "target": "/data"},
					mount(configPath, "/run/matrix/redis.conf"), mount(aclPath, "/run/matrix/users.acl"),
					mount(credentialPath, "/run/secrets/redis-password"),
				},
				"healthcheck": map[string]any{
					"test":     []string{"CMD-SHELL", "REDISCLI_AUTH=$$(cat /run/secrets/redis-password) redis-cli --user matrix --no-auth-warning --raw PING | grep -qx PONG"},
					"interval": "2s", "timeout": "2s", "retries": 30, "start_period": "5s",
				},
				"labels": labels,
			},
		},
	})
	if err != nil {
		return nil, errors.New("Redis deployment cannot be encoded")
	}
	return encoded, nil
}
