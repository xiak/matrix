// Package managedserviceonboarding contains executable product-team examples.
// These providers are deliberately absent from the released catalog and worker.
package managedserviceonboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	adapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedv1 "github.com/xiak/matrix/api/managedservice/v1"
	compose "github.com/xiak/matrix/app/adapter/apphosting/compose"
	localcontainer "github.com/xiak/matrix/app/adapter/managedservice/localcontainer"
)

const Version = "8.19.23"

// InstallationConfig is trusted composition input, never a tenant wire body.
// Request is resolved from accepted authority facts before constructing a provider.
type InstallationConfig struct {
	Root    string
	ImageID string
	Runtime compose.Runtime
	Request adapterv1.ProvisionRequest
}

type installation struct {
	expected adapterv1.ProvisionRequest
	provider *localcontainer.Provisioner
}

var _ adapterv1.Provisioner = (*installation)(nil)

func (p *installation) Ready(ctx context.Context) error { return p.provider.Ready(ctx) }
func (p *installation) Ensure(ctx context.Context, request adapterv1.ProvisionRequest) (adapterv1.ProvisionResult, error) {
	return p.provider.Ensure(ctx, request)
}
func (p *installation) Delete(ctx context.Context, request adapterv1.DeprovisionRequest) error {
	if adapterv1.ValidateDeprovisionRequest(request) != nil ||
		request.TenantID != p.expected.TenantID || request.InstallationID != p.expected.InstallationID ||
		request.OfferingID != p.expected.OfferingID || request.EngineVersion != p.expected.EngineVersion ||
		request.RegionID != p.expected.RegionID {
		return errors.New("onboarding deletion identity is invalid")
	}
	return p.provider.Delete(ctx, request)
}

func newInstallation(config InstallationConfig, service string, compile func(localcontainer.DocumentInput) ([]byte, error)) (adapterv1.Provisioner, error) {
	if adapterv1.ValidateProvisionRequest(config.Request) != nil ||
		config.Request.EngineVersion != Version || config.Request.RegionID != "local-primary" ||
		config.Request.OfferingID != service+"-8.19-onboarding" ||
		config.Request.QuotaShape != Shape(service) {
		return nil, errors.New("onboarding installation profile is invalid")
	}
	expected := config.Request
	expected.OperationID = ""
	provider, err := localcontainer.New(localcontainer.Config{
		Root: config.Root, ImageID: config.ImageID, ServiceName: service,
		CredentialFiles:   []localcontainer.CredentialFile{{Name: service + "-secret", Mode: 0o640}},
		DataDirectoryMode: os.ModeSticky | 0o777, Runtime: config.Runtime,
		ValidateRequest: func(request adapterv1.ProvisionRequest) error {
			request.OperationID = ""
			if request != expected {
				return errors.New("onboarding installation identity or configuration changed")
			}
			return nil
		},
		CompileDocument: compile,
		Endpoint:        func(port int) string { return fmt.Sprintf("http://127.0.0.1:%d", port) },
	})
	if err != nil {
		return nil, err
	}
	return &installation{expected: expected, provider: provider}, nil
}

// Shape is a fixed acceptance profile, not a released customer offering.
func Shape(service string) managedv1.QuotaShape {
	return managedv1.QuotaShape{ID: service + "-onboarding", DisplayName: "接入验收",
		CPUMillicores: 1000, MemoryMiB: 1536, StorageGiB: 10}
}

func commitConfiguration(input localcontainer.DocumentInput, revision string, dependency any) error {
	request := input.Request
	request.OperationID = ""
	content, err := json.Marshal(struct {
		Revision   string
		ImageID    string
		Request    adapterv1.ProvisionRequest
		Dependency any
	}{revision, input.ImageID, request, dependency})
	if err != nil {
		return errors.New("onboarding configuration cannot be encoded")
	}
	return writeImmutable(filepath.Join(filepath.Dir(input.DataDirectory), "product-configuration.json"), content, 0o600)
}

// Existing content is compared, never overwritten. The parent is the exact
// protected project directory already checked by localcontainer.
func writeImmutable(path string, content []byte, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != mode) || info.Size() > 64*1024 {
			return errors.New("onboarding configuration file conflicts")
		}
		existing, readErr := os.ReadFile(path)
		defer clear(existing)
		if readErr != nil || !bytes.Equal(existing, content) {
			return errors.New("onboarding immutable configuration changed")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("onboarding configuration is unavailable")
	}
	// Publish only complete, synced content. A crash while preparing a file
	// must not leave a partial named configuration that prevents equal replay.
	file, err := os.CreateTemp(filepath.Dir(path), ".onboarding-configuration-")
	if err != nil {
		return errors.New("onboarding configuration cannot be created")
	}
	defer os.Remove(file.Name())
	writeErr := file.Chmod(mode)
	if writeErr == nil {
		_, writeErr = file.Write(content)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("onboarding configuration cannot be committed")
	}
	if err := os.Link(file.Name(), path); errors.Is(err, os.ErrExist) {
		return writeImmutable(path, content, mode)
	} else if err != nil {
		return errors.New("onboarding configuration cannot be published")
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return errors.New("onboarding configuration directory is unavailable")
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return errors.New("onboarding configuration durability is unconfirmed")
		}
	}
	return nil
}

func readProtectedSecret(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("onboarding credential reference is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 && info.Mode().Perm() != 0o640) || info.Size() < 32 || info.Size() > 256 {
		return nil, errors.New("onboarding credential is unavailable")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("onboarding credential cannot be read")
	}
	for _, b := range value {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			clear(value)
			return nil, errors.New("onboarding credential format is invalid")
		}
	}
	return value, nil
}

func serviceDocument(input localcontainer.DocumentInput, service string, port int) map[string]any {
	return map[string]any{
		"image": input.ImageID, "pull_policy": "never", "restart": "unless-stopped",
		"mem_limit": fmt.Sprintf("%dm", input.Request.QuotaShape.MemoryMiB), "cpus": "1.000",
		"pids_limit": 512, "cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"},
		"group_add": []string{fmt.Sprint(input.CredentialGroupIDs[service+"-secret"])}, "ports": []string{fmt.Sprintf("127.0.0.1:%d:%d/tcp", input.PublishedPort, port)},
		"labels": map[string]string{
			"com.xiak.matrix.managed":                     "true",
			"com.xiak.matrix.managedservice.installation": input.Request.InstallationID,
			"com.xiak.matrix.managedservice.offering":     input.Request.OfferingID,
			"com.xiak.matrix.managedservice.region":       input.Request.RegionID,
			"com.xiak.matrix.onboarding":                  "true",
		},
	}
}

func mount(source, target string, readOnly bool) map[string]any {
	return map[string]any{"type": "bind", "source": source, "target": target, "read_only": readOnly}
}
