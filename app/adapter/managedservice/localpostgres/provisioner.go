// Package localpostgres installs the one closed PostgreSQL offering on the
// local Docker host without accepting provider-native caller input.
package localpostgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
)

const (
	minimumPublishedPort = 20000
	maximumPublishedPort = 39999
	postgresServiceName  = "postgres"
)

var imageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Config struct {
	Root      string
	ImageID   string
	Runtime   composeadapter.Runtime
	NewSecret func() ([]byte, error)
}

type Provisioner struct {
	root      string
	imageID   string
	runtime   composeadapter.Runtime
	newSecret func() ([]byte, error)
	locks     sync.Map
}

func New(config Config) (*Provisioner, error) {
	if !imageIDPattern.MatchString(config.ImageID) || config.Runtime == nil {
		return nil, errors.New("local PostgreSQL provisioner configuration is invalid")
	}
	root, err := prepareRoot(config.Root)
	if err != nil {
		return nil, err
	}
	if config.NewSecret == nil {
		config.NewSecret = newSecret
	}
	return &Provisioner{
		root: root, imageID: config.ImageID, runtime: config.Runtime,
		newSecret: config.NewSecret,
	}, nil
}

func (provisioner *Provisioner) Ready(ctx context.Context) error {
	if provisioner == nil || provisioner.runtime == nil || ctx == nil {
		return errors.New("local PostgreSQL provisioner is unavailable")
	}
	if runtime, ok := provisioner.runtime.(interface{ Ready(context.Context) error }); ok {
		if err := runtime.Ready(ctx); err != nil {
			return errors.New("local PostgreSQL Docker runtime is unavailable")
		}
	}
	_, err := prepareRoot(provisioner.root)
	return err
}

func (provisioner *Provisioner) Ensure(
	ctx context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	if provisioner == nil || ctx == nil || validateRequest(request) != nil {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local PostgreSQL request is invalid")
	}
	projectName := projectName(request.TenantID, request.InstallationID)
	lockValue, _ := provisioner.locks.LoadOrStore(projectName, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	project, endpoint, credentialReference, err := provisioner.prepareProject(projectName, request)
	if err != nil {
		return managedserviceadapterv1.ProvisionResult{}, err
	}
	containers, observeErr := provisioner.runtime.Observe(ctx, project)
	if observeErr == nil && ready(containers, projectName, request.InstallationID) {
		return managedserviceadapterv1.ProvisionResult{
			Endpoint: endpoint, CredentialReference: credentialReference,
		}, nil
	}
	if observeErr == nil && len(containers) > 1 {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local PostgreSQL ownership observation conflicts")
	}
	applyErr := provisioner.runtime.Apply(ctx, project)
	containers, observeErr = provisioner.runtime.Observe(ctx, project)
	if observeErr != nil || !ready(containers, projectName, request.InstallationID) {
		if applyErr != nil {
			return managedserviceadapterv1.ProvisionResult{}, errors.New("local PostgreSQL effect is unavailable")
		}
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local PostgreSQL did not become ready")
	}
	return managedserviceadapterv1.ProvisionResult{
		Endpoint: endpoint, CredentialReference: credentialReference,
	}, nil
}

func (provisioner *Provisioner) prepareProject(
	projectName string,
	request managedserviceadapterv1.ProvisionRequest,
) (composeadapter.RuntimeProject, string, string, error) {
	directory := filepath.Join(provisioner.root, projectName)
	if err := prepareOwnedDirectory(provisioner.root, directory); err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	dataDirectory := filepath.Join(directory, "data")
	if err := preparePostgresDataDirectory(provisioner.root, dataDirectory); err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	passwordPath := filepath.Join(directory, "postgres-password")
	if err := provisioner.ensurePassword(passwordPath); err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	port, err := ensurePort(filepath.Join(directory, "published-port"), projectName)
	if err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	document, err := compileDocument(
		projectName, provisioner.imageID, request, dataDirectory, passwordPath, port,
	)
	if err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	effectPath := filepath.Join(directory, "compose.json")
	observationPath := filepath.Join(directory, "observe.json")
	if err := writeManagedFile(provisioner.root, effectPath, document, 0o600); err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	if err := writeManagedFile(provisioner.root, observationPath, document, 0o600); err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	return composeadapter.RuntimeProject{
		Name: projectName, Directory: directory,
		EffectDocument: effectPath, ObservationDocument: observationPath,
		TimeoutSeconds: 120,
	}, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), credentialReference(request), nil
}

func (provisioner *Provisioner) ensurePassword(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() < 32 || info.Size() > 256 {
			return errors.New("local PostgreSQL credential file conflicts")
		}
		if info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
			return errors.New("local PostgreSQL credential file is overexposed")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("local PostgreSQL credential file is unavailable")
	}
	secret, err := provisioner.newSecret()
	if err != nil || len(secret) < 32 || len(secret) > 256 || strings.ContainsAny(string(secret), "\x00\r\n") {
		clear(secret)
		return errors.New("local PostgreSQL credential cannot be generated")
	}
	defer clear(secret)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("local PostgreSQL credential cannot be created")
	}
	_, writeErr := file.Write(secret)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("local PostgreSQL credential cannot be committed")
	}
	return nil
}

func compileDocument(
	projectName string,
	imageID string,
	request managedserviceadapterv1.ProvisionRequest,
	dataDirectory string,
	passwordPath string,
	port int,
) ([]byte, error) {
	document := map[string]any{
		"name": projectName,
		"services": map[string]any{
			postgresServiceName: map[string]any{
				"image": imageID, "pull_policy": "never", "restart": "unless-stopped",
				"read_only": false, "init": false,
				"environment": map[string]string{
					"POSTGRES_DB": "service", "POSTGRES_USER": "matrix_service",
					"POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
				},
				"ports": []string{fmt.Sprintf("127.0.0.1:%d:5432/tcp", port)},
				"volumes": []map[string]any{
					{"type": "bind", "source": dataDirectory, "target": "/var/lib/postgresql"},
					{"type": "bind", "source": passwordPath, "target": "/run/secrets/postgres-password", "read_only": true},
				},
				"tmpfs":        []string{"/tmp:rw,noexec,nosuid,size=64m", "/var/run/postgresql:rw,nosuid,size=16m"},
				"security_opt": []string{"no-new-privileges:true"},
				"cap_drop":     []string{"ALL"},
				"cap_add":      []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"},
				"healthcheck": map[string]any{
					"test":     []string{"CMD", "pg_isready", "-h", "127.0.0.1", "-U", "matrix_service", "-d", "service"},
					"interval": "2s", "timeout": "2s", "retries": 30, "start_period": "5s",
				},
				"deploy": map[string]any{"resources": map[string]any{"limits": map[string]string{
					"cpus":   formatCPUs(request.QuotaShape.CPUMillicores),
					"memory": strconv.FormatUint(uint64(request.QuotaShape.MemoryMiB), 10) + "M",
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
	return managedserviceadapterv1.ValidateProvisionRequest(request)
}

func ready(
	containers []composeadapter.RuntimeContainer,
	projectName string,
	installationID string,
) bool {
	if len(containers) != 1 {
		return false
	}
	container := containers[0]
	return container.Project == projectName && container.Service == postgresServiceName &&
		container.State == "running" && container.Health == "healthy" &&
		!container.OneOff && container.PublishedPorts == 1 &&
		container.Labels["com.xiak.matrix.managed"] == "true" &&
		container.Labels["com.xiak.matrix.managedservice.installation"] == installationID
}

func prepareRoot(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) == root {
		return "", errors.New("local PostgreSQL managed root is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", errors.New("local PostgreSQL managed root cannot be created")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("local PostgreSQL managed root is unavailable")
	}
	return root, nil
}

func prepareOwnedDirectory(root, path string) error {
	if !withinRoot(root, path) {
		return errors.New("local PostgreSQL path escapes its managed root")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return errors.New("local PostgreSQL directory cannot be created")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("local PostgreSQL directory conflicts")
	}
	return nil
}

func preparePostgresDataDirectory(root, path string) error {
	if err := prepareOwnedDirectory(root, path); err != nil {
		return err
	}
	if os.PathSeparator != '/' {
		return nil
	}
	// The fixed PostgreSQL 18 image owns /var/lib/postgresql as a sticky
	// mount root, then creates and confines PGDATA below it as the postgres
	// user. The project directory above this bind source remains mode 0700.
	if err := os.Chmod(path, os.ModeSticky|0o777); err != nil {
		return errors.New("local PostgreSQL data mount mode cannot be set")
	}
	return nil
}

func writeManagedFile(root, path string, content []byte, mode os.FileMode) error {
	if !withinRoot(root, path) {
		return errors.New("local PostgreSQL file escapes its managed root")
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("local PostgreSQL file conflicts")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("local PostgreSQL file cannot be inspected")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".matrix-managed-postgres-")
	if err != nil {
		return errors.New("local PostgreSQL file cannot be staged")
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return errors.New("local PostgreSQL file mode cannot be set")
	}
	if _, err := temporary.Write(content); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("local PostgreSQL file cannot be staged")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("local PostgreSQL file cannot be committed")
	}
	committed = true
	return nil
}

func ensurePort(path, projectName string) (int, error) {
	if content, err := os.ReadFile(path); err == nil {
		port, parseErr := strconv.Atoi(string(content))
		if parseErr == nil && port >= minimumPublishedPort && port <= maximumPublishedPort {
			return port, nil
		}
		return 0, errors.New("local PostgreSQL published port conflicts")
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, errors.New("local PostgreSQL published port is unavailable")
	}
	digest := sha256.Sum256([]byte(projectName))
	span := maximumPublishedPort - minimumPublishedPort + 1
	start := minimumPublishedPort + int(uint16(digest[0])<<8|uint16(digest[1]))%span
	for offset := 0; offset < span; offset++ {
		port := minimumPublishedPort + (start-minimumPublishedPort+offset)%span
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		_ = listener.Close()
		if err := writeManagedFile(filepath.Dir(filepath.Dir(path)), path, []byte(strconv.Itoa(port)), 0o600); err != nil {
			return 0, err
		}
		return port, nil
	}
	return 0, errors.New("local PostgreSQL has no available published port")
}

func withinRoot(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && !filepath.IsAbs(relative)
}

func projectName(tenantID, installationID string) string {
	digest := sha256.Sum256([]byte(tenantID + "\x00" + installationID))
	return "matrix-" + hex.EncodeToString(digest[:12])
}

func credentialReference(request managedserviceadapterv1.ProvisionRequest) string {
	digest := sha256.Sum256([]byte(request.TenantID + "\x00" + request.InstallationID + "\x00credential"))
	return "credential-" + hex.EncodeToString(digest[:12])
}

func newSecret() ([]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	result := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(result, raw[:])
	clear(raw[:])
	return result, nil
}

func formatCPUs(millicores uint32) string {
	whole := millicores / 1000
	fraction := millicores % 1000
	if fraction == 0 {
		return strconv.FormatUint(uint64(whole), 10)
	}
	return strconv.FormatUint(uint64(whole), 10) + "." +
		strings.TrimRight(fmt.Sprintf("%03d", fraction), "0")
}
