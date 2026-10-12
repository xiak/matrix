// Package localcontainer owns the shared, closed local-container effect used
// by managed-service providers. Product adapters still own their image,
// configuration, health check and protocol semantics.
package localcontainer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
)

var (
	imageIDPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	fileNamePattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

type DocumentInput struct {
	ProjectName     string
	ImageID         string
	Request         managedserviceadapterv1.ProvisionRequest
	DataDirectory   string
	CredentialPaths map[string]string
	// CredentialGroupIDs is populated only for group-readable protected files
	// and always comes from the file that will be bind-mounted.
	CredentialGroupIDs map[string]uint32
	PublishedPort      int
}

type CredentialFile struct {
	Name string
	Mode os.FileMode
}

type Config struct {
	Root              string
	ImageID           string
	ServiceName       string
	CredentialFiles   []CredentialFile
	DataDirectoryMode os.FileMode
	Runtime           composeadapter.Runtime
	ValidateRequest   func(managedserviceadapterv1.ProvisionRequest) error
	CompileDocument   func(DocumentInput) ([]byte, error)
	Endpoint          func(int) string
	NewSecret         func() ([]byte, error)
}

type Provisioner struct {
	root              string
	imageID           string
	serviceName       string
	credentialFiles   []CredentialFile
	dataDirectoryMode os.FileMode
	runtime           composeadapter.Runtime
	dataPurger        composeadapter.DataPurger
	validateRequest   func(managedserviceadapterv1.ProvisionRequest) error
	compileDocument   func(DocumentInput) ([]byte, error)
	endpoint          func(int) string
	newSecret         func() ([]byte, error)
	locks             sync.Map
}

func New(config Config) (*Provisioner, error) {
	if !imageIDPattern.MatchString(config.ImageID) ||
		!serviceNamePattern.MatchString(config.ServiceName) ||
		len(config.CredentialFiles) == 0 || len(config.CredentialFiles) > 4 ||
		config.Runtime == nil || config.ValidateRequest == nil ||
		config.CompileDocument == nil || config.Endpoint == nil {
		return nil, errors.New("local managed-service provider configuration is invalid")
	}
	dataPurger, ok := config.Runtime.(composeadapter.DataPurger)
	if !ok {
		return nil, errors.New("local managed-service provider requires a data purge boundary")
	}
	credentialFiles := make([]CredentialFile, len(config.CredentialFiles))
	credentialNames := make(map[string]struct{}, len(config.CredentialFiles))
	for index, credential := range config.CredentialFiles {
		credential.Mode = credential.Mode.Perm()
		if !fileNamePattern.MatchString(credential.Name) || credential.Mode == 0 ||
			credential.Mode&0o022 != 0 || credential.Mode&0o111 != 0 {
			return nil, errors.New("local managed-service credential configuration is invalid")
		}
		if _, duplicate := credentialNames[credential.Name]; duplicate {
			return nil, errors.New("local managed-service credential configuration is invalid")
		}
		credentialNames[credential.Name] = struct{}{}
		credentialFiles[index] = credential
	}
	dataMode := config.DataDirectoryMode
	if dataMode.Perm()&0o700 != 0o700 || dataMode&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, errors.New("local managed-service data mode is invalid")
	}
	root, err := prepareRoot(config.Root)
	if err != nil {
		return nil, err
	}
	if config.NewSecret == nil {
		config.NewSecret = newSecret
	}
	return &Provisioner{
		root: root, imageID: config.ImageID, serviceName: config.ServiceName,
		credentialFiles: credentialFiles, dataDirectoryMode: dataMode,
		runtime: config.Runtime, dataPurger: dataPurger, validateRequest: config.ValidateRequest,
		compileDocument: config.CompileDocument, endpoint: config.Endpoint,
		newSecret: config.NewSecret,
	}, nil
}

func (provisioner *Provisioner) Ready(ctx context.Context) error {
	if provisioner == nil || provisioner.runtime == nil || ctx == nil {
		return errors.New("local managed-service provider is unavailable")
	}
	if runtime, ok := provisioner.runtime.(interface{ Ready(context.Context) error }); ok {
		if err := runtime.Ready(ctx); err != nil {
			return errors.New("local managed-service Docker runtime is unavailable")
		}
	}
	_, err := prepareRoot(provisioner.root)
	return err
}

func (provisioner *Provisioner) Ensure(
	ctx context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	if provisioner == nil || ctx == nil ||
		managedserviceadapterv1.ValidateProvisionRequest(request) != nil ||
		provisioner.validateRequest(request) != nil {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local managed-service request is invalid")
	}
	projectName := ProjectName(request.TenantID, request.InstallationID)
	lockValue, _ := provisioner.locks.LoadOrStore(projectName, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	project, endpoint, credentialReference, err := provisioner.prepareProject(projectName, request)
	if err != nil {
		return managedserviceadapterv1.ProvisionResult{}, err
	}
	containers, observeErr := provisioner.runtime.Observe(ctx, project)
	if observeErr == nil && provisioner.ready(containers, projectName, request) {
		return managedserviceadapterv1.ProvisionResult{
			Endpoint: endpoint, CredentialReference: credentialReference,
		}, nil
	}
	if observeErr == nil && len(containers) > 1 {
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local managed-service ownership observation conflicts")
	}
	applyErr := provisioner.runtime.Apply(ctx, project)
	containers, observeErr = provisioner.runtime.Observe(ctx, project)
	if observeErr != nil || !provisioner.ready(containers, projectName, request) {
		if applyErr != nil {
			return managedserviceadapterv1.ProvisionResult{}, errors.New("local managed-service effect is unavailable")
		}
		return managedserviceadapterv1.ProvisionResult{}, errors.New("local managed-service did not become ready")
	}
	return managedserviceadapterv1.ProvisionResult{
		Endpoint: endpoint, CredentialReference: credentialReference,
	}, nil
}

// Delete removes exactly one authority-derived installation. The Compose
// project identity is recomputed from tenant and installation IDs; callers
// cannot supply paths, project names, endpoints or credential references.
// Runtime removal is observed before the protected project directory is
// removed, making equal retries safe after an unknown caller outcome.
func (provisioner *Provisioner) Delete(
	ctx context.Context,
	request managedserviceadapterv1.DeprovisionRequest,
) error {
	if provisioner == nil || ctx == nil ||
		managedserviceadapterv1.ValidateDeprovisionRequest(request) != nil ||
		request.OfferingID == "" || request.RegionID != "local-primary" {
		return errors.New("local managed-service deletion request is invalid")
	}
	projectName := ProjectName(request.TenantID, request.InstallationID)
	lockValue, _ := provisioner.locks.LoadOrStore(projectName, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	directory := filepath.Join(provisioner.root, projectName)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!withinRoot(provisioner.root, directory) || filepath.Dir(directory) != provisioner.root {
		return errors.New("local managed-service deletion target conflicts")
	}
	project := composeadapter.RuntimeProject{
		Name: projectName, Directory: directory,
		EffectDocument:      filepath.Join(directory, "compose.json"),
		ObservationDocument: filepath.Join(directory, "observe.json"),
		TimeoutSeconds:      120,
	}
	for _, document := range []string{project.EffectDocument, project.ObservationDocument} {
		documentInfo, statErr := os.Lstat(document)
		if statErr != nil || !documentInfo.Mode().IsRegular() || documentInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("local managed-service deletion evidence conflicts")
		}
	}
	dataDirectory := filepath.Join(directory, "data")
	dataInfo, dataErr := os.Lstat(dataDirectory)
	if dataErr != nil || !dataInfo.IsDir() || dataInfo.Mode()&os.ModeSymlink != 0 ||
		!withinRoot(provisioner.root, dataDirectory) || filepath.Dir(dataDirectory) != directory {
		return errors.New("local managed-service data target conflicts")
	}
	containers, err := provisioner.runtime.Observe(ctx, project)
	if err != nil {
		return errors.New("local managed-service deletion observation is unavailable")
	}
	for _, container := range containers {
		if !provisioner.owns(container, projectName, request.InstallationID, request.OfferingID, request.RegionID) {
			return errors.New("local managed-service deletion ownership conflicts")
		}
	}
	if len(containers) > 0 {
		if err := provisioner.runtime.Stop(ctx, project); err != nil {
			return errors.New("local managed-service deletion effect is unavailable")
		}
		containers, err = provisioner.runtime.Observe(ctx, project)
		if err != nil || len(containers) != 0 {
			return errors.New("local managed-service deletion outcome is unknown")
		}
	}
	if err := provisioner.dataPurger.PurgeData(ctx, project, provisioner.imageID); err != nil {
		return errors.New("local managed-service data cleanup is unavailable")
	}
	if err := os.RemoveAll(directory); err != nil {
		return errors.New("local managed-service data cannot be removed")
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("local managed-service data removal is incomplete")
	}
	provisioner.locks.Delete(projectName)
	return nil
}

func (provisioner *Provisioner) prepareProject(
	projectName string,
	request managedserviceadapterv1.ProvisionRequest,
) (composeadapter.RuntimeProject, string, string, error) {
	directory := filepath.Join(provisioner.root, projectName)
	if err := prepareOwnedDirectory(provisioner.root, directory, 0o700); err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	dataDirectory := filepath.Join(directory, "data")
	if err := prepareOwnedDirectory(provisioner.root, dataDirectory, provisioner.dataDirectoryMode); err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	credentialPaths := make(map[string]string, len(provisioner.credentialFiles))
	credentialGroupIDs := make(map[string]uint32, len(provisioner.credentialFiles))
	for _, credential := range provisioner.credentialFiles {
		credentialPath := filepath.Join(directory, credential.Name)
		if err := provisioner.ensureCredential(credentialPath, credential.Mode); err != nil {
			return composeadapter.RuntimeProject{}, "", "", err
		}
		credentialPaths[credential.Name] = credentialPath
		if credential.Mode&0o040 != 0 {
			groupID, available, groupErr := credentialFileGroupID(credentialPath)
			if groupErr != nil {
				return composeadapter.RuntimeProject{}, "", "", groupErr
			}
			if available {
				credentialGroupIDs[credential.Name] = groupID
			}
		}
	}
	port, err := ensurePort(provisioner.root, filepath.Join(directory, "published-port"), projectName)
	if err != nil {
		return composeadapter.RuntimeProject{}, "", "", err
	}
	document, err := provisioner.compileDocument(DocumentInput{
		ProjectName: projectName, ImageID: provisioner.imageID, Request: request,
		DataDirectory: dataDirectory, CredentialPaths: credentialPaths,
		CredentialGroupIDs: credentialGroupIDs, PublishedPort: port,
	})
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
	}, provisioner.endpoint(port), CredentialReference(request), nil
}

func (provisioner *Provisioner) ensureCredential(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() < 32 || info.Size() > 256 {
			return errors.New("local managed-service credential file conflicts")
		}
		if info.Mode().Perm() != mode && os.PathSeparator == '/' {
			return errors.New("local managed-service credential file mode conflicts")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("local managed-service credential file is unavailable")
	}
	secret, err := provisioner.newSecret()
	if err != nil || len(secret) < 32 || len(secret) > 256 || strings.ContainsAny(string(secret), "\x00\r\n") {
		clear(secret)
		return errors.New("local managed-service credential cannot be generated")
	}
	defer clear(secret)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("local managed-service credential cannot be created")
	}
	_, writeErr := file.Write(secret)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("local managed-service credential cannot be committed")
	}
	return nil
}

func (provisioner *Provisioner) ready(
	containers []composeadapter.RuntimeContainer,
	projectName string,
	request managedserviceadapterv1.ProvisionRequest,
) bool {
	if len(containers) != 1 {
		return false
	}
	container := containers[0]
	return provisioner.owns(container, projectName, request.InstallationID, request.OfferingID, request.RegionID) &&
		container.State == "running" && container.Health == "healthy" &&
		container.PublishedPorts == 1
}

func (provisioner *Provisioner) owns(
	container composeadapter.RuntimeContainer,
	projectName, installationID, offeringID, regionID string,
) bool {
	return container.Project == projectName && container.Service == provisioner.serviceName &&
		!container.OneOff &&
		container.Labels["com.xiak.matrix.managed"] == "true" &&
		container.Labels["com.xiak.matrix.managedservice.installation"] == installationID &&
		container.Labels["com.xiak.matrix.managedservice.offering"] == offeringID &&
		container.Labels["com.xiak.matrix.managedservice.region"] == regionID
}

func prepareRoot(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) == root {
		return "", errors.New("local managed-service root is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", errors.New("local managed-service root cannot be created")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("local managed-service root is unavailable")
	}
	return root, nil
}

func prepareOwnedDirectory(root, path string, mode os.FileMode) error {
	if !withinRoot(root, path) {
		return errors.New("local managed-service path escapes its root")
	}
	if err := os.MkdirAll(path, mode.Perm()); err != nil {
		return errors.New("local managed-service directory cannot be created")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("local managed-service directory conflicts")
	}
	if os.PathSeparator == '/' &&
		info.Mode()&(os.ModePerm|os.ModeSticky) != mode&(os.ModePerm|os.ModeSticky) {
		if err := os.Chmod(path, mode); err != nil {
			return errors.New("local managed-service directory mode cannot be set")
		}
	}
	return nil
}

func writeManagedFile(root, path string, content []byte, mode os.FileMode) error {
	if !withinRoot(root, path) {
		return errors.New("local managed-service file escapes its root")
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("local managed-service file conflicts")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("local managed-service file cannot be inspected")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".matrix-managed-service-")
	if err != nil {
		return errors.New("local managed-service file cannot be staged")
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
		return errors.New("local managed-service file mode cannot be set")
	}
	if _, err := temporary.Write(content); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("local managed-service file cannot be staged")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("local managed-service file cannot be committed")
	}
	committed = true
	return nil
}

func ensurePort(root, path, projectName string) (int, error) {
	if content, err := os.ReadFile(path); err == nil {
		port, parseErr := strconv.Atoi(string(content))
		if parseErr == nil && port >= minimumPublishedPort && port <= maximumPublishedPort {
			return port, nil
		}
		return 0, errors.New("local managed-service published port conflicts")
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, errors.New("local managed-service published port is unavailable")
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
		if err := writeManagedFile(root, path, []byte(strconv.Itoa(port)), 0o600); err != nil {
			return 0, err
		}
		return port, nil
	}
	return 0, errors.New("local managed-service has no available published port")
}

func withinRoot(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && !filepath.IsAbs(relative)
}

func ProjectName(tenantID, installationID string) string {
	digest := sha256.Sum256([]byte(tenantID + "\x00" + installationID))
	return "matrix-" + hex.EncodeToString(digest[:12])
}

func CredentialReference(request managedserviceadapterv1.ProvisionRequest) string {
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

func FormatCPUs(millicores uint32) string {
	whole := millicores / 1000
	fraction := millicores % 1000
	if fraction == 0 {
		return strconv.FormatUint(uint64(whole), 10)
	}
	return strconv.FormatUint(uint64(whole), 10) + "." +
		strings.TrimRight(fmt.Sprintf("%03d", fraction), "0")
}
