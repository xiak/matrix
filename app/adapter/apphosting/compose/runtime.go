package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	maxRuntimeOutputBytes = 4 * 1024 * 1024
	maxRuntimeContainers  = 1000
)

var (
	// ErrEffectOutcomeUnknown means a provider effect was started but its final
	// result could not be established. Callers must observe before retrying.
	ErrEffectOutcomeUnknown = errors.New("Compose effect outcome is unknown")
	ErrRuntimeUnavailable   = errors.New("Docker Compose runtime is unavailable")
	ErrRuntimeOutputInvalid = errors.New("Docker Compose returned an invalid observation")
)

type RuntimeProject struct {
	Name                string
	Directory           string
	EffectDocument      string
	ObservationDocument string
	TimeoutSeconds      uint32
}

type RuntimeContainer struct {
	ID             string
	Name           string
	Project        string
	Service        string
	State          string
	Health         string
	ExitCode       int
	OneOff         bool
	Labels         map[string]string
	PublishedPorts uint32
}

// Runtime exposes closed provider operations rather than arbitrary command
// execution. The production implementation below is the only code that forms
// Docker/Compose CLI arguments.
type Runtime interface {
	Apply(context.Context, RuntimeProject) error
	Observe(context.Context, RuntimeProject) ([]RuntimeContainer, error)
	Stop(context.Context, RuntimeProject) error
}

// DataPurger is a narrower, destructive boundary used only after a managed
// product runtime has been stopped and observed absent. It mounts only that
// project's data directory into a fixed, network-isolated helper; credentials
// and Compose evidence are never exposed to the helper image.
type DataPurger interface {
	PurgeData(context.Context, RuntimeProject, string) error
}

type LocalRuntime struct{}

func NewLocalRuntime() *LocalRuntime {
	return &LocalRuntime{}
}

// Ready proves that both the local Docker Engine and the Compose plugin can
// accept commands. Version/profile admission remains the installation
// preflight's responsibility; the worker only needs a live effect boundary.
func (*LocalRuntime) Ready(ctx context.Context) error {
	if ctx == nil {
		return errors.New("Docker Compose readiness context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := runDocker(ctx, nil, "version", "--format", "{{.Server.Version}}"); err != nil {
		return ErrRuntimeUnavailable
	}
	if _, err := runDocker(ctx, nil, "compose", "version", "--short"); err != nil {
		return ErrRuntimeUnavailable
	}
	return nil
}

func (*LocalRuntime) Apply(ctx context.Context, project RuntimeProject) error {
	if err := validateRuntimeProject(project); err != nil {
		return err
	}
	arguments := append(runtimePrefix(project, project.EffectDocument),
		"up",
		"--detach",
		"--pull", "never",
		"--no-build",
		"--remove-orphans",
		"--wait",
		"--wait-timeout", strconv.FormatUint(uint64(project.TimeoutSeconds), 10),
		"--no-color",
	)
	started, err := runDocker(ctx, nil, arguments...)
	if err == nil {
		return nil
	}
	if started {
		return ErrEffectOutcomeUnknown
	}
	return ErrRuntimeUnavailable
}

func (*LocalRuntime) Stop(ctx context.Context, project RuntimeProject) error {
	if err := validateRuntimeProject(project); err != nil {
		return err
	}
	arguments := append(runtimePrefix(project, project.ObservationDocument),
		"down",
		"--remove-orphans",
		"--timeout", strconv.FormatUint(uint64(project.TimeoutSeconds), 10),
	)
	started, err := runDocker(ctx, nil, arguments...)
	if err == nil {
		return nil
	}
	if started {
		return ErrEffectOutcomeUnknown
	}
	return ErrRuntimeUnavailable
}

func (*LocalRuntime) PurgeData(ctx context.Context, project RuntimeProject, imageID string) error {
	if err := validateRuntimeProject(project); err != nil {
		return err
	}
	digest := strings.TrimPrefix(imageID, "sha256:")
	decoded, err := hex.DecodeString(digest)
	if !strings.HasPrefix(imageID, "sha256:") || len(decoded) != sha256.Size || err != nil {
		return errors.New("managed data cleanup image identity is invalid")
	}
	dataDirectory := filepath.Join(project.Directory, "data")
	info, err := os.Lstat(dataDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		filepath.Dir(dataDirectory) != project.Directory || strings.Contains(dataDirectory, ",") {
		return errors.New("managed data cleanup target is invalid")
	}
	owner, err := dataCleanupOwner()
	if err != nil {
		return err
	}
	arguments := []string{
		"run", "--rm",
		"--label", "com.xiak.matrix.managed=true",
		"--label", "com.xiak.matrix.role=managed-storage-cleanup",
		"--label", "com.xiak.matrix.project=" + project.Name,
		"--network", "none", "--read-only",
		"--cpus", "0.25", "--memory", "64m", "--memory-swap", "64m", "--pids-limit", "32",
		"--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
		"--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
		"--user", "0:0",
		"--mount", "type=bind,source=" + dataDirectory + ",target=/matrix-data",
		"--entrypoint", "sh", imageID,
		"-c", `set -eu; rm -rf -- /matrix-data/* /matrix-data/.[!.]* /matrix-data/..?*; chown "$1" /matrix-data; chmod 700 /matrix-data; test -z "$(ls -A /matrix-data)"`,
		"sh", owner,
	}
	started, err := runDocker(ctx, nil, arguments...)
	if err == nil {
		return nil
	}
	if started {
		return ErrEffectOutcomeUnknown
	}
	return ErrRuntimeUnavailable
}

func dataCleanupOwner() (string, error) {
	if runtime.GOOS == "windows" {
		// Docker Desktop maps container ownership through the host filesystem;
		// keep the historical root owner inside the utility container. Windows
		// removal is governed by the host ACL rather than this numeric owner.
		return "0:0", nil
	}
	current, err := user.Current()
	if err != nil {
		return "", errors.New("managed data cleanup owner is unavailable")
	}
	uid, uidErr := strconv.ParseUint(current.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(current.Gid, 10, 32)
	if uidErr != nil || gidErr != nil {
		return "", errors.New("managed data cleanup owner is invalid")
	}
	return strconv.FormatUint(uid, 10) + ":" + strconv.FormatUint(gid, 10), nil
}

func (*LocalRuntime) Observe(
	ctx context.Context,
	project RuntimeProject,
) ([]RuntimeContainer, error) {
	if err := validateRuntimeProject(project); err != nil {
		return nil, err
	}
	var output boundedBuffer
	output.maximum = maxRuntimeOutputBytes
	arguments := append(runtimePrefix(project, project.ObservationDocument),
		"ps",
		"--all",
		"--no-trunc",
		"--orphans=true",
		"--format", "json",
	)
	_, err := runDocker(ctx, &output, arguments...)
	if err != nil || output.exceeded {
		return nil, ErrRuntimeUnavailable
	}
	containers, err := decodeRuntimeContainers(output.Bytes())
	if err != nil {
		return nil, ErrRuntimeOutputInvalid
	}
	return containers, nil
}

func runtimePrefix(project RuntimeProject, document string) []string {
	return []string{
		"compose",
		"--ansi", "never",
		"--progress", "quiet",
		"--project-name", project.Name,
		"--project-directory", project.Directory,
		"--file", document,
	}
}

func validateRuntimeProject(project RuntimeProject) error {
	if !strings.HasPrefix(project.Name, "matrix-") || len(project.Name) != len("matrix-")+24 {
		return errors.New("Compose project identity is invalid")
	}
	if project.TimeoutSeconds == 0 || project.TimeoutSeconds > 300 {
		return errors.New("Compose timeout is outside the supported range")
	}
	if !filepath.IsAbs(project.Directory) || filepath.Clean(project.Directory) != project.Directory {
		return errors.New("Compose project directory is invalid")
	}
	for _, document := range []string{project.EffectDocument, project.ObservationDocument} {
		if !filepath.IsAbs(document) || filepath.Clean(document) != document || filepath.Dir(document) != project.Directory {
			return errors.New("Compose document path is invalid")
		}
	}
	return nil
}

func runDocker(ctx context.Context, output io.Writer, arguments ...string) (bool, error) {
	if ctx == nil {
		return false, errors.New("Docker command context is required")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Stdin = nil
	command.Stdout = io.Discard
	if output != nil {
		command.Stdout = output
	}
	command.Stderr = io.Discard
	command.Env = append(os.Environ(),
		"COMPOSE_MENU=0",
		"COMPOSE_INTERACTIVE_NO_CLI=1",
		"DOCKER_CLI_HINTS=false",
	)
	if err := command.Start(); err != nil {
		return false, err
	}
	return true, command.Wait()
}

type boundedBuffer struct {
	bytes.Buffer
	maximum  int
	exceeded bool
}

func (buffer *boundedBuffer) Write(content []byte) (int, error) {
	if buffer.exceeded {
		return 0, errors.New("runtime output exceeds the size limit")
	}
	remaining := buffer.maximum - buffer.Len()
	if len(content) > remaining {
		if remaining > 0 {
			_, _ = buffer.Buffer.Write(content[:remaining])
		}
		buffer.exceeded = true
		return 0, errors.New("runtime output exceeds the size limit")
	}
	return buffer.Buffer.Write(content)
}

type composePSRecord struct {
	ID         string         `json:"ID"`
	Name       string         `json:"Name"`
	Project    string         `json:"Project"`
	Service    string         `json:"Service"`
	State      string         `json:"State"`
	Health     string         `json:"Health"`
	ExitCode   int            `json:"ExitCode"`
	OneOff     bool           `json:"OneOff"`
	Labels     providerLabels `json:"Labels"`
	Publishers []struct {
		PublishedPort uint32 `json:"PublishedPort"`
	} `json:"Publishers"`
}

type providerLabels map[string]string

func (labels *providerLabels) UnmarshalJSON(content []byte) error {
	var object map[string]string
	if len(content) > 0 && content[0] == '{' {
		if err := json.Unmarshal(content, &object); err != nil {
			return err
		}
		*labels = object
		return nil
	}
	var flat string
	if err := json.Unmarshal(content, &flat); err != nil {
		return err
	}
	object = make(map[string]string)
	for _, item := range strings.Split(flat, ",") {
		key, value, found := strings.Cut(item, "=")
		if found && key != "" {
			object[key] = value
		}
	}
	*labels = object
	return nil
}

func decodeRuntimeContainers(content []byte) ([]RuntimeContainer, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return []RuntimeContainer{}, nil
	}
	records := make([]composePSRecord, 0)
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &records); err != nil {
			return nil, err
		}
	} else {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		for {
			var record composePSRecord
			if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, err
			}
			records = append(records, record)
			if len(records) > maxRuntimeContainers {
				return nil, errors.New("too many provider records")
			}
		}
	}
	if len(records) > maxRuntimeContainers {
		return nil, errors.New("too many provider records")
	}
	result := make([]RuntimeContainer, 0, len(records))
	for _, record := range records {
		published := uint32(0)
		for _, publisher := range record.Publishers {
			if publisher.PublishedPort != 0 {
				published++
			}
		}
		result = append(result, RuntimeContainer{
			ID: record.ID, Name: record.Name, Project: record.Project,
			Service: record.Service, State: strings.ToLower(record.State),
			Health: strings.ToLower(record.Health), ExitCode: record.ExitCode,
			OneOff: record.OneOff, Labels: map[string]string(record.Labels),
			PublishedPorts: published,
		})
	}
	return result, nil
}
