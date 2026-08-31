package compose

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	maxEngineError = 4096
)

var (
	ErrTerminalUnsupported = errors.New("container terminal is unsupported")
	ErrTerminalUnavailable = errors.New("container terminal runtime is unavailable")
	ErrTerminalFailed      = errors.New("container terminal failed")
)

// Terminal is one provider-owned TTY stream. Provider container and exec
// identities remain inside this adapter and never cross the node boundary.
type Terminal interface {
	io.ReadWriteCloser
	Resize(context.Context, paasv1.TerminalSize) error
	ExitCode(context.Context) (int32, error)
}

// TerminalRuntime is deliberately optional. A Runtime without this closed
// capability reports UNSUPPORTED instead of gaining an arbitrary command API.
type TerminalRuntime interface {
	OpenTerminal(context.Context, RuntimeProject, RuntimeContainer, paasv1.TerminalSize) (Terminal, error)
}

// OpenDeploymentTerminal repeats the exact current-generation proof under the
// Compose project lock, resolves one opaque instance and opens only /bin/sh in
// its already-configured container identity.
func (executor *Executor) OpenDeploymentTerminal(
	ctx context.Context,
	request paasv1.ObserveDeploymentRuntimeRequest,
	instanceID paasv1.ResourceID,
	size paasv1.TerminalSize,
) (Terminal, error) {
	if executor == nil || executor.compiler == nil || ctx == nil ||
		paasv1.ValidateDeploymentInstanceID(instanceID) != nil ||
		paasv1.ValidateTerminalSize(size) != nil {
		return nil, invalidRequestFault()
	}
	provider, supported := executor.runtime.(TerminalRuntime)
	if !supported {
		return nil, ErrTerminalUnsupported
	}
	var terminal Terminal
	err := executor.withCurrentRuntime(
		ctx,
		request,
		func(
			operationContext context.Context,
			state projectState,
			runtimeProject RuntimeProject,
			containers []inspectedRuntimeContainer,
			_ time.Time,
		) error {
			var selected *RuntimeContainer
			for index := range containers {
				item := containers[index]
				if !item.current || opaqueDeploymentInstanceID(state, request.ExecutionTargetID, item.value.ID) != instanceID {
					continue
				}
				if selected != nil || item.value.State != "running" {
					return conflictFault()
				}
				value := item.value
				selected = &value
			}
			if selected == nil {
				return notFoundFault()
			}
			opened, openErr := provider.OpenTerminal(operationContext, runtimeProject, *selected, size)
			if openErr != nil {
				return openErr
			}
			if opened == nil {
				return ErrTerminalFailed
			}
			terminal = opened
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return terminal, nil
}

type dockerExecCreateResponse struct {
	ID string `json:"Id"`
}

type dockerExecInspection struct {
	Running  bool  `json:"Running"`
	ExitCode int64 `json:"ExitCode"`
}

func (runtime *LocalRuntime) OpenTerminal(
	ctx context.Context,
	project RuntimeProject,
	container RuntimeContainer,
	size paasv1.TerminalSize,
) (Terminal, error) {
	if runtime == nil || ctx == nil || validateRuntimeProject(project) != nil ||
		paasv1.ValidateTerminalSize(size) != nil || !validProviderContainerID(container.ID) ||
		container.Project != project.Name || container.State != "running" {
		return nil, ErrTerminalFailed
	}
	execID, err := createDockerExec(ctx, container.ID)
	if err != nil {
		return nil, err
	}
	return startDockerExec(ctx, execID, size)
}

func createDockerExec(ctx context.Context, containerID string) (string, error) {
	request := struct {
		AttachStdin  bool     `json:"AttachStdin"`
		AttachStdout bool     `json:"AttachStdout"`
		AttachStderr bool     `json:"AttachStderr"`
		TTY          bool     `json:"Tty"`
		Command      []string `json:"Cmd"`
	}{true, true, true, true, []string{"/bin/sh"}}
	body, _ := json.Marshal(request)
	response, err := dockerJSON(ctx, http.MethodPost, "/containers/"+containerID+"/exec", body, http.StatusCreated)
	if err != nil {
		return "", err
	}
	var decoded dockerExecCreateResponse
	if decodeClosedJSON(response, &decoded) != nil || !validProviderExecID(decoded.ID) {
		return "", ErrTerminalFailed
	}
	return decoded.ID, nil
}

func startDockerExec(ctx context.Context, execID string, size paasv1.TerminalSize) (Terminal, error) {
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", dockerEngineSocket)
	if err != nil {
		return nil, ErrTerminalUnavailable
	}
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	body, _ := json.Marshal(struct {
		Detach      bool      `json:"Detach"`
		TTY         bool      `json:"Tty"`
		ConsoleSize [2]uint16 `json:"ConsoleSize"`
	}{false, true, [2]uint16{size.Rows, size.Columns}})
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		dockerEngineEndpoint+"/exec/"+execID+"/start",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, ErrTerminalFailed
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "tcp")
	request.Header.Set("User-Agent", "matrix-node-terminal/v1")
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := request.Write(connection); err != nil {
		return nil, ErrTerminalUnavailable
	}
	reader := bufio.NewReaderSize(connection, 32*1024)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, ErrTerminalUnavailable
	}
	if response.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(response.Header.Get("Connection"), "Upgrade") {
		message, _ := io.ReadAll(io.LimitReader(response.Body, maxEngineError+1))
		_ = response.Body.Close()
		if missingShell(message) {
			return nil, ErrTerminalUnsupported
		}
		return nil, classifyDockerStatus(response.StatusCode)
	}
	_ = connection.SetDeadline(time.Time{})
	failed = false
	return &dockerTerminal{connection: connection, reader: reader, execID: execID}, nil
}

type dockerTerminal struct {
	connection net.Conn
	reader     *bufio.Reader
	execID     string
	closeOnce  sync.Once
}

func (terminal *dockerTerminal) Read(content []byte) (int, error) {
	if terminal == nil || terminal.connection == nil || len(content) == 0 {
		return 0, io.ErrClosedPipe
	}
	return terminal.reader.Read(content)
}

func (terminal *dockerTerminal) Write(content []byte) (int, error) {
	if terminal == nil || terminal.connection == nil || len(content) == 0 {
		return 0, io.ErrClosedPipe
	}
	return terminal.connection.Write(content)
}

func (terminal *dockerTerminal) Close() error {
	if terminal == nil {
		return nil
	}
	var err error
	terminal.closeOnce.Do(func() {
		// A TTY shell receives an explicit EOF command before the provider stream
		// closes. The Engine remains the owner of process cleanup.
		_, _ = terminal.connection.Write([]byte("exit\n"))
		err = terminal.connection.Close()
	})
	return err
}

func (terminal *dockerTerminal) Resize(ctx context.Context, size paasv1.TerminalSize) error {
	if terminal == nil || !validProviderExecID(terminal.execID) || ctx == nil ||
		paasv1.ValidateTerminalSize(size) != nil {
		return ErrTerminalFailed
	}
	path := "/exec/" + terminal.execID + "/resize?h=" + strconv.FormatUint(uint64(size.Rows), 10) +
		"&w=" + strconv.FormatUint(uint64(size.Columns), 10)
	_, err := dockerJSON(ctx, http.MethodPost, path, nil, http.StatusOK)
	return err
}

func (terminal *dockerTerminal) ExitCode(ctx context.Context) (int32, error) {
	if terminal == nil || !validProviderExecID(terminal.execID) || ctx == nil {
		return 0, ErrTerminalFailed
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		content, err := dockerJSON(ctx, http.MethodGet, "/exec/"+terminal.execID+"/json", nil, http.StatusOK)
		if err != nil {
			return 0, err
		}
		var inspection dockerExecInspection
		if decodeClosedJSON(content, &inspection) != nil || inspection.ExitCode < -2147483648 || inspection.ExitCode > 2147483647 {
			return 0, ErrTerminalFailed
		}
		if !inspection.Running {
			return int32(inspection.ExitCode), nil
		}
		select {
		case <-ctx.Done():
			return 0, ErrTerminalUnavailable
		case <-ticker.C:
		}
	}
}

func dockerJSON(ctx context.Context, method, path string, body []byte, expected int) ([]byte, error) {
	if ctx == nil || (method != http.MethodGet && method != http.MethodPost) ||
		!strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, ErrTerminalFailed
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialContext context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(dialContext, "unix", dockerEngineSocket)
		},
		DisableCompression: true,
		DisableKeepAlives:  true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var source io.Reader
	if body != nil {
		source = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, dockerEngineEndpoint+path, source)
	if err != nil {
		return nil, ErrTerminalFailed
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "matrix-node-terminal/v1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, ErrTerminalUnavailable
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maxEngineError+1))
	if err != nil || len(content) > maxEngineError {
		return nil, ErrTerminalFailed
	}
	if response.StatusCode != expected {
		if missingShell(content) {
			return nil, ErrTerminalUnsupported
		}
		return nil, classifyDockerStatus(response.StatusCode)
	}
	return content, nil
}

func decodeClosedJSON(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("Docker response contains trailing data")
	}
	return nil
}

func classifyDockerStatus(status int) error {
	switch status {
	case http.StatusNotFound, http.StatusConflict:
		return ErrTerminalFailed
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return ErrTerminalUnsupported
	default:
		return ErrTerminalUnavailable
	}
}

func missingShell(content []byte) bool {
	message := strings.ToLower(string(content))
	return strings.Contains(message, "/bin/sh") &&
		(strings.Contains(message, "no such file") || strings.Contains(message, "executable file not found"))
}

func validProviderContainerID(value string) bool { return validProviderHexID(value) }
func validProviderExecID(value string) bool      { return validProviderHexID(value) }

func validProviderHexID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
