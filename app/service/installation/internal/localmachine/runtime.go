package localmachine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
)

const maximumDockerOutput = 4 * 1024 * 1024

type dockerRuntime interface {
	Run(context.Context, io.Reader, ...string) ([]byte, bool, error)
}

type localDockerRuntime struct{}

func (localDockerRuntime) Run(
	ctx context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if ctx == nil {
		return nil, false, errors.New("Docker command context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	var output boundedOutput
	output.maximum = maximumDockerOutput
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Stdin = input
	command.Stdout = &output
	command.Stderr = io.Discard
	command.Env = localDockerEnvironment(os.Environ())
	if err := command.Start(); err != nil {
		return nil, false, err
	}
	err := command.Wait()
	if output.exceeded {
		return nil, true, errors.New("Docker command output exceeds its bound")
	}
	return append([]byte(nil), output.Bytes()...), true, err
}

func localDockerEnvironment(source []string) []string {
	result := make([]string, 0, len(source)+5)
	for _, entry := range source {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		switch strings.ToUpper(key) {
		case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_API_VERSION",
			"DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_DEFAULT_PLATFORM",
			"COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "COMPOSE_PROFILES",
			"COMPOSE_ENV_FILES", "COMPOSE_DISABLE_ENV_FILE", "COMPOSE_PATH_SEPARATOR",
			"COMPOSE_CONVERT_WINDOWS_PATHS", "COMPOSE_REMOVE_ORPHANS", "COMPOSE_IGNORE_ORPHANS",
			"COMPOSE_MENU", "COMPOSE_INTERACTIVE_NO_CLI", "DOCKER_CLI_HINTS":
			continue
		}
		result = append(result, entry)
	}
	return append(result,
		"DOCKER_HOST=unix:///var/run/docker.sock",
		"COMPOSE_MENU=0",
		"COMPOSE_INTERACTIVE_NO_CLI=1",
		"DOCKER_CLI_HINTS=false",
		"COMPOSE_DISABLE_ENV_FILE=1",
		"COMPOSE_REMOVE_ORPHANS=false",
	)
}

type boundedOutput struct {
	bytes.Buffer
	maximum  int
	exceeded bool
}

func (output *boundedOutput) Write(content []byte) (int, error) {
	if output.exceeded {
		return 0, errors.New("provider output exceeds its bound")
	}
	remaining := output.maximum - output.Len()
	if len(content) > remaining {
		if remaining > 0 {
			_, _ = output.Buffer.Write(content[:remaining])
		}
		output.exceeded = true
		return 0, errors.New("provider output exceeds its bound")
	}
	return output.Buffer.Write(content)
}
