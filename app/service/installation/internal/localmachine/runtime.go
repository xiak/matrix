package localmachine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
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
	command.Env = append(os.Environ(),
		"COMPOSE_MENU=0",
		"COMPOSE_INTERACTIVE_NO_CLI=1",
		"DOCKER_CLI_HINTS=false",
	)
	if err := command.Start(); err != nil {
		return nil, false, err
	}
	err := command.Wait()
	if output.exceeded {
		return nil, true, errors.New("Docker command output exceeds its bound")
	}
	return append([]byte(nil), output.Bytes()...), true, err
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
