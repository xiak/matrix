package localmachine

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	errSSHHostKeyMismatch = errors.New("SSH host key mismatch")
	errSSHOutputLimit     = errors.New("SSH probe output limit exceeded")
)

type goSSHProbeExecutor struct {
	maxOutputBytes int64
	connectTimeout time.Duration
	probeTimeout   time.Duration
}

type sshProbeConnection struct {
	network net.Conn
	client  *ssh.Client
}

type preparedRemoteProbe struct {
	id      RemoteProbeID
	command string
}

func (executor goSSHProbeExecutor) Execute(
	ctx context.Context,
	binding MachineBinding,
	credential SSHCredential,
	probes []RemoteProbeID,
) (map[RemoteProbeID]remoteProbeResult, error) {
	if executor.maxOutputBytes <= 0 {
		executor.maxOutputBytes = 64 * 1024
	}
	if executor.connectTimeout <= 0 {
		executor.connectTimeout = 10 * time.Second
	}
	if executor.probeTimeout <= 0 {
		executor.probeTimeout = 5 * time.Second
	}
	if err := ValidateMachineBinding(binding); err != nil || binding.kind != BindingSSH {
		return nil, ProbeFailure{Kind: ProbeFailureValidation, ID: "ssh-binding"}
	}
	if err := ValidateSSHCredential(credential); err != nil {
		return nil, ProbeFailure{Kind: ProbeFailurePermission, ID: "ssh-credential"}
	}
	if len(probes) == 0 {
		return nil, ProbeFailure{Kind: ProbeFailureValidation, ID: "ssh-probes"}
	}
	prepared := make([]preparedRemoteProbe, 0, len(probes))
	seen := make(map[RemoteProbeID]struct{}, len(probes))
	for _, id := range probes {
		if _, duplicate := seen[id]; duplicate {
			return nil, ProbeFailure{Kind: ProbeFailureValidation, ID: string(id)}
		}
		command, err := remoteProbeCommand(id, binding.storagePath)
		if err != nil {
			return nil, ProbeFailure{Kind: ProbeFailureValidation, ID: string(id)}
		}
		seen[id] = struct{}{}
		prepared = append(prepared, preparedRemoteProbe{id: id, command: command})
	}
	connection, err := executor.dial(ctx, binding, credential)
	if err != nil {
		return nil, err
	}
	defer connection.client.Close()

	results := make(map[RemoteProbeID]remoteProbeResult, len(probes))
	for _, probe := range prepared {
		probeContext, cancel := context.WithTimeout(ctx, executor.probeTimeout)
		result, err := executor.run(
			probeContext,
			connection,
			probe.id,
			probe.command,
		)
		cancel()
		if err != nil {
			return nil, err
		}
		results[probe.id] = result
	}
	return results, nil
}

func (executor goSSHProbeExecutor) dial(
	ctx context.Context,
	binding MachineBinding,
	credential SSHCredential,
) (*sshProbeConnection, error) {
	connectContext, cancel := context.WithTimeout(ctx, executor.connectTimeout)
	defer cancel()
	dialer := net.Dialer{}
	networkConnection, err := dialer.DialContext(
		connectContext,
		"tcp",
		binding.endpoint,
	)
	if err != nil {
		return nil, networkFailure(connectContext, "ssh-connect")
	}
	hostKeyMismatch := false
	config := &ssh.ClientConfig{
		User: credential.username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(credential.signer),
		},
		HostKeyCallback: func(
			_ string,
			_ net.Addr,
			key ssh.PublicKey,
		) error {
			actual := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare(
				[]byte(actual),
				[]byte(binding.hostKeySHA256),
			) != 1 {
				hostKeyMismatch = true
				return errSSHHostKeyMismatch
			}
			return nil
		},
		Timeout: executor.connectTimeout,
	}
	stopHandshakeCancellation := context.AfterFunc(connectContext, func() {
		_ = networkConnection.Close()
	})
	clientConnection, channels, requests, err := ssh.NewClientConn(
		networkConnection,
		binding.endpoint,
		config,
	)
	stopHandshakeCancellation()
	if err != nil {
		_ = networkConnection.Close()
		if hostKeyMismatch || errors.Is(err, errSSHHostKeyMismatch) {
			return nil, ProbeFailure{Kind: ProbeFailureHostKey, ID: "ssh-handshake"}
		}
		if strings.Contains(err.Error(), "ssh: unable to authenticate") {
			return nil, ProbeFailure{Kind: ProbeFailurePermission, ID: "ssh-authentication"}
		}
		return nil, networkFailure(connectContext, "ssh-handshake")
	}
	if err := connectContext.Err(); err != nil {
		_ = clientConnection.Close()
		return nil, contextProbeFailure(err, "ssh-handshake")
	}
	return &sshProbeConnection{
		network: networkConnection,
		client:  ssh.NewClient(clientConnection, channels, requests),
	}, nil
}

type boundedReadResult struct {
	output []byte
	err    error
}

func (executor goSSHProbeExecutor) run(
	ctx context.Context,
	connection *sshProbeConnection,
	id RemoteProbeID,
	command string,
) (remoteProbeResult, error) {
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.network.Close()
	})
	defer stopCancellation()
	session, err := connection.client.NewSession()
	if err != nil {
		return remoteProbeResult{}, networkFailure(ctx, string(id))
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return remoteProbeResult{}, ProbeFailure{Kind: ProbeFailureInternal, ID: string(id)}
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return remoteProbeResult{}, ProbeFailure{Kind: ProbeFailureInternal, ID: string(id)}
	}
	err = session.Start(command)
	if err != nil {
		return remoteProbeResult{}, classifySSHSessionError(ctx, id, err)
	}
	if err := ctx.Err(); err != nil {
		return remoteProbeResult{}, contextProbeFailure(err, string(id))
	}

	stdoutResult := make(chan boundedReadResult, 1)
	stderrResult := make(chan boundedReadResult, 1)
	waitResult := make(chan error, 1)
	go func() {
		output, readErr := readBounded(stdout, executor.maxOutputBytes)
		stdoutResult <- boundedReadResult{output: output, err: readErr}
	}()
	go func() {
		output, readErr := readBounded(stderr, executor.maxOutputBytes)
		stderrResult <- boundedReadResult{output: output, err: readErr}
	}()
	go func() {
		waitResult <- session.Wait()
	}()

	var stdoutValue boundedReadResult
	var stderrValue boundedReadResult
	var waitErr error
	stdoutDone := false
	stderrDone := false
	waitDone := false
	for !stdoutDone || !stderrDone || !waitDone {
		select {
		case <-ctx.Done():
			_ = session.Close()
			return remoteProbeResult{}, contextProbeFailure(ctx.Err(), string(id))
		case stdoutValue = <-stdoutResult:
			stdoutDone = true
			if stdoutValue.err != nil {
				_ = session.Close()
				return remoteProbeResult{}, outputFailure(ctx, id, stdoutValue.err)
			}
		case stderrValue = <-stderrResult:
			stderrDone = true
			if stderrValue.err != nil {
				_ = session.Close()
				return remoteProbeResult{}, outputFailure(ctx, id, stderrValue.err)
			}
		case waitErr = <-waitResult:
			waitDone = true
		}
	}
	if err := ctx.Err(); err != nil {
		return remoteProbeResult{}, contextProbeFailure(err, string(id))
	}
	_ = stderrValue.output
	if waitErr == nil {
		return remoteProbeResult{output: stdoutValue.output, succeeded: true}, nil
	}
	var exitError *ssh.ExitError
	if errors.As(waitErr, &exitError) {
		return remoteProbeResult{output: stdoutValue.output, succeeded: false}, nil
	}
	return remoteProbeResult{}, classifySSHSessionError(ctx, id, waitErr)
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	output, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(output)) > limit {
		return nil, errSSHOutputLimit
	}
	return output, nil
}

func outputFailure(
	ctx context.Context,
	id RemoteProbeID,
	err error,
) ProbeFailure {
	if ctx.Err() != nil {
		return contextProbeFailure(ctx.Err(), string(id))
	}
	if errors.Is(err, errSSHOutputLimit) {
		return ProbeFailure{Kind: ProbeFailureValidation, ID: string(id)}
	}
	return ProbeFailure{Kind: ProbeFailureUnavailable, ID: string(id)}
}

func classifySSHSessionError(
	ctx context.Context,
	id RemoteProbeID,
	err error,
) ProbeFailure {
	if ctx.Err() != nil {
		return contextProbeFailure(ctx.Err(), string(id))
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return ProbeFailure{Kind: ProbeFailureTimeout, ID: string(id)}
	}
	return ProbeFailure{Kind: ProbeFailureUnavailable, ID: string(id)}
}

func networkFailure(ctx context.Context, id string) ProbeFailure {
	if ctx.Err() != nil {
		return contextProbeFailure(ctx.Err(), id)
	}
	return ProbeFailure{Kind: ProbeFailureUnavailable, ID: id}
}
