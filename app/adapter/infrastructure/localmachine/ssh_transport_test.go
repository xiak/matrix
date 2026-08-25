package localmachine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	paasv1 "matrix/api/paas/v1"
)

type sshServerResponse struct {
	stdout           []byte
	stderr           []byte
	exitStatus       uint32
	block            bool
	blockBeforeReply bool
}

type ephemeralSSHServer struct {
	listener  net.Listener
	config    *ssh.ServerConfig
	hostKey   ssh.Signer
	responses map[string]sshServerResponse

	accepted      atomic.Int64
	commandMu     sync.Mutex
	commands      []string
	commandEvents chan string
	connMu        sync.Mutex
	conns         map[net.Conn]struct{}
	closed        chan struct{}
	closeOnce     sync.Once
	wg            sync.WaitGroup
}

func TestPinnedSSHAdapterInspectsEphemeralLinuxServer(t *testing.T) {
	clientSigner, _ := mustSSHSignerAndPEM(t)
	server := newEphemeralSSHServer(
		t,
		"matrix",
		clientSigner.PublicKey(),
		validSSHServerResponses(t, "/var/lib/matrix"),
	)
	credential := SSHCredential{username: "matrix", signer: clientSigner}
	resolver, err := NewStaticSSHCredentialResolver(NamedSSHCredential{
		Ref:        "credential-node-1",
		Credential: credential,
	})
	if err != nil {
		t.Fatalf("NewStaticSSHCredentialResolver() error = %v", err)
	}
	probe, err := newSSHHostProbe(resolver, goSSHProbeExecutor{
		maxOutputBytes: 1024,
		connectTimeout: 2 * time.Second,
		probeTimeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("newSSHHostProbe() error = %v", err)
	}
	binding := mustSSHBinding(
		t,
		server.endpoint(),
		server.hostKeyFingerprint(),
		"/var/lib/matrix",
	)
	adapter := mustRemoteAdapter(t, binding, probe)
	request := validInspectTargetRequest()
	request.Command.BindingRef = binding.ID()

	observation, err := adapter.InspectTarget(context.Background(), request)
	if err != nil {
		t.Fatalf("InspectTarget() through SSH error = %v", err)
	}
	if err := paasv1.ValidateTargetObservation(observation); err != nil {
		t.Fatalf("SSH observation is invalid: %v", err)
	}
	if observation.Health != paasv1.TargetHealthReady ||
		observation.IdentityFingerprint == "" ||
		observation.Capacity.CPUMillis != 4000 ||
		observation.Capacity.MemoryBytes != 8192*1024 ||
		observation.Capacity.StorageBytes != 16384*1024 ||
		observation.Labels["matrix-os"] != "linux" ||
		observation.Labels["matrix-arch"] != "amd64" ||
		observation.Labels["location"] != "remote" {
		t.Fatalf("SSH observation = %+v", observation)
	}

	expectedCommands := make([]string, 0, len(remoteProbeSequence))
	for _, id := range remoteProbeSequence {
		command, commandErr := remoteProbeCommand(id, "/var/lib/matrix")
		if commandErr != nil {
			t.Fatalf("remoteProbeCommand(%q) error = %v", id, commandErr)
		}
		expectedCommands = append(expectedCommands, command)
	}
	if got := server.recordedCommands(); !reflect.DeepEqual(got, expectedCommands) {
		t.Fatalf("executed SSH commands = %#v, want exact closed set %#v", got, expectedCommands)
	}
}

func TestPinnedSSHExecutorRejectsWrongHostKeyBeforeExec(t *testing.T) {
	clientSigner, _ := mustSSHSignerAndPEM(t)
	server := newEphemeralSSHServer(
		t,
		"matrix",
		clientSigner.PublicKey(),
		validSSHServerResponses(t, "/"),
	)
	executor := goSSHProbeExecutor{
		maxOutputBytes: 1024,
		connectTimeout: 2 * time.Second,
		probeTimeout:   time.Second,
	}
	_, err := executor.Execute(
		context.Background(),
		mustSSHBinding(t, server.endpoint(), pinnedTestHostKey(), "/"),
		SSHCredential{username: "matrix", signer: clientSigner},
		remoteProbeSequence,
	)
	requireProbeFailure(t, err, ProbeFailureHostKey, "ssh-handshake")
	if commands := server.recordedCommands(); len(commands) != 0 {
		t.Fatalf("wrong host key executed commands: %#v", commands)
	}
}

func TestPinnedSSHExecutorRejectsCredentialAndNormalizesFailure(t *testing.T) {
	authorizedSigner, _ := mustSSHSignerAndPEM(t)
	rejectedSigner, _ := mustSSHSignerAndPEM(t)
	server := newEphemeralSSHServer(
		t,
		"matrix",
		authorizedSigner.PublicKey(),
		validSSHServerResponses(t, "/"),
	)
	executor := goSSHProbeExecutor{
		maxOutputBytes: 1024,
		connectTimeout: 2 * time.Second,
		probeTimeout:   time.Second,
	}
	_, err := executor.Execute(
		context.Background(),
		mustSSHBinding(t, server.endpoint(), server.hostKeyFingerprint(), "/"),
		SSHCredential{username: "matrix", signer: rejectedSigner},
		remoteProbeSequence,
	)
	requireProbeFailure(t, err, ProbeFailurePermission, "ssh-authentication")
	if commands := server.recordedCommands(); len(commands) != 0 {
		t.Fatalf("rejected credential executed commands: %#v", commands)
	}
}

func TestPinnedSSHExecutorBoundsOutputWhileReading(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			clientSigner, _ := mustSSHSignerAndPEM(t)
			responses := validSSHServerResponses(t, "/")
			machineIDCommand, err := remoteProbeCommand(RemoteProbeMachineID, "/")
			if err != nil {
				t.Fatalf("remoteProbeCommand(machine-id) error = %v", err)
			}
			oversized := bytes.Repeat([]byte("a"), 1025)
			response := responses[machineIDCommand]
			if stream == "stdout" {
				response.stdout = oversized
			} else {
				response.stderr = oversized
			}
			responses[machineIDCommand] = response
			server := newEphemeralSSHServer(
				t,
				"matrix",
				clientSigner.PublicKey(),
				responses,
			)
			executor := goSSHProbeExecutor{
				maxOutputBytes: 1024,
				connectTimeout: 2 * time.Second,
				probeTimeout:   time.Second,
			}
			_, err = executor.Execute(
				context.Background(),
				mustSSHBinding(
					t,
					server.endpoint(),
					server.hostKeyFingerprint(),
					"/",
				),
				SSHCredential{username: "matrix", signer: clientSigner},
				remoteProbeSequence,
			)
			requireProbeFailure(
				t,
				err,
				ProbeFailureValidation,
				string(RemoteProbeMachineID),
			)
		})
	}
}

func TestPinnedSSHExecutorNormalizesProbeDeadline(t *testing.T) {
	clientSigner, _ := mustSSHSignerAndPEM(t)
	responses := validSSHServerResponses(t, "/")
	osCommand, err := remoteProbeCommand(RemoteProbeOS, "/")
	if err != nil {
		t.Fatalf("remoteProbeCommand(os) error = %v", err)
	}
	responses[osCommand] = sshServerResponse{block: true}
	server := newEphemeralSSHServer(t, "matrix", clientSigner.PublicKey(), responses)
	executor := goSSHProbeExecutor{
		maxOutputBytes: 1024,
		connectTimeout: 2 * time.Second,
		probeTimeout:   50 * time.Millisecond,
	}
	_, err = executor.Execute(
		context.Background(),
		mustSSHBinding(t, server.endpoint(), server.hostKeyFingerprint(), "/"),
		SSHCredential{username: "matrix", signer: clientSigner},
		remoteProbeSequence,
	)
	requireProbeFailure(t, err, ProbeFailureTimeout, string(RemoteProbeOS))
}

func TestUnknownRemoteProbeIsRejectedBeforeNetworkTransport(t *testing.T) {
	clientSigner, _ := mustSSHSignerAndPEM(t)
	server := newEphemeralSSHServer(
		t,
		"matrix",
		clientSigner.PublicKey(),
		validSSHServerResponses(t, "/"),
	)
	executor := goSSHProbeExecutor{
		maxOutputBytes: 1024,
		connectTimeout: 2 * time.Second,
		probeTimeout:   time.Second,
	}
	_, err := executor.Execute(
		context.Background(),
		mustSSHBinding(t, server.endpoint(), server.hostKeyFingerprint(), "/"),
		SSHCredential{username: "matrix", signer: clientSigner},
		[]RemoteProbeID{"caller-supplied-command"},
	)
	requireProbeFailure(t, err, ProbeFailureValidation, "caller-supplied-command")
	if got := server.accepted.Load(); got != 0 {
		t.Fatalf("unknown probe opened %d network connections, want zero", got)
	}
	if commands := server.recordedCommands(); len(commands) != 0 {
		t.Fatalf("unknown probe executed commands: %#v", commands)
	}

	_, err = executor.Execute(
		context.Background(),
		mustSSHBinding(t, server.endpoint(), server.hostKeyFingerprint(), "/"),
		SSHCredential{username: "matrix", signer: clientSigner},
		nil,
	)
	requireProbeFailure(t, err, ProbeFailureValidation, "ssh-probes")
	_, err = executor.Execute(
		context.Background(),
		mustSSHBinding(t, server.endpoint(), server.hostKeyFingerprint(), "/"),
		SSHCredential{username: "matrix", signer: clientSigner},
		[]RemoteProbeID{RemoteProbeOS, RemoteProbeOS},
	)
	requireProbeFailure(t, err, ProbeFailureValidation, string(RemoteProbeOS))
	if got := server.accepted.Load(); got != 0 {
		t.Fatalf("invalid probe sets opened %d network connections, want zero", got)
	}
}

func TestPinnedSSHExecutorHonorsCancellationDuringHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	clientSigner, _ := mustSSHSignerAndPEM(t)
	executor := goSSHProbeExecutor{
		maxOutputBytes: 1024,
		connectTimeout: 5 * time.Second,
		probeTimeout:   time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	binding := mustSSHBinding(t, listener.Addr().String(), pinnedTestHostKey(), "/")
	result := make(chan error, 1)
	go func() {
		_, executeErr := executor.Execute(
			ctx,
			binding,
			SSHCredential{username: "matrix", signer: clientSigner},
			remoteProbeSequence,
		)
		result <- executeErr
	}()
	var serverConnection net.Conn
	select {
	case serverConnection = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("SSH executor did not connect to stalled handshake server")
	}
	defer serverConnection.Close()
	cancel()
	select {
	case err := <-result:
		requireProbeFailure(t, err, ProbeFailureUnavailable, "ssh-handshake")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SSH handshake did not stop promptly after context cancellation")
	}
}

func TestPinnedSSHExecutorHonorsCancellationDuringExecStart(t *testing.T) {
	clientSigner, _ := mustSSHSignerAndPEM(t)
	responses := validSSHServerResponses(t, "/")
	machineIDCommand, err := remoteProbeCommand(RemoteProbeMachineID, "/")
	if err != nil {
		t.Fatalf("remoteProbeCommand(machine-id) error = %v", err)
	}
	responses[machineIDCommand] = sshServerResponse{blockBeforeReply: true}
	server := newEphemeralSSHServer(t, "matrix", clientSigner.PublicKey(), responses)
	executor := goSSHProbeExecutor{
		maxOutputBytes: 1024,
		connectTimeout: 2 * time.Second,
		probeTimeout:   5 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	binding := mustSSHBinding(
		t,
		server.endpoint(),
		server.hostKeyFingerprint(),
		"/",
	)
	result := make(chan error, 1)
	go func() {
		_, executeErr := executor.Execute(
			ctx,
			binding,
			SSHCredential{username: "matrix", signer: clientSigner},
			remoteProbeSequence,
		)
		result <- executeErr
	}()
	select {
	case command := <-server.commandEvents:
		if command != machineIDCommand {
			t.Fatalf("first command = %q, want machine-id command", command)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH server did not receive the first exec request")
	}
	cancel()
	select {
	case err := <-result:
		requireProbeFailure(
			t,
			err,
			ProbeFailureUnavailable,
			string(RemoteProbeMachineID),
		)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SSH exec start did not stop promptly after context cancellation")
	}
}

func newEphemeralSSHServer(
	t *testing.T,
	username string,
	authorizedKey ssh.PublicKey,
	responses map[string]sshServerResponse,
) *ephemeralSSHServer {
	t.Helper()
	hostSigner, _ := mustSSHSignerAndPEM(t)
	authorizedFingerprint := ssh.FingerprintSHA256(authorizedKey)
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(
			metadata ssh.ConnMetadata,
			key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			if metadata.User() != username ||
				ssh.FingerprintSHA256(key) != authorizedFingerprint {
				return nil, errors.New("public key rejected")
			}
			return nil, nil
		},
	}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	server := &ephemeralSSHServer{
		listener:      listener,
		config:        config,
		hostKey:       hostSigner,
		responses:     responses,
		conns:         make(map[net.Conn]struct{}),
		closed:        make(chan struct{}),
		commandEvents: make(chan string, 32),
	}
	server.wg.Add(1)
	go server.acceptLoop()
	t.Cleanup(server.Close)
	return server
}

func (server *ephemeralSSHServer) endpoint() string {
	return server.listener.Addr().String()
}

func (server *ephemeralSSHServer) hostKeyFingerprint() string {
	return ssh.FingerprintSHA256(server.hostKey.PublicKey())
}

func (server *ephemeralSSHServer) recordedCommands() []string {
	server.commandMu.Lock()
	defer server.commandMu.Unlock()
	return append([]string(nil), server.commands...)
}

func (server *ephemeralSSHServer) acceptLoop() {
	defer server.wg.Done()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.accepted.Add(1)
		server.connMu.Lock()
		server.conns[connection] = struct{}{}
		server.connMu.Unlock()
		server.wg.Add(1)
		go server.handleConnection(connection)
	}
}

func (server *ephemeralSSHServer) handleConnection(networkConnection net.Conn) {
	defer server.wg.Done()
	defer func() {
		server.connMu.Lock()
		delete(server.conns, networkConnection)
		server.connMu.Unlock()
		_ = networkConnection.Close()
	}()
	_, channels, requests, err := ssh.NewServerConn(networkConnection, server.config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, sessionRequests, err := channelRequest.Accept()
		if err != nil {
			continue
		}
		server.wg.Add(1)
		go server.handleSession(channel, sessionRequests)
	}
}

func (server *ephemeralSSHServer) handleSession(
	channel ssh.Channel,
	requests <-chan *ssh.Request,
) {
	defer server.wg.Done()
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct {
			Command string
		}
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		server.commandMu.Lock()
		server.commands = append(server.commands, payload.Command)
		server.commandMu.Unlock()
		response, found := server.responses[payload.Command]
		if !found {
			response = sshServerResponse{exitStatus: 127}
		}
		select {
		case server.commandEvents <- payload.Command:
		default:
		}
		if response.blockBeforeReply {
			<-server.closed
			return
		}
		_ = request.Reply(true, nil)
		if response.block {
			<-server.closed
			return
		}
		if len(response.stdout) != 0 {
			_, _ = channel.Write(response.stdout)
		}
		if len(response.stderr) != 0 {
			_, _ = channel.Stderr().Write(response.stderr)
		}
		_, _ = channel.SendRequest(
			"exit-status",
			false,
			ssh.Marshal(struct {
				Status uint32
			}{Status: response.exitStatus}),
		)
		return
	}
}

func (server *ephemeralSSHServer) Close() {
	server.closeOnce.Do(func() {
		close(server.closed)
		_ = server.listener.Close()
		server.connMu.Lock()
		for connection := range server.conns {
			_ = connection.Close()
		}
		server.connMu.Unlock()
		server.wg.Wait()
	})
}

func validSSHServerResponses(
	t *testing.T,
	storagePath string,
) map[string]sshServerResponse {
	t.Helper()
	outputs := map[RemoteProbeID][]byte{
		RemoteProbeMachineID: []byte("0123456789abcdef0123456789abcdef\n"),
		RemoteProbeOS:        []byte("Linux\n"),
		RemoteProbeArch:      []byte("x86_64\n"),
		RemoteProbeCPU:       []byte("4\n"),
		RemoteProbeMemory:    []byte("8192 4096\n"),
		RemoteProbeStorage:   []byte("16384 8192\n"),
		RemoteProbeDocker:    nil,
		RemoteProbeCompose:   nil,
	}
	responses := make(map[string]sshServerResponse, len(outputs))
	for _, id := range remoteProbeSequence {
		command, err := remoteProbeCommand(id, storagePath)
		if err != nil {
			t.Fatalf("remoteProbeCommand(%q) error = %v", id, err)
		}
		responses[command] = sshServerResponse{stdout: outputs[id]}
	}
	return responses
}

func requireProbeFailure(
	t *testing.T,
	err error,
	kind ProbeFailureKind,
	id string,
) {
	t.Helper()
	if err == nil {
		t.Fatal("expected probe failure, got nil")
	}
	var failure ProbeFailure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want ProbeFailure: %v", err, err)
	}
	if failure.Kind != kind || failure.ID != id {
		t.Fatalf("probe failure = %+v, want kind %s id %s", failure, kind, id)
	}
}
