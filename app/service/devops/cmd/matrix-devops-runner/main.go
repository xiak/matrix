// matrix-devops-runner is the outbound-only composition root for one
// dedicated Linux/amd64 execution node. It owns the private journal,
// workspace, and local Docker/runsc side effect, but no Matrix database,
// provider, IAM, Audit, PaaS, reporter, or executor-admin authority.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorgatewayhttp"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnerjournalfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnersandboxdocker"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnerworkspacefile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runnerexecution"
	"github.com/xiak/matrix/app/service/internal/processhttp"
	"github.com/xiak/matrix/app/service/internal/processmtls"
)

const (
	journalRootEnvironment          = "MATRIX_DEVOPS_RUNNER_JOURNAL_ROOT"
	workspaceRootEnvironment        = "MATRIX_DEVOPS_RUNNER_WORKSPACE_ROOT"
	storageRootEnvironment          = "MATRIX_DEVOPS_RUNNER_STORAGE_ROOT"
	dockerSocketEnvironment         = "MATRIX_DEVOPS_RUNNER_DOCKER_SOCKET"
	listenAddressEnvironment        = "MATRIX_DEVOPS_RUNNER_LISTEN_ADDRESS"
	gatewayOriginEnvironment        = "MATRIX_DEVOPS_RUNNER_GATEWAY_ORIGIN"
	gatewayNameEnvironment          = "MATRIX_DEVOPS_RUNNER_GATEWAY_SERVER_NAME"
	clientIdentityEnvironment       = "MATRIX_DEVOPS_RUNNER_CLIENT_IDENTITY"
	runnerNamespaceEnvironment      = "MATRIX_DEVOPS_RUNNER_NAMESPACE"
	credentialsDirectoryEnvironment = "CREDENTIALS_DIRECTORY"
	clientCertificateCredential     = "client.crt"
	clientPrivateKeyCredential      = "client.key"
	serverCACredential              = "server-ca.pem"

	idlePollInterval = 10 * time.Second
)

type configuration struct {
	journalRoot         string
	workspaceRoot       string
	storageRoot         string
	dockerSocket        string
	listenAddress       string
	gatewayOrigin       string
	gatewayName         string
	credentialDirectory string
	clientIdentity      string
	runnerNamespace     string
}

type runnerOutcome struct {
	result runnerexecution.Result
	err    error
}

type runnerReadiness struct {
	mutex sync.RWMutex
	ready bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix DevOps runner failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) (runErr error) {
	if ctx == nil {
		return errors.New("DevOps runner context is required")
	}
	config, err := loadConfiguration()
	if err != nil {
		return err
	}
	credentials, err := processmtls.LoadSystemdClientCredentials(
		config.credentialDirectory,
		clientCertificateCredential,
		clientPrivateKeyCredential,
		serverCACredential,
		config.clientIdentity,
		time.Now(),
	)
	if err != nil {
		return errors.New("DevOps runner mTLS identity is unavailable")
	}
	gateway, err := executorgatewayhttp.NewRunnerClient(
		config.gatewayOrigin,
		config.gatewayName,
		credentials.Certificate,
		credentials.ServerRoots,
		config.runnerNamespace,
	)
	if err != nil || gateway == nil ||
		devopsv1.ValidateID("runner.id", gateway.RunnerID()) != nil {
		return errors.New("DevOps runner gateway boundary is invalid")
	}

	journalOwnership, err := runnerjournalfile.AcquireOwnership(config.journalRoot)
	if err != nil {
		return errors.New("DevOps runner journal ownership is unavailable")
	}
	defer func() { runErr = errors.Join(runErr, journalOwnership.Close()) }()
	journal, err := runnerjournalfile.New(config.journalRoot, gateway.RunnerID())
	if err != nil {
		return errors.New("DevOps runner journal is unavailable")
	}
	workspaces, err := runnerworkspacefile.New(config.workspaceRoot, gateway.RunnerID())
	if err != nil {
		return errors.New("DevOps runner workspace boundary is unavailable")
	}
	defer func() { runErr = errors.Join(runErr, workspaces.Close()) }()
	engine, err := runnersandboxdocker.New(config.dockerSocket, config.storageRoot)
	if err != nil {
		return errors.New("DevOps runner Docker boundary is unavailable")
	}
	sandbox, err := runnersandboxdocker.NewSandbox(engine)
	if err != nil {
		return errors.New("DevOps runner sandbox boundary is unavailable")
	}
	runner, err := runnerexecution.NewService(
		gateway, journal, workspaces, sandbox, gateway,
	)
	if err != nil {
		return errors.New("DevOps runner workflow is unavailable")
	}

	readiness := &runnerReadiness{}
	handler, err := processhttp.NewReadinessHandler(readiness.check)
	if err != nil {
		return err
	}
	return processhttp.ServeWithBackground(
		ctx,
		config.listenAddress,
		handler,
		func(runnerContext context.Context) error {
			return runRunnerLoop(
				runnerContext, runner.WorkOnce, readiness, idlePollInterval,
			)
		},
	)
}

func runRunnerLoop(
	ctx context.Context,
	workOnce func(context.Context) (runnerexecution.Result, error),
	readiness *runnerReadiness,
	idleInterval time.Duration,
) error {
	if ctx == nil || workOnce == nil || readiness == nil || idleInterval <= 0 {
		return errors.New("DevOps runner loop configuration is invalid")
	}
	loopContext, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.NewTimer(time.Hour)
	if !idle.Stop() {
		<-idle.C
	}
	defer idle.Stop()
	outcomes := make(chan runnerOutcome, 1)
	startWork := func() {
		go func() {
			result, err := workOnce(loopContext)
			outcomes <- runnerOutcome{result: result, err: err}
		}()
	}
	startWork()
	for {
		select {
		case <-ctx.Done():
			readiness.set(false)
			return nil
		case <-idle.C:
			startWork()
		case outcome := <-outcomes:
			if outcome.err != nil || !validRunnerResult(outcome.result) {
				readiness.set(false)
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("DevOps runner execution cycle failed")
			}
			readiness.set(true)
			if outcome.result.Claimed {
				startWork()
				continue
			}
			idle.Reset(idleInterval)
		}
	}
}

func validRunnerResult(value runnerexecution.Result) bool {
	if !value.Claimed {
		return value.ExecutionID == "" && !value.Deferred && !value.Acknowledged
	}
	return devopsv1.ValidateDigest("runner.executionId", value.ExecutionID) == nil &&
		value.Deferred != value.Acknowledged
}

func (state *runnerReadiness) check(ctx context.Context) error {
	if state == nil || ctx == nil {
		return errors.New("DevOps runner readiness is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	state.mutex.RLock()
	defer state.mutex.RUnlock()
	if !state.ready {
		return errors.New("DevOps runner is not ready")
	}
	return nil
}

func (state *runnerReadiness) set(ready bool) {
	state.mutex.Lock()
	state.ready = ready
	state.mutex.Unlock()
}

func loadConfiguration() (configuration, error) {
	credentialsDirectory := os.Getenv(credentialsDirectoryEnvironment)
	if !validAbsolutePath(credentialsDirectory) {
		return configuration{}, errors.New("DevOps runner credential directory is invalid")
	}
	config := configuration{
		journalRoot:         os.Getenv(journalRootEnvironment),
		workspaceRoot:       os.Getenv(workspaceRootEnvironment),
		storageRoot:         os.Getenv(storageRootEnvironment),
		dockerSocket:        os.Getenv(dockerSocketEnvironment),
		listenAddress:       os.Getenv(listenAddressEnvironment),
		gatewayOrigin:       os.Getenv(gatewayOriginEnvironment),
		gatewayName:         os.Getenv(gatewayNameEnvironment),
		credentialDirectory: credentialsDirectory,
		clientIdentity:      os.Getenv(clientIdentityEnvironment),
		runnerNamespace:     os.Getenv(runnerNamespaceEnvironment),
	}
	for _, required := range []string{
		config.journalRoot, config.workspaceRoot, config.storageRoot,
		config.dockerSocket, config.listenAddress, config.gatewayOrigin,
		config.gatewayName, config.clientIdentity, config.runnerNamespace,
	} {
		if required == "" {
			return configuration{}, errors.New("DevOps runner configuration is incomplete")
		}
	}
	for _, candidate := range []string{
		config.journalRoot, config.workspaceRoot, config.storageRoot,
		config.dockerSocket,
	} {
		if !validAbsolutePath(candidate) {
			return configuration{}, errors.New("DevOps runner path configuration is invalid")
		}
	}
	if !strictDescendant(config.storageRoot, config.journalRoot) ||
		!strictDescendant(config.storageRoot, config.workspaceRoot) ||
		config.journalRoot == config.workspaceRoot ||
		strictDescendant(config.journalRoot, config.workspaceRoot) ||
		strictDescendant(config.workspaceRoot, config.journalRoot) {
		return configuration{}, errors.New("DevOps runner storage roots are invalid")
	}
	for _, protected := range []string{config.dockerSocket} {
		if strictDescendant(config.storageRoot, protected) {
			return configuration{}, errors.New("DevOps runner protected input overlaps writable storage")
		}
	}
	if config.storageRoot == credentialsDirectory ||
		strictDescendant(config.storageRoot, credentialsDirectory) ||
		strictDescendant(credentialsDirectory, config.storageRoot) {
		return configuration{}, errors.New("DevOps runner credential directory overlaps writable storage")
	}
	if !validLoopbackAddress(config.listenAddress) {
		return configuration{}, errors.New("DevOps runner readiness listener is invalid")
	}
	return config, nil
}

func validAbsolutePath(value string) bool {
	if value == "" || len(value) > 4096 || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	volume := filepath.VolumeName(value)
	return value != volume+string(filepath.Separator)
}

func strictDescendant(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != "." && !filepath.IsAbs(relative) &&
		relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validLoopbackAddress(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return false
	}
	address := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	return address != nil && address.IsLoopback() && address.String() == host &&
		portErr == nil && port >= 1 && port <= 65535 &&
		strconv.Itoa(port) == portText && net.JoinHostPort(host, portText) == value
}
