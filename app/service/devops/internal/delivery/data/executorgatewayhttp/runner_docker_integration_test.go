//go:build linux

package executorgatewayhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorspoolfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnerjournalfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnersandboxdocker"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnerworkspacefile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runnerexecution"
)

const (
	runnerDockerIntegrationEnvironment = "MATRIX_RUNNER_DOCKER_INTEGRATION"
	adversarialSecretSentinel          = "matrix-attack-secret-must-not-survive"
	adversarialPathSentinel            = "/matrix/control-plane/private"
	crossTenantSourceSentinel          = "matrix-foreign-tenant-source-must-not-survive"
)

// TestRealDockerRunscRunnerCompletesMTLSExecution is the opt-in dedicated-host
// gate from a canonical source archive, through both mTLS gateway roles, to the
// production runner workflow and its real Docker/runsc side effect. It also
// drives an adversarial repository into the fixed PID and log-sanitization
// boundaries, then proves a whole-run log overflow is contained and removed.
func TestRealDockerRunscRunnerCompletesMTLSExecution(t *testing.T) {
	if os.Getenv(runnerDockerIntegrationEnvironment) != "1" {
		t.Skip("set MATRIX_RUNNER_DOCKER_INTEGRATION=1 on a dedicated Linux runner")
	}

	spool := gatewaySpool(t)
	pki := newGatewayTestPKI(t)
	adminServer := startAdminServer(t, spool, pki)
	runnerServer := startRunnerServer(t, spool, pki, func() time.Time {
		return time.Now().UTC().Truncate(time.Microsecond)
	})
	admin, err := NewAdminClient(
		adminServer.URL, gatewayServerName, pki.adminCertificate, pki.serverRoots,
	)
	if err != nil {
		t.Fatal(err)
	}
	admin.pollInterval = 5 * time.Millisecond
	runnerGateway, err := NewRunnerClient(
		runnerServer.URL, gatewayServerName, pki.runnerOneCertificate,
		pki.serverRoots, runnerNamespace,
	)
	if err != nil {
		t.Fatal(err)
	}

	journalRoot := privateRunnerIntegrationRoot(t)
	journalOwnership, err := runnerjournalfile.AcquireOwnership(journalRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := journalOwnership.Close(); closeErr != nil {
			t.Errorf("close runner journal ownership: %v", closeErr)
		}
	})
	journal, err := runnerjournalfile.New(journalRoot, runnerGateway.RunnerID())
	if err != nil {
		t.Fatal(err)
	}
	workspaces, err := runnerworkspacefile.New(
		privateRunnerIntegrationRoot(t), runnerGateway.RunnerID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := workspaces.Close(); closeErr != nil {
			t.Errorf("close runner workspaces: %v", closeErr)
		}
	})
	engine, err := runnersandboxdocker.New(
		"/var/run/docker.sock", privateRunnerIntegrationRoot(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := runnersandboxdocker.NewSandbox(engine)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := runnerexecution.NewService(
		runnerGateway, journal, workspaces, sandbox, runnerGateway,
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(devopsv1.FixedRunTimeoutSeconds+30)*time.Second,
	)
	defer cancel()
	request, archive := executableGatewayFixture(t)
	receipt, logs := executeRealRunnerRequest(
		t, ctx, spool, admin, runner, request, archive,
	)
	if !strings.Contains(logs, "example.invalid/matrixgateb") ||
		strings.Contains(logs, journalRoot) || strings.Contains(logs, "/var/run/docker.sock") {
		t.Fatalf(
			"real normalized log evidence is invalid: receipt=%#v logs=%q",
			receipt, logs,
		)
	}
	wantReceipt := gatewayReceipt(
		request, runnerGateway.RunnerID(), devopsbuildv1.ConclusionPassed,
		devopsbuildv1.StepConclusionPassed, devopsbuildv1.StepConclusionPassed,
	)
	if receipt != wantReceipt {
		t.Fatalf("real admin receipt=%#v logs=%q", receipt, logs)
	}
	assertRealRunnerContainersAbsent(t, ctx, workspaces, sandbox, request, archive)

	foreignRequest, foreignArchive, foreignWorkspace := publishForeignTenantWorkspace(
		t, ctx, workspaces,
	)
	adversarialRequest, adversarialArchive := adversarialGatewayFixture(
		t, foreignWorkspace.SourceRoot,
	)
	adversarialReceipt, adversarialLogs := executeRealRunnerRequest(
		t, ctx, spool, admin, runner, adversarialRequest, adversarialArchive,
	)
	wantAdversarialReceipt := gatewayReceipt(
		adversarialRequest, runnerGateway.RunnerID(), devopsbuildv1.ConclusionFailed,
		devopsbuildv1.StepConclusionFailed, devopsbuildv1.StepConclusionNotRun,
	)
	if adversarialReceipt != wantAdversarialReceipt ||
		!strings.Contains(adversarialLogs, "matrix-pid-limit-contained") ||
		!strings.Contains(adversarialLogs, "matrix-cross-tenant-contained") ||
		!strings.Contains(adversarialLogs, "matrix-traversal-symlink-contained") {
		t.Fatalf(
			"real adversarial receipt=%#v logs=%q",
			adversarialReceipt, adversarialLogs,
		)
	}
	for _, marker := range []string{
		"[matrix:secret-shaped]", "[matrix:absolute-path]",
		"[matrix:ansi-escape]", "[matrix:control-bytes]",
		"[matrix:invalid-utf8]", "[matrix:line-too-long]",
	} {
		if !strings.Contains(adversarialLogs, marker) {
			t.Fatalf("real adversarial logs omitted %q: %q", marker, adversarialLogs)
		}
	}
	for _, forbidden := range []string{
		adversarialSecretSentinel, adversarialPathSentinel,
		crossTenantSourceSentinel, foreignWorkspace.SourceRoot,
		strings.Repeat("x", int(devopsv1.FixedMaxLogLineBytes)+1),
	} {
		if strings.Contains(adversarialLogs, forbidden) {
			t.Fatalf("real adversarial logs retained unsafe content: %q", forbidden)
		}
	}
	assertRealRunnerContainersAbsent(
		t, ctx, workspaces, sandbox, adversarialRequest, adversarialArchive,
	)
	assertForeignTenantWorkspaceIntact(t, foreignWorkspace)
	assertRealRunnerContainersAbsent(
		t, ctx, workspaces, sandbox, foreignRequest, foreignArchive,
	)
	assertRealOversizedLogContained(t, ctx, workspaces, sandbox)

	entries, err := journal.Entries(ctx)
	if err != nil || len(entries) != 2 {
		t.Fatalf("real runner journal entries=%#v err=%v", entries, err)
	}
	for _, entry := range entries {
		if entry.Phase != port.RunnerJournalAcknowledged {
			t.Fatalf("real runner journal entry=%#v", entry)
		}
	}
}

func executeRealRunnerRequest(
	t *testing.T,
	ctx context.Context,
	spool *executorspoolfile.Spool,
	admin *AdminClient,
	runner *runnerexecution.Service,
	request devopsbuildv1.Request,
	archive []byte,
) (devopsbuildv1.Receipt, string) {
	t.Helper()
	type executeOutcome struct {
		receipt devopsbuildv1.Receipt
		err     error
	}
	executed := make(chan executeOutcome, 1)
	go func() {
		receipt, executeErr := admin.Execute(ctx, request, bytes.NewReader(archive))
		executed <- executeOutcome{receipt: receipt, err: executeErr}
	}()
	waitForGatewayExecution(t, ctx, spool, request)
	result, err := runner.WorkOnce(ctx)
	if err != nil || !result.Claimed || !result.Acknowledged || result.Deferred {
		t.Fatalf("real runner result=%#v err=%v", result, err)
	}
	outcome := <-executed
	if outcome.err != nil {
		t.Fatalf("real admin execution: %v", outcome.err)
	}
	return outcome.receipt, readRealRunnerLogs(t, ctx, admin, request)
}

func readRealRunnerLogs(
	t *testing.T,
	ctx context.Context,
	admin *AdminClient,
	request devopsbuildv1.Request,
) string {
	t.Helper()
	var normalized strings.Builder
	afterSequence := uint64(0)
	for batchIndex := 0; batchIndex < len(request.Steps); batchIndex++ {
		batch, found, err := admin.ReadLogs(ctx, request, afterSequence)
		if err != nil {
			t.Fatalf("read real runner logs after %d: %v", afterSequence, err)
		}
		if !found {
			break
		}
		if batch.Previous.LastSequence != afterSequence {
			t.Fatalf("real log cursor=%#v want after %d", batch.Previous, afterSequence)
		}
		for _, chunk := range batch.Chunks {
			normalized.WriteString(chunk.Content)
		}
		afterSequence = batch.Next.LastSequence
	}
	if _, found, err := admin.ReadLogs(ctx, request, afterSequence); err != nil || found {
		t.Fatalf("real runner log tail found=%t err=%v", found, err)
	}
	return normalized.String()
}

func assertRealRunnerContainersAbsent(
	t *testing.T,
	ctx context.Context,
	workspaces *runnerworkspacefile.Store,
	sandbox *runnersandboxdocker.Sandbox,
	request devopsbuildv1.Request,
	archive []byte,
) {
	t.Helper()
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaces.Ensure(
		ctx, executionID, request, io.NopCloser(bytes.NewReader(archive)),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range request.Steps {
		state, observeErr := sandbox.Observe(ctx, realRunnerReference(executionID, workspace, step))
		if observeErr != nil || state != port.RunnerSandboxAbsent {
			t.Fatalf(
				"real runner residual step=%d state=%q err=%v",
				step.Ordinal, state, observeErr,
			)
		}
	}
}

func publishForeignTenantWorkspace(
	t *testing.T,
	ctx context.Context,
	workspaces *runnerworkspacefile.Store,
) (devopsbuildv1.Request, []byte, port.RunnerWorkspace) {
	t.Helper()
	request, archive := gatewayFixtureWithFiles(t, 'a', []sourcearchive.File{
		integrationSourceFile("foreign.txt", crossTenantSourceSentinel),
		integrationSourceFile(
			"go.mod", "module example.invalid/matrixforeign\n\ngo 1.26.0\n",
		),
	})
	request.TenantID = "tenant-two"
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaces.Ensure(
		ctx, executionID, request, io.NopCloser(bytes.NewReader(archive)),
	)
	if err != nil {
		t.Fatalf("publish foreign tenant workspace: %v", err)
	}
	assertForeignTenantWorkspaceIntact(t, workspace)
	return request, archive, workspace
}

func assertForeignTenantWorkspaceIntact(
	t *testing.T,
	workspace port.RunnerWorkspace,
) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(workspace.SourceRoot, "foreign.txt"))
	if err != nil || string(content) != crossTenantSourceSentinel {
		t.Fatalf("foreign tenant workspace changed: bytes=%d err=%v", len(content), err)
	}
}

func assertRealOversizedLogContained(
	t *testing.T,
	ctx context.Context,
	workspaces *runnerworkspacefile.Store,
	sandbox *runnersandboxdocker.Sandbox,
) {
	t.Helper()
	request, archive := oversizedLogGatewayFixture(t)
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaces.Ensure(
		ctx, executionID, request, io.NopCloser(bytes.NewReader(archive)),
	)
	if err != nil {
		t.Fatal(err)
	}
	reference := realRunnerReference(executionID, workspace, request.Steps[0])
	if err := sandbox.Preflight(ctx); err != nil {
		t.Fatalf("preflight real oversized-log sandbox: %v", err)
	}
	if err := sandbox.Create(ctx, reference); err != nil {
		t.Fatalf("create real oversized-log sandbox: %v", err)
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		state, observeErr := sandbox.Observe(cleanupContext, reference)
		if observeErr == nil && (state == port.RunnerSandboxCreated ||
			state == port.RunnerSandboxRunning) {
			_, _ = sandbox.Cancel(cleanupContext, reference)
		}
		if deleteErr := sandbox.Delete(cleanupContext, reference); deleteErr != nil {
			t.Errorf("clean real oversized-log sandbox: %v", deleteErr)
		}
	}()
	if err := sandbox.Start(ctx, reference); err != nil {
		t.Fatalf("start real oversized-log sandbox: %v", err)
	}
	result, err := sandbox.Follow(ctx, reference, runnerlog.Progress{})
	if !errors.Is(err, runnersandboxdocker.ErrLogLimit) ||
		result.State != "" || len(result.Chunks) != 0 ||
		result.LogProgress != (runnerlog.Progress{}) {
		t.Fatalf("real oversized-log result=%#v err=%v", result, err)
	}
	state, err := sandbox.Cancel(ctx, reference)
	if err != nil || (state != port.RunnerSandboxCancelled &&
		state != port.RunnerSandboxFailed) {
		t.Fatalf("contain real oversized-log sandbox state=%q err=%v", state, err)
	}
	if err := sandbox.Delete(ctx, reference); err != nil {
		t.Fatalf("delete real oversized-log sandbox: %v", err)
	}
	state, err = sandbox.Observe(ctx, reference)
	if err != nil || state != port.RunnerSandboxAbsent {
		t.Fatalf("real oversized-log residual state=%q err=%v", state, err)
	}
}

func realRunnerReference(
	executionID string,
	workspace port.RunnerWorkspace,
	step devopsv1.VerificationStep,
) port.RunnerStepReference {
	digest := strings.TrimPrefix(executionID, "sha256:")
	return port.RunnerStepReference{
		EffectID:   "matrix-build-" + digest[:48],
		Step:       step,
		SourceRoot: workspace.SourceRoot,
	}
}

func executableGatewayFixture(t *testing.T) (devopsbuildv1.Request, []byte) {
	t.Helper()
	files := []sourcearchive.File{
		integrationSourceFile("calc.go", `package matrixgateb

func Add(left, right int) int { return left + right }
`),
		integrationSourceFile("calc_test.go", `package matrixgateb

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestAdd(t *testing.T) {
	if Add(19, 23) != 42 {
		t.Fatal("unexpected sum")
	}
}

func TestIsolation(t *testing.T) {
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS", "GITHUB_TOKEN",
		"CI_JOB_TOKEN", "SSH_AUTH_SOCK", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
	} {
		if os.Getenv(name) != "" {
			t.Fatalf("sensitive environment is not empty: %s", name)
		}
	}
	for _, name := range []string{"/var/run/docker.sock", "/dev/kvm", "/dev/mem", "/dev/dri"} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("protected host input is reachable: %s", name)
		}
	}
	if err := os.WriteFile("repository-write-probe", []byte("denied"), 0o600); err == nil {
		t.Fatal("repository source is writable")
	}
	if err := os.WriteFile("/matrix-root-write-probe", []byte("denied"), 0o600); err == nil {
		t.Fatal("container root is writable")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) > 1 {
		t.Fatalf("unexpected network interfaces: %v / %v", interfaces, err)
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagLoopback == 0 {
			t.Fatalf("non-loopback network interface is present: %v", networkInterface)
		}
	}
	connection, err := net.DialTimeout("tcp", "192.0.2.1:443", 100*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatal("unapproved egress succeeded")
	}
}
`),
		integrationSourceFile("go.mod", `module example.invalid/matrixgateb

go 1.26.0
`),
	}
	return gatewayFixtureWithFiles(t, 'd', files)
}

func adversarialGatewayFixture(
	t *testing.T,
	foreignSourceRoot string,
) (devopsbuildv1.Request, []byte) {
	t.Helper()
	if !strings.HasPrefix(foreignSourceRoot, "/") {
		t.Fatal("foreign source root is not absolute")
	}
	files := []sourcearchive.File{
		integrationSourceFile("guard_test.go", `package matrixgatebadversarial

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const attackSecret = "`+adversarialSecretSentinel+`"
const attackPath = "`+adversarialPathSentinel+`"
const foreignSource = `+strconv.Quote(foreignSourceRoot)+`

func TestAdversarialRepository(t *testing.T) {
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS", "GITHUB_TOKEN",
		"CI_JOB_TOKEN", "SSH_AUTH_SOCK", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
	} {
		if os.Getenv(name) != "" {
			t.Fatalf("sensitive environment is not empty: %s", name)
		}
	}
	for _, name := range []string{
		"/var/run/docker.sock", "/proc/1/root/var/run/docker.sock",
		"/dev/kvm", "/dev/mem", "/dev/dri",
	} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("protected host input is reachable: %s", name)
		}
	}
	for _, name := range []string{
		"/run/secrets/kubernetes.io/serviceaccount/token",
		"/root/.docker/config.json", "/etc/matrix/credentials",
	} {
		if content, err := os.ReadFile(name); err == nil || len(content) != 0 {
			t.Fatalf("protected credential input is readable: %s", name)
		}
	}
	if err := os.WriteFile("repository-write-probe", []byte("denied"), 0o600); err == nil {
		t.Fatal("repository source is writable")
	}
	if err := os.WriteFile("/matrix-root-write-probe", []byte("denied"), 0o600); err == nil {
		t.Fatal("container root is writable")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) > 1 {
		t.Fatalf("unexpected network interface count=%d", len(interfaces))
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagLoopback == 0 {
			t.Fatal("non-loopback network interface is present")
		}
	}
	for _, target := range []string{
		"192.0.2.1:443", "169.254.169.254:80", "10.0.0.1:443",
	} {
		connection, err := net.DialTimeout("tcp", target, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			t.Fatal("unapproved egress succeeded")
		}
	}
	if connection, err := net.DialTimeout(
		"unix", "/var/run/postgresql/.s.PGSQL.5432", 100*time.Millisecond,
	); err == nil {
		connection.Close()
		t.Fatal("control-plane database socket is reachable")
	}

	foreignFile := filepath.Join(foreignSource, "foreign.txt")
	if content, err := os.ReadFile(foreignFile); err == nil || len(content) != 0 {
		t.Fatal("foreign tenant workspace is directly readable")
	}
	if entries, err := os.ReadDir(foreignSource); err == nil || len(entries) != 0 {
		t.Fatal("foreign tenant workspace is listable")
	}
	traversal := "/workspace/src/../../" + strings.TrimPrefix(foreignFile, "/")
	if content, err := os.ReadFile(traversal); err == nil || len(content) != 0 {
		t.Fatal("parent traversal reached foreign tenant workspace")
	}
	if err := os.WriteFile(traversal, []byte("attacker"), 0o600); err == nil {
		t.Fatal("parent traversal changed foreign tenant workspace")
	}
	controlLink := "/cache/own-source-link"
	if err := os.Symlink("/workspace/src/guard_test.go", controlLink); err != nil {
		t.Fatal("create control symlink")
	}
	if content, err := os.ReadFile(controlLink); err != nil ||
		!bytes.Contains(content, []byte("TestAdversarialRepository")) {
		t.Fatal("control symlink is not usable")
	}
	foreignLink := "/cache/foreign-source-link"
	if err := os.Symlink(traversal, foreignLink); err != nil {
		t.Fatal("create foreign symlink")
	}
	if content, err := os.ReadFile(foreignLink); err == nil || len(content) != 0 {
		t.Fatal("symlink escaped into foreign tenant workspace")
	}

	const processAttempts = 384
	children := make([]*exec.Cmd, 0, processAttempts)
	var denied error
	for attempt := 0; attempt < processAttempts; attempt++ {
		child := exec.Command("sleep", "30")
		if err := child.Start(); err != nil {
			denied = err
			break
		}
		children = append(children, child)
	}
	for _, child := range children {
		_ = child.Process.Kill()
	}
	for _, child := range children {
		_ = child.Wait()
	}
	// runsc helper tasks consume the same fixed PID budget, so the exact number
	// of child processes is deliberately not a contract. Native cgroups report
	// EAGAIN at the limit while runsc reports ENOMEM; both are closed resource
	// denials. The attack must make progress and then hit one before all tries.
	resourceDenied := errors.Is(denied, syscall.EAGAIN) ||
		errors.Is(denied, syscall.ENOMEM)
	if !resourceDenied || len(children) == 0 ||
		len(children) >= processAttempts {
		t.Fatalf(
			"process containment count=%d eagain=%t enomem=%t",
			len(children), errors.Is(denied, syscall.EAGAIN),
			errors.Is(denied, syscall.ENOMEM),
		)
	}

	fmt.Println("matrix-pid-limit-contained")
	fmt.Println("matrix-cross-tenant-contained")
	fmt.Println("matrix-traversal-symlink-contained")
	fmt.Println("TOKEN=" + attackSecret)
	fmt.Println("attempted path " + attackPath)
	fmt.Println("\x1b[31munsafe ANSI\x1b[0m")
	if _, err := os.Stdout.Write([]byte("control\x00bytes\n")); err != nil {
		t.Fatal("write control-byte probe")
	}
	if _, err := os.Stdout.Write([]byte{'i', 'n', 'v', 'a', 'l', 'i', 'd', 0xff, '\n'}); err != nil {
		t.Fatal("write invalid UTF-8 probe")
	}
	fmt.Println(strings.Repeat("x", 16*1024+1))
	t.Fatal("intentional adversarial verification failure")
}
`),
		integrationSourceFile("go.mod", `module example.invalid/matrixgatebadversarial

go 1.26.0
`),
	}
	return gatewayFixtureWithFiles(t, 'e', files)
}

func oversizedLogGatewayFixture(t *testing.T) (devopsbuildv1.Request, []byte) {
	t.Helper()
	files := []sourcearchive.File{
		integrationSourceFile("oversized_test.go", `package matrixgateboversized

import (
	"os"
	"testing"
)

func TestWholeRunLogLimit(t *testing.T) {
	block := make([]byte, 64*1024)
	for index := range block {
		block[index] = 'z'
	}
	for chunk := 0; chunk < 129; chunk++ {
		if _, err := os.Stdout.Write(block); err != nil {
			t.Fatal("write whole-run log probe")
		}
	}
	t.Fatal("intentional whole-run log overflow")
}
`),
		integrationSourceFile("go.mod", `module example.invalid/matrixgateboversized

go 1.26.0
`),
	}
	return gatewayFixtureWithFiles(t, 'f', files)
}

func gatewayFixtureWithFiles(
	t *testing.T,
	identity byte,
	files []sourcearchive.File,
) (devopsbuildv1.Request, []byte) {
	t.Helper()
	request, _ := gatewayExecutionFixture(t, identity)
	var archive bytes.Buffer
	content, err := sourcearchive.Write(context.Background(), &archive, files)
	if err != nil {
		t.Fatal(err)
	}
	request.SourceArchiveDigest = digestGatewayBytes(archive.Bytes())
	request.SourceArchiveBytes = int64(archive.Len())
	request.SourceExpandedBytes = content.ExpandedBytes
	request.SourcePathCount = content.PathCount
	return request, append([]byte(nil), archive.Bytes()...)
}

func integrationSourceFile(path, content string) sourcearchive.File {
	payload := []byte(content)
	return sourcearchive.File{
		Path: path, Size: int64(len(payload)),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		},
	}
}

func privateRunnerIntegrationRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func waitForGatewayExecution(
	t *testing.T,
	ctx context.Context,
	spool *executorspoolfile.Spool,
	request devopsbuildv1.Request,
) {
	t.Helper()
	for {
		if _, err := spool.Observe(ctx, request); err == nil {
			return
		} else if !errors.Is(err, executorspoolfile.ErrNotFound) {
			t.Fatalf("observe submitted gateway execution: %v", err)
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
}
