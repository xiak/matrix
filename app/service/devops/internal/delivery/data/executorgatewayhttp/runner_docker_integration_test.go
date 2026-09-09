//go:build linux

package executorgatewayhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runnerexecution"
)

const runnerDockerIntegrationEnvironment = "MATRIX_RUNNER_DOCKER_INTEGRATION"

// TestRealDockerRunscRunnerCompletesMTLSExecution is the opt-in dedicated-host
// gate from a canonical source archive, through both mTLS gateway roles, to the
// production runner workflow and its real Docker/runsc side effect.
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

	request, archive := executableGatewayFixture(t)
	type executeOutcome struct {
		receipt devopsbuildv1.Receipt
		err     error
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(devopsv1.FixedRunTimeoutSeconds+30)*time.Second,
	)
	defer cancel()
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

	var normalized strings.Builder
	afterSequence := uint64(0)
	for batchIndex := 0; batchIndex < len(request.Steps); batchIndex++ {
		batch, found, readErr := admin.ReadLogs(ctx, request, afterSequence)
		if readErr != nil {
			t.Fatalf("read real runner logs after %d: %v", afterSequence, readErr)
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
	if _, found, readErr := admin.ReadLogs(ctx, request, afterSequence); readErr != nil || found {
		t.Fatalf("real runner log tail found=%t err=%v", found, readErr)
	}
	logs := normalized.String()
	if !strings.Contains(logs, "example.invalid/matrixgateb") ||
		strings.Contains(logs, journalRoot) || strings.Contains(logs, "/var/run/docker.sock") {
		t.Fatalf(
			"real normalized log evidence is invalid: receipt=%#v logs=%q",
			outcome.receipt, logs,
		)
	}
	wantReceipt := gatewayReceipt(
		request, runnerGateway.RunnerID(), devopsbuildv1.ConclusionPassed,
		devopsbuildv1.StepConclusionPassed, devopsbuildv1.StepConclusionPassed,
	)
	if outcome.receipt != wantReceipt {
		t.Fatalf("real admin receipt=%#v logs=%q", outcome.receipt, logs)
	}
	entries, err := journal.Entries(ctx)
	if err != nil || len(entries) != 1 || entries[0].Phase != port.RunnerJournalAcknowledged {
		t.Fatalf("real runner journal entries=%#v err=%v", entries, err)
	}
}

func executableGatewayFixture(t *testing.T) (devopsbuildv1.Request, []byte) {
	t.Helper()
	request, _ := gatewayExecutionFixture(t, 'd')
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
