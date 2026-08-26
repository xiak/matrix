package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/test/composefixture"
)

func assertRealComposeWorkerWorkflow(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	apiPool *pgxpool.Pool,
	workerPool *pgxpool.Pool,
	placementUsecase *createplacement.Usecase,
	fixture integrationFixture,
	prefix string,
) {
	t.Helper()
	fixtureImage, err := composefixture.Import(ctx)
	if err != nil {
		t.Fatalf("import worker Compose fixture: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = fixtureImage.Close(cleanupContext)
	})

	spec := applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[0])
	secretReference := *spec.Components[0].Bindings[1].SecretVersion
	secretSource := t.TempDir()
	if err := os.Chmod(secretSource, 0o700); err != nil {
		t.Fatalf("protect worker secret root: %v", err)
	}
	secretResolver, err := composeadapter.NewFileSecretResolver(secretSource)
	if err != nil {
		t.Fatalf("create worker file SecretResolver: %v", err)
	}
	secretDirectory := filepath.Join(secretSource, string(secretReference.SecretID))
	if err := os.Mkdir(secretDirectory, 0o700); err != nil {
		t.Fatalf("create worker secret directory: %v", err)
	}
	secretPlaintext := []byte("worker-offline-secret-value")
	if err := os.WriteFile(
		filepath.Join(secretDirectory, secretReference.Version), secretPlaintext, 0o600,
	); err != nil {
		t.Fatalf("provision worker secret version: %v", err)
	}
	secretHash := sha256.Sum256(secretPlaintext)
	secretDigest := "sha256:" + hex.EncodeToString(secretHash[:])

	stateRoot := t.TempDir()
	runtime := &workerComposeRuntime{delegate: composeadapter.NewLocalRuntime()}
	executor, err := composeadapter.New(composeadapter.Config{
		BindingRef: "compose-real-postgres", BindingRoot: stateRoot,
		Artifacts: workerArtifactResolver{
			artifactDigest: integrationDigest(prefix + "-artifact"), imageID: fixtureImage.ID,
		},
		Secrets: secretResolver, Runtime: runtime,
	})
	if err != nil {
		t.Fatalf("create worker Compose executor: %v", err)
	}
	t.Cleanup(func() {
		project, found := runtime.lastProject()
		if !found {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = composeadapter.NewLocalRuntime().Stop(cleanupContext, composeadapter.RuntimeProject{
			Name: project.Name, Directory: project.Directory,
			EffectDocument:      project.ObservationDocument,
			ObservationDocument: project.ObservationDocument,
			TimeoutSeconds:      10,
		})
	})

	expandExecutionTargetCapacity(t, ctx, admin, fixture.targetID)
	workerFixture := newDeploymentWorkerFixture(
		t, apiPool, workerPool, placementUsecase, executor,
		"compose-real-postgres", 20*time.Second,
	)
	requestedBy := paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "real-compose-user"}
	deploymentID := paasv1.ResourceID(prefix + "-real-compose-deployment")
	created := submitWorkerDeployment(
		t,
		ctx,
		workerFixture.application,
		applicationlifecycle.SubmitCommand{
			Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "real-compose-deploy"),
			DeploymentID:  deploymentID, Name: "real-compose-deployment", Spec: spec,
			IdempotencyKey: "real-compose-deploy",
		},
		paasv1.OperationDeploy,
	)
	processWorkerOperation(t, ctx, workerFixture.worker)
	ready, operation := loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, created.Operation.ID)
	assertWorkerOutcome(t, ready, operation, 1, 1, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)
	project, found := runtime.lastProject()
	if !found {
		t.Fatal("real Compose runtime did not record its deterministic project")
	}
	_, networkID := assertWorkerComposeProject(t, project.Name)
	probeWorkerFixture(t, fixtureImage.ID, networkID, "one", secretDigest, "1")

	updated := submitWorkerDeployment(
		t,
		ctx,
		workerFixture.application,
		applicationlifecycle.SubmitCommand{
			Authorization:           integrationAuthorization(fixture.tenantA, requestedBy, "real-compose-update"),
			DeploymentID:            deploymentID,
			Spec:                    applicationIntegrationSpec(fixture, fixture.configurationRevisionIDs[1]),
			ExpectedResourceVersion: ready.Metadata.ResourceVersion,
			IdempotencyKey:          "real-compose-update",
		},
		paasv1.OperationUpdate,
	)
	runtime.injectUnknown()
	processWorkerOperation(t, ctx, workerFixture.worker)
	applying, operation := loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, updated.Operation.ID)
	if operation.State != paasv1.OperationReconciling || applying.Status.Phase != paasv1.DeploymentApplying {
		t.Fatalf("real unknown effect state = %#v / %#v", applying.Status, operation)
	}
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 2)
	assertWorkerComposeProject(t, project.Name)
	processDueWorkerOperation(t, ctx, workerFixture.worker)
	ready, operation = loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, updated.Operation.ID)
	assertWorkerOutcome(t, ready, operation, 2, 2, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	if runtime.applyCount() != 2 {
		t.Fatalf("real worker replayed an effect before observe: %d applies", runtime.applyCount())
	}
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)
	_, networkID = assertWorkerComposeProject(t, project.Name)
	probeWorkerFixture(t, fixtureImage.ID, networkID, "two", secretDigest, "2")

	rolledBack, err := workerFixture.application.Rollback(ctx, applicationlifecycle.RollbackCommand{
		Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "real-compose-rollback"),
		DeploymentID:  deploymentID, SourceGeneration: 1,
		ExpectedResourceVersion: ready.Metadata.ResourceVersion,
		IdempotencyKey:          "real-compose-rollback",
	})
	if err != nil {
		t.Fatalf("submit real Compose rollback: %v", err)
	}
	processWorkerOperation(t, ctx, workerFixture.worker)
	ready, operation = loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, rolledBack.Operation.ID)
	assertWorkerOutcome(t, ready, operation, 3, 3, paasv1.DeploymentReady, paasv1.OperationSucceeded)
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 1)
	_, networkID = assertWorkerComposeProject(t, project.Name)
	probeWorkerFixture(t, fixtureImage.ID, networkID, "one", secretDigest, "1")

	stopSpec := ready.Spec
	stopSpec.DesiredState = paasv1.DeploymentDesiredStopped
	stopping := submitWorkerDeployment(
		t,
		ctx,
		workerFixture.application,
		applicationlifecycle.SubmitCommand{
			Authorization: integrationAuthorization(fixture.tenantA, requestedBy, "real-compose-stop"),
			DeploymentID:  deploymentID, Spec: stopSpec,
			ExpectedResourceVersion: ready.Metadata.ResourceVersion,
			IdempotencyKey:          "real-compose-stop",
		},
		paasv1.OperationStop,
	)
	activePlacement := ready.Status.PlacementDecisionID
	processWorkerOperation(t, ctx, workerFixture.worker)
	stopped, operation := loadWorkerOutcome(t, ctx, admin, fixture.tenantA, deploymentID, stopping.Operation.ID)
	assertWorkerOutcome(t, stopped, operation, 4, 4, paasv1.DeploymentStopped, paasv1.OperationSucceeded)
	assertReservationState(t, ctx, admin, fixture.tenantA, activePlacement, "RELEASED")
	assertConsumingClaims(t, ctx, admin, fixture.targetID, 0)
	assertWorkerComposeProjectAbsent(t, project.Name)
	assertWorkerTreeExcludes(t, stateRoot, string(secretPlaintext))
	assertWorkerTreeExcludes(t, stateRoot, secretSource)
	assertExecutionPersistenceExcludes(
		t, ctx, admin, fixture.tenantA, deploymentID, string(secretPlaintext),
	)
}

type workerArtifactResolver struct {
	artifactDigest string
	imageID        string
}

func (resolver workerArtifactResolver) ResolveVerifiedImage(
	_ context.Context,
	artifact paasv1.ArtifactRef,
) (composeadapter.VerifiedImage, error) {
	if artifact.Digest != resolver.artifactDigest {
		return composeadapter.VerifiedImage{}, errors.New("fixture artifact digest differs")
	}
	return composeadapter.VerifiedImage{
		ArtifactDigest: artifact.Digest, LocalReference: resolver.imageID,
	}, nil
}

type workerComposeRuntime struct {
	delegate composeadapter.Runtime
	mu       sync.Mutex
	unknown  bool
	applies  int
	project  composeadapter.RuntimeProject
}

func (runtime *workerComposeRuntime) Apply(
	ctx context.Context,
	project composeadapter.RuntimeProject,
) error {
	if err := runtime.delegate.Apply(ctx, project); err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.applies++
	runtime.project = project
	if runtime.unknown {
		runtime.unknown = false
		return composeadapter.ErrEffectOutcomeUnknown
	}
	return nil
}

func (runtime *workerComposeRuntime) Observe(
	ctx context.Context,
	project composeadapter.RuntimeProject,
) ([]composeadapter.RuntimeContainer, error) {
	return runtime.delegate.Observe(ctx, project)
}

func (runtime *workerComposeRuntime) Stop(
	ctx context.Context,
	project composeadapter.RuntimeProject,
) error {
	return runtime.delegate.Stop(ctx, project)
}

func (runtime *workerComposeRuntime) injectUnknown() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.unknown = true
}

func (runtime *workerComposeRuntime) applyCount() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.applies
}

func (runtime *workerComposeRuntime) lastProject() (composeadapter.RuntimeProject, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.project, runtime.project.Name != ""
}

func probeWorkerFixture(
	t *testing.T,
	imageID, networkID, setting, secretDigest, generation string,
) {
	t.Helper()
	probeContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := composefixture.Probe(
		probeContext, imageID, networkID, setting, secretDigest, generation,
	); err != nil {
		t.Fatal(err)
	}
}

func assertWorkerComposeProject(t *testing.T, project string) (string, string) {
	t.Helper()
	containerIDs := workerDockerLines(t,
		"container", "ls", "--all",
		"--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.ID}}",
	)
	networkIDs := workerDockerLines(t,
		"network", "ls",
		"--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.ID}}",
	)
	if len(containerIDs) != 1 || len(networkIDs) != 1 {
		t.Fatalf("real worker project containers/networks = %d/%d, want 1/1", len(containerIDs), len(networkIDs))
	}
	if output := workerDockerOutput(t, "port", containerIDs[0]); strings.TrimSpace(output) != "" {
		t.Fatalf("real worker application published a host port: %q", output)
	}
	return containerIDs[0], networkIDs[0]
}

func assertWorkerComposeProjectAbsent(t *testing.T, project string) {
	t.Helper()
	containers := workerDockerLines(t,
		"container", "ls", "--all",
		"--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.ID}}",
	)
	networks := workerDockerLines(t,
		"network", "ls",
		"--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.ID}}",
	)
	if len(containers) != 0 || len(networks) != 0 {
		t.Fatalf("stopped worker project retained containers/networks = %v/%v", containers, networks)
	}
}

func workerDockerLines(t *testing.T, arguments ...string) []string {
	t.Helper()
	result := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(workerDockerOutput(t, arguments...)), "\n") {
		if value := strings.TrimSpace(line); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func workerDockerOutput(t *testing.T, arguments ...string) string {
	t.Helper()
	commandContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		if len(output) > 2048 {
			output = output[:2048]
		}
		t.Fatalf("Docker worker assertion failed: %v: %s", err, output)
	}
	return string(output)
}

func assertWorkerTreeExcludes(t *testing.T, root, forbidden string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(content), forbidden) {
			return fmt.Errorf("secret material entered %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertExecutionPersistenceExcludes(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
	forbidden string,
) {
	t.Helper()
	var found bool
	err := admin.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM paas.deployment_generations
			 WHERE tenant_id = $1 AND deployment_id = $2
			   AND strpos(document::text, $3) > 0
			UNION ALL
			SELECT 1
			  FROM paas.operations
			 WHERE tenant_id = $1 AND target_id = $2
			   AND (strpos(document::text, $3) > 0 OR strpos(COALESCE(error::text, ''), $3) > 0)
			UNION ALL
			SELECT 1
			  FROM paas.adapter_commands
			 WHERE tenant_id = $1 AND deployment_id = $2
			   AND strpos(document::text, $3) > 0
			UNION ALL
			SELECT 1
			  FROM paas.adapter_receipts AS receipt
			  JOIN paas.adapter_commands AS command
			    ON command.tenant_id = receipt.tenant_id AND command.id = receipt.command_id
			 WHERE command.tenant_id = $1 AND command.deployment_id = $2
			   AND strpos(COALESCE(receipt.normalized_error::text, '') || receipt.evidence::text, $3) > 0
			UNION ALL
			SELECT 1
			  FROM paas.deployment_observations
			 WHERE tenant_id = $1 AND deployment_id = $2
			   AND strpos(document::text, $3) > 0
			UNION ALL
			SELECT 1
			  FROM paas.audit_outbox AS audit
			  JOIN paas.operations AS operation
			    ON operation.tenant_id = audit.tenant_id AND operation.id = audit.operation_id
			 WHERE operation.tenant_id = $1 AND operation.target_id = $2
			   AND strpos(audit.document::text, $3) > 0
		)
	`, tenantID, deploymentID, forbidden).Scan(&found)
	if err != nil {
		t.Fatalf("inspect execution persistence for secret material: %v", err)
	}
	if found {
		t.Fatal("secret plaintext entered PostgreSQL execution or Audit state")
	}
}
