package phase1e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/release"
)

const (
	applicationID            paasv1.ResourceID = "phase1-application"
	configurationID          paasv1.ResourceID = "phase1-configuration"
	configurationRevisionOne paasv1.ResourceID = "phase1-configuration-r1"
	configurationRevisionTwo paasv1.ResourceID = "phase1-configuration-r2"
	applicationRevisionID    paasv1.ResourceID = "phase1-application-r1"
	deploymentID             paasv1.ResourceID = "phase1-deployment"
	placementPolicyID        paasv1.ResourceID = "placement-policy-local"
	secretID                 paasv1.ResourceID = "phase1-credential"
	secretVersion                              = "version-0001"
	settingOne                                 = "phase1-setting-one-e24f"
	settingTwo                                 = "phase1-setting-two-91ad"
)

type gate struct {
	config          options
	releases        releasePair
	edge            *edgeClient
	sensitive       [][]byte
	workloadProject string
	workloadRunning string
}

func newGate(config options, releases releasePair) *gate {
	return &gate{config: config, releases: releases, edge: newEdgeClient(config.edge)}
}

func (value *gate) beforeRestart(ctx context.Context) error {
	defer value.edge.close()
	if err := value.assertFreshHost(ctx); err != nil {
		return err
	}
	if _, err := os.Stat(value.config.root); err == nil || !errors.Is(err, os.ErrNotExist) {
		return fail("empty-installation-root")
	}
	install, err := runMX(ctx, value.releases.a, "install", []string{
		"--bundle", value.releases.a.Root,
		"--root", value.config.root,
		"--trust-key", value.config.trustKey,
	}, value.pathLeakage())
	if err != nil || install.ReleaseID != value.releases.a.Manifest.Release.ID || !install.Changed {
		return fail("release-a-install")
	}
	state, err := assertPlatform(ctx, value.config.root, value.releases.a.Manifest, "")
	if err != nil {
		return err
	}
	dataRootBefore, err := os.Stat(filepath.Join(value.config.root, filepath.FromSlash(layout.PostgresData)))
	if err != nil || !dataRootBefore.IsDir() {
		return fail("postgres-data-identity")
	}
	emit("release-a-install")

	if err := value.repeatedStatusAndVerify(ctx, value.releases.a, value.releases.a.Manifest.Release.ID, ""); err != nil {
		return err
	}
	emit("release-a-status-verify")

	initialPassword, err := os.ReadFile(filepath.Join(
		value.config.root, filepath.FromSlash(layout.InitialAdministratorPassword),
	))
	if err != nil || len(initialPassword) == 0 {
		clear(initialPassword)
		return fail("iam-initial-password")
	}
	defer clear(initialPassword)
	newPassword, err := randomPassword(rand.Reader)
	if err != nil {
		return fail("iam-new-password")
	}
	defer clear(newPassword)
	firstSession, err := value.edge.login(ctx, initialPassword, "phase1-login-initial")
	if err != nil {
		return fail("iam-login-initial")
	}
	defer clear(firstSession)
	value.edge.addForbidden(initialPassword, newPassword, firstSession)
	if err := value.edge.changePassword(ctx, firstSession, initialPassword, newPassword); err != nil {
		return fail("iam-change-password")
	}
	if err := value.edge.logout(ctx, firstSession); err != nil {
		return fail("iam-logout-initial")
	}
	bearer, err := value.edge.login(ctx, newPassword, "phase1-login-current")
	if err != nil {
		return fail("iam-login-current")
	}
	defer clear(bearer)
	value.edge.addForbidden(bearer)
	emit("iam-user-authority-through-apisix")

	secret, secretDigest, err := value.provisionSecret()
	if err != nil {
		return err
	}
	defer clear(secret)
	value.edge.addForbidden(secret)
	value.sensitive = [][]byte{initialPassword, newPassword, firstSession, bearer, secret}
	application, err := value.createApplication(ctx, bearer)
	if err != nil {
		return err
	}
	if err := value.assertWorkload(ctx, value.releases.a.Manifest, application.deployment, 1, "1", settingOne, secretDigest); err != nil {
		return err
	}
	if active, err := value.activeCapacityClaims(ctx, state.InstallationID); err != nil || active != 1 {
		return fail("active-capacity-after-deploy")
	}
	emit("application-generation-one")

	updated, err := value.updateConfiguration(ctx, bearer, application.deployment)
	if err != nil {
		return err
	}
	if err := value.assertWorkload(ctx, value.releases.a.Manifest, updated, 2, "2", settingTwo, secretDigest); err != nil {
		return err
	}
	emit("application-generation-two")

	wantInitialAudit := map[auditv1.Action]string{
		auditv1.ActionIAMBootstrapApplied:              "",
		auditv1.ActionIAMSessionIssued:                 "",
		auditv1.ActionIAMPasswordChanged:               "principal-admin",
		auditv1.ActionIAMAuthorizationDecided:          "",
		auditv1.ActionPaaSApplicationCreated:           string(applicationID),
		auditv1.ActionPaaSConfigurationCreated:         string(configurationID),
		auditv1.ActionPaaSConfigurationRevisionCreated: string(configurationRevisionTwo),
		auditv1.ActionPaaSApplicationRevisionCreated:   string(applicationRevisionID),
		auditv1.ActionPaaSDeploymentCreated:            string(deploymentID),
		auditv1.ActionPaaSDeploymentUpdated:            string(deploymentID),
	}
	recordsBeforeBackup, err := value.edge.waitAuditActions(ctx, bearer, wantInitialAudit)
	if err != nil || !scanAuditForConfigurationValues(recordsBeforeBackup, settingOne, settingTwo) {
		return fail("initial-audit-delivery")
	}
	if _, err := value.edge.verifyAuditChain(ctx, bearer); err != nil {
		return fail("initial-audit-integrity")
	}
	recordsBeforeBackup, err = value.edge.waitAuditActions(ctx, bearer, map[auditv1.Action]string{
		auditv1.ActionAuditRecordsRead:       "",
		auditv1.ActionAuditIntegrityVerified: "",
	})
	if err != nil {
		return fail("audit-access-delivery")
	}
	backupBaseline := auditRecordHashes(recordsBeforeBackup)
	emit("audit-query-integrity-through-apisix")

	backup, err := runMX(ctx, value.releases.a, "backup", []string{"--root", value.config.root}, value.forbidden(secret, newPassword, bearer))
	if err != nil || backup.BackupID == "" || !backup.Changed {
		return fail("protected-backup")
	}
	emit("protected-backup")

	if err := value.failedUpgrade(ctx, secret, newPassword, bearer); err != nil {
		return err
	}
	if _, err := assertPlatform(ctx, value.config.root, value.releases.a.Manifest, ""); err != nil {
		return err
	}
	if err := assertNoPlatformReleaseContainers(ctx, value.releases.b.Manifest.Release.ID); err != nil {
		return err
	}
	if err := value.assertWorkload(ctx, value.releases.a.Manifest, updated, 2, "2", settingTwo, secretDigest); err != nil {
		return err
	}
	if err := value.repeatedStatusAndVerify(ctx, value.releases.a, value.releases.a.Manifest.Release.ID, ""); err != nil {
		return err
	}
	emit("automatic-upgrade-rollback")

	upgrade, err := runMX(ctx, value.releases.a, "upgrade", []string{
		"--bundle", value.releases.b.Root, "--root", value.config.root,
	}, value.forbidden(secret, newPassword, bearer))
	if err != nil || upgrade.ReleaseID != value.releases.b.Manifest.Release.ID ||
		upgrade.PreviousID != value.releases.a.Manifest.Release.ID || !upgrade.Changed {
		return fail("release-b-upgrade")
	}
	if _, err := assertPlatform(
		ctx, value.config.root, value.releases.b.Manifest, value.releases.a.Manifest.Release.ID,
	); err != nil {
		return err
	}
	if err := value.assertWorkload(ctx, value.releases.b.Manifest, updated, 2, "2", settingTwo, secretDigest); err != nil {
		return err
	}
	if err := value.assertApplicationHistory(ctx, bearer, 2); err != nil {
		return err
	}
	recordsAfterUpgrade, err := value.edge.allAuditRecords(ctx, bearer)
	if err != nil || !containsAuditHistory(recordsAfterUpgrade, backupBaseline) {
		return fail("upgrade-audit-history")
	}
	if err := value.repeatedStatusAndVerify(
		ctx, value.releases.b, value.releases.b.Manifest.Release.ID, value.releases.a.Manifest.Release.ID,
	); err != nil {
		return err
	}
	emit("release-b-upgrade-preservation")

	rollback, err := runMX(ctx, value.releases.b, "rollback", []string{"--root", value.config.root}, value.forbidden(secret, newPassword, bearer))
	if err != nil || rollback.ReleaseID != value.releases.a.Manifest.Release.ID ||
		rollback.PreviousID != "" || !rollback.Changed {
		return fail("platform-rollback")
	}
	if _, err := assertPlatform(ctx, value.config.root, value.releases.a.Manifest, ""); err != nil {
		return err
	}
	if err := assertNoPlatformReleaseContainers(ctx, value.releases.b.Manifest.Release.ID); err != nil {
		return err
	}
	if err := value.assertWorkload(ctx, value.releases.a.Manifest, updated, 2, "2", settingTwo, secretDigest); err != nil {
		return err
	}
	if err := value.repeatedStatusAndVerify(ctx, value.releases.a, value.releases.a.Manifest.Release.ID, ""); err != nil {
		return err
	}
	emit("explicit-platform-rollback")

	value.workloadRunning = ""
	recovery, err := runMX(ctx, value.releases.a, "recover", []string{
		"--root", value.config.root, "--backup", backup.BackupID,
	}, value.forbidden(secret, newPassword, bearer))
	if err != nil || recovery.ReleaseID != value.releases.a.Manifest.Release.ID ||
		recovery.PreviousID != "" || !recovery.Changed {
		return fail("backup-recovery")
	}
	if _, err := assertPlatform(ctx, value.config.root, value.releases.a.Manifest, ""); err != nil {
		return err
	}
	recovered, err := value.readDeployment(ctx, bearer)
	if err != nil || recovered.Generation != 2 || recovered.Status.ObservedGeneration != 2 ||
		recovered.Status.Phase != paasv1.DeploymentReady {
		return fail("recovered-application-state")
	}
	if err := value.assertWorkload(ctx, value.releases.a.Manifest, recovered, 2, "2", settingTwo, secretDigest); err != nil {
		return err
	}
	recoveredAudit, err := value.edge.allAuditRecords(ctx, bearer)
	if err != nil || !containsAuditHistory(recoveredAudit, backupBaseline) {
		return fail("recovered-audit-history")
	}
	if err := value.repeatedStatusAndVerify(ctx, value.releases.a, value.releases.a.Manifest.Release.ID, ""); err != nil {
		return err
	}
	emit("backup-recovery")

	rolledBack, err := value.rollbackApplication(ctx, bearer, recovered)
	if err != nil {
		return err
	}
	if err := value.assertWorkload(ctx, value.releases.a.Manifest, rolledBack, 3, "1", settingOne, secretDigest); err != nil {
		return err
	}
	rollbackAudit, err := value.edge.waitAuditActions(ctx, bearer, map[auditv1.Action]string{
		auditv1.ActionPaaSDeploymentRolledBack: string(deploymentID),
	})
	if err != nil || !containsAuditHistory(rollbackAudit, backupBaseline) {
		return fail("application-rollback-audit")
	}
	emit("application-rollback")

	stopped, err := value.stopApplication(ctx, bearer, rolledBack)
	if err != nil {
		return err
	}
	if stopped.Status.Phase != paasv1.DeploymentStopped || stopped.Status.ObservedGeneration != 4 {
		return fail("stopped-application-state")
	}
	if err := value.assertWorkloadRemoved(ctx); err != nil {
		return err
	}
	if active, err := value.activeCapacityClaims(ctx, state.InstallationID); err != nil || active != 0 {
		return fail("released-capacity-after-stop")
	}
	if _, err := value.edge.waitAuditActions(ctx, bearer, map[auditv1.Action]string{
		auditv1.ActionPaaSDeploymentStopped: string(deploymentID),
	}); err != nil {
		return fail("stop-audit-delivery")
	}
	if _, err := value.edge.verifyAuditChain(ctx, bearer); err != nil {
		return fail("final-audit-integrity")
	}
	if err := value.edge.logout(ctx, bearer); err != nil {
		return fail("iam-logout-current")
	}
	emit("application-stop-capacity-release")

	if err := value.writeAndScanSupport(ctx, value.releases.a, "phase1-before-restart.json", backup.BackupID, secret, newPassword, bearer); err != nil {
		return err
	}
	dataRootAfter, err := os.Stat(filepath.Join(value.config.root, filepath.FromSlash(layout.PostgresData)))
	if err != nil || !os.SameFile(dataRootBefore, dataRootAfter) {
		return fail("postgres-data-identity-preservation")
	}
	if err := assertNoExternalRoute(); err != nil {
		return err
	}
	emit("bounded-support-zero-leakage")
	emit("restart-required")
	return nil
}

func (value *gate) afterRestart(ctx context.Context) error {
	defer value.edge.close()
	if err := assertNoExternalRoute(); err != nil {
		return err
	}
	if _, err := os.Stat(value.config.root); err != nil {
		return fail("restart-installation-root")
	}
	if err := value.repeatedStatusAndVerify(ctx, value.releases.a, value.releases.a.Manifest.Release.ID, ""); err != nil {
		return err
	}
	state, err := assertPlatform(ctx, value.config.root, value.releases.a.Manifest, "")
	if err != nil {
		return err
	}
	if err := value.assertWorkloadRemoved(ctx); err != nil {
		return err
	}
	if active, err := value.activeCapacityClaims(ctx, state.InstallationID); err != nil || active != 0 {
		return fail("restart-capacity-release")
	}
	if err := value.writeAndScanSupport(ctx, value.releases.a, "phase1-after-restart.json", nil); err != nil {
		return err
	}
	if err := assertNoExternalRoute(); err != nil {
		return err
	}
	emit("post-restart-status-verify")
	emit("complete-offline-lifecycle")
	return nil
}

func (value *gate) assertFreshHost(ctx context.Context) error {
	if err := assertNoExternalRoute(); err != nil {
		return err
	}
	if _, err := os.Lstat(value.config.root); !errors.Is(err, os.ErrNotExist) {
		return fail("clean-installation-root")
	}
	if err := assertEmptyDocker(ctx); err != nil {
		return err
	}
	return nil
}

func (value *gate) pathLeakage() [][]byte {
	result := [][]byte{
		[]byte(value.config.root), []byte(value.config.releaseA), []byte(value.config.releaseB),
		[]byte(value.config.trustKey),
	}
	return append(result, value.sensitive...)
}

func (value *gate) forbidden(values ...[]byte) [][]byte {
	result := value.pathLeakage()
	return append(result, values...)
}

func (value *gate) repeatedStatusAndVerify(
	ctx context.Context,
	bundle release.VerifiedBundle,
	releaseID, previousID string,
) error {
	before, err := readJournal(ctx, value.config.root)
	if err != nil {
		return fail("status-journal-before")
	}
	for index := 0; index < 2; index++ {
		result, err := runMX(ctx, bundle, "status", []string{"--root", value.config.root}, value.pathLeakage())
		if err != nil || result.ReleaseID != releaseID || result.PreviousID != previousID || result.Changed {
			return fail("repeated-status")
		}
	}
	after, err := readJournal(ctx, value.config.root)
	if err != nil || !journalsEqual(before, after) {
		return fail("status-read-only")
	}
	for index := 0; index < 2; index++ {
		result, err := runMX(ctx, bundle, "verify", []string{"--root", value.config.root}, value.pathLeakage())
		if err != nil || result.ReleaseID != releaseID || result.PreviousID != previousID {
			return fail("repeated-verify")
		}
	}
	_, err = assertPlatform(ctx, value.config.root, bundle.Manifest, previousID)
	return err
}

func journalsEqual(left, right lifecycle.Journal) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

type applicationState struct {
	deployment paasv1.Deployment
}

func (value *gate) createApplication(
	ctx context.Context,
	bearer []byte,
) (applicationState, error) {
	if _, err := value.edge.createResource(
		ctx, "/api/paas/v1/applications", "phase1-create-application", bearer,
		paasv1.CreateApplicationRequest{ID: applicationID, Name: "phase1-application"},
		paasv1.OperationCreateApplication, paasv1.ResourceRef{Kind: "Application", ID: applicationID},
	); err != nil {
		return applicationState{}, fail("create-application")
	}
	if _, err := value.edge.createResource(
		ctx, "/api/paas/v1/configurations", "phase1-create-configuration", bearer,
		paasv1.CreateConfigurationRequest{
			ID: configurationID, Name: "phase1-configuration", ApplicationID: applicationID,
		},
		paasv1.OperationCreateConfiguration, paasv1.ResourceRef{Kind: "Configuration", ID: configurationID},
	); err != nil {
		return applicationState{}, fail("create-configuration")
	}
	values := map[string]string{"MATRIX_SETTING": settingOne, "MATRIX_GENERATION": "1"}
	if _, err := value.edge.createResource(
		ctx, "/api/paas/v1/configuration-revisions", "phase1-create-configuration-r1", bearer,
		paasv1.CreateConfigurationRevisionRequest{
			ID: configurationRevisionOne, Name: "phase1-configuration-r1",
			Spec: paasv1.ConfigurationRevisionSpec{
				ConfigurationID: configurationID, Values: values,
				ContentDigest: paasv1.ConfigurationValuesDigest(values),
			},
		},
		paasv1.OperationCreateConfigurationRevision,
		paasv1.ResourceRef{Kind: "ConfigurationRevision", ID: configurationRevisionOne},
	); err != nil {
		return applicationState{}, fail("create-configuration-revision-one")
	}
	workload, ok := workloadImage(value.releases.a.Manifest)
	if !ok {
		return applicationState{}, fail("release-workload")
	}
	revision := paasv1.CreateApplicationRevisionRequest{
		ID: applicationRevisionID, Name: "phase1-application-r1",
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: applicationID, Revision: "revision-0001",
			ContentDigest: fixedDigest("phase1-application-revision-one"),
			Components: []paasv1.ApplicationRevisionComponent{{
				Name: "web",
				Artifact: paasv1.ArtifactRef{
					Kind: paasv1.ArtifactOCIImage, Locator: "offline.matrix.invalid/verification",
					Digest: workload.SourceDigest,
				},
				Resources: paasv1.ResourceRequirements{CPUMillis: 100, MemoryBytes: 32 * 1024 * 1024},
				Endpoints: []paasv1.ApplicationEndpoint{{
					Name: "ready", Port: 8080, Protocol: paasv1.EndpointHTTP,
					Visibility: paasv1.EndpointPrivate,
				}},
				Inputs: []paasv1.ComponentInput{
					{Name: "settings", Kind: paasv1.InputConfiguration, Injection: paasv1.InjectionEnvironment, Required: true},
					{Name: "credential", Kind: paasv1.InputSecret, Injection: paasv1.InjectionFile, Required: true},
				},
			}},
		},
	}
	if _, err := value.edge.createResource(
		ctx, "/api/paas/v1/application-revisions", "phase1-create-application-r1", bearer,
		revision, paasv1.OperationCreateApplicationRevision,
		paasv1.ResourceRef{Kind: "ApplicationRevision", ID: applicationRevisionID},
	); err != nil {
		return applicationState{}, fail("create-application-revision")
	}
	spec := deploymentSpec(configurationRevisionOne, paasv1.DeploymentDesiredRunning)
	operation, err := value.edge.mutateDeployment(
		ctx, http.MethodPost, "/api/paas/v1/deployments", "phase1-create-deployment", "", bearer,
		paasv1.CreateDeploymentRequest{ID: deploymentID, Name: "phase1-deployment", Spec: spec},
		paasv1.OperationDeploy, deploymentID,
	)
	if err != nil {
		return applicationState{}, fail("create-deployment")
	}
	if _, err := value.edge.waitOperation(ctx, bearer, operation.ID); err != nil {
		return applicationState{}, fail("deploy-operation")
	}
	deployment, err := value.edge.waitDeployment(ctx, bearer, deploymentID, 1, paasv1.DeploymentReady)
	if err != nil {
		return applicationState{}, fail("deploy-convergence")
	}
	return applicationState{deployment: deployment}, nil
}

func deploymentSpec(
	configurationRevisionID paasv1.ResourceID,
	desired paasv1.DeploymentDesiredState,
) paasv1.DeploymentSpec {
	return paasv1.DeploymentSpec{
		ApplicationRevisionID: applicationRevisionID,
		PlacementPolicyID:     placementPolicyID,
		DesiredState:          desired,
		Components: []paasv1.DeploymentComponent{{
			Name: "web", Replicas: 1,
			Bindings: []paasv1.ComponentBinding{
				{Name: "settings", ConfigurationRevisionID: configurationRevisionID},
				{Name: "credential", SecretVersion: &paasv1.SecretVersionReference{
					SecretID: secretID, Version: secretVersion,
				}},
			},
		}},
	}
}

func (value *gate) updateConfiguration(
	ctx context.Context,
	bearer []byte,
	current paasv1.Deployment,
) (paasv1.Deployment, error) {
	values := map[string]string{"MATRIX_SETTING": settingTwo, "MATRIX_GENERATION": "2"}
	if _, err := value.edge.createResource(
		ctx, "/api/paas/v1/configuration-revisions", "phase1-create-configuration-r2", bearer,
		paasv1.CreateConfigurationRevisionRequest{
			ID: configurationRevisionTwo, Name: "phase1-configuration-r2",
			Spec: paasv1.ConfigurationRevisionSpec{
				ConfigurationID: configurationID, Values: values,
				ContentDigest: paasv1.ConfigurationValuesDigest(values),
			},
		},
		paasv1.OperationCreateConfigurationRevision,
		paasv1.ResourceRef{Kind: "ConfigurationRevision", ID: configurationRevisionTwo},
	); err != nil {
		return paasv1.Deployment{}, fail("create-configuration-revision-two")
	}
	spec := deploymentSpec(configurationRevisionTwo, paasv1.DeploymentDesiredRunning)
	operation, err := value.edge.mutateDeployment(
		ctx, http.MethodPut, "/api/paas/v1/deployments/"+string(deploymentID),
		"phase1-update-deployment", formatResourceVersion(current.Metadata.ResourceVersion), bearer,
		spec, paasv1.OperationUpdate, deploymentID,
	)
	if err != nil {
		return paasv1.Deployment{}, fail("update-deployment")
	}
	if _, err := value.edge.waitOperation(ctx, bearer, operation.ID); err != nil {
		return paasv1.Deployment{}, fail("update-operation")
	}
	deployment, err := value.edge.waitDeployment(ctx, bearer, deploymentID, 2, paasv1.DeploymentReady)
	if err != nil {
		return paasv1.Deployment{}, fail("update-convergence")
	}
	return deployment, nil
}

func (value *gate) rollbackApplication(
	ctx context.Context,
	bearer []byte,
	current paasv1.Deployment,
) (paasv1.Deployment, error) {
	operation, err := value.edge.mutateDeployment(
		ctx, http.MethodPost, "/api/paas/v1/deployments/"+string(deploymentID)+"/rollback",
		"phase1-rollback-deployment", formatResourceVersion(current.Metadata.ResourceVersion), bearer,
		paasv1.RollbackDeploymentRequest{SourceGeneration: 1},
		paasv1.OperationRollback, deploymentID,
	)
	if err != nil {
		return paasv1.Deployment{}, fail("rollback-deployment")
	}
	if _, err := value.edge.waitOperation(ctx, bearer, operation.ID); err != nil {
		return paasv1.Deployment{}, fail("rollback-operation")
	}
	deployment, err := value.edge.waitDeployment(ctx, bearer, deploymentID, 3, paasv1.DeploymentReady)
	if err != nil {
		return paasv1.Deployment{}, fail("rollback-convergence")
	}
	return deployment, nil
}

func (value *gate) stopApplication(
	ctx context.Context,
	bearer []byte,
	current paasv1.Deployment,
) (paasv1.Deployment, error) {
	spec := current.Spec
	spec.DesiredState = paasv1.DeploymentDesiredStopped
	operation, err := value.edge.mutateDeployment(
		ctx, http.MethodPut, "/api/paas/v1/deployments/"+string(deploymentID),
		"phase1-stop-deployment", formatResourceVersion(current.Metadata.ResourceVersion), bearer,
		spec, paasv1.OperationStop, deploymentID,
	)
	if err != nil {
		return paasv1.Deployment{}, fail("stop-deployment")
	}
	if _, err := value.edge.waitOperation(ctx, bearer, operation.ID); err != nil {
		return paasv1.Deployment{}, fail("stop-operation")
	}
	deployment, err := value.edge.waitDeployment(ctx, bearer, deploymentID, current.Generation+1, paasv1.DeploymentStopped)
	if err != nil {
		return paasv1.Deployment{}, fail("stop-convergence")
	}
	return deployment, nil
}

func (value *gate) readDeployment(ctx context.Context, bearer []byte) (paasv1.Deployment, error) {
	var deployment paasv1.Deployment
	header, err := value.edge.get(ctx, "/api/paas/v1/deployments/"+string(deploymentID), bearer, &deployment)
	if err != nil || paasv1.ValidateDeployment(deployment) != nil ||
		!isQuotedResourceVersion(header, deployment.Metadata.ResourceVersion) {
		return paasv1.Deployment{}, errors.New("read Deployment failed")
	}
	return deployment, nil
}

func (value *gate) assertApplicationHistory(
	ctx context.Context,
	bearer []byte,
	wantGeneration uint64,
) error {
	reads := []struct {
		path     string
		validate func(any) bool
		value    any
	}{
		{"/api/paas/v1/applications/" + string(applicationID), func(item any) bool {
			resource := item.(*paasv1.Application)
			return paasv1.ValidateApplication(*resource) == nil && resource.Metadata.ID == applicationID
		}, &paasv1.Application{}},
		{"/api/paas/v1/configurations/" + string(configurationID), func(item any) bool {
			resource := item.(*paasv1.Configuration)
			return paasv1.ValidateConfiguration(*resource) == nil && resource.Metadata.ID == configurationID
		}, &paasv1.Configuration{}},
		{"/api/paas/v1/configuration-revisions/" + string(configurationRevisionOne), func(item any) bool {
			resource := item.(*paasv1.ConfigurationRevision)
			return paasv1.ValidateConfigurationRevision(*resource) == nil && resource.Metadata.ID == configurationRevisionOne
		}, &paasv1.ConfigurationRevision{}},
		{"/api/paas/v1/configuration-revisions/" + string(configurationRevisionTwo), func(item any) bool {
			resource := item.(*paasv1.ConfigurationRevision)
			return paasv1.ValidateConfigurationRevision(*resource) == nil && resource.Metadata.ID == configurationRevisionTwo
		}, &paasv1.ConfigurationRevision{}},
		{"/api/paas/v1/application-revisions/" + string(applicationRevisionID), func(item any) bool {
			resource := item.(*paasv1.ApplicationRevision)
			return paasv1.ValidateApplicationRevision(*resource) == nil && resource.Metadata.ID == applicationRevisionID
		}, &paasv1.ApplicationRevision{}},
	}
	for _, read := range reads {
		if _, err := value.edge.get(ctx, read.path, bearer, read.value); err != nil || !read.validate(read.value) {
			return fail("application-history")
		}
	}
	for generation := uint64(1); generation <= wantGeneration; generation++ {
		var snapshot paasv1.DeploymentGeneration
		if _, err := value.edge.get(
			ctx,
			"/api/paas/v1/deployments/"+string(deploymentID)+"/generations/"+strconv.FormatUint(generation, 10),
			bearer,
			&snapshot,
		); err != nil || paasv1.ValidateDeploymentGeneration(snapshot) != nil || snapshot.Generation != generation {
			return fail("deployment-generation-history")
		}
	}
	return nil
}

func (value *gate) provisionSecret() ([]byte, string, error) {
	secret := make([]byte, 48)
	if _, err := rand.Read(secret); err != nil {
		clear(secret)
		return nil, "", fail("workload-secret-entropy")
	}
	directory := filepath.Join(
		value.config.root, filepath.FromSlash(layout.WorkloadSecretRoot), string(secretID),
	)
	if err := os.Mkdir(directory, 0o700); err != nil || os.Chmod(directory, 0o700) != nil {
		clear(secret)
		return nil, "", fail("workload-secret-directory")
	}
	path := filepath.Join(directory, secretVersion)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		clear(secret)
		return nil, "", fail("workload-secret-file")
	}
	_, writeErr := file.Write(secret)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || os.Chmod(path, 0o600) != nil {
		clear(secret)
		return nil, "", fail("workload-secret-write")
	}
	digest := sha256.Sum256(secret)
	return secret, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (value *gate) failedUpgrade(
	ctx context.Context,
	secret, password, bearer []byte,
) error {
	upgradeContext, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	command, stdout, stderr, err := startMX(
		upgradeContext, value.releases.a, "upgrade",
		[]string{"--bundle", value.releases.b.Root, "--root", value.config.root},
	)
	if err != nil {
		return fail("failed-upgrade-start")
	}
	waited := make(chan error, 1)
	go func() {
		waited <- command.Wait()
	}()
	injected := false
	for !injected && upgradeContext.Err() == nil {
		select {
		case <-waited:
			return fail("failed-upgrade-ended-before-injection")
		default:
		}
		ids, listErr := dockerLines(
			upgradeContext, "container", "ls", "--all", "--quiet",
			"--filter", "label=com.xiak.matrix.release="+value.releases.b.Manifest.Release.ID,
			"--filter", "label=com.xiak.matrix.role=apisix",
		)
		if listErr == nil && len(ids) == 1 {
			if _, removeErr := docker(upgradeContext, "container", "remove", "--force", ids[0]); removeErr == nil {
				injected = true
				break
			}
		}
		if !waitPoll(upgradeContext, 50*time.Millisecond) {
			break
		}
	}
	if !injected {
		_ = command.Process.Kill()
		<-waited
		return fail("failed-upgrade-injection")
	}
	waitErr := <-waited
	if err := validateExpectedMXFailure(
		waitErr, stdout, stderr, "upgrade", value.forbidden(secret, password, bearer),
	); err != nil {
		return err
	}
	return nil
}

func (value *gate) assertWorkload(
	ctx context.Context,
	manifest release.Manifest,
	deployment paasv1.Deployment,
	generation uint64,
	configurationGeneration string,
	setting, secretDigest string,
) error {
	if deployment.Metadata.ID != deploymentID || deployment.Generation != generation ||
		deployment.Status.ObservedGeneration != generation || deployment.Status.Phase != paasv1.DeploymentReady {
		return fail("workload-deployment-state")
	}
	ids, err := dockerLines(
		ctx, "container", "ls", "--all", "--quiet",
		"--filter", "label=com.xiak.matrix.deployment-id="+string(deploymentID),
	)
	if err != nil || len(ids) != 1 {
		return fail("workload-container-inventory")
	}
	inspections, err := inspectContainers(ctx, ids)
	if err != nil || len(inspections) != 1 {
		return fail("workload-container-inspection")
	}
	inspection := inspections[0]
	if !inspection.State.Running || inspection.State.Status != "running" ||
		inspection.Config.Labels["com.xiak.matrix.generation"] != generationText(generation) ||
		inspection.Config.Labels["com.xiak.matrix.application-revision-id"] != string(applicationRevisionID) ||
		len(inspection.HostConfig.PortBindings) != 0 {
		return fail("workload-container-state")
	}
	if !value.signedWorkloadImage(inspection.Config.Image) {
		return fail("workload-image-identity")
	}
	if generation == 2 {
		if value.workloadRunning == "" {
			value.workloadRunning = inspection.ID
		} else if value.workloadRunning != inspection.ID {
			return fail("running-workload-preservation")
		}
	}
	for _, ports := range inspection.NetworkSettings.Ports {
		if len(ports) != 0 {
			return fail("workload-host-port")
		}
	}
	secretReadOnly := false
	for _, mount := range inspection.Mounts {
		if mount.Destination == "/run/secrets/credential" && !mount.RW {
			secretReadOnly = true
		}
	}
	if !secretReadOnly || len(inspection.NetworkSettings.Networks) != 1 {
		return fail("workload-secret-network-boundary")
	}
	var network string
	for name := range inspection.NetworkSettings.Networks {
		network = name
	}
	project := inspection.Config.Labels["com.docker.compose.project"]
	if project == "" || inspection.Config.Labels["com.docker.compose.service"] != "web" ||
		!strings.HasPrefix(network, project+"_") {
		return fail("workload-project-identity")
	}
	value.workloadProject = project
	workload, ok := workloadImage(manifest)
	if !ok {
		return fail("workload-probe-image")
	}
	if _, err := docker(
		ctx, "run", "--rm", "--pull", "never", "--network", network,
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", workload.ImageID,
		"probe", "http://web:8080/ready", setting, secretDigest, configurationGeneration,
	); err != nil {
		return fail("workload-network-probe")
	}
	return nil
}

func (value *gate) signedWorkloadImage(imageID string) bool {
	for _, manifest := range []release.Manifest{value.releases.a.Manifest, value.releases.b.Manifest} {
		workload, ok := workloadImage(manifest)
		if ok && workload.ImageID == imageID {
			return true
		}
	}
	return false
}

func (value *gate) assertWorkloadRemoved(ctx context.Context) error {
	ids, err := dockerLines(
		ctx, "container", "ls", "--all", "--quiet",
		"--filter", "label=com.xiak.matrix.deployment-id="+string(deploymentID),
	)
	if err != nil || len(ids) != 0 {
		return fail("workload-project-removal")
	}
	if value.workloadProject != "" {
		networks, err := dockerLines(
			ctx, "network", "ls", "--quiet",
			"--filter", "label=com.docker.compose.project="+value.workloadProject,
		)
		if err != nil || len(networks) != 0 {
			return fail("workload-network-removal")
		}
	}
	return nil
}

func (value *gate) activeCapacityClaims(ctx context.Context, installationID string) (int, error) {
	ids, err := dockerLines(
		ctx, "container", "ls", "--all", "--quiet",
		"--filter", "label=com.xiak.matrix.installation="+installationID,
		"--filter", "label=com.xiak.matrix.role=postgres",
	)
	if err != nil || len(ids) != 1 {
		return 0, errors.New("PostgreSQL container is unavailable")
	}
	query := "SELECT count(*) FROM paas.capacity_reservations AS reservation " +
		"JOIN paas.capacity_claims AS claim ON claim.id = reservation.capacity_claim_id " +
		"WHERE reservation.tenant_id = 'organization-default' " +
		"AND reservation.deployment_id = 'phase1-deployment' AND claim.state = 'ACTIVE'"
	content, err := docker(
		ctx, "container", "exec", "--user", "postgres", ids[0],
		"psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
		"--username", "matrix", "--dbname", "matrix", "--command", query,
	)
	if err != nil {
		return 0, err
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || count < 0 || count > 1 {
		return 0, errors.New("capacity observation is invalid")
	}
	return count, nil
}

func (value *gate) writeAndScanSupport(
	ctx context.Context,
	bundle release.VerifiedBundle,
	name string,
	extra ...any,
) error {
	output := filepath.Join(value.config.root, filepath.FromSlash(layout.SupportDirectory), name)
	var forbidden [][]byte
	forbidden = append(forbidden, value.pathLeakage()...)
	for _, item := range extra {
		switch typed := item.(type) {
		case string:
			forbidden = append(forbidden, []byte(typed))
		case []byte:
			forbidden = append(forbidden, typed)
		case nil:
		}
	}
	result, err := runMX(ctx, bundle, "support", []string{
		"--root", value.config.root, "--output", output,
	}, forbidden)
	if err != nil || !result.Changed {
		return fail("support-command")
	}
	content, err := os.ReadFile(output)
	if err != nil || len(content) == 0 || len(content) > maximumHTTPBody {
		return fail("support-output")
	}
	defer clear(content)
	secretValues, err := installedSecretValues(value.config.root)
	if err != nil {
		return fail("support-secret-inventory")
	}
	defer func() {
		for _, secret := range secretValues {
			clear(secret)
		}
	}()
	forbidden = append(forbidden, secretValues...)
	forbidden = append(forbidden, []byte(output), []byte("backup-"))
	if containsAny(content, forbidden) {
		return fail("support-leakage")
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fail("support-permissions")
	}
	var document map[string]json.RawMessage
	if decodeOne(content, &document) != nil {
		return fail("support-contract")
	}
	var apiVersion, kind, state, releaseID string
	if json.Unmarshal(document["apiVersion"], &apiVersion) != nil ||
		json.Unmarshal(document["kind"], &kind) != nil ||
		json.Unmarshal(document["state"], &state) != nil ||
		json.Unmarshal(document["releaseId"], &releaseID) != nil ||
		apiVersion == "" || kind == "" || state != "READY" || releaseID != bundle.Manifest.Release.ID {
		return fail("support-contract")
	}
	return nil
}

func installedSecretValues(root string) ([][]byte, error) {
	secretRoot := filepath.Join(root, "secrets")
	var values [][]byte
	err := filepath.WalkDir(secretRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumHTTPBody {
			return errors.New("installed Secret inventory is unsafe")
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		values = append(values, content)
		if strings.HasSuffix(filepath.ToSlash(path), "/"+filepath.ToSlash(layout.IAMBootstrap)) {
			document, decodeErr := iamv1.DecodeBootstrapDocument(bytes.NewReader(content))
			if decodeErr != nil {
				return decodeErr
			}
			values = append(values, document.Administrator.Password.CopyBytes())
			for _, service := range document.Services {
				values = append(values, service.Credential.CopyBytes())
			}
		}
		if parsed, parseErr := url.Parse(strings.TrimSpace(string(content))); parseErr == nil && parsed.User != nil {
			if password, found := parsed.User.Password(); found && password != "" {
				values = append(values, []byte(password))
			}
		}
		return nil
	})
	if err != nil {
		for _, value := range values {
			clear(value)
		}
		return nil, err
	}
	journalKey, err := os.ReadFile(filepath.Join(root, "state", "journal.key"))
	if err != nil || len(journalKey) == 0 {
		for _, value := range values {
			clear(value)
		}
		clear(journalKey)
		return nil, errors.New("installation journal key is unavailable")
	}
	values = append(values, journalKey)
	return values, nil
}
