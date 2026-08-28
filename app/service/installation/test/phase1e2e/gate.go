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
	"slices"
	"strconv"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
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
	tenantApplicationID      paasv1.ResourceID = "phase1-tenant-application"
	tenantConfigurationID    paasv1.ResourceID = "phase1-tenant-configuration"
	tenantConfigurationRev   paasv1.ResourceID = "phase1-tenant-configuration-r1"
	postUpgradeApplicationID paasv1.ResourceID = "phase1-after-upgrade"
)

type gate struct {
	config          options
	releases        releasePair
	edge            *edgeClient
	sensitive       [][]byte
	workloadProject string
	workloadRunning string
	retainedIAM     *iamRetention
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
	if err := value.edge.changePassword(ctx, firstSession, initialPassword, newPassword, true, nil); err != nil {
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
	if err := value.prepareTenantRetention(ctx, bearer, newPassword, state.InstallationID); err != nil {
		return err
	}
	emit("tenant-primary-member-revocation-baseline")

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
	if _, err := value.edge.verifyAuditChain(ctx, bearer, "organization-default", ""); err != nil {
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
	if err := value.assertTenantRetention(ctx); err != nil {
		return err
	}

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
	recordsAfterUpgrade, err := value.edge.allAuditRecords(ctx, bearer, "organization-default", "")
	if err != nil || !containsAuditHistory(recordsAfterUpgrade, backupBaseline) {
		return fail("upgrade-audit-history")
	}
	if err := value.repeatedStatusAndVerify(
		ctx, value.releases.b, value.releases.b.Manifest.Release.ID, value.releases.a.Manifest.Release.ID,
	); err != nil {
		return err
	}
	emit("release-b-upgrade-preservation")
	if err := value.assertTenantRetention(ctx); err != nil {
		return err
	}
	postUpgrade, err := value.writePostUpgradeTenantResource(ctx)
	if err != nil {
		return err
	}

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
	if err := value.assertTenantRetention(ctx); err != nil {
		return err
	}
	if err := value.assertPostUpgradeTenantResource(ctx, postUpgrade, true); err != nil {
		return err
	}

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
	recoveredAudit, err := value.edge.allAuditRecords(ctx, bearer, "organization-default", "")
	if err != nil || !containsAuditHistory(recoveredAudit, backupBaseline) {
		return fail("recovered-audit-history")
	}
	if err := value.repeatedStatusAndVerify(ctx, value.releases.a, value.releases.a.Manifest.Release.ID, ""); err != nil {
		return err
	}
	emit("backup-recovery")
	if err := value.assertTenantRetention(ctx); err != nil {
		return err
	}
	if err := value.assertPostUpgradeTenantResource(ctx, postUpgrade, false); err != nil {
		return err
	}

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
	if _, err := value.edge.verifyAuditChain(ctx, bearer, "organization-default", ""); err != nil {
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
	if err := value.readTenantRetention(state.InstallationID); err != nil {
		return err
	}
	if err := value.assertTenantRetention(ctx); err != nil {
		return err
	}
	if err := value.restorePausedTenant(ctx); err != nil {
		return err
	}
	emit("restart-retained-tenants-primary-recovery-and-revocation")
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

func (value *gate) prepareTenantRetention(ctx context.Context, operator, administratorPassword []byte, installationID string) error {
	value.retainedIAM = &iamRetention{InstallationID: installationID,
		AdministratorPassword: append([]byte(nil), administratorPassword...)}
	for index, label := range []string{"alpha", "beta"} {
		tenant := tenantRetention{}
		for _, password := range []*[]byte{&tenant.InitialPassword, &tenant.PrimaryPassword, &tenant.PreviousPrimaryPassword, &tenant.ChildPassword,
			&tenant.RecoveryPassword, &tenant.FinalPrimaryPassword} {
			generated, err := randomPassword(rand.Reader)
			if err != nil {
				return fail("tenant-fixture-password")
			}
			*password = generated
			value.edge.addForbidden(generated)
		}
		tenantID := iamv1.OrganizationID("phase1-tenant-" + label)
		if err := value.edge.mutateIAM(ctx, "/organizations", operator, map[string]any{
			"id": tenantID, "displayName": "Offline " + label,
			"administratorLoginName": "offline." + label + ".primary", "administratorDisplayName": "Offline primary",
			"initialPassword": string(tenant.InitialPassword), "requestId": "phase1-open-" + label,
		}, &tenant.Account, http.StatusCreated); err != nil || iamv1.ValidateOrganizationAccount(tenant.Account) != nil || tenant.Account.Organization.ID != tenantID {
			return fail("tenant-onboarding-" + label)
		}
		primary, err := value.edge.loginNamed(ctx, tenant.Account.PrimaryLoginName, tenant.InitialPassword,
			tenantID, tenant.Account.PrimaryPrincipalID, "phase1-primary-login-"+label)
		if err != nil || !primary.MustChangePassword {
			return fail("tenant-primary-first-login-" + label)
		}
		tenant.OldPrimaryCredential = primary.Credential.CopyBytes()
		value.edge.addForbidden(tenant.OldPrimaryCredential)
		temporary, err := value.edge.loginNamed(ctx, tenant.Account.PrimaryLoginName, tenant.InitialPassword,
			tenantID, tenant.Account.PrimaryPrincipalID, "phase1-primary-temporary-"+label)
		if err != nil || !temporary.MustChangePassword {
			return fail("tenant-primary-temporary-login-" + label)
		}
		tenant.TemporaryPrimaryCredential = temporary.Credential.CopyBytes()
		value.edge.addForbidden(tenant.TemporaryPrimaryCredential)
		keepOtherSessions := false
		if err := value.edge.changePassword(ctx, tenant.OldPrimaryCredential, tenant.InitialPassword, tenant.PreviousPrimaryPassword, false, &keepOtherSessions); err != nil {
			return fail("tenant-primary-password-" + label)
		}
		retained, err := value.edge.loginNamed(ctx, tenant.Account.PrimaryLoginName, tenant.PreviousPrimaryPassword,
			tenantID, tenant.Account.PrimaryPrincipalID, "phase1-primary-retained-"+label)
		if err != nil || retained.MustChangePassword {
			return fail("tenant-primary-retained-login-" + label)
		}
		tenant.RetainedPrimaryCredential = retained.Credential.CopyBytes()
		value.edge.addForbidden(tenant.RetainedPrimaryCredential)
		if err := value.edge.changePassword(ctx, tenant.OldPrimaryCredential, tenant.PreviousPrimaryPassword, tenant.PrimaryPassword, false, &keepOtherSessions); err != nil {
			return fail("tenant-primary-retain-valid-session-" + label)
		}
		if err := value.edge.mutateIAM(ctx, "/principals", tenant.OldPrimaryCredential, map[string]any{
			"loginName": "developer", "displayName": "Offline developer", "initialPassword": string(tenant.InitialPassword),
			"requestId": "phase1-child-" + label,
		}, &tenant.Child, http.StatusCreated); err != nil || iamv1.ValidatePrincipal(tenant.Child) != nil ||
			tenant.Child.OrganizationID != tenantID || tenant.Child.Type != iamv1.PrincipalUser {
			return fail("tenant-child-create-" + label)
		}
		if err := value.edge.mutateIAM(ctx, "/role-bindings", tenant.OldPrimaryCredential,
			iamv1.PutRoleBindingRequest{PrincipalID: tenant.Child.ID, Role: iamv1.RolePaaSDeveloper, RequestID: "phase1-grant-" + label},
			&tenant.ChildBinding, http.StatusOK); err != nil || iamv1.ValidateRoleBinding(tenant.ChildBinding) != nil {
			return fail("tenant-child-grant-" + label)
		}
		child, err := value.edge.loginNamed(ctx, "developer@"+string(tenantID), tenant.InitialPassword,
			tenantID, tenant.Child.ID, "phase1-child-login-"+label)
		if err != nil || !child.MustChangePassword {
			return fail("tenant-child-first-login-" + label)
		}
		tenant.OldChildCredential = child.Credential.CopyBytes()
		value.edge.addForbidden(tenant.OldChildCredential)
		temporaryChild, err := value.edge.loginNamed(ctx, "developer@"+string(tenantID), tenant.InitialPassword,
			tenantID, tenant.Child.ID, "phase1-child-temporary-"+label)
		if err != nil || !temporaryChild.MustChangePassword {
			return fail("tenant-child-temporary-login-" + label)
		}
		tenant.TemporaryChildCredential = temporaryChild.Credential.CopyBytes()
		value.edge.addForbidden(tenant.TemporaryChildCredential)
		if err := value.edge.changePassword(ctx, tenant.OldChildCredential, tenant.InitialPassword, tenant.ChildPassword, false, &keepOtherSessions); err != nil {
			return fail("tenant-child-password-" + label)
		}
		values := map[string]string{"TENANT_SETTING": string(tenantID) + "-private-value"}
		for _, creation := range []struct {
			path, key string
			body      any
			action    paasv1.OperationAction
			target    paasv1.ResourceRef
		}{
			{"/applications", "tenant-application", paasv1.CreateApplicationRequest{ID: tenantApplicationID, Name: string(tenantID)}, paasv1.OperationCreateApplication, paasv1.ResourceRef{Kind: "Application", ID: tenantApplicationID}},
			{"/configurations", "tenant-configuration", paasv1.CreateConfigurationRequest{ID: tenantConfigurationID, Name: string(tenantID), ApplicationID: tenantApplicationID}, paasv1.OperationCreateConfiguration, paasv1.ResourceRef{Kind: "Configuration", ID: tenantConfigurationID}},
			{"/configuration-revisions", "tenant-configuration-r1", paasv1.CreateConfigurationRevisionRequest{ID: tenantConfigurationRev, Name: string(tenantID), Spec: paasv1.ConfigurationRevisionSpec{ConfigurationID: tenantConfigurationID, Values: values, ContentDigest: paasv1.ConfigurationValuesDigest(values)}}, paasv1.OperationCreateConfigurationRevision, paasv1.ResourceRef{Kind: "ConfigurationRevision", ID: tenantConfigurationRev}},
		} {
			operation, err := value.edge.createResource(ctx, "/api/paas/v1"+creation.path, creation.key, tenant.OldChildCredential, creation.body, creation.action, creation.target)
			if err != nil || string(operation.Scope.TenantID) != string(tenantID) || operation.RequestedBy.ID != string(tenant.Child.ID) {
				return fail("tenant-resource-creation-" + label)
			}
			tenant.Operations = append(tenant.Operations, operation)
		}
		quota, err := value.edge.json(ctx, http.MethodPost, "/api/managed-services/v1/quota-entitlements", tenant.OldChildCredential,
			managedservicev1.ActivateQuotaRequest{OfferingID: "postgresql-18", QuotaShapeID: "pg-small", InstanceCount: 1},
			map[string]string{"Idempotency-Key": "tenant-same-quota-key"}, http.StatusCreated)
		if err != nil || decodeOne(quota.body, &tenant.Quota) != nil || managedservicev1.ValidateQuotaEntitlement(tenant.Quota) != nil {
			return fail("tenant-quota-creation-" + label)
		}
		clear(quota.body)
		if index == 0 {
			if err := value.edge.mutateIAM(ctx, "/role-bindings/"+string(tenant.ChildBinding.ID)+":revoke", tenant.OldPrimaryCredential,
				iamv1.RevokeRoleBindingRequest{RequestID: "phase1-revoke-child-role"}, nil, http.StatusOK); err != nil {
				return fail("tenant-role-revoke")
			}
			if err := value.edge.logout(ctx, tenant.OldChildCredential); err != nil {
				return fail("tenant-session-revoke")
			}
		} else {
			var identity iamv1.CurrentIdentity
			if _, err := value.edge.get(ctx, "/api/iam/v1/auth/me", tenant.OldChildCredential, &identity); err != nil || iamv1.ValidateCurrentIdentity(identity) != nil {
				return fail("tenant-child-current-version")
			}
			if err := value.edge.mutateIAM(ctx, "/principals/"+string(tenant.Child.ID)+":set-status", tenant.OldPrimaryCredential,
				iamv1.SetPrincipalStatusRequest{Status: iamv1.PrincipalDisabled, ResourceVersion: identity.Principal.ResourceVersion, RequestID: "phase1-disable-child"},
				&tenant.Child, http.StatusOK); err != nil {
				return fail("tenant-child-disable")
			}
		}
		if err := value.assertTenantResources(ctx, &tenant, tenant.OldPrimaryCredential, true); err != nil {
			return err
		}
		if index == 0 {
			if err := value.edge.logout(ctx, tenant.OldPrimaryCredential); err != nil {
				return fail("tenant-primary-session-revoke")
			}
		} else {
			if err := value.edge.mutateIAM(ctx, "/organizations/"+string(tenantID)+":set-status", operator,
				iamv1.SetOrganizationStatusRequest{Status: iamv1.OrganizationDisabled, ResourceVersion: tenant.Account.Organization.ResourceVersion, RequestID: "phase1-pause-tenant"},
				&tenant.Account, http.StatusOK); err != nil {
				return fail("tenant-pause")
			}
			if err := value.edge.mutateIAM(ctx, "/organizations/"+string(tenantID)+":recover-administrator", operator, map[string]any{
				"principalId": tenant.Account.PrimaryPrincipalID, "resourceVersion": tenant.Account.Organization.ResourceVersion,
				"initialPassword": string(tenant.RecoveryPassword), "requestId": "phase1-recover-original-primary",
			}, &tenant.Account, http.StatusOK); err != nil || tenant.Account.Organization.Status != iamv1.OrganizationDisabled {
				return fail("tenant-original-primary-recovery")
			}
		}
		value.retainedIAM.Tenants = append(value.retainedIAM.Tenants, tenant)
	}
	if err := value.assertTenantRetention(ctx); err != nil {
		return err
	}
	encoded, err := json.Marshal(value.retainedIAM)
	if err != nil || len(encoded) > 64*1024 {
		return fail("tenant-retention-fixture-encoding")
	}
	defer clear(encoded)
	file, err := os.OpenFile(value.config.root+"-iam-retention.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fail("tenant-retention-fixture-create")
	}
	_, writeErr := file.Write(encoded)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return fail("tenant-retention-fixture-write")
	}
	return nil
}

func (value *gate) readTenantRetention(installationID string) error {
	path := value.config.root + "-iam-retention.json"
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64*1024 {
		return fail("tenant-retention-fixture-permissions")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fail("tenant-retention-fixture-read")
	}
	defer clear(content)
	var retained iamRetention
	if decodeOne(content, &retained) != nil || retained.InstallationID != installationID || len(retained.Tenants) != 2 || len(retained.AdministratorPassword) == 0 {
		return fail("tenant-retention-fixture-identity")
	}
	value.retainedIAM = &retained
	value.edge.addForbidden(retained.AdministratorPassword)
	for _, tenant := range retained.Tenants {
		value.edge.addForbidden(tenant.InitialPassword, tenant.PrimaryPassword, tenant.ChildPassword, tenant.RecoveryPassword,
			tenant.FinalPrimaryPassword, tenant.OldChildCredential, tenant.OldPrimaryCredential, tenant.PreviousPrimaryPassword,
			tenant.TemporaryPrimaryCredential, tenant.TemporaryChildCredential, tenant.RetainedPrimaryCredential)
	}
	return nil
}

func (value *gate) assertTenantRetention(ctx context.Context) error {
	operator, err := value.edge.login(ctx, value.retainedIAM.AdministratorPassword, "phase1-retained-operator")
	if err != nil {
		return fail("tenant-retained-operator-login")
	}
	defer clear(operator)
	value.edge.addForbidden(operator)
	defer func() { _ = value.edge.logout(ctx, operator) }()
	if err := value.assertPlatformAuditRetention(ctx, operator); err != nil {
		return err
	}
	for index := range value.retainedIAM.Tenants {
		tenant := &value.retainedIAM.Tenants[index]
		id := tenant.Account.Organization.ID
		var account iamv1.OrganizationAccount
		if _, err := value.edge.get(ctx, "/api/iam/v1/organizations/"+string(id), operator, &account); err != nil ||
			iamv1.ValidateOrganizationAccount(account) != nil || account.PrimaryPrincipalID != tenant.Account.PrimaryPrincipalID ||
			account.PrimaryLoginName != tenant.Account.PrimaryLoginName || account.Organization.Status != tenant.Account.Organization.Status ||
			account.Organization.ResourceVersion != tenant.Account.Organization.ResourceVersion {
			return fail("tenant-retained-original-account")
		}
		for _, credential := range [][]byte{tenant.OldChildCredential, tenant.OldPrimaryCredential, tenant.TemporaryPrimaryCredential, tenant.TemporaryChildCredential} {
			response, err := value.edge.json(ctx, http.MethodGet, "/api/iam/v1/auth/me", credential, nil, nil, http.StatusUnauthorized)
			clear(response.body)
			if err != nil {
				return fail("tenant-revoked-session-denial")
			}
		}
		for _, login := range []loginWire{
			{LoginName: account.PrimaryLoginName, Password: string(tenant.InitialPassword), RequestID: "phase1-retained-old-primary-password"},
			{LoginName: account.PrimaryLoginName, Password: string(tenant.PreviousPrimaryPassword), RequestID: "phase1-retained-previous-primary-password"},
			{LoginName: "developer@" + string(id), Password: string(tenant.InitialPassword), RequestID: "phase1-retained-old-child-password"},
			{LoginName: "developer@" + string(value.retainedIAM.Tenants[1-index].Account.Organization.ID), Password: string(tenant.ChildPassword), RequestID: "phase1-retained-wrong-realm"},
		} {
			response, err := value.edge.json(ctx, http.MethodPost, "/api/iam/v1/auth/login", nil, login, nil, http.StatusUnauthorized)
			clear(response.body)
			if err != nil {
				return fail("tenant-old-password-or-wrong-realm-admitted")
			}
		}
		if index == 1 {
			response, err := value.edge.json(ctx, http.MethodGet, "/api/iam/v1/auth/me", tenant.RetainedPrimaryCredential, nil, nil, http.StatusUnauthorized)
			clear(response.body)
			if err != nil {
				return fail("tenant-pause-revived-retained-password-session")
			}
			for _, password := range [][]byte{tenant.PrimaryPassword, tenant.RecoveryPassword} {
				response, err := value.edge.json(ctx, http.MethodPost, "/api/iam/v1/auth/login", nil,
					loginWire{LoginName: account.PrimaryLoginName, Password: string(password), RequestID: "phase1-retained-paused-primary"}, nil, http.StatusUnauthorized)
				clear(response.body)
				if err != nil {
					return fail("tenant-pause-resurrected-access")
				}
			}
			continue
		}
		var retainedIdentity iamv1.CurrentIdentity
		if _, err := value.edge.get(ctx, "/api/iam/v1/auth/me", tenant.RetainedPrimaryCredential, &retainedIdentity); err != nil ||
			iamv1.ValidateCurrentIdentity(retainedIdentity) != nil || retainedIdentity.Principal.ID != account.PrimaryPrincipalID ||
			retainedIdentity.Principal.OrganizationID != id || retainedIdentity.Principal.MustChangePassword ||
			!slices.Contains(retainedIdentity.Roles, iamv1.RoleOrganizationAdmin) || slices.Contains(retainedIdentity.Roles, iamv1.RolePlatformOperator) {
			return fail("tenant-valid-password-session-not-retained")
		}
		primary, err := value.edge.loginNamed(ctx, account.PrimaryLoginName, tenant.PrimaryPassword, id, account.PrimaryPrincipalID, "phase1-retained-primary")
		if err != nil || primary.MustChangePassword {
			return fail("tenant-retained-primary-password")
		}
		bearer := primary.Credential.CopyBytes()
		defer clear(bearer)
		value.edge.addForbidden(bearer)
		var identity iamv1.CurrentIdentity
		if _, err := value.edge.get(ctx, "/api/iam/v1/auth/me", bearer, &identity); err != nil || iamv1.ValidateCurrentIdentity(identity) != nil ||
			identity.Principal.ID != account.PrimaryPrincipalID || !slices.Contains(identity.Roles, iamv1.RoleOrganizationAdmin) ||
			slices.Contains(identity.Roles, iamv1.RolePlatformOperator) || identity.CanCreateOrganizations {
			return fail("tenant-primary-became-platform-operator")
		}
		if err := value.assertTenantResources(ctx, tenant, bearer, false); err != nil {
			return err
		}
		var members iamv1.PrincipalList
		if _, err := value.edge.get(ctx, "/api/iam/v1/principals", bearer, &members); err != nil || iamv1.ValidatePrincipalList(members) != nil {
			return fail("tenant-retained-member-list")
		}
		found := false
		for _, member := range members.Items {
			if member.Principal.ID != tenant.Child.ID {
				continue
			}
			found = member.Principal.Status == iamv1.PrincipalActive && !member.Principal.MustChangePassword
			if len(member.RoleBindings) != 0 {
				return fail("tenant-revoked-role-resurrected")
			}
		}
		if !found {
			return fail("tenant-retained-child-identity")
		}
		child, err := value.edge.loginNamed(ctx, "developer@"+string(id), tenant.ChildPassword, id, tenant.Child.ID, "phase1-retained-roleless-child")
		if err != nil || child.MustChangePassword {
			return fail("tenant-retained-child-password")
		}
		childBearer := child.Credential.CopyBytes()
		value.edge.addForbidden(childBearer)
		response, requestErr := value.edge.json(ctx, http.MethodGet, "/api/paas/v1/applications/"+string(tenantApplicationID), childBearer, nil, nil, http.StatusForbidden)
		clear(response.body)
		logoutErr := value.edge.logout(ctx, childBearer)
		clear(childBearer)
		if requestErr != nil || logoutErr != nil {
			return fail("tenant-revoked-role-admitted-resource")
		}
		other := value.retainedIAM.Tenants[1-index]
		for _, path := range []string{"/api/paas/v1/operations/" + string(other.Operations[0].ID), "/api/managed-services/v1/quota-entitlements/" + other.Quota.ID} {
			response, err := value.edge.json(ctx, http.MethodGet, path, bearer, nil, map[string]string{"X-Tenant-ID": string(other.Account.Organization.ID)}, http.StatusNotFound)
			clear(response.body)
			if err != nil {
				return fail("tenant-retained-foreign-resource")
			}
		}
		if err := value.edge.logout(ctx, bearer); err != nil {
			return fail("tenant-retained-primary-logout")
		}
	}
	return nil
}

func (value *gate) assertTenantResources(ctx context.Context, tenant *tenantRetention, bearer []byte, capture bool) error {
	id := string(tenant.Account.Organization.ID)
	var application paasv1.Application
	if _, err := value.edge.get(ctx, "/api/paas/v1/applications/"+string(tenantApplicationID), bearer, &application); err != nil ||
		paasv1.ValidateApplication(application) != nil || application.Metadata.Name != id || string(application.Metadata.Scope.TenantID) != id {
		return fail("tenant-retained-application")
	}
	var revision paasv1.ConfigurationRevision
	wantValues := map[string]string{"TENANT_SETTING": id + "-private-value"}
	if _, err := value.edge.get(ctx, "/api/paas/v1/configuration-revisions/"+string(tenantConfigurationRev), bearer, &revision); err != nil ||
		paasv1.ValidateConfigurationRevision(revision) != nil || string(revision.Metadata.Scope.TenantID) != id ||
		revision.Spec.Values["TENANT_SETTING"] != wantValues["TENANT_SETTING"] || revision.Spec.ContentDigest != paasv1.ConfigurationValuesDigest(wantValues) {
		return fail("tenant-retained-configuration-value")
	}
	for _, before := range tenant.Operations {
		var after paasv1.Operation
		if _, err := value.edge.get(ctx, "/api/paas/v1/operations/"+string(before.ID), bearer, &after); err != nil ||
			paasv1.ValidateOperation(after) != nil || after.ID != before.ID || after.Action != before.Action || after.Target != before.Target ||
			after.Scope != before.Scope || after.RequestedBy != before.RequestedBy || after.State != paasv1.OperationSucceeded {
			return fail("tenant-retained-operation-ownership")
		}
	}
	var quota managedservicev1.QuotaEntitlement
	if _, err := value.edge.get(ctx, "/api/managed-services/v1/quota-entitlements/"+tenant.Quota.ID, bearer, &quota); err != nil || quota != tenant.Quota {
		return fail("tenant-retained-quota")
	}
	poll, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for poll.Err() == nil {
		records, err := value.edge.allAuditRecords(poll, bearer, tenant.Account.Organization.ID, "")
		if err == nil {
			complete := true
			for _, operation := range tenant.Operations {
				matches := 0
				for _, record := range records {
					if record.Event.OperationID != auditv1.OperationID(operation.ID) {
						continue
					}
					if string(record.Event.TenantID) != id || record.Event.Actor.ID != auditv1.ActorID(tenant.Child.ID) ||
						record.Event.Target.ID != string(operation.Target.ID) || record.Event.IAMDecisionID == "" {
						return fail("tenant-audit-ownership")
					}
					matches++
				}
				if matches > 1 {
					return fail("tenant-audit-replayed-as-new-fact")
				}
				complete = complete && matches == 1
			}
			if complete {
				if !scanAuditForConfigurationValues(records, wantValues["TENANT_SETTING"]) {
					return fail("tenant-audit-configuration-leak")
				}
				if capture {
					tenant.AuditHashes = auditRecordHashes(records)
				} else if !containsAuditHistory(records, tenant.AuditHashes) {
					return fail("tenant-audit-history-lost")
				}
				if _, err := value.edge.verifyAuditChain(poll, bearer, tenant.Account.Organization.ID, ""); err != nil {
					return fail("tenant-audit-chain-retained")
				}
				return nil
			}
		}
		if !waitPoll(poll, 200*time.Millisecond) {
			break
		}
	}
	return fail("tenant-audit-outbox-delivery")
}

func (value *gate) writePostUpgradeTenantResource(ctx context.Context) (paasv1.Operation, error) {
	tenant := value.retainedIAM.Tenants[0]
	login, err := value.edge.loginNamed(ctx, tenant.Account.PrimaryLoginName, tenant.PrimaryPassword,
		tenant.Account.Organization.ID, tenant.Account.PrimaryPrincipalID, "phase1-post-upgrade-primary")
	if err != nil {
		return paasv1.Operation{}, fail("post-upgrade-tenant-login")
	}
	bearer := login.Credential.CopyBytes()
	defer clear(bearer)
	defer func() { _ = value.edge.logout(ctx, bearer) }()
	operation, err := value.edge.createResource(ctx, "/api/paas/v1/applications", "phase1-after-upgrade", bearer,
		paasv1.CreateApplicationRequest{ID: postUpgradeApplicationID, Name: string(postUpgradeApplicationID)},
		paasv1.OperationCreateApplication, paasv1.ResourceRef{Kind: "Application", ID: postUpgradeApplicationID})
	if err != nil || string(operation.Scope.TenantID) != string(tenant.Account.Organization.ID) {
		return paasv1.Operation{}, fail("post-upgrade-tenant-resource")
	}
	return operation, nil
}

func (value *gate) assertPostUpgradeTenantResource(ctx context.Context, operation paasv1.Operation, retained bool) error {
	tenant := value.retainedIAM.Tenants[0]
	login, err := value.edge.loginNamed(ctx, tenant.Account.PrimaryLoginName, tenant.PrimaryPassword,
		tenant.Account.Organization.ID, tenant.Account.PrimaryPrincipalID, "phase1-post-upgrade-read")
	if err != nil {
		return fail("post-upgrade-tenant-read-login")
	}
	bearer := login.Credential.CopyBytes()
	defer clear(bearer)
	defer func() { _ = value.edge.logout(ctx, bearer) }()
	status := http.StatusNotFound
	if retained {
		status = http.StatusOK
	}
	for _, path := range []string{"/api/paas/v1/applications/" + string(postUpgradeApplicationID), "/api/paas/v1/operations/" + string(operation.ID)} {
		response, err := value.edge.json(ctx, http.MethodGet, path, bearer, nil, nil, status)
		clear(response.body)
		if err != nil {
			return fail("rollback-retained-new-data-or-recovery-snapshot")
		}
	}
	return nil
}

func (value *gate) restorePausedTenant(ctx context.Context) error {
	operator, err := value.edge.login(ctx, value.retainedIAM.AdministratorPassword, "phase1-restore-operator")
	if err != nil {
		return fail("restore-tenant-operator")
	}
	defer clear(operator)
	defer func() { _ = value.edge.logout(ctx, operator) }()
	tenant := &value.retainedIAM.Tenants[1]
	id := tenant.Account.Organization.ID
	var account iamv1.OrganizationAccount
	if _, err := value.edge.get(ctx, "/api/iam/v1/organizations/"+string(id), operator, &account); err != nil {
		return fail("restore-tenant-read")
	}
	if err := value.edge.mutateIAM(ctx, "/organizations/"+string(id)+":set-status", operator,
		iamv1.SetOrganizationStatusRequest{Status: iamv1.OrganizationActive, ResourceVersion: account.Organization.ResourceVersion, RequestID: "phase1-explicit-tenant-resume"},
		&account, http.StatusOK); err != nil || account.PrimaryPrincipalID != tenant.Account.PrimaryPrincipalID {
		return fail("restore-original-tenant")
	}
	for _, password := range [][]byte{tenant.InitialPassword, tenant.PrimaryPassword} {
		response, err := value.edge.json(ctx, http.MethodPost, "/api/iam/v1/auth/login", nil,
			loginWire{LoginName: account.PrimaryLoginName, Password: string(password), RequestID: "phase1-recovered-old-password"}, nil, http.StatusUnauthorized)
		clear(response.body)
		if err != nil {
			return fail("recovery-restored-old-primary-password")
		}
	}
	primary, err := value.edge.loginNamed(ctx, account.PrimaryLoginName, tenant.RecoveryPassword, id, account.PrimaryPrincipalID, "phase1-recovered-primary-login")
	if err != nil || !primary.MustChangePassword {
		return fail("recovered-primary-required-password-change")
	}
	bearer := primary.Credential.CopyBytes()
	defer clear(bearer)
	defer func() { _ = value.edge.logout(ctx, bearer) }()
	value.edge.addForbidden(bearer)
	if err := value.edge.changePassword(ctx, bearer, tenant.RecoveryPassword, tenant.FinalPrimaryPassword, false, nil); err != nil {
		return fail("recovered-primary-password")
	}
	var identity iamv1.CurrentIdentity
	if _, err := value.edge.get(ctx, "/api/iam/v1/auth/me", bearer, &identity); err != nil || iamv1.ValidateCurrentIdentity(identity) != nil ||
		identity.Principal.ID != account.PrimaryPrincipalID || identity.Principal.MustChangePassword ||
		!slices.Contains(identity.Roles, iamv1.RoleOrganizationAdmin) || slices.Contains(identity.Roles, iamv1.RolePlatformOperator) || identity.CanCreateOrganizations {
		return fail("recovered-primary-scope")
	}
	var principals iamv1.PrincipalList
	if _, err := value.edge.get(ctx, "/api/iam/v1/principals", bearer, &principals); err != nil || iamv1.ValidatePrincipalList(principals) != nil {
		return fail("recovered-member-list")
	}
	var disabled iamv1.Principal
	for _, member := range principals.Items {
		if member.Principal.ID == tenant.Child.ID {
			disabled = member.Principal
		}
	}
	if disabled.Status != iamv1.PrincipalDisabled || disabled.MustChangePassword {
		return fail("recovered-member-disabled-state")
	}
	var enabled iamv1.Principal
	if err := value.edge.mutateIAM(ctx, "/principals/"+string(disabled.ID)+":set-status", bearer,
		iamv1.SetPrincipalStatusRequest{Status: iamv1.PrincipalActive, ResourceVersion: disabled.ResourceVersion, RequestID: "phase1-explicit-child-resume"},
		&enabled, http.StatusOK); err != nil || enabled.ID != tenant.Child.ID || enabled.OrganizationID != id {
		return fail("recovered-member-resume")
	}
	response, err := value.edge.json(ctx, http.MethodGet, "/api/iam/v1/auth/me", tenant.OldChildCredential, nil, nil, http.StatusUnauthorized)
	clear(response.body)
	if err != nil {
		return fail("member-resume-revived-old-session")
	}
	child, err := value.edge.loginNamed(ctx, "developer@"+string(id), tenant.ChildPassword, id, tenant.Child.ID, "phase1-resumed-child-login")
	if err != nil || child.MustChangePassword {
		return fail("resumed-child-password")
	}
	childBearer := child.Credential.CopyBytes()
	defer clear(childBearer)
	defer func() { _ = value.edge.logout(ctx, childBearer) }()
	var application paasv1.Application
	if _, err := value.edge.get(ctx, "/api/paas/v1/applications/"+string(tenantApplicationID), childBearer, &application); err != nil ||
		string(application.Metadata.Scope.TenantID) != string(id) {
		return fail("resumed-child-authorized-resource")
	}
	if err := value.assertTenantResources(ctx, tenant, bearer, false); err != nil {
		return err
	}
	return value.assertPlatformAuditRetention(ctx, operator)
}

func (value *gate) assertPlatformAuditRetention(ctx context.Context, bearer []byte) error {
	alpha, beta := value.retainedIAM.Tenants[0], value.retainedIAM.Tenants[1]
	expected := map[string]struct {
		action auditv1.Action
		target auditv1.TargetReference
	}{
		"phase1-open-alpha":   {auditv1.ActionIAMTenantCreated, auditv1.TargetReference{Kind: auditv1.TargetOrganization, ID: string(alpha.Account.Organization.ID)}},
		"phase1-open-beta":    {auditv1.ActionIAMTenantCreated, auditv1.TargetReference{Kind: auditv1.TargetOrganization, ID: string(beta.Account.Organization.ID)}},
		"phase1-pause-tenant": {auditv1.ActionIAMTenantDisabled, auditv1.TargetReference{Kind: auditv1.TargetOrganization, ID: string(beta.Account.Organization.ID)}},
		"phase1-recover-original-primary": {auditv1.ActionIAMTenantAdministratorRecovered, auditv1.TargetReference{
			Kind: auditv1.TargetPrincipal, ID: string(beta.Account.PrimaryPrincipalID), TenantID: auditv1.TenantID(beta.Account.Organization.ID),
		}},
	}
	poll, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for poll.Err() == nil {
		records, err := value.edge.allAuditRecords(poll, bearer, "", value.retainedIAM.InstallationID)
		if err == nil {
			counts := make(map[string]int, len(expected))
			for _, record := range records {
				want, found := expected[record.Event.RequestID]
				if !found {
					continue
				}
				if record.Source != auditv1.SourceIAM || record.Event.Action != want.action || record.Event.Target != want.target ||
					record.Event.InstallationID != value.retainedIAM.InstallationID || record.Event.TenantID != "" ||
					record.Event.Actor.ID != "principal-admin" {
					return fail("platform-lifecycle-audit-identity")
				}
				counts[record.Event.RequestID]++
				if counts[record.Event.RequestID] != 1 {
					return fail("platform-lifecycle-audit-replay")
				}
			}
			if len(counts) == len(expected) {
				if value.retainedIAM.PlatformAuditHashes == nil {
					value.retainedIAM.PlatformAuditHashes = auditRecordHashes(records)
				} else if !containsAuditHistory(records, value.retainedIAM.PlatformAuditHashes) {
					return fail("platform-lifecycle-audit-history-lost")
				}
				if _, err := value.edge.verifyAuditChain(poll, bearer, "", value.retainedIAM.InstallationID); err != nil {
					return fail("platform-lifecycle-audit-chain")
				}
				return nil
			}
		}
		if !waitPoll(poll, 200*time.Millisecond) {
			break
		}
	}
	return fail("platform-lifecycle-outbox-delivery")
}

func (value *gate) assertSignedProfile(ctx context.Context, bundle release.VerifiedBundle) error {
	profile := bundle.Manifest.Database
	if profile != release.CurrentDatabaseProfile() {
		return fail("offline-release-profile")
	}
	for _, authority := range []struct {
		name    string
		version uint64
	}{
		{"iam", profile.Authorities.IAM}, {"audit", profile.Authorities.Audit}, {"paas", profile.Authorities.PaaS},
	} {
		response, err := value.edge.json(ctx, http.MethodGet, "/api/"+authority.name+"/ready", nil, nil, nil, http.StatusOK)
		if err != nil {
			return fail("offline-authority-readiness-" + authority.name)
		}
		var readiness struct {
			SchemaVersion uint64 `json:"schemaVersion"`
		}
		err = json.Unmarshal(response.body, &readiness)
		clear(response.body)
		if err != nil || readiness.SchemaVersion != authority.version {
			return fail("offline-authority-profile-" + authority.name)
		}
	}
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
	if value.retainedIAM != nil {
		result = append(result, value.retainedIAM.AdministratorPassword)
		for _, tenant := range value.retainedIAM.Tenants {
			result = append(result, tenant.InitialPassword, tenant.PrimaryPassword, tenant.ChildPassword,
				tenant.RecoveryPassword, tenant.FinalPrimaryPassword, tenant.OldPrimaryCredential, tenant.OldChildCredential,
				tenant.PreviousPrimaryPassword, tenant.TemporaryPrimaryCredential, tenant.TemporaryChildCredential, tenant.RetainedPrimaryCredential,
				[]byte(string(tenant.Account.Organization.ID)+"-private-value"))
		}
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
	if _, err := assertPlatform(ctx, value.config.root, bundle.Manifest, previousID); err != nil {
		return err
	}
	return value.assertSignedProfile(ctx, bundle)
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
	var database release.DatabaseProfile
	if json.Unmarshal(document["apiVersion"], &apiVersion) != nil ||
		json.Unmarshal(document["kind"], &kind) != nil ||
		json.Unmarshal(document["state"], &state) != nil ||
		json.Unmarshal(document["releaseId"], &releaseID) != nil ||
		decodeOne(document["database"], &database) != nil || database != bundle.Manifest.Database ||
		apiVersion != "installation.matrix.xiak.com/v2" || kind != "PlatformSupportEvidence" ||
		state != "READY" || releaseID != bundle.Manifest.Release.ID {
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
