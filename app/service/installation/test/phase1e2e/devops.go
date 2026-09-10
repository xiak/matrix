package phase1e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/devops/sourcetrust"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
)

const (
	devOpsProjectID                devopsv1.ResourceID  = "phase1-project"
	devOpsSourceConnectionID       devopsv1.ResourceID  = "phase1-source"
	devOpsRepositoryBindingID      devopsv1.ResourceID  = "phase1-repository"
	devOpsPipelineID               devopsv1.ResourceID  = "phase1-pipeline"
	devOpsTenant                   devopsv1.TenantID    = "organization-default"
	devOpsForeignOrganization      iamv1.OrganizationID = "organization-phase1-foreign"
	devOpsForeignPrincipal         iamv1.PrincipalID    = "principal-phase1-foreign"
	devOpsForeignLogin                                  = "phase1-foreign-viewer"
	devOpsViewerLogin                                   = "phase1-devops-viewer"
	devOpsSourceEndpoint                                = "https://gitea.phase1.invalid"
	devOpsWebhookSecretRef         devopsv1.ResourceID  = "phase1-webhook"
	devOpsFetchCredentialRef       devopsv1.ResourceID  = "phase1-fetch"
	devOpsReportCredentialRef      devopsv1.ResourceID  = "phase1-report"
	devOpsSourceTrustMaterialIndex                      = 4
	devOpsSourceMaterialCount                           = 5
)

const seedForeignTenantSQL = `BEGIN;
INSERT INTO iam.organizations (
    id, display_name, status, resource_version, created_at, updated_at
) VALUES (
    'organization-phase1-foreign', 'Phase 1 Foreign Organization',
    'ACTIVE', 1, transaction_timestamp(), transaction_timestamp()
);
INSERT INTO iam.principals (
    tenant_id, id, principal_type, login_name, display_name, status,
    must_change_password, resource_version, created_at, updated_at
) VALUES (
    'organization-phase1-foreign', 'principal-phase1-foreign', 'USER',
    'phase1-foreign-viewer', 'Phase 1 Foreign Viewer', 'ACTIVE', false, 1,
    transaction_timestamp(), transaction_timestamp()
);
INSERT INTO iam.user_credentials (tenant_id, principal_id, password_hash, changed_at)
SELECT 'organization-phase1-foreign', 'principal-phase1-foreign',
       credential.password_hash, transaction_timestamp()
  FROM iam.user_credentials AS credential
 WHERE credential.tenant_id = 'organization-default'
   AND credential.principal_id = 'principal-admin';
INSERT INTO iam.login_index (login_name, tenant_id, principal_id)
VALUES (
    'phase1-foreign-viewer', 'organization-phase1-foreign',
    'principal-phase1-foreign'
);
INSERT INTO iam.role_bindings (
    tenant_id, id, principal_id, role_name, resource_version,
    created_at, updated_at
) VALUES (
    'organization-phase1-foreign', 'phase1-foreign-devops-viewer',
    'principal-phase1-foreign', 'DEVOPS_VIEWER', 1,
    transaction_timestamp(), transaction_timestamp()
);
COMMIT;
SELECT CASE WHEN
    (SELECT count(*) FROM iam.organizations
      WHERE id = 'organization-phase1-foreign') = 1
    AND (SELECT count(*) FROM iam.principals
      WHERE tenant_id = 'organization-phase1-foreign'
        AND id = 'principal-phase1-foreign') = 1
    AND (SELECT count(*) FROM iam.user_credentials
      WHERE tenant_id = 'organization-phase1-foreign'
        AND principal_id = 'principal-phase1-foreign') = 1
    AND (SELECT count(*) FROM iam.role_bindings
      WHERE tenant_id = 'organization-phase1-foreign'
        AND principal_id = 'principal-phase1-foreign'
        AND role_name = 'DEVOPS_VIEWER' AND revoked_at IS NULL) = 1
THEN 'READY' ELSE 'INVALID' END;`

const removeForeignTenantSQL = `BEGIN;
DELETE FROM iam.session_index WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.sessions WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.authorization_decisions WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.audit_outbox WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.role_bindings WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.user_credentials WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.login_index WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.principals WHERE tenant_id = 'organization-phase1-foreign';
DELETE FROM iam.organizations WHERE id = 'organization-phase1-foreign';
COMMIT;
SELECT CASE WHEN
    NOT EXISTS (SELECT 1 FROM iam.organizations
      WHERE id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.principals
      WHERE tenant_id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.sessions
      WHERE tenant_id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.session_index
      WHERE tenant_id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.authorization_decisions
      WHERE tenant_id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.audit_outbox
      WHERE tenant_id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.role_bindings
      WHERE tenant_id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.user_credentials
      WHERE tenant_id = 'organization-phase1-foreign')
    AND NOT EXISTS (SELECT 1 FROM iam.login_index
      WHERE tenant_id = 'organization-phase1-foreign')
THEN 'REMOVED' ELSE 'PRESENT' END;`

const observeDevOpsConfigurationSQL = `SELECT CASE WHEN EXISTS (
    SELECT 1
      FROM delivery.projects AS project
      JOIN delivery.source_connections AS connection
        ON connection.tenant_id = project.tenant_id
       AND connection.id = 'phase1-source'
      JOIN delivery.repository_bindings AS binding
        ON binding.tenant_id = project.tenant_id
       AND binding.id = 'phase1-repository'
       AND binding.project_id = project.id
       AND binding.source_connection_id = connection.id
      JOIN delivery.pipelines AS pipeline
        ON pipeline.tenant_id = project.tenant_id
       AND pipeline.id = 'phase1-pipeline'
       AND pipeline.project_id = project.id
       AND pipeline.repository_binding_id = binding.id
      JOIN delivery.pipeline_revisions AS revision
        ON revision.tenant_id = pipeline.tenant_id
       AND revision.id = pipeline.active_revision_id
       AND revision.pipeline_id = pipeline.id
       AND revision.project_id = project.id
       AND revision.repository_binding_id = binding.id
       AND revision.revision = pipeline.active_revision
       AND revision.content_digest = pipeline.active_revision_digest
     WHERE project.tenant_id = 'organization-default'
       AND project.id = 'phase1-project'
) AND NOT EXISTS (
    SELECT 1 FROM delivery.projects
     WHERE id = 'phase1-project' AND tenant_id <> 'organization-default'
) THEN 'READY' ELSE 'INVALID' END;`

func (value *gate) exerciseDevOpsAccess(
	ctx context.Context,
	administrator, administratorPassword []byte,
	installationID string,
) (sourceMaterials [][]byte, returnErr error) {
	sourceMaterials = make([][]byte, devOpsSourceMaterialCount)
	defer func() {
		if returnErr != nil {
			clearDevOpsSourceMaterials(sourceMaterials)
			sourceMaterials = nil
		}
	}()
	for index := 0; index < devOpsSourceTrustMaterialIndex; index++ {
		material, err := randomPassword(rand.Reader)
		if err != nil {
			returnErr = fail("devops-source-credential-entropy")
			return
		}
		sourceMaterials[index] = material
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(material, sourceMaterials[previous]) {
				returnErr = fail("devops-source-credential-entropy")
				return
			}
		}
	}
	sourceTrust, err := newDevOpsSourceTrustBundle(time.Now().UTC())
	if err != nil {
		returnErr = fail("devops-source-trust-entropy")
		return
	}
	sourceMaterials[devOpsSourceTrustMaterialIndex] = sourceTrust
	value.edge.addForbidden(sourceMaterials...)
	webhookInitial := sourceMaterials[0]
	webhookRotated := sourceMaterials[1]
	fetchCredential := sourceMaterials[2]
	reportCredential := sourceMaterials[3]

	for _, credential := range []struct {
		purpose   sourcecredential.Purpose
		reference devopsv1.ResourceID
		material  []byte
	}{
		{
			purpose: sourcecredential.PurposeWebhook, reference: devOpsWebhookSecretRef,
			material: webhookInitial,
		},
		{
			purpose: sourcecredential.PurposeFetch, reference: devOpsFetchCredentialRef,
			material: fetchCredential,
		},
		{
			purpose: sourcecredential.PurposeReport, reference: devOpsReportCredentialRef,
			material: reportCredential,
		},
	} {
		if err := value.applyDevOpsSourceCredential(
			ctx, credential.purpose, credential.reference, credential.material,
			"APPLIED", sourceMaterials,
		); err != nil {
			returnErr = fail("devops-source-credential-initial-apply")
			return
		}
	}
	if err := value.applyDevOpsSourceTrust(
		ctx, sourceTrust, "APPLIED", sourceMaterials,
	); err != nil {
		returnErr = fail("devops-source-trust-initial-apply")
		return
	}
	if err := value.applyDevOpsSourceTrust(
		ctx, sourceTrust, "UNCHANGED", sourceMaterials,
	); err != nil {
		returnErr = fail("devops-source-trust-equal-replay")
		return
	}
	if err := value.assertDevOpsSourceTrust(sourceTrust); err != nil {
		returnErr = fail("devops-source-trust-initial-state")
		return
	}
	if err := value.createDevOpsConfiguration(ctx, administrator); err != nil {
		returnErr = fail("devops-admin-control-plane")
		return
	}
	if _, err := value.waitDevOpsSourceUnavailable(ctx, administrator, 1); err != nil {
		returnErr = fail("devops-source-credential-initial-observation")
		return
	}
	if err := value.waitDevOpsBindingConnectionNotReady(ctx, administrator, 1); err != nil {
		returnErr = fail("devops-source-binding-initial-observation")
		return
	}

	if err := value.applyDevOpsSourceCredential(
		ctx, sourcecredential.PurposeWebhook, devOpsWebhookSecretRef, webhookRotated,
		"APPLIED", sourceMaterials,
	); err != nil {
		returnErr = fail("devops-source-credential-rotation")
		return
	}
	if err := value.applyDevOpsSourceCredential(
		ctx, sourcecredential.PurposeWebhook, devOpsWebhookSecretRef, webhookRotated,
		"UNCHANGED", sourceMaterials,
	); err != nil {
		returnErr = fail("devops-source-credential-equal-replay")
		return
	}
	for index := 0; index < 2; index++ {
		if err := runMXSourceCredential(
			ctx, value.releases.a, "retire-previous", value.config.root,
			string(devOpsTenant), string(sourcecredential.PurposeWebhook),
			string(devOpsWebhookSecretRef), "",
			"PREVIOUS_RETIRED", value.forbidden(sourceMaterials...),
		); err != nil {
			returnErr = fail("devops-source-credential-retirement")
			return
		}
	}
	rechecked, err := scheduleDevOpsRecheck(
		ctx, value.edge,
		"/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID),
		"phase1-recheck-devops-source-after-credential-rotation", administrator,
		devopsv1.ValidateSourceConnection,
		func(resource devopsv1.SourceConnection) uint64 {
			return resource.Metadata.ResourceVersion
		},
	)
	if err != nil {
		returnErr = fail("devops-source-credential-recheck")
		return
	}
	if _, err := value.waitDevOpsSourceUnavailable(
		ctx, administrator, rechecked.Metadata.ResourceVersion,
	); err != nil {
		returnErr = fail("devops-source-credential-rotated-observation")
		return
	}
	if err := value.assertDevOpsConfiguration(ctx, administrator); err != nil {
		returnErr = fail("devops-admin-readback")
		return
	}
	if err := value.assertDevOpsViewerBoundary(ctx, administrator); err != nil {
		returnErr = fail("devops-viewer-boundary")
		return
	}
	if err := value.assertForeignTenantBoundary(
		ctx, administratorPassword, installationID,
	); err != nil {
		returnErr = fail("devops-foreign-tenant-boundary")
		return
	}
	return
}

func (value *gate) applyDevOpsSourceCredential(
	ctx context.Context,
	purpose sourcecredential.Purpose,
	reference devopsv1.ResourceID,
	material []byte,
	wantState string,
	allMaterials [][]byte,
) error {
	return value.withDevOpsSourceInput(material, allMaterials, func(
		input string,
		forbidden [][]byte,
	) error {
		return runMXSourceCredential(
			ctx, value.releases.a, "apply", value.config.root, string(devOpsTenant),
			string(purpose), string(reference), input, wantState, forbidden,
		)
	})
}

func (value *gate) applyDevOpsSourceTrust(
	ctx context.Context,
	material []byte,
	wantState string,
	allMaterials [][]byte,
) error {
	return value.withDevOpsSourceInput(material, allMaterials, func(
		input string,
		forbidden [][]byte,
	) error {
		return runMXSourceTrust(
			ctx, value.releases.a, "apply", value.config.root, string(devOpsTenant),
			devOpsSourceEndpoint, input, wantState, forbidden,
		)
	})
}

func (value *gate) withDevOpsSourceInput(
	material []byte,
	allMaterials [][]byte,
	apply func(string, [][]byte) error,
) (returnErr error) {
	if len(material) == 0 || apply == nil {
		return errors.New("DevOps source input is invalid")
	}
	directory, err := os.MkdirTemp(
		filepath.Dir(value.config.root), ".matrix-phase1-source-input-",
	)
	if err != nil {
		return errors.New("DevOps source input directory creation failed")
	}
	if chmodErr := os.Chmod(directory, 0o700); chmodErr != nil {
		return errors.Join(
			errors.New("DevOps source input directory protection failed"),
			removeDevOpsSourceInput(directory),
		)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.Join(
			errors.New("DevOps source input directory is not private"),
			removeDevOpsSourceInput(directory),
		)
	}
	defer func() {
		if cleanupErr := removeDevOpsSourceInput(directory); cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()
	input := filepath.Join(directory, "material.input")
	defer func() {
		if cleanupErr := removeDevOpsSourceInput(input); cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()
	if err := writeDevOpsSourceInput(input, material); err != nil {
		return err
	}
	forbidden := value.forbidden(allMaterials...)
	forbidden = append(forbidden, []byte(directory), []byte(input))
	return apply(input, forbidden)
}

func writeDevOpsSourceInput(path string, material []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("source credential input creation failed")
	}
	written, writeErr := file.Write(material)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(material) || syncErr != nil || closeErr != nil ||
		os.Chmod(path, 0o600) != nil {
		return errors.New("source credential input write failed")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("source credential input is not private")
	}
	return nil
}

func removeDevOpsSourceInput(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("source credential input removal failed")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("source credential input remains after removal")
	}
	return nil
}

func clearDevOpsSourceMaterials(materials [][]byte) {
	for _, material := range materials {
		clear(material)
	}
}

func newDevOpsSourceTrustBundle(now time.Time) ([]byte, error) {
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errors.New("source trust time is invalid")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("source trust key generation failed")
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Matrix Phase 1 local provider root"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &privateKey.PublicKey, privateKey,
	)
	privateKey.D.SetInt64(0)
	if err != nil {
		return nil, errors.New("source trust certificate generation failed")
	}
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	canonical, err := sourcetrust.Canonicalize(content, now)
	clear(content)
	if err != nil {
		return nil, errors.New("source trust certificate is invalid")
	}
	return canonical, nil
}

func (value *gate) assertDevOpsSourceTrust(expected []byte) error {
	entries, err := inspectDevOpsSourceTrustRoot(value.config.root)
	if err != nil {
		return err
	}
	if expected == nil {
		if len(entries) != 0 {
			return errors.New("source trust root is not empty")
		}
		return nil
	}
	content, err := value.readDevOpsSourceTrust()
	if err != nil {
		return err
	}
	defer clear(content)
	if !bytes.Equal(content, expected) {
		return errors.New("source trust bundle changed")
	}
	return nil
}

func inspectDevOpsSourceTrustRoot(root string) ([]os.DirEntry, error) {
	path := filepath.Join(root, filepath.FromSlash(layout.DevOpsSourceTrustRoot))
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("source trust root is unsafe")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, errors.New("source trust root cannot be read")
	}
	return entries, nil
}

func (value *gate) readDevOpsSourceTrust() ([]byte, error) {
	entries, err := inspectDevOpsSourceTrustRoot(value.config.root)
	if err != nil {
		return nil, err
	}
	directoryName, err := sourcetrust.DirectoryName(
		devopsv1.ResourceScope{TenantID: devOpsTenant}, devOpsSourceEndpoint,
	)
	if err != nil || len(entries) != 1 || entries[0].Name() != directoryName ||
		!entries[0].IsDir() || entries[0].Type()&os.ModeSymlink != 0 {
		return nil, errors.New("source trust record identity is invalid")
	}
	directory := filepath.Join(
		value.config.root, filepath.FromSlash(layout.DevOpsSourceTrustRoot), directoryName,
	)
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 ||
		directoryInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("source trust record is unsafe")
	}
	children, err := os.ReadDir(directory)
	if err != nil || len(children) != 1 || children[0].Name() != sourcetrust.BundleFilename ||
		children[0].IsDir() || children[0].Type()&os.ModeSymlink != 0 {
		return nil, errors.New("source trust record shape is invalid")
	}
	path := filepath.Join(directory, sourcetrust.BundleFilename)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() < 1 ||
		info.Size() > sourcetrust.MaximumBundleBytes {
		return nil, errors.New("source trust bundle is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("source trust bundle cannot be read")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, sourcetrust.MaximumBundleBytes+1))
	openedInfo, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil ||
		len(content) == 0 || len(content) > sourcetrust.MaximumBundleBytes ||
		!openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		clear(content)
		return nil, errors.New("source trust bundle cannot be read")
	}
	if _, err := sourcetrust.CertPool(content, time.Now().UTC()); err != nil {
		clear(content)
		return nil, errors.New("source trust bundle is invalid")
	}
	return content, nil
}

func (value *gate) waitDevOpsSourceUnavailable(
	ctx context.Context,
	bearer []byte,
	afterVersion uint64,
) (devopsv1.SourceConnection, error) {
	poll, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for poll.Err() == nil {
		var connection devopsv1.SourceConnection
		_, err := value.edge.get(
			poll,
			"/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID),
			bearer, &connection,
		)
		if err == nil && devopsv1.ValidateSourceConnection(connection) == nil &&
			connection.Metadata.ResourceVersion > afterVersion &&
			connection.Status.Health == devopsv1.SourceConnectionUnavailable &&
			connection.Status.Reason == devopsv1.SourceConnectionReasonProviderUnavailable {
			return connection, nil
		}
		if !waitPoll(poll, 200*time.Millisecond) {
			break
		}
	}
	return devopsv1.SourceConnection{}, errors.New("DevOps source observation did not converge")
}

func (value *gate) waitDevOpsBindingConnectionNotReady(
	ctx context.Context,
	bearer []byte,
	afterVersion uint64,
) error {
	poll, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for poll.Err() == nil {
		var binding devopsv1.RepositoryBinding
		_, err := value.edge.get(
			poll,
			"/api/devops/v1/repository-bindings/"+string(devOpsRepositoryBindingID),
			bearer, &binding,
		)
		if err == nil && devopsv1.ValidateRepositoryBinding(binding) == nil &&
			binding.Metadata.ResourceVersion > afterVersion &&
			binding.Status.Health == devopsv1.RepositoryBindingPending &&
			binding.Status.Reason == devopsv1.RepositoryBindingReasonConnectionNotReady {
			return nil
		}
		if !waitPoll(poll, 200*time.Millisecond) {
			break
		}
	}
	return errors.New("DevOps repository observation did not converge")
}

func (value *gate) assertDevOpsDatabaseState(
	ctx context.Context,
	installationID string,
) error {
	observed, err := value.postgresScalar(
		ctx, installationID, observeDevOpsConfigurationSQL,
	)
	if err != nil || observed != "READY" {
		return errors.New("DevOps database state observation failed")
	}
	return nil
}

func (value *gate) createDevOpsConfiguration(
	ctx context.Context,
	bearer []byte,
) error {
	project, err := createDevOpsResource(
		ctx, value.edge, "/api/devops/v1/projects", "phase1-create-devops-project",
		"/v1/projects/"+string(devOpsProjectID), bearer,
		devopsv1.CreateDevOpsProjectRequest{ID: devOpsProjectID, Name: "phase1-project"},
		devopsv1.ValidateDevOpsProject,
		func(resource devopsv1.DevOpsProject) uint64 { return resource.Metadata.ResourceVersion },
	)
	if err != nil || project.Metadata.ID != devOpsProjectID ||
		project.Metadata.Scope.TenantID != devOpsTenant {
		return errors.New("DevOps project creation failed")
	}

	connection, err := createDevOpsResource(
		ctx, value.edge, "/api/devops/v1/source-connections", "phase1-create-devops-source",
		"/v1/source-connections/"+string(devOpsSourceConnectionID), bearer,
		devopsv1.CreateSourceConnectionRequest{
			ID: devOpsSourceConnectionID, Name: "phase1-source",
			Spec: devopsv1.SourceConnectionSpec{
				AdapterID: "source-adapter-gitea-v1", EndpointOrigin: devOpsSourceEndpoint,
				WebhookSecretRef: devOpsWebhookSecretRef, FetchCredentialRef: devOpsFetchCredentialRef,
				ReportCredentialRef: devOpsReportCredentialRef,
			},
		},
		devopsv1.ValidateSourceConnection,
		func(resource devopsv1.SourceConnection) uint64 { return resource.Metadata.ResourceVersion },
	)
	if err != nil || connection.Metadata.ID != devOpsSourceConnectionID ||
		connection.Metadata.Scope.TenantID != devOpsTenant ||
		connection.Status.Health != devopsv1.SourceConnectionPending ||
		connection.Status.Reason != devopsv1.SourceConnectionReasonConfigurationChanged {
		return errors.New("DevOps source connection creation failed")
	}
	if _, err := scheduleDevOpsRecheck(
		ctx, value.edge, "/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID),
		"phase1-recheck-devops-source", bearer, devopsv1.ValidateSourceConnection,
		func(resource devopsv1.SourceConnection) uint64 { return resource.Metadata.ResourceVersion },
	); err != nil {
		return err
	}

	binding, err := createDevOpsResource(
		ctx, value.edge, "/api/devops/v1/repository-bindings", "phase1-create-devops-repository",
		"/v1/repository-bindings/"+string(devOpsRepositoryBindingID), bearer,
		devopsv1.CreateRepositoryBindingRequest{
			ID: devOpsRepositoryBindingID, Name: "phase1-repository", ProjectID: devOpsProjectID,
			Spec: devopsv1.RepositoryBindingSpec{
				SourceConnectionID:   devOpsSourceConnectionID,
				ExternalRepositoryID: "repository-phase1", RepositoryPath: "matrix/service",
				TrustedDefaultBranch: "main",
			},
		},
		devopsv1.ValidateRepositoryBinding,
		func(resource devopsv1.RepositoryBinding) uint64 { return resource.Metadata.ResourceVersion },
	)
	if err != nil || binding.Metadata.ID != devOpsRepositoryBindingID ||
		binding.Metadata.Scope.TenantID != devOpsTenant || binding.ProjectID != devOpsProjectID ||
		binding.Status.Health != devopsv1.RepositoryBindingPending ||
		binding.Status.Reason != devopsv1.RepositoryBindingReasonConfigurationChanged {
		return errors.New("DevOps repository binding creation failed")
	}
	if _, err := scheduleDevOpsRecheck(
		ctx, value.edge, "/api/devops/v1/repository-bindings/"+string(devOpsRepositoryBindingID),
		"phase1-recheck-devops-repository", bearer, devopsv1.ValidateRepositoryBinding,
		func(resource devopsv1.RepositoryBinding) uint64 { return resource.Metadata.ResourceVersion },
	); err != nil {
		return err
	}

	pipeline, err := createDevOpsResource(
		ctx, value.edge, "/api/devops/v1/pipelines", "phase1-create-devops-pipeline",
		"/v1/pipelines/"+string(devOpsPipelineID), bearer,
		devopsv1.CreatePipelineRequest{
			ID: devOpsPipelineID, Name: "phase1-pipeline", ProjectID: devOpsProjectID,
			Draft: devopsv1.PipelineDraftSpec{
				RepositoryBindingID: devOpsRepositoryBindingID,
				TriggerPolicy:       devopsv1.TriggerChange,
				VerificationProfile: devopsv1.VerificationGo126OfflineV1,
				DependencyEgress:    devopsv1.DependencyEgressNone,
				ReporterPolicy:      devopsv1.ReporterChangeCheckV1,
			},
		},
		devopsv1.ValidatePipeline,
		func(resource devopsv1.Pipeline) uint64 { return resource.Metadata.ResourceVersion },
	)
	if err != nil || pipeline.Metadata.ID != devOpsPipelineID ||
		pipeline.Metadata.Scope.TenantID != devOpsTenant || pipeline.ProjectID != devOpsProjectID ||
		pipeline.ActiveRevision != nil {
		return errors.New("DevOps Pipeline creation failed")
	}

	response, err := value.edge.json(
		ctx, http.MethodPost,
		"/api/devops/v1/pipelines/"+string(devOpsPipelineID)+"/activate", bearer, nil,
		map[string]string{
			"Idempotency-Key": "phase1-activate-devops-pipeline",
			"If-Match":        formatResourceVersion(pipeline.Metadata.ResourceVersion),
		},
		http.StatusCreated,
	)
	if err != nil {
		return err
	}
	defer clear(response.body)
	var activation devopsv1.PipelineActivation
	if decodeOne(response.body, &activation) != nil ||
		devopsv1.ValidatePipelineActivation(activation) != nil ||
		activation.Pipeline.Metadata.ID != devOpsPipelineID ||
		activation.Pipeline.Metadata.Scope.TenantID != devOpsTenant ||
		activation.Revision.PipelineID != devOpsPipelineID ||
		activation.Revision.Scope.TenantID != devOpsTenant ||
		activation.Pipeline.ActiveRevision == nil ||
		activation.Pipeline.ActiveRevision.ID != activation.Revision.ID ||
		!isQuotedResourceVersion(response.header, activation.Pipeline.Metadata.ResourceVersion) ||
		response.header.Get("Location") != "/v1/pipelines/"+string(devOpsPipelineID)+
			"/revisions/"+string(activation.Revision.ID) {
		return errors.New("DevOps Pipeline activation failed")
	}
	return nil
}

func (value *gate) assertDevOpsConfiguration(ctx context.Context, bearer []byte) error {
	var project devopsv1.DevOpsProject
	projectHeader, err := value.edge.get(
		ctx, "/api/devops/v1/projects/"+string(devOpsProjectID), bearer, &project,
	)
	if err != nil || devopsv1.ValidateDevOpsProject(project) != nil ||
		project.Metadata.ID != devOpsProjectID || project.Metadata.Scope.TenantID != devOpsTenant ||
		!isQuotedResourceVersion(projectHeader, project.Metadata.ResourceVersion) {
		return errors.New("DevOps project readback failed")
	}

	var connection devopsv1.SourceConnection
	connectionHeader, err := value.edge.get(
		ctx, "/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID), bearer, &connection,
	)
	if err != nil || devopsv1.ValidateSourceConnection(connection) != nil ||
		connection.Metadata.ID != devOpsSourceConnectionID ||
		connection.Metadata.Scope.TenantID != devOpsTenant ||
		!isQuotedResourceVersion(connectionHeader, connection.Metadata.ResourceVersion) {
		return errors.New("DevOps source connection readback failed")
	}

	var binding devopsv1.RepositoryBinding
	bindingHeader, err := value.edge.get(
		ctx, "/api/devops/v1/repository-bindings/"+string(devOpsRepositoryBindingID), bearer, &binding,
	)
	if err != nil || devopsv1.ValidateRepositoryBinding(binding) != nil ||
		binding.Metadata.ID != devOpsRepositoryBindingID ||
		binding.Metadata.Scope.TenantID != devOpsTenant || binding.ProjectID != devOpsProjectID ||
		!isQuotedResourceVersion(bindingHeader, binding.Metadata.ResourceVersion) {
		return errors.New("DevOps repository binding readback failed")
	}

	var pipeline devopsv1.Pipeline
	pipelineHeader, err := value.edge.get(
		ctx, "/api/devops/v1/pipelines/"+string(devOpsPipelineID), bearer, &pipeline,
	)
	if err != nil || devopsv1.ValidatePipeline(pipeline) != nil ||
		pipeline.Metadata.ID != devOpsPipelineID || pipeline.Metadata.Scope.TenantID != devOpsTenant ||
		pipeline.ProjectID != devOpsProjectID || pipeline.ActiveRevision == nil ||
		!isQuotedResourceVersion(pipelineHeader, pipeline.Metadata.ResourceVersion) {
		return errors.New("DevOps Pipeline readback failed")
	}

	var revision devopsv1.PipelineRevision
	revisionHeader, err := value.edge.get(
		ctx,
		"/api/devops/v1/pipelines/"+string(devOpsPipelineID)+"/revisions/"+
			string(pipeline.ActiveRevision.ID),
		bearer, &revision,
	)
	if err != nil || devopsv1.ValidatePipelineRevision(revision) != nil ||
		revision.ID != pipeline.ActiveRevision.ID || revision.PipelineID != devOpsPipelineID ||
		revision.Scope.TenantID != devOpsTenant || revision.ContentDigest != pipeline.ActiveRevision.ContentDigest ||
		revisionHeader.Get("ETag") != `"`+revision.ContentDigest+`"` {
		return errors.New("DevOps Pipeline revision readback failed")
	}
	return nil
}

func (value *gate) assertDevOpsViewerBoundary(
	ctx context.Context,
	administrator []byte,
) error {
	initialPassword, err := randomPassword(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(initialPassword)
	currentPassword, err := randomPassword(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(currentPassword)
	value.edge.addForbidden(initialPassword, currentPassword)

	principal, err := value.edge.createUser(
		ctx, administrator, devOpsViewerLogin, "Phase 1 DevOps Viewer",
		initialPassword, "phase1-create-devops-viewer",
	)
	if err != nil {
		return err
	}
	if _, err := value.edge.putRoleBinding(
		ctx, administrator, principal.ID, iamv1.RoleDevOpsViewer,
		"phase1-bind-devops-viewer",
	); err != nil {
		return err
	}
	initialSession, err := value.edge.loginAs(
		ctx, devOpsViewerLogin, initialPassword, "phase1-login-devops-viewer-initial",
		principal.ID, "organization-default",
	)
	if err != nil {
		return err
	}
	defer clear(initialSession)
	value.edge.addForbidden(initialSession)
	if err := value.edge.changePasswordAs(
		ctx, initialSession, initialPassword, currentPassword,
		"phase1-change-devops-viewer-password", false,
	); err != nil {
		return err
	}
	if err := value.edge.logout(ctx, initialSession); err != nil {
		return err
	}
	viewer, err := value.edge.loginAs(
		ctx, devOpsViewerLogin, currentPassword, "phase1-login-devops-viewer-current",
		principal.ID, "organization-default",
	)
	if err != nil {
		return err
	}
	defer clear(viewer)
	value.edge.addForbidden(viewer)
	if err := value.assertDevOpsConfiguration(ctx, viewer); err != nil {
		return err
	}
	if err := expectDevOpsProblem(
		ctx, value.edge, http.MethodPost, "/api/devops/v1/projects", viewer,
		devopsv1.CreateDevOpsProjectRequest{ID: "phase1-viewer-denied", Name: "phase1-viewer-denied"},
		map[string]string{"Idempotency-Key": "phase1-viewer-create-denied"},
		http.StatusForbidden, devopsv1.ErrorForbidden,
	); err != nil {
		return err
	}
	var connection devopsv1.SourceConnection
	header, err := value.edge.get(
		ctx, "/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID),
		viewer, &connection,
	)
	if err != nil || devopsv1.ValidateSourceConnection(connection) != nil || header.Get("ETag") == "" {
		return errors.New("DevOps Viewer source read failed")
	}
	if err := expectDevOpsProblem(
		ctx, value.edge, http.MethodPost,
		"/api/devops/v1/source-connections/"+string(devOpsSourceConnectionID)+"/recheck",
		viewer, nil,
		map[string]string{
			"Idempotency-Key": "phase1-viewer-recheck-denied",
			"If-Match":        header.Get("ETag"),
		},
		http.StatusForbidden, devopsv1.ErrorForbidden,
	); err != nil {
		return err
	}
	return value.edge.logout(ctx, viewer)
}

func (value *gate) assertForeignTenantBoundary(
	ctx context.Context,
	password []byte,
	installationID string,
) (returnErr error) {
	seeded, err := value.postgresScalar(ctx, installationID, seedForeignTenantSQL)
	if err != nil || seeded != "READY" {
		return errors.New("foreign tenant fixture creation failed")
	}
	defer func() {
		if cleanupErr := value.removeForeignTenantFixture(ctx, installationID); cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()

	bearer, err := value.edge.loginAs(
		ctx, devOpsForeignLogin, password, "phase1-login-foreign-viewer",
		devOpsForeignPrincipal, devOpsForeignOrganization,
	)
	if err != nil {
		return err
	}
	defer clear(bearer)
	value.edge.addForbidden(bearer)
	if err := expectDevOpsProblem(
		ctx, value.edge, http.MethodGet,
		"/api/devops/v1/projects/"+string(devOpsProjectID), bearer, nil, nil,
		http.StatusNotFound, devopsv1.ErrorNotFound,
	); err != nil {
		return err
	}
	return value.edge.logout(ctx, bearer)
}

func (value *gate) removeForeignTenantFixture(
	ctx context.Context,
	installationID string,
) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		removed, err := value.postgresScalar(
			cleanupContext, installationID, removeForeignTenantSQL,
		)
		if err == nil && removed == "REMOVED" {
			return nil
		}
		if !waitPoll(cleanupContext, 100*time.Millisecond) {
			break
		}
	}
	return errors.New("foreign tenant fixture removal failed")
}

func createDevOpsResource[T any](
	ctx context.Context,
	client *edgeClient,
	path, idempotencyKey, location string,
	bearer []byte,
	body any,
	validate func(T) error,
	resourceVersion func(T) uint64,
) (T, error) {
	var zero T
	response, err := client.json(
		ctx, http.MethodPost, path, bearer, body,
		map[string]string{"Idempotency-Key": idempotencyKey}, http.StatusCreated,
	)
	if err != nil {
		return zero, err
	}
	defer clear(response.body)
	var resource T
	if decodeOne(response.body, &resource) != nil || validate(resource) != nil ||
		!isQuotedResourceVersion(response.header, resourceVersion(resource)) ||
		response.header.Get("Location") != location {
		return zero, errors.New("DevOps resource creation response failed")
	}
	return resource, nil
}

func scheduleDevOpsRecheck[T any](
	ctx context.Context,
	client *edgeClient,
	resourcePath, idempotencyKey string,
	bearer []byte,
	validate func(T) error,
	resourceVersion func(T) uint64,
) (T, error) {
	var zero T
	for attempt := 0; attempt < 8; attempt++ {
		var current T
		header, err := client.get(ctx, resourcePath, bearer, &current)
		if err != nil || validate(current) != nil ||
			!isQuotedResourceVersion(header, resourceVersion(current)) {
			return zero, errors.New("DevOps recheck read failed")
		}
		response, err := client.json(
			ctx, http.MethodPost, resourcePath+"/recheck", bearer, nil,
			map[string]string{
				"Idempotency-Key": idempotencyKey,
				"If-Match":        header.Get("ETag"),
			},
			http.StatusAccepted, http.StatusPreconditionFailed,
		)
		if err != nil {
			return zero, err
		}
		if response.status == http.StatusPreconditionFailed {
			problemErr := validateDevOpsProblem(
				response, http.StatusPreconditionFailed, devopsv1.ErrorPreconditionFailed,
			)
			clear(response.body)
			if problemErr != nil {
				return zero, problemErr
			}
			if !waitPoll(ctx, 25*time.Millisecond) {
				return zero, errors.New("DevOps recheck was interrupted")
			}
			continue
		}
		var resource T
		if decodeOne(response.body, &resource) != nil || validate(resource) != nil ||
			!isQuotedResourceVersion(response.header, resourceVersion(resource)) ||
			response.header.Get("Location") != resourcePath[len("/api/devops"):] {
			clear(response.body)
			return zero, errors.New("DevOps recheck response failed")
		}
		clear(response.body)
		return resource, nil
	}
	return zero, errors.New("DevOps recheck exceeded conflict retry bound")
}

func expectDevOpsProblem(
	ctx context.Context,
	client *edgeClient,
	method, path string,
	bearer []byte,
	body any,
	headers map[string]string,
	status int,
	code devopsv1.ErrorCode,
) error {
	response, err := client.problem(ctx, method, path, bearer, body, headers, status)
	if err != nil {
		return err
	}
	defer clear(response.body)
	return validateDevOpsProblem(response, status, code)
}

func validateDevOpsProblem(
	response httpResult,
	status int,
	code devopsv1.ErrorCode,
) error {
	var problem devopsv1.Problem
	if decodeOne(response.body, &problem) != nil || devopsv1.ValidateProblem(problem) != nil ||
		problem.Status != status || problem.Code != code || response.header.Get("ETag") != "" ||
		response.header.Get("Location") != "" {
		return errors.New("DevOps problem response failed")
	}
	return nil
}
