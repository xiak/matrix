// Package layout owns the closed relative filesystem contract below one
// Matrix installation root. Paths are slash-normalized so the same constants
// can feed Linux Compose mounts and host-local filesystem adapters.
package layout

import "strings"

const (
	ReleaseTrust                    = "config/release-trust.json"
	Compose                         = "config/compose.json"
	ArtifactCatalog                 = "config/artifact-catalog.json"
	APISIXRoutes                    = "config/apisix.yaml"
	APISIXConfig                    = "config/apisix-config.yaml"
	APISIXUID                       = "config/apisix.uid"
	APISIXNginx                     = "runtime/apisix/nginx.conf"
	NodeConfiguration               = "config/node.json"
	NodeStartupDirectory            = "config/native"
	NodeDockerConfiguration         = "config/docker-client/config.json"
	CollectorConfiguration          = "config/collector.yaml"
	NodeCertificate                 = "secrets/node/node.pem"
	NodePrivateKey                  = "secrets/node/node-key.pem"
	NodeTrust                       = "secrets/node/trust.pem"
	CollectorCertificate            = "secrets/node/collector.pem"
	CollectorPrivateKey             = "secrets/node/collector-key.pem"
	CollectorExecutable             = "runtime/collector/node-exporter"
	NodeEnrollmentIntent            = "state/node-enrollment-intent.json"
	NodeEnrollmentAttempt           = "state/node-enrollment-attempted"
	NodeEnrollmentResponse          = "state/node-enrollment-response.json"
	NodeEnrollmentCleanup           = "state/node-enrollment-cleanup.json"
	NodeControllerDirectory         = "secrets/node-controller"
	NodeControllerConfiguration     = "secrets/node-controller/configuration.json"
	EnrollmentControllerCertificate = "secrets/node-controller/enrollment-controller.pem"
	EnrollmentControllerPrivateKey  = "secrets/node-controller/enrollment-controller-key.pem"
	EnrollmentControllerTrust       = "secrets/node-controller/enrollment-controller-trust.pem"
	NodeControllerPending           = "secrets/operator/node-controller-pending.json"

	PostgresPassword          = "secrets/database/postgres-superuser-password"
	PostgresMigration         = "secrets/database/postgres-migration-dsn"
	IAMAPI                    = "secrets/database/iam-api-dsn"
	IAMWorker                 = "secrets/database/iam-worker-dsn"
	IAMCredentialRecovery     = "secrets/database/iam-credential-recovery-dsn"
	IAMAuthenticationRecovery = "secrets/database/iam-authentication-recovery-dsn"
	IAMBackupCustody          = "secrets/database/iam-backup-custody-dsn"
	IAMNotificationWorker     = "secrets/database/iam-notification-worker-dsn"
	IAMAccessAnalysisWorker   = "secrets/database/iam-access-analysis-worker-dsn"
	AuditRuntime              = "secrets/database/audit-runtime-dsn"
	PaaSAPI                   = "secrets/database/paas-api-dsn"
	PaaSWorker                = "secrets/database/paas-worker-dsn"
	DevOpsAPI                 = "secrets/database/devops-api-dsn"
	DevOpsCheckReporter       = "secrets/database/devops-check-reporter-dsn"
	DevOpsWorker              = "secrets/database/devops-worker-dsn"
	DevOpsSourceFetcher       = "secrets/database/devops-source-fetcher-dsn"
	DevOpsSourceObserver      = "secrets/database/devops-source-observer-dsn"

	IAMBootstrap                        = "secrets/authority/iam-bootstrap.json"
	IAMAccessKeyWrappingKeyring         = "secrets/authority/iam-access-key-wrapping-keyring.json"
	IAMTOTPKeyring                      = "secrets/authority/iam-totp-keyring.json"
	IAMEmailVerificationKeyring         = "secrets/authority/iam-email-verification-keyring.json"
	IAMSecurityMailSMTPChannel          = "secrets/authority/iam-security-mail-smtp-channel.json"
	IAMCursorKey                        = "secrets/authority/iam-cursor-key"
	AuditIAMCredential                  = "secrets/authority/audit-iam-credential"
	IAMAuditCredential                  = "secrets/authority/iam-audit-credential"
	PlatformIAMCredential               = "secrets/authority/platform-iam-credential"
	PaaSIAMCredential                   = "secrets/authority/paas-iam-credential"
	PaaSAuditCredential                 = "secrets/authority/paas-audit-credential"
	DevOpsIAMCredential                 = "secrets/authority/devops-iam-credential"
	DevOpsAuditCredential               = "secrets/authority/devops-audit-credential"
	InstallationVerifierCredential      = "secrets/authority/installation-verifier-iam-credential"
	EnrollmentIssuerCertificate         = "secrets/authority/node-enrollment-issuer.der"
	EnrollmentIssuerPrivateKey          = "secrets/authority/node-enrollment-issuer-key.der"
	EnrollmentIngressCertificate        = "secrets/authority/node-enrollment-ingress.pem"
	EnrollmentIngressPrivateKey         = "secrets/authority/node-enrollment-ingress-key.pem"
	AuditCursorKey                      = "secrets/authority/audit-cursor-key"
	PaaSCursorKey                       = "secrets/authority/paas-cursor-key"
	AuditEdgeAssertion                  = "secrets/authority/audit-edge-assertion"
	PaaSEdgeAssertion                   = "secrets/authority/paas-edge-assertion"
	BackupSealKey                       = "secrets/authority/backup-seal-key"
	InitialAdministratorPassword        = "secrets/operator/initial-admin-password"
	IAMLocalRecoveryAuthority           = "secrets/operator/iam-local-recovery-authority.json"
	IAMLocalRecoveryRequest             = "secrets/operator/iam-local-recovery-request.json"
	IAMLocalRecoveryQuery               = "secrets/operator/iam-local-recovery-query.json"
	IAMAuthenticationRecoveryCompletion = "state/iam-authentication-recovery/completion.json"

	PostgresData                = "data/postgres"
	ExecutorRoot                = "runtime/executor"
	WorkloadSecretRoot          = "secrets/workloads"
	DevOpsWebhookCredentialRoot = "secrets/devops/source-webhooks"
	DevOpsFetchCredentialRoot   = "secrets/devops/source-fetch"
	DevOpsReportCredentialRoot  = "secrets/devops/source-report"
	DevOpsSourceTrustRoot       = "config/devops/source-trust"
	DevOpsSourceArchiveRoot     = "data/devops/source-archives"
	DevOpsExecutorSpoolRoot     = "data/devops/executor-spool"
	DevOpsExecutorPKIRoot       = "secrets/devops/executor-pki"
	DevOpsExecutorPKIBundle     = "secrets/devops/executor-pki/authority-bundle.json"
	DevOpsExecutorServerCA      = "secrets/devops/executor-pki/server-ca.crt"
	DevOpsExecutorServerCert    = "secrets/devops/executor-pki/gateway-server.crt"
	DevOpsExecutorServerKey     = "secrets/devops/executor-pki/gateway-server.key"
	DevOpsExecutorAdminCA       = "secrets/devops/executor-pki/admin-client-ca.crt"
	DevOpsExecutorRunnerCA      = "secrets/devops/executor-pki/runner-client-ca.crt"
	DevOpsBuildWorkerClientCert = "secrets/devops/executor-pki/build-worker.crt"
	DevOpsBuildWorkerClientKey  = "secrets/devops/executor-pki/build-worker.key"
	DevOpsRunnerEnrollmentRoot  = "secrets/devops/runner-enrollments"
	BackupDirectory             = "backups"
	SupportDirectory            = "support"
)

func ReleaseDirectory(releaseID string) string {
	return "releases/" + releaseID
}

// Callers validate the digest before resolving any managed filesystem path.
func NodeCredentialSnapshot(digest string) string {
	return "secrets/node-rotations/" + strings.TrimPrefix(digest, "sha256:") + ".json"
}

func IAMAuthenticationRecoveryIntent(commandID string) string {
	return "state/iam-authentication-recovery/" + commandID + ".intent.json"
}

func IAMAuthenticationRecoveryPreflightIntent(commandID string) string {
	return "state/iam-authentication-recovery/" + commandID + ".preflight.json"
}

func IAMAuthenticationRecoveryClosure(commandID string) string {
	return "state/iam-authentication-recovery/" + commandID + ".closure.json"
}

func IAMAuthenticationRecoverySecuritySnapshot(commandID string) string {
	return "state/iam-authentication-recovery/" + commandID + ".security-snapshot.json"
}
