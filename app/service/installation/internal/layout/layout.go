// Package layout owns the closed relative filesystem contract below one
// Matrix installation root. Paths are slash-normalized so the same constants
// can feed Linux Compose mounts and host-local filesystem adapters.
package layout

const (
	ReleaseTrust    = "config/release-trust.json"
	Compose         = "config/compose.json"
	ArtifactCatalog = "config/artifact-catalog.json"
	APISIXRoutes    = "config/apisix.yaml"
	APISIXConfig    = "config/apisix-config.yaml"
	APISIXUID       = "config/apisix.uid"
	APISIXNginx     = "runtime/apisix/nginx.conf"

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

	IAMBootstrap                        = "secrets/authority/iam-bootstrap.json"
	IAMAccessKeyWrappingKeyring         = "secrets/authority/iam-access-key-wrapping-keyring.json"
	IAMTOTPKeyring                      = "secrets/authority/iam-totp-keyring.json"
	IAMEmailVerificationKeyring         = "secrets/authority/iam-email-verification-keyring.json"
	IAMSecurityMailSMTPChannel          = "secrets/authority/iam-security-mail-smtp-channel.json"
	IAMCursorKey                        = "secrets/authority/iam-cursor-key"
	AuditIAMCredential                  = "secrets/authority/audit-iam-credential"
	IAMAuditCredential                  = "secrets/authority/iam-audit-credential"
	PaaSIAMCredential                   = "secrets/authority/paas-iam-credential"
	PaaSAuditCredential                 = "secrets/authority/paas-audit-credential"
	InstallationVerifierCredential      = "secrets/authority/installation-verifier-iam-credential"
	AuditCursorKey                      = "secrets/authority/audit-cursor-key"
	BackupSealKey                       = "secrets/authority/backup-seal-key"
	InitialAdministratorPassword        = "secrets/operator/initial-admin-password"
	IAMAuthenticationRecoveryCompletion = "state/iam-authentication-recovery/completion.json"

	PostgresData       = "data/postgres"
	ExecutorRoot       = "runtime/executor"
	WorkloadSecretRoot = "secrets/workloads"
	BackupDirectory    = "backups"
	SupportDirectory   = "support"
)

func ReleaseDirectory(releaseID string) string {
	return "releases/" + releaseID
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
