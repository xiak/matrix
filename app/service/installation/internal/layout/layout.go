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

	PostgresPassword     = "secrets/database/postgres-superuser-password"
	PostgresMigration    = "secrets/database/postgres-migration-dsn"
	IAMAPI               = "secrets/database/iam-api-dsn"
	IAMWorker            = "secrets/database/iam-worker-dsn"
	AuditRuntime         = "secrets/database/audit-runtime-dsn"
	PaaSAPI              = "secrets/database/paas-api-dsn"
	PaaSWorker           = "secrets/database/paas-worker-dsn"
	DevOpsAPI            = "secrets/database/devops-api-dsn"
	DevOpsWorker         = "secrets/database/devops-worker-dsn"
	DevOpsSourceFetcher  = "secrets/database/devops-source-fetcher-dsn"
	DevOpsSourceObserver = "secrets/database/devops-source-observer-dsn"

	IAMBootstrap                   = "secrets/authority/iam-bootstrap.json"
	AuditIAMCredential             = "secrets/authority/audit-iam-credential"
	IAMAuditCredential             = "secrets/authority/iam-audit-credential"
	PlatformIAMCredential          = "secrets/authority/platform-iam-credential"
	PaaSIAMCredential              = "secrets/authority/paas-iam-credential"
	PaaSAuditCredential            = "secrets/authority/paas-audit-credential"
	DevOpsIAMCredential            = "secrets/authority/devops-iam-credential"
	DevOpsAuditCredential          = "secrets/authority/devops-audit-credential"
	InstallationVerifierCredential = "secrets/authority/installation-verifier-iam-credential"
	AuditCursorKey                 = "secrets/authority/audit-cursor-key"
	BackupSealKey                  = "secrets/authority/backup-seal-key"
	InitialAdministratorPassword   = "secrets/operator/initial-admin-password"

	PostgresData                = "data/postgres"
	ExecutorRoot                = "runtime/executor"
	WorkloadSecretRoot          = "secrets/workloads"
	DevOpsWebhookCredentialRoot = "secrets/devops/source-webhooks"
	DevOpsFetchCredentialRoot   = "secrets/devops/source-fetch"
	DevOpsReportCredentialRoot  = "secrets/devops/source-report"
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
	BackupDirectory             = "backups"
	SupportDirectory            = "support"
)

func ReleaseDirectory(releaseID string) string {
	return "releases/" + releaseID
}
