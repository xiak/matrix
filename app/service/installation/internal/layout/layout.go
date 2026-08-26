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

	PostgresPassword  = "secrets/database/postgres-superuser-password"
	PostgresMigration = "secrets/database/postgres-migration-dsn"
	IAMAPI            = "secrets/database/iam-api-dsn"
	IAMWorker         = "secrets/database/iam-worker-dsn"
	AuditRuntime      = "secrets/database/audit-runtime-dsn"
	PaaSAPI           = "secrets/database/paas-api-dsn"
	PaaSWorker        = "secrets/database/paas-worker-dsn"

	IAMBootstrap                   = "secrets/authority/iam-bootstrap.json"
	AuditIAMCredential             = "secrets/authority/audit-iam-credential"
	IAMAuditCredential             = "secrets/authority/iam-audit-credential"
	PaaSIAMCredential              = "secrets/authority/paas-iam-credential"
	PaaSAuditCredential            = "secrets/authority/paas-audit-credential"
	InstallationVerifierCredential = "secrets/authority/installation-verifier-iam-credential"
	AuditCursorKey                 = "secrets/authority/audit-cursor-key"
	BackupSealKey                  = "secrets/authority/backup-seal-key"
	APISIXIAMCredential            = "secrets/gateway/apisix-iam-credential"
	InitialAdministratorPassword   = "secrets/operator/initial-admin-password"

	PostgresData       = "data/postgres"
	ExecutorRoot       = "runtime/executor"
	WorkloadSecretRoot = "secrets/workloads"
	BackupDirectory    = "backups"
	SupportDirectory   = "support"
)

func ReleaseDirectory(releaseID string) string {
	return "releases/" + releaseID
}
