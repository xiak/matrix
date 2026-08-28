// Package layout owns the closed relative filesystem contract below one
// Matrix installation root. Paths are slash-normalized so the same constants
// can feed Linux Compose mounts and host-local filesystem adapters.
package layout

import "strings"

const (
	ReleaseTrust                = "config/release-trust.json"
	Compose                     = "config/compose.json"
	ArtifactCatalog             = "config/artifact-catalog.json"
	APISIXRoutes                = "config/apisix.yaml"
	APISIXConfig                = "config/apisix-config.yaml"
	APISIXUID                   = "config/apisix.uid"
	APISIXNginx                 = "runtime/apisix/nginx.conf"
	NodeConfiguration           = "config/node.json"
	NodeStartupDirectory        = "config/native"
	NodeDockerConfiguration     = "config/docker-client/config.json"
	CollectorConfiguration      = "config/collector.yaml"
	NodeCertificate             = "secrets/node/node.pem"
	NodePrivateKey              = "secrets/node/node-key.pem"
	NodeTrust                   = "secrets/node/trust.pem"
	CollectorCertificate        = "secrets/node/collector.pem"
	CollectorPrivateKey         = "secrets/node/collector-key.pem"
	CollectorExecutable         = "runtime/collector/node-exporter"
	NodeControllerDirectory     = "secrets/node-controller"
	NodeControllerConfiguration = "secrets/node-controller/configuration.json"
	NodeControllerPending       = "secrets/operator/node-controller-pending.json"

	PostgresPassword      = "secrets/database/postgres-superuser-password"
	PostgresMigration     = "secrets/database/postgres-migration-dsn"
	IAMAPI                = "secrets/database/iam-api-dsn"
	IAMWorker             = "secrets/database/iam-worker-dsn"
	IAMCredentialRecovery = "secrets/database/iam-credential-recovery-dsn"
	AuditRuntime          = "secrets/database/audit-runtime-dsn"
	PaaSAPI               = "secrets/database/paas-api-dsn"
	PaaSWorker            = "secrets/database/paas-worker-dsn"

	IAMBootstrap                   = "secrets/authority/iam-bootstrap.json"
	AuditIAMCredential             = "secrets/authority/audit-iam-credential"
	IAMAuditCredential             = "secrets/authority/iam-audit-credential"
	PaaSIAMCredential              = "secrets/authority/paas-iam-credential"
	PaaSAuditCredential            = "secrets/authority/paas-audit-credential"
	InstallationVerifierCredential = "secrets/authority/installation-verifier-iam-credential"
	AuditCursorKey                 = "secrets/authority/audit-cursor-key"
	BackupSealKey                  = "secrets/authority/backup-seal-key"
	InitialAdministratorPassword   = "secrets/operator/initial-admin-password"
	IAMLocalRecoveryAuthority      = "secrets/operator/iam-local-recovery-authority.json"
	IAMLocalRecoveryRequest        = "secrets/operator/iam-local-recovery-request.json"
	IAMLocalRecoveryQuery          = "secrets/operator/iam-local-recovery-query.json"

	PostgresData       = "data/postgres"
	ExecutorRoot       = "runtime/executor"
	WorkloadSecretRoot = "secrets/workloads"
	BackupDirectory    = "backups"
	SupportDirectory   = "support"
)

func ReleaseDirectory(releaseID string) string {
	return "releases/" + releaseID
}

// Callers validate the digest before resolving any managed filesystem path.
func NodeCredentialSnapshot(digest string) string {
	return "secrets/node-rotations/" + strings.TrimPrefix(digest, "sha256:") + ".json"
}
