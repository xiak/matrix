package installationv1

// IAMAuthorizationProfilesMigrationFileEnvironment is the only file selector
// accepted by the one-shot IAM migration process for the release-authenticated
// additional product catalog. It is not mounted into any resident service.
const IAMAuthorizationProfilesMigrationFileEnvironment = "MATRIX_MIGRATION_IAM_AUTHORIZATION_PROFILES_FILE"
