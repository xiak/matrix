package installationv1

// IAMProductAuthorizationMigrationFileEnvironment is the only file selector
// accepted by the one-shot IAM migration process for the release-authenticated
// additional product catalog. It is not mounted into any resident service.
const IAMProductAuthorizationMigrationFileEnvironment = "MATRIX_MIGRATION_IAM_PRODUCT_AUTHORIZATION_FILE"
