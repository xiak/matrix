package managedservicev1

type OfferingKind string
type OfferingState string
type RegionProfile string
type RegionState string
type InstallationPhase string
type InstallationOperationKind string
type ErrorCode string

const (
	OfferingPostgreSQL      OfferingKind = "POSTGRESQL"
	PostgreSQLOfferingID                 = "postgresql-18"
	OfferingMySQL           OfferingKind = "MYSQL"
	MySQLOfferingID                      = "mysql-8.4"
	OfferingElasticsearch   OfferingKind = "ELASTICSEARCH"
	ElasticsearchOfferingID              = "elasticsearch-8.19"
	OfferingRabbitMQ        OfferingKind = "RABBITMQ"
	RabbitMQOfferingID                   = "rabbitmq-4.1"
)

const (
	OfferingAvailable   OfferingState = "AVAILABLE"
	OfferingUnavailable OfferingState = "UNAVAILABLE"
)

const RegionLocalMachine RegionProfile = "LOCAL_MACHINE"

const (
	RegionReady       RegionState = "READY"
	RegionStale       RegionState = "STALE"
	RegionUnavailable RegionState = "UNAVAILABLE"
)

const (
	InstallationPending            InstallationPhase = "PENDING"
	InstallationProvisioning       InstallationPhase = "PROVISIONING"
	InstallationReady              InstallationPhase = "READY"
	InstallationFailed             InstallationPhase = "FAILED"
	InstallationRollbackFailed     InstallationPhase = "ROLLBACK_FAILED"
	InstallationTerminationPending InstallationPhase = "TERMINATION_PENDING"
	InstallationTerminating        InstallationPhase = "TERMINATING"
	InstallationTerminationFailed  InstallationPhase = "TERMINATION_FAILED"
	InstallationTerminated         InstallationPhase = "TERMINATED"
)

const (
	InstallationOperationProvision InstallationOperationKind = "PROVISION"
	InstallationOperationTerminate InstallationOperationKind = "TERMINATE"
)

const (
	ErrorInvalidArgument       ErrorCode = "INVALID_ARGUMENT"
	ErrorUnauthenticated       ErrorCode = "UNAUTHENTICATED"
	ErrorPermissionDenied      ErrorCode = "PERMISSION_DENIED"
	ErrorIdentityUnavailable   ErrorCode = "IDENTITY_UNAVAILABLE"
	ErrorNotFound              ErrorCode = "NOT_FOUND"
	ErrorAlreadyExists         ErrorCode = "ALREADY_EXISTS"
	ErrorIdempotencyConflict   ErrorCode = "IDEMPOTENCY_CONFLICT"
	ErrorQuotaExhausted        ErrorCode = "QUOTA_EXHAUSTED"
	ErrorRegionUnavailable     ErrorCode = "REGION_UNAVAILABLE"
	ErrorServiceRoleConflict   ErrorCode = "SERVICE_ROLE_CONFLICT"
	ErrorResourceStateConflict ErrorCode = "RESOURCE_STATE_CONFLICT"
	ErrorInternal              ErrorCode = "INTERNAL"
)
