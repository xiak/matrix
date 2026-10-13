package managedservicev1

type ServiceDefinitionState string
type ServiceActivationPrerequisite string
type OfferingState string
type RegionProfile string
type RegionState string
type InstallationPhase string
type InstallationOperationKind string
type CommandType string
type CommandState string
type CommandTargetKind string
type ErrorCode string

const MaxCommandResultItems = 100

const (
	PostgreSQLServiceID     = "postgresql"
	PostgreSQLOfferingID    = "postgresql-18"
	MySQLServiceID          = "mysql"
	MySQLOfferingID         = "mysql-8.4"
	ElasticsearchServiceID  = "elasticsearch"
	ElasticsearchOfferingID = "elasticsearch-8.19"
	RabbitMQServiceID       = "rabbitmq"
	RabbitMQOfferingID      = "rabbitmq-4.1"
)

const (
	ServiceDefinitionAvailable   ServiceDefinitionState = "AVAILABLE"
	ServiceDefinitionUnavailable ServiceDefinitionState = "UNAVAILABLE"
)

// PermissionOnly is the only admitted first-release prerequisite. Products
// that require billing, legal, original-root or third-party consent remain
// unpublished until their closed server-side prerequisite is implemented.
const ServiceActivationPermissionOnly ServiceActivationPrerequisite = "PERMISSION_ONLY"

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

// Command results are a closed managed-service recovery surface. They are not
// generic receipts and cannot be extended by callers with arbitrary command
// names or resource kinds.
const (
	CommandQuotaActivate         CommandType = "QUOTA_ACTIVATE"
	CommandInstallationCreate    CommandType = "INSTALLATION_CREATE"
	CommandInstallationTerminate CommandType = "INSTALLATION_TERMINATE"
	CommandServiceRoleBind       CommandType = "SERVICE_ROLE_BIND"
	CommandServiceRoleUnbind     CommandType = "SERVICE_ROLE_UNBIND"
)

const (
	CommandInProgress CommandState = "IN_PROGRESS"
	CommandSucceeded  CommandState = "SUCCEEDED"
	CommandFailed     CommandState = "FAILED"
)

const (
	CommandTargetQuotaEntitlement    CommandTargetKind = "QUOTA_ENTITLEMENT"
	CommandTargetServiceInstallation CommandTargetKind = "SERVICE_INSTALLATION"
)

const (
	ErrorInvalidArgument           ErrorCode = "INVALID_ARGUMENT"
	ErrorUnauthenticated           ErrorCode = "UNAUTHENTICATED"
	ErrorPermissionDenied          ErrorCode = "PERMISSION_DENIED"
	ErrorIdentityUnavailable       ErrorCode = "IDENTITY_UNAVAILABLE"
	ErrorNotFound                  ErrorCode = "NOT_FOUND"
	ErrorAlreadyExists             ErrorCode = "ALREADY_EXISTS"
	ErrorIdempotencyConflict       ErrorCode = "IDEMPOTENCY_CONFLICT"
	ErrorServiceDefinitionConflict ErrorCode = "SERVICE_DEFINITION_CONFLICT"
	ErrorServiceUnavailable        ErrorCode = "SERVICE_UNAVAILABLE"
	ErrorServiceNotActivated       ErrorCode = "SERVICE_NOT_ACTIVATED"
	ErrorQuotaExhausted            ErrorCode = "QUOTA_EXHAUSTED"
	ErrorRegionUnavailable         ErrorCode = "REGION_UNAVAILABLE"
	ErrorServiceRoleConflict       ErrorCode = "SERVICE_ROLE_CONFLICT"
	ErrorResourceStateConflict     ErrorCode = "RESOURCE_STATE_CONFLICT"
	ErrorInternal                  ErrorCode = "INTERNAL"
)
