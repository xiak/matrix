package managedservicev1

type OfferingKind string
type OfferingState string
type RegionProfile string
type RegionState string
type InstallationPhase string
type ErrorCode string

const (
	OfferingPostgreSQL   OfferingKind = "POSTGRESQL"
	PostgreSQLOfferingID              = "postgresql-18"
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
	InstallationPending      InstallationPhase = "PENDING"
	InstallationProvisioning InstallationPhase = "PROVISIONING"
	InstallationReady        InstallationPhase = "READY"
	InstallationFailed       InstallationPhase = "FAILED"
)

const (
	ErrorInvalidArgument     ErrorCode = "INVALID_ARGUMENT"
	ErrorUnauthenticated     ErrorCode = "UNAUTHENTICATED"
	ErrorPermissionDenied    ErrorCode = "PERMISSION_DENIED"
	ErrorIdentityUnavailable ErrorCode = "IDENTITY_UNAVAILABLE"
	ErrorNotFound            ErrorCode = "NOT_FOUND"
	ErrorAlreadyExists       ErrorCode = "ALREADY_EXISTS"
	ErrorIdempotencyConflict ErrorCode = "IDEMPOTENCY_CONFLICT"
	ErrorQuotaExhausted      ErrorCode = "QUOTA_EXHAUSTED"
	ErrorRegionUnavailable   ErrorCode = "REGION_UNAVAILABLE"
	ErrorInternal            ErrorCode = "INTERNAL"
)
