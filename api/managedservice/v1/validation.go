package managedservicev1

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const maximumSafeInteger = uint64(9007199254740991)

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,61}[a-z0-9]$`)
	codePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
)

func ValidateActivateQuotaRequest(value ActivateQuotaRequest) error {
	return errors.Join(
		validateID("offeringId", value.OfferingID),
		validateID("quotaShapeId", value.QuotaShapeID),
		validatePositiveCount("instanceCount", value.InstanceCount),
	)
}

func ValidateCreateInstallationRequest(value CreateInstallationRequest) error {
	return errors.Join(
		validateName("id", value.ID),
		validateText("name", value.Name, 1, 128),
		validateID("offeringId", value.OfferingID),
		validateID("quotaEntitlementId", value.QuotaEntitlementID),
		validateID("regionId", value.RegionID),
	)
}

func ValidateServiceOffering(value ServiceOffering) error {
	var problems []error
	problems = append(problems,
		validateID("offering.id", value.ID),
		validateText("offering.displayName", value.DisplayName, 1, 128),
		validateText("offering.description", value.Description, 1, 512),
		validateName("offering.engineFamily", value.EngineFamily),
		validateID("offering.engineVersion", value.EngineVersion),
	)
	if value.Kind != OfferingPostgreSQL {
		problems = append(problems, errors.New("offering kind is invalid"))
	}
	if value.State != OfferingAvailable && value.State != OfferingUnavailable {
		problems = append(problems, errors.New("offering state is invalid"))
	}
	if len(value.QuotaShapes) == 0 || len(value.QuotaShapes) > 16 {
		problems = append(problems, errors.New("offering quota shape inventory is invalid"))
	}
	seen := map[string]struct{}{}
	for _, shape := range value.QuotaShapes {
		if _, duplicate := seen[shape.ID]; duplicate {
			problems = append(problems, errors.New("offering quota shape IDs must be unique"))
		}
		seen[shape.ID] = struct{}{}
		problems = append(problems, ValidateQuotaShape(shape))
	}
	return errors.Join(problems...)
}

func ValidateQuotaShape(value QuotaShape) error {
	return errors.Join(
		validateID("quotaShape.id", value.ID),
		validateText("quotaShape.displayName", value.DisplayName, 1, 128),
		validatePositiveCapacity("quotaShape.cpuMillicores", value.CPUMillicores),
		validatePositiveCapacity("quotaShape.memoryMiB", value.MemoryMiB),
		validatePositiveCapacity("quotaShape.storageGiB", value.StorageGiB),
	)
}

func ValidateRegion(value Region) error {
	var problems []error
	problems = append(problems,
		validateID("region.id", value.ID),
		validateText("region.displayName", value.DisplayName, 1, 128),
		validatePositiveCapacity("region.capacity.cpuMillicores", value.Capacity.CPUMillicores),
		validatePositiveCapacity("region.capacity.memoryMiB", value.Capacity.MemoryMiB),
		validatePositiveCapacity("region.capacity.storageGiB", value.Capacity.StorageGiB),
	)
	if value.Profile != RegionLocalMachine {
		problems = append(problems, errors.New("region profile is invalid"))
	}
	if value.State != RegionReady && value.State != RegionStale && value.State != RegionUnavailable {
		problems = append(problems, errors.New("region state is invalid"))
	}
	if value.State == RegionReady && value.InspectedAt == nil {
		problems = append(problems, errors.New("ready region requires an inspection time"))
	}
	if value.InspectedAt != nil {
		problems = append(problems, validateTime("region.inspectedAt", *value.InspectedAt))
	}
	return errors.Join(problems...)
}

func ValidateQuotaEntitlement(value QuotaEntitlement) error {
	var problems []error
	problems = append(problems,
		validateID("quotaEntitlement.id", value.ID),
		validateID("quotaEntitlement.offeringId", value.OfferingID),
		validateID("quotaEntitlement.quotaShapeId", value.QuotaShapeID),
		validatePositiveCount("quotaEntitlement.purchasedCount", value.PurchasedCount),
		validateResourceVersion(value.ResourceVersion),
		validateTime("quotaEntitlement.activatedAt", value.ActivatedAt),
	)
	if uint64(value.ReservedCount)+uint64(value.ConsumedCount) > uint64(value.PurchasedCount) {
		problems = append(problems, errors.New("quota entitlement usage exceeds purchased count"))
	}
	return errors.Join(problems...)
}

func ValidateServiceInstallation(value ServiceInstallation) error {
	var problems []error
	problems = append(problems,
		validateName("serviceInstallation.id", value.ID),
		validateText("serviceInstallation.name", value.Name, 1, 128),
		validateID("serviceInstallation.offeringId", value.OfferingID),
		validateID("serviceInstallation.engineVersion", value.EngineVersion),
		validateID("serviceInstallation.quotaEntitlementId", value.QuotaEntitlementID),
		validateID("serviceInstallation.regionId", value.RegionID),
		validateInstallationPhase(value.Phase),
		validateID("serviceInstallation.operation.id", value.Operation.ID),
		validateInstallationPhase(value.Operation.Phase),
		validateTime("serviceInstallation.operation.observedAt", value.Operation.ObservedAt),
		validateTime("serviceInstallation.createdAt", value.CreatedAt),
	)
	if value.Phase != value.Operation.Phase {
		problems = append(problems, errors.New("installation and operation phases differ"))
	}
	if value.Endpoint != nil {
		problems = append(problems, validateText("serviceInstallation.endpoint", *value.Endpoint, 1, 256))
	}
	if value.CredentialReference != nil {
		problems = append(problems, validateID("serviceInstallation.credentialReference", *value.CredentialReference))
	}
	if value.Operation.SafeFailureCode != nil && !codePattern.MatchString(*value.Operation.SafeFailureCode) {
		problems = append(problems, errors.New("installation failure code is invalid"))
	}
	if value.Phase == InstallationReady && (value.Endpoint == nil || value.CredentialReference == nil) {
		problems = append(problems, errors.New("ready installation requires endpoint and credential reference"))
	}
	if value.Phase != InstallationReady && (value.Endpoint != nil || value.CredentialReference != nil) {
		problems = append(problems, errors.New("non-ready installation cannot expose endpoint or credential reference"))
	}
	if value.Phase == InstallationFailed && value.Operation.SafeFailureCode == nil {
		problems = append(problems, errors.New("failed installation requires a safe failure code"))
	}
	if value.Phase != InstallationFailed && value.Operation.SafeFailureCode != nil {
		problems = append(problems, errors.New("non-failed installation cannot expose a failure code"))
	}
	return errors.Join(problems...)
}

func ValidateProblem(value Problem) error {
	return errors.Join(
		validateText("problem.type", value.Type, 1, 512),
		validateText("problem.title", value.Title, 1, 128),
		validateText("problem.detail", value.Detail, 1, 1024),
		validateID("problem.traceId", value.TraceID),
		validateProblemStatus(value.Status),
		validateErrorCode(value.Code),
	)
}

func ValidateID(name, value string) error {
	return validateID(name, value)
}

func ValidateInstallationID(value string) error {
	return validateName("installationId", value)
}

func ValidateIdempotencyKey(value string) error {
	return validateID("idempotencyKey", value)
}

func validateID(name, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateName(name, value string) error {
	if !namePattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateText(name, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validatePositiveCount(name string, value uint32) error {
	if value == 0 || value > 100 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validatePositiveCapacity(name string, value uint32) error {
	if value == 0 || uint64(value) > maximumSafeInteger {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateResourceVersion(value uint64) error {
	if value == 0 || value > maximumSafeInteger {
		return errors.New("resourceVersion is invalid")
	}
	return nil
}

func validateTime(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf("%s must be UTC with microsecond precision", name)
	}
	return nil
}

func validateInstallationPhase(value InstallationPhase) error {
	switch value {
	case InstallationPending, InstallationProvisioning, InstallationReady, InstallationFailed:
		return nil
	default:
		return errors.New("installation phase is invalid")
	}
}

func validateProblemStatus(value int) error {
	if value < 400 || value > 599 {
		return errors.New("problem status is invalid")
	}
	return nil
}

func validateErrorCode(value ErrorCode) error {
	switch value {
	case ErrorInvalidArgument, ErrorUnauthenticated, ErrorPermissionDenied,
		ErrorIdentityUnavailable, ErrorNotFound, ErrorAlreadyExists,
		ErrorIdempotencyConflict, ErrorQuotaExhausted, ErrorRegionUnavailable,
		ErrorInternal:
		return nil
	default:
		return errors.New("problem code is invalid")
	}
}
