package managedservicev1

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const maximumSafeInteger = uint64(9007199254740991)

var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,61}[a-z0-9]$`)
	codePattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func ValidateActivateServiceRequest(value ActivateServiceRequest) error {
	return ValidateServiceDefinitionReference(value.Service)
}

func ValidateServiceDefinitionReference(value ServiceDefinitionReference) error {
	return errors.Join(
		validateName("service.id", value.ID),
		validateRevision("service.revision", value.Revision),
		validateDigest("service.contentDigest", value.ContentDigest),
	)
}

func ValidateServiceID(value string) error {
	return validateName("service.id", value)
}

func ValidateServiceDefinition(value ServiceDefinition) error {
	problems := []error{
		validateText("service.displayName", value.DisplayName, 1, 128),
		validateText("service.description", value.Description, 1, 512),
		validateServiceDefinitionCommitment(value.ID, value.Revision, value.ActivationPrerequisite),
		validateDigest("service.contentDigest", value.ContentDigest),
	}
	if value.State != ServiceDefinitionAvailable && value.State != ServiceDefinitionUnavailable {
		problems = append(problems, errors.New("service definition state is invalid"))
	}
	_, expected, err := CanonicalizeServiceDefinition(value)
	if err != nil || expected != value.ContentDigest {
		problems = append(problems, errors.New("service definition digest differs from its activation contract"))
	}
	return errors.Join(problems...)
}

func ValidateServiceDefinitionList(value ServiceDefinitionList) error {
	if value.Kind != "ServiceDefinitionList" || value.Items == nil ||
		len(value.Items) > iamv1.MaxAuthorizationBatchItems ||
		iamv1.ValidateActionCapability(value.ActivationCapability) != nil ||
		value.ActivationCapability.Action != iamv1.ActionManagedServiceActivationActivate ||
		value.ActivationCapability.Resource != (iamv1.ResourceReference{
			Kind: iamv1.ResourceServiceActivation, ID: "collection",
		}) {
		return errors.New("service definition list is invalid")
	}
	previous := ""
	for _, item := range value.Items {
		if ValidateServiceDefinition(item) != nil || item.ID <= previous {
			return errors.New("service definition list is invalid")
		}
		previous = item.ID
	}
	return nil
}

func ValidateServiceActivation(value ServiceActivation) error {
	return errors.Join(
		ValidateServiceDefinitionReference(value.Service),
		validateResourceVersion(value.ResourceVersion),
		validateTime("serviceActivation.activatedAt", value.ActivatedAt),
	)
}

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

func ValidateBindServiceRoleRequest(value BindServiceRoleRequest) error {
	if iamv1.ValidateServiceRoleTemplateReference(value.Template) != nil {
		return errors.New("service role template reference is invalid")
	}
	return nil
}

func ValidateUnbindServiceRoleRequest(value UnbindServiceRoleRequest) error {
	if value.ResourceVersion != 1 {
		return errors.New("service role binding resource version is invalid")
	}
	return nil
}

func ValidateServiceRoleBindingReceipt(value ServiceRoleBindingReceipt) error {
	if value.Kind != "ServiceRoleBindingReceipt" ||
		value.Status != iamv1.WorkloadRoleBindingActive || value.ResourceVersion != 1 ||
		iamv1.ValidateServiceRoleTemplateReference(value.Template) != nil {
		return errors.New("service role binding receipt is invalid")
	}
	return errors.Join(
		ValidateInstallationID(value.ServiceInstallationID),
		iamv1.ValidateID("bindingId", string(value.BindingID)),
		iamv1.ValidateID("roleId", string(value.RoleID)),
		validateTime("createdAt", value.CreatedAt),
	)
}

func ValidateServiceRoleUnbindingReceipt(value ServiceRoleUnbindingReceipt) error {
	if value.Kind != "ServiceRoleUnbindingReceipt" ||
		value.Status != iamv1.WorkloadRoleBindingRevoked || value.ResourceVersion != 2 ||
		iamv1.ValidateServiceRoleTemplateReference(value.Template) != nil ||
		value.RevokedAt.Before(value.CreatedAt) {
		return errors.New("service role unbinding receipt is invalid")
	}
	return errors.Join(
		ValidateInstallationID(value.ServiceInstallationID),
		iamv1.ValidateID("bindingId", string(value.BindingID)),
		iamv1.ValidateID("roleId", string(value.RoleID)),
		validateTime("createdAt", value.CreatedAt),
		validateTime("revokedAt", value.RevokedAt),
	)
}

func ValidateServiceOffering(value ServiceOffering) error {
	var problems []error
	problems = append(problems,
		validateID("offering.id", value.ID),
		ValidateServiceDefinitionReference(value.Service),
		validateText("offering.displayName", value.DisplayName, 1, 128),
		validateText("offering.description", value.Description, 1, 512),
		validateName("offering.engineFamily", value.EngineFamily),
		validateID("offering.engineVersion", value.EngineVersion),
	)
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

func validateServiceDefinitionCommitment(
	id string,
	revision uint64,
	prerequisite ServiceActivationPrerequisite,
) error {
	var problems []error
	problems = append(problems, validateName("service.id", id), validateRevision("service.revision", revision))
	if prerequisite != ServiceActivationPermissionOnly {
		problems = append(problems, errors.New("service activation prerequisite is not supported"))
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
		validateInstallationOperationKind(value.Operation.Kind),
		validateInstallationPhase(value.Operation.Phase),
		validateResourceVersion(value.ResourceVersion),
		validateTime("serviceInstallation.operation.observedAt", value.Operation.ObservedAt),
		validateTime("serviceInstallation.createdAt", value.CreatedAt),
	)
	if !installationOperationMatchesPhase(value.Operation.Kind, value.Operation.Phase, value.Phase) {
		problems = append(problems, errors.New("installation and operation state is inconsistent"))
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
	retainsReadyResult := value.Phase == InstallationReady ||
		value.Phase == InstallationTerminationPending || value.Phase == InstallationTerminating ||
		value.Phase == InstallationTerminationFailed
	if retainsReadyResult && (value.Endpoint == nil || value.CredentialReference == nil) {
		problems = append(problems, errors.New("ready installation requires endpoint and credential reference"))
	}
	if !retainsReadyResult && (value.Endpoint != nil || value.CredentialReference != nil) {
		problems = append(problems, errors.New("non-ready installation cannot expose endpoint or credential reference"))
	}
	failed := value.Phase == InstallationFailed || value.Phase == InstallationRollbackFailed ||
		value.Phase == InstallationTerminationFailed
	if failed && value.Operation.SafeFailureCode == nil {
		problems = append(problems, errors.New("failed installation requires a safe failure code"))
	}
	if !failed && value.Operation.SafeFailureCode != nil {
		problems = append(problems, errors.New("non-failed installation cannot expose a failure code"))
	}
	return errors.Join(problems...)
}

func ValidateCommandType(value CommandType) error {
	switch value {
	case CommandQuotaActivate, CommandInstallationCreate, CommandInstallationTerminate,
		CommandServiceRoleBind, CommandServiceRoleUnbind:
		return nil
	default:
		return errors.New("managed-service command type is invalid")
	}
}

func ValidateCommandResult(value CommandResult) error {
	var problems []error
	if value.Kind != "ManagedServiceCommandResult" {
		problems = append(problems, errors.New("managed-service command result kind is invalid"))
	}
	problems = append(problems,
		ValidateCommandType(value.CommandType),
		validateID("requestId", value.RequestID),
		validateDigest("inputDigest", value.InputDigest),
		validateID("target.id", value.Target.ID),
	)
	if value.State != CommandInProgress && value.State != CommandSucceeded && value.State != CommandFailed {
		problems = append(problems, errors.New("managed-service command state is invalid"))
	}
	if (value.State == CommandInProgress) != (value.CompletedAt == nil) {
		problems = append(problems, errors.New("managed-service command completion time is inconsistent"))
	}
	if value.CompletedAt != nil {
		problems = append(problems, validateTime("completedAt", *value.CompletedAt))
	}

	switch value.CommandType {
	case CommandQuotaActivate:
		if value.Target.Kind != CommandTargetQuotaEntitlement || value.State != CommandSucceeded ||
			value.Operation != nil || value.BindingID != nil {
			problems = append(problems, errors.New("quota command result shape is invalid"))
		}
	case CommandInstallationCreate, CommandInstallationTerminate:
		expectedKind := InstallationOperationProvision
		if value.CommandType == CommandInstallationTerminate {
			expectedKind = InstallationOperationTerminate
		}
		if value.Target.Kind != CommandTargetServiceInstallation || value.Operation == nil ||
			value.Operation.Kind != expectedKind || value.BindingID != nil {
			problems = append(problems, errors.New("installation command result shape is invalid"))
		} else {
			problems = append(problems, validateInstallationOperation(*value.Operation))
			if commandStateForOperation(*value.Operation) != value.State {
				problems = append(problems, errors.New("installation command state differs from its operation"))
			}
		}
	case CommandServiceRoleBind, CommandServiceRoleUnbind:
		if value.Target.Kind != CommandTargetServiceInstallation || value.State != CommandSucceeded ||
			value.Operation != nil || value.BindingID == nil ||
			iamv1.ValidateID("bindingId", string(*value.BindingID)) != nil {
			problems = append(problems, errors.New("service Role command result shape is invalid"))
		}
	}
	return errors.Join(problems...)
}

func ValidateCommandResultList(value CommandResultList) error {
	if value.Kind != "ManagedServiceCommandResultList" || value.Items == nil || len(value.Items) > MaxCommandResultItems {
		return errors.New("managed-service command result list is invalid")
	}
	seen := make(map[string]struct{}, len(value.Items))
	for _, item := range value.Items {
		if ValidateCommandResult(item) != nil {
			return errors.New("managed-service command result list is invalid")
		}
		identity := string(item.CommandType) + "\x00" + item.RequestID
		if _, duplicate := seen[identity]; duplicate {
			return errors.New("managed-service command result list contains duplicates")
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func validateInstallationOperation(value InstallationOperation) error {
	return errors.Join(
		validateID("operation.id", value.ID),
		validateInstallationOperationKind(value.Kind),
		validateInstallationPhase(value.Phase),
		validateTime("operation.observedAt", value.ObservedAt),
	)
}

func commandStateForOperation(value InstallationOperation) CommandState {
	if value.Kind != InstallationOperationProvision && value.Kind != InstallationOperationTerminate {
		return ""
	}
	switch value.Phase {
	case InstallationPending, InstallationProvisioning:
		return CommandInProgress
	case InstallationReady:
		return CommandSucceeded
	case InstallationFailed:
		return CommandFailed
	}
	return ""
}

func validateInstallationOperationKind(value InstallationOperationKind) error {
	if value != InstallationOperationProvision && value != InstallationOperationTerminate {
		return errors.New("installation operation kind is invalid")
	}
	return nil
}

func installationOperationMatchesPhase(
	kind InstallationOperationKind,
	operationPhase InstallationPhase,
	installationPhase InstallationPhase,
) bool {
	switch kind {
	case InstallationOperationProvision:
		if installationPhase == InstallationRollbackFailed {
			return operationPhase == InstallationFailed
		}
		return operationPhase == installationPhase &&
			(installationPhase == InstallationPending || installationPhase == InstallationProvisioning ||
				installationPhase == InstallationReady || installationPhase == InstallationFailed)
	case InstallationOperationTerminate:
		switch installationPhase {
		case InstallationTerminationPending:
			return operationPhase == InstallationPending
		case InstallationTerminating:
			return operationPhase == InstallationProvisioning
		case InstallationTerminationFailed:
			return operationPhase == InstallationFailed
		case InstallationTerminated:
			return operationPhase == InstallationReady
		}
	}
	return false
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

func validateRevision(name string, value uint64) error {
	if value == 0 || value > maximumSafeInteger {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateDigest(name, value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
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
	case InstallationPending, InstallationProvisioning, InstallationReady, InstallationFailed,
		InstallationRollbackFailed, InstallationTerminationPending, InstallationTerminating,
		InstallationTerminationFailed, InstallationTerminated:
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
		ErrorIdempotencyConflict, ErrorServiceDefinitionConflict,
		ErrorServiceUnavailable, ErrorServiceNotActivated,
		ErrorQuotaExhausted, ErrorRegionUnavailable,
		ErrorServiceRoleConflict, ErrorResourceStateConflict, ErrorInternal:
		return nil
	default:
		return errors.New("problem code is invalid")
	}
}
