package paasv1

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	idPattern              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	namePattern            = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	contractVersionPattern = regexp.MustCompile(`^v[1-9][0-9]*$`)
)

var sensitiveKeyFragments = [...]string{
	"access_key",
	"accesskey",
	"api_key",
	"apikey",
	"authorization",
	"cookie",
	"credential",
	"password",
	"private_key",
	"privatekey",
	"refresh_token",
	"secret",
	"set-cookie",
	"token",
}

var rawSensitiveMaterialMarkers = [...]string{
	"authorization: bearer",
	"bearer ",
	"password=",
	"passwd=",
	"secret=",
	"client_secret=",
	"token=",
	"access_token=",
	"refresh_token=",
	"id_token=",
	"api_key=",
	"private_key=",
	"-----begin private key-----",
	"aws_secret_access_key",
	"credential_material=",
	"session_cookie=",
}

func ValidateID(name, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s must be an opaque 1-128 character identifier", name)
	}
	return nil
}

func ValidateDigest(name, value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("%s must be a lowercase sha256 digest", name)
	}
	return nil
}

func ValidateResourceScope(scope ResourceScope) error {
	switch scope.Kind {
	case AuthorityPlatform:
		if scope.TenantID != "" {
			return errors.New("platform scope cannot contain tenantId")
		}
	case AuthorityTenant:
		if err := ValidateID("tenantId", string(scope.TenantID)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown scope kind %q", scope.Kind)
	}
	return nil
}

func ValidateResourceMetadata(value ResourceMetadata) error {
	var problems []error
	problems = append(problems,
		ValidateID("metadata.id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		validateContractTime("metadata.createdAt", value.CreatedAt),
		validateContractTime("metadata.updatedAt", value.UpdatedAt),
	)
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, errors.New("metadata.name must be a DNS label"))
	}
	if value.ResourceVersion == 0 {
		problems = append(problems, errors.New("metadata.resourceVersion must be positive"))
	}
	if value.UpdatedAt.Before(value.CreatedAt) {
		problems = append(problems, errors.New("metadata.updatedAt cannot precede createdAt"))
	}
	if err := validateLabels("metadata labels", value.Labels); err != nil {
		problems = append(problems, err)
	}
	return errors.Join(problems...)
}

func ValidateResourcePool(value ResourcePool) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ResourcePool" {
		problems = append(problems, errors.New("resource pool type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateLabelSelector("spec.targetSelector", value.Spec.TargetSelector),
		validateUniqueKnown(
			"spec.allowedIsolationClasses",
			value.Spec.AllowedIsolationClasses,
			IsolationClasses(),
			true,
		),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityPlatform {
		problems = append(problems, errors.New("resource pool must be platform scoped"))
	}
	if !contains(
		[]ResourcePoolPhase{ResourcePoolReady, ResourcePoolDegraded, ResourcePoolUnavailable},
		value.Status.Phase,
	) {
		problems = append(problems, fmt.Errorf("unknown resource pool phase %q", value.Status.Phase))
	}
	if value.Status.ReadyTargetCount > value.Status.TargetCount {
		problems = append(problems, errors.New("readyTargetCount cannot exceed targetCount"))
	}
	return errors.Join(problems...)
}

func ValidateRuntimeTarget(value RuntimeTarget) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "RuntimeTarget" {
		problems = append(problems, errors.New("runtime target type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("spec.resourcePoolId", string(value.Spec.ResourcePoolID)),
		validateAdapterRef(
			"spec.infrastructureAdapter",
			value.Spec.InfrastructureAdapter,
			AdapterInfrastructure,
		),
		validateAdapterRef("spec.runtimeAdapter", value.Spec.RuntimeAdapter, AdapterRuntime),
		validateCapacity("status.capacity", value.Status.Capacity),
		validateCapacity("status.allocatable", value.Status.Allocatable),
		validateUniqueKnown(
			"status.supportedIsolationClasses",
			value.Status.SupportedIsolationClasses,
			IsolationClasses(),
			true,
		),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityPlatform {
		problems = append(problems, errors.New("runtime target must be platform scoped"))
	}
	if value.Spec.GatewayAdapter != nil {
		problems = append(
			problems,
			validateAdapterRef("spec.gatewayAdapter", *value.Spec.GatewayAdapter, AdapterGateway),
		)
	}
	if !contains([]TargetDesiredState{TargetActive, TargetDraining}, value.Spec.DesiredState) {
		problems = append(problems, fmt.Errorf("unknown target desired state %q", value.Spec.DesiredState))
	}
	if !contains(
		[]TargetHealth{
			TargetHealthUnknown,
			TargetHealthReady,
			TargetHealthDegraded,
			TargetHealthUnavailable,
		},
		value.Status.Health,
	) {
		problems = append(problems, fmt.Errorf("unknown target health %q", value.Status.Health))
	}
	if exceedsCapacity(value.Status.Allocatable, value.Status.Capacity) {
		problems = append(problems, errors.New("allocatable resources cannot exceed capacity"))
	}
	return errors.Join(problems...)
}

func ValidatePlacementPolicy(value PlacementPolicy) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "PlacementPolicy" {
		problems = append(problems, errors.New("placement policy type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateLabelSelector("spec.targetSelector", value.Spec.TargetSelector),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("placement policy must be tenant scoped"))
	}
	if !contains(IsolationClasses(), value.Spec.RequiredIsolationClass) {
		problems = append(problems, errors.New("required isolation class is invalid"))
	}
	if !contains(
		[]PlacementStrategy{PlacementFirstFit, PlacementSpread, PlacementBinPack},
		value.Spec.Strategy,
	) {
		problems = append(problems, fmt.Errorf("unknown placement strategy %q", value.Spec.Strategy))
	}
	if len(value.Spec.EligibleResourcePools) == 0 {
		problems = append(problems, errors.New("eligibleResourcePoolIds must not be empty"))
	}
	seen := make(map[ResourceID]struct{}, len(value.Spec.EligibleResourcePools))
	for index, resourcePoolID := range value.Spec.EligibleResourcePools {
		problems = append(
			problems,
			ValidateID(
				fmt.Sprintf("spec.eligibleResourcePoolIds[%d]", index),
				string(resourcePoolID),
			),
		)
		if _, found := seen[resourcePoolID]; found {
			problems = append(
				problems,
				fmt.Errorf("spec.eligibleResourcePoolIds[%d] is duplicated", index),
			)
		}
		seen[resourcePoolID] = struct{}{}
	}
	return errors.Join(problems...)
}

func ValidateTenant(value Tenant) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Tenant" {
		problems = append(problems, errors.New("tenant type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("tenant.id", string(value.ID)),
		ValidateSafeExternalText("tenant.displayName", value.DisplayName, 256, true),
		ValidateID("tenant.iamResourceVersion", value.IAMResourceVersion),
		validateContractTime("tenant.observedAt", value.ObservedAt),
	)
	if !contains([]TenantStatus{TenantActive, TenantSuspended, TenantDeactivated}, value.Status) {
		problems = append(problems, fmt.Errorf("unknown tenant status %q", value.Status))
	}
	return errors.Join(problems...)
}

func ValidatePlacementDecision(value PlacementDecision) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "PlacementDecision" {
		problems = append(problems, errors.New("placement decision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("workloadReleaseId", string(value.WorkloadReleaseID)),
		ValidateID("placementPolicyId", string(value.PlacementPolicyID)),
		ValidateDigest("candidateSetDigest", value.CandidateSetDigest),
		validateContractTime("decidedAt", value.DecidedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("placement decision must be tenant scoped"))
	}
	if value.PolicyResourceVersion == 0 {
		problems = append(problems, errors.New("policyResourceVersion must be positive"))
	}
	if !contains(IsolationClasses(), value.RequestedIsolation) {
		problems = append(problems, errors.New("requested isolation class is invalid"))
	}
	switch value.Outcome {
	case PlacementScheduled:
		problems = append(problems, ValidateID("runtimeTargetId", string(value.RuntimeTargetID)))
		if value.RuntimeTargetResourceVersion == 0 {
			problems = append(
				problems,
				errors.New("runtimeTargetResourceVersion must be positive for a scheduled decision"),
			)
		}
		if value.GrantedIsolation != value.RequestedIsolation {
			problems = append(problems, errors.New("granted isolation must exactly equal requested isolation"))
		}
		if value.Reason != nil {
			problems = append(problems, errors.New("scheduled decision cannot contain a reason"))
		}
	case PlacementUnschedulable:
		if value.RuntimeTargetID != "" ||
			value.RuntimeTargetResourceVersion != 0 ||
			value.GrantedIsolation != "" {
			problems = append(
				problems,
				errors.New("unschedulable decision cannot select or version a target or grant isolation"),
			)
		}
		if value.Reason == nil ||
			(value.Reason.Code != ErrorUnschedulable &&
				value.Reason.Code != ErrorCapabilityUnsupported) {
			problems = append(problems, errors.New("unschedulable decision requires a normalized scheduling reason"))
		} else {
			problems = append(problems, ValidateProblem(*value.Reason))
		}
	default:
		problems = append(problems, fmt.Errorf("unknown placement outcome %q", value.Outcome))
	}
	return errors.Join(problems...)
}

func ValidateWorkloadRelease(value WorkloadRelease) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "WorkloadRelease" {
		problems = append(problems, errors.New("workload release type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("spec.workloadId", string(value.Spec.WorkloadID)),
		ValidateID("spec.revision", value.Spec.Revision),
		ValidateDigest("spec.contentDigest", value.Spec.ContentDigest),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("workload release must be tenant scoped"))
	}
	if len(value.Spec.Components) == 0 {
		problems = append(problems, errors.New("release must contain at least one component"))
	}
	seen := make(map[string]struct{}, len(value.Spec.Components))
	for index, component := range value.Spec.Components {
		if !namePattern.MatchString(component.Name) {
			problems = append(problems, fmt.Errorf("components[%d].name is invalid", index))
		}
		if _, duplicate := seen[component.Name]; duplicate {
			problems = append(problems, fmt.Errorf("components[%d].name is duplicated", index))
		}
		seen[component.Name] = struct{}{}
		if component.Replicas == 0 {
			problems = append(problems, fmt.Errorf("components[%d].replicas must be positive", index))
		}
		if component.Resources.CPUMillis < 0 || component.Resources.MemoryBytes < 0 {
			problems = append(problems, fmt.Errorf("components[%d].resources cannot be negative", index))
		}
		if !contains(
			[]ArtifactKind{ArtifactOCIImage, ArtifactOCIArtifact, ArtifactReleaseBundle},
			component.Artifact.Kind,
		) || strings.TrimSpace(component.Artifact.Locator) == "" {
			problems = append(problems, fmt.Errorf("components[%d].artifact is incomplete", index))
		}
		problems = append(
			problems,
			ValidateSafeExternalText(
				fmt.Sprintf("components[%d].artifact.locator", index),
				component.Artifact.Locator,
				2048,
				true,
			),
		)
		problems = append(
			problems,
			ValidateDigest(
				fmt.Sprintf("components[%d].artifact.digest", index),
				component.Artifact.Digest,
			),
		)
		configurationRefs := make(map[ResourceID]struct{}, len(component.ConfigurationRefs))
		for configurationIndex, resourceID := range component.ConfigurationRefs {
			problems = append(
				problems,
				ValidateID(
					fmt.Sprintf(
						"components[%d].configurationRefs[%d]",
						index,
						configurationIndex,
					),
					string(resourceID),
				),
			)
			if _, found := configurationRefs[resourceID]; found {
				problems = append(
					problems,
					fmt.Errorf(
						"components[%d].configurationRefs[%d] is duplicated",
						index,
						configurationIndex,
					),
				)
			}
			configurationRefs[resourceID] = struct{}{}
		}
		secretNames := make(map[string]struct{}, len(component.SecretReferences))
		for secretIndex, secret := range component.SecretReferences {
			if !namePattern.MatchString(secret.Name) {
				problems = append(
					problems,
					fmt.Errorf("components[%d].secretReferences[%d].name is invalid", index, secretIndex),
				)
			}
			problems = append(
				problems,
				ValidateID(
					fmt.Sprintf("components[%d].secretReferences[%d].resourceId", index, secretIndex),
					string(secret.ResourceID),
				),
			)
			if _, found := secretNames[secret.Name]; found {
				problems = append(
					problems,
					fmt.Errorf(
						"components[%d].secretReferences[%d].name is duplicated",
						index,
						secretIndex,
					),
				)
			}
			secretNames[secret.Name] = struct{}{}
		}
		endpointNames := make(map[string]struct{}, len(component.Endpoints))
		for endpointIndex, endpoint := range component.Endpoints {
			if !namePattern.MatchString(endpoint.Name) {
				problems = append(
					problems,
					fmt.Errorf("components[%d].endpoints[%d].name is invalid", index, endpointIndex),
				)
			}
			if _, found := endpointNames[endpoint.Name]; found {
				problems = append(
					problems,
					fmt.Errorf(
						"components[%d].endpoints[%d].name is duplicated",
						index,
						endpointIndex,
					),
				)
			}
			endpointNames[endpoint.Name] = struct{}{}
			if endpoint.Port == 0 {
				problems = append(
					problems,
					fmt.Errorf("components[%d].endpoints[%d].port must be positive", index, endpointIndex),
				)
			}
			if !contains(
				[]EndpointProtocol{EndpointHTTP, EndpointGRPC, EndpointTCP},
				endpoint.Protocol,
			) {
				problems = append(
					problems,
					fmt.Errorf("components[%d].endpoints[%d].protocol is invalid", index, endpointIndex),
				)
			}
			if !contains(
				[]EndpointVisibility{EndpointPrivate, EndpointPublic},
				endpoint.Visibility,
			) {
				problems = append(
					problems,
					fmt.Errorf("components[%d].endpoints[%d].visibility is invalid", index, endpointIndex),
				)
			}
		}
	}
	if !contains(ReleasePhases(), value.Status.Phase) {
		problems = append(problems, fmt.Errorf("unknown release phase %q", value.Status.Phase))
	}
	if value.Status.ReadyComponents > uint32(len(value.Spec.Components)) {
		problems = append(problems, errors.New("readyComponents cannot exceed component count"))
	}
	if value.Status.PlacementDecisionID != "" {
		problems = append(
			problems,
			ValidateID("status.placementDecisionId", string(value.Status.PlacementDecisionID)),
		)
	}
	if value.Status.CurrentOperationID != "" {
		problems = append(
			problems,
			ValidateID("status.currentOperationId", string(value.Status.CurrentOperationID)),
		)
	}
	return errors.Join(problems...)
}

func ValidateProblem(value Problem) error {
	var problems []error
	if value.Status < 400 || value.Status > 599 {
		problems = append(problems, errors.New("problem status must be an HTTP error status"))
	}
	if !contains(ErrorCodes(), value.Code) {
		problems = append(problems, fmt.Errorf("unknown problem code %q", value.Code))
	}
	problems = append(problems,
		ValidateSafeExternalText("problem.type", value.Type, 512, true),
		ValidateSafeExternalText("problem.title", value.Title, 256, true),
		ValidateSafeExternalText("problem.detail", value.Detail, 2048, true),
		ValidateID("problem.traceId", value.TraceID),
	)
	if len(value.Violations) > 64 {
		problems = append(problems, errors.New("problem violations cannot exceed 64 entries"))
	}
	for index, violation := range value.Violations {
		problems = append(problems,
			ValidateSafeExternalText(
				fmt.Sprintf("problem.violations[%d].field", index),
				violation.Field,
				256,
				true,
			),
			ValidateSafeExternalText(
				fmt.Sprintf("problem.violations[%d].description", index),
				violation.Description,
				512,
				true,
			),
		)
	}
	return errors.Join(problems...)
}

func ValidateOperation(value Operation) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Operation" {
		problems = append(problems, errors.New("operation type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("operation.id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		ValidateID("operation.target.id", string(value.Target.ID)),
		ValidateID("operation.requestedBy.id", value.RequestedBy.ID),
		ValidateDigest("operation.idempotencyFingerprint", value.IdempotencyFingerprint),
		ValidateDigest("operation.requestDigest", value.RequestDigest),
		validateContractTime("operation.createdAt", value.CreatedAt),
		validateContractTime("operation.updatedAt", value.UpdatedAt),
	)
	if value.Attempt == 0 {
		problems = append(problems, errors.New("operation attempt must be positive"))
	}
	if !contains(
		[]OperationAction{
			OperationCreateResourcePool,
			OperationRegisterTarget,
			OperationCreatePlacement,
			OperationDeploy,
			OperationUpdate,
			OperationStop,
			OperationRollback,
		},
		value.Action,
	) {
		problems = append(problems, fmt.Errorf("unknown operation action %q", value.Action))
	}
	switch value.Action {
	case OperationCreateResourcePool, OperationRegisterTarget:
		if value.Scope.Kind != AuthorityPlatform {
			problems = append(problems, errors.New("platform operation action requires platform scope"))
		}
	case OperationCreatePlacement, OperationDeploy, OperationStop, OperationRollback:
		if value.Scope.Kind != AuthorityTenant {
			problems = append(problems, errors.New("tenant operation action requires tenant scope"))
		}
	}
	if !contains(OperationStates(), value.State) {
		problems = append(problems, fmt.Errorf("unknown operation state %q", value.State))
	}
	if strings.TrimSpace(value.Target.Kind) == "" {
		problems = append(problems, errors.New("operation target kind is required"))
	}
	if !contains(
		[]SubjectType{SubjectUser, SubjectServiceAccount, SubjectAgent, SubjectSystemUser},
		value.RequestedBy.Type,
	) {
		problems = append(problems, fmt.Errorf("unknown requester type %q", value.RequestedBy.Type))
	}
	if value.UpdatedAt.Before(value.CreatedAt) {
		problems = append(problems, errors.New("operation.updatedAt cannot precede createdAt"))
	}
	if value.Error != nil {
		problems = append(problems, ValidateProblem(*value.Error))
	}
	if value.TerminalAt != nil {
		problems = append(problems, validateContractTime("operation.terminalAt", *value.TerminalAt))
	}
	terminal := contains(
		[]OperationState{
			OperationSucceeded,
			OperationFailed,
			OperationCancelled,
			OperationManualIntervention,
		},
		value.State,
	)
	if terminal && value.TerminalAt == nil {
		problems = append(problems, errors.New("terminal operation requires terminalAt"))
	}
	if !terminal && value.TerminalAt != nil {
		problems = append(problems, errors.New("non-terminal operation cannot contain terminalAt"))
	}
	if value.TerminalAt != nil &&
		(value.TerminalAt.Before(value.CreatedAt) || value.TerminalAt.After(value.UpdatedAt)) {
		problems = append(
			problems,
			errors.New("operation.terminalAt must be between createdAt and updatedAt"),
		)
	}
	failed := value.State == OperationFailed || value.State == OperationManualIntervention
	if failed && value.Error == nil {
		problems = append(problems, errors.New("failed operation requires a normalized error"))
	}
	if !failed && value.Error != nil {
		problems = append(problems, errors.New("only failed operations can contain an error"))
	}
	return errors.Join(problems...)
}

func ValidateEvidence(value Evidence) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Evidence" {
		problems = append(problems, errors.New("evidence type metadata is invalid"))
	}
	problems = append(problems,
		ValidateID("evidence.id", string(value.ID)),
		ValidateResourceScope(value.Scope),
		ValidateID("evidence.operationId", string(value.OperationID)),
		ValidateID("evidence.source", value.Source),
		ValidateID("evidence.code", value.Code),
		ValidateSafeExternalText("evidence.message", value.Message, 1024, true),
		ValidateDigest("evidence.contentDigest", value.ContentDigest),
		validateContractTime("evidence.occurredAt", value.OccurredAt),
	)
	if value.Sequence == 0 {
		problems = append(problems, errors.New("evidence sequence must be positive"))
	}
	if value.PreviousDigest != "" {
		problems = append(problems, ValidateDigest("evidence.previousDigest", value.PreviousDigest))
	}
	if !contains(
		[]EvidenceType{
			EvidencePolicyDecision,
			EvidencePlacementDecision,
			EvidenceAdapterCommand,
			EvidenceAdapterResult,
			EvidenceObservation,
			EvidenceVerification,
			EvidenceAuditDispatch,
		},
		value.Type,
	) {
		problems = append(problems, fmt.Errorf("unknown evidence type %q", value.Type))
	}
	if !contains(
		[]EvidenceSeverity{EvidenceInfo, EvidenceWarning, EvidenceError},
		value.Severity,
	) {
		problems = append(problems, fmt.Errorf("unknown evidence severity %q", value.Severity))
	}
	if len(value.Attributes) > 64 {
		problems = append(problems, errors.New("evidence attributes cannot exceed 64 entries"))
	}
	for key, item := range value.Attributes {
		normalized := strings.ToLower(key)
		for _, fragment := range sensitiveKeyFragments {
			if strings.Contains(normalized, fragment) {
				problems = append(problems, fmt.Errorf("evidence attribute key %q is sensitive", key))
				break
			}
		}
		problems = append(problems,
			ValidateSafeExternalText("evidence attribute key", key, 128, true),
			ValidateSafeExternalText("evidence attribute value", item, 4096, false),
		)
	}
	return errors.Join(problems...)
}

func ValidateAdapterCommand(value AdapterCommandEnvelope) error {
	var problems []error
	problems = append(problems,
		ValidateID("operationId", string(value.OperationID)),
		ValidateID("commandId", string(value.CommandID)),
		ValidateResourceScope(value.Scope),
		ValidateID("runtimeTargetId", string(value.RuntimeTargetID)),
		ValidateDigest("requestDigest", value.RequestDigest),
		ValidateID("bindingRef", value.BindingRef),
		validateContractTime("deadline", value.Deadline),
	)
	if value.Attempt == 0 {
		problems = append(problems, errors.New("attempt must be positive"))
	}
	if !contains(adapterActions(), value.Action) {
		problems = append(problems, fmt.Errorf("unknown adapter action %q", value.Action))
	}
	if value.WorkloadID != "" {
		problems = append(problems, ValidateID("workloadId", string(value.WorkloadID)))
	}
	if value.ReleaseID != "" {
		problems = append(problems, ValidateID("releaseId", string(value.ReleaseID)))
	}
	if value.TraceParent != "" {
		problems = append(
			problems,
			ValidateSafeExternalText("traceparent", value.TraceParent, 55, false),
		)
	}
	return errors.Join(problems...)
}

func ValidateInspectTargetRequest(value InspectTargetRequest) error {
	if err := ValidateAdapterCommand(value.Command); err != nil {
		return err
	}
	if value.Command.Action != AdapterInspectTarget {
		return fmt.Errorf(
			"inspect target request action = %q, want %q",
			value.Command.Action,
			AdapterInspectTarget,
		)
	}
	if value.Command.Scope.Kind != AuthorityPlatform {
		return errors.New("inspect target request requires platform scope")
	}
	return nil
}

func ValidateObserveTargetRequest(value ObserveTargetRequest) error {
	if err := ValidateAdapterCommand(value.Command); err != nil {
		return err
	}
	if value.Command.Action != AdapterObserveTarget {
		return fmt.Errorf(
			"observe target request action = %q, want %q",
			value.Command.Action,
			AdapterObserveTarget,
		)
	}
	if value.Command.Scope.Kind != AuthorityPlatform {
		return errors.New("observe target request requires platform scope")
	}
	return nil
}

func ValidateTargetObservation(value TargetObservation) error {
	var problems []error
	problems = append(problems,
		ValidateID("runtimeTargetId", string(value.RuntimeTargetID)),
		ValidateDigest("identityFingerprint", value.IdentityFingerprint),
		validateLabels("labels", value.Labels),
		validateCapacity("capacity", value.Capacity),
		validateCapacity("allocatable", value.Allocatable),
		validateUniqueKnown(
			"supportedIsolationClasses",
			value.SupportedIsolationClasses,
			IsolationClasses(),
			false,
		),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if !contains(
		[]TargetHealth{
			TargetHealthUnknown,
			TargetHealthReady,
			TargetHealthDegraded,
			TargetHealthUnavailable,
		},
		value.Health,
	) {
		problems = append(problems, fmt.Errorf("unknown target health %q", value.Health))
	}
	if exceedsCapacity(value.Allocatable, value.Capacity) {
		problems = append(problems, errors.New("allocatable resources cannot exceed capacity"))
	}
	return errors.Join(problems...)
}

func ValidateAdapterCapabilities(value AdapterCapabilitiesContract) error {
	var problems []error
	problems = append(problems,
		validateAdapterRef("adapter", value.Adapter, value.Adapter.Kind),
		validateUniqueKnown(
			"actions",
			value.Actions,
			adapterActionsForKind(value.Adapter.Kind),
			true,
		),
		validateUniqueKnown("isolationClasses", value.IsolationClasses, IsolationClasses(), false),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if !contains(
		[]AdapterKind{AdapterInfrastructure, AdapterRuntime, AdapterGateway},
		value.Adapter.Kind,
	) {
		problems = append(problems, fmt.Errorf("unknown adapter kind %q", value.Adapter.Kind))
	}
	return errors.Join(problems...)
}

func ValidateNormalizedAdapterError(value NormalizedAdapterError) error {
	var problems []error
	if !contains(
		[]AdapterErrorClass{
			AdapterErrorValidation,
			AdapterErrorConflict,
			AdapterErrorPermissionDenied,
			AdapterErrorQuotaExceeded,
			AdapterErrorRateLimited,
			AdapterErrorTransient,
			AdapterErrorUnavailable,
			AdapterErrorTimeout,
			AdapterErrorNotFound,
			AdapterErrorUnknownOutcome,
			AdapterErrorInternal,
		},
		value.Class,
	) {
		problems = append(problems, fmt.Errorf("unknown adapter error class %q", value.Class))
	}
	if !contains(ErrorCodes(), value.Code) {
		problems = append(problems, fmt.Errorf("unknown adapter error code %q", value.Code))
	}
	problems = append(
		problems,
		ValidateSafeExternalText("adapter error message", value.Message, 1024, true),
	)
	if value.RetryAfterSeconds != nil &&
		(*value.RetryAfterSeconds == 0 || *value.RetryAfterSeconds > 86400) {
		problems = append(problems, errors.New("retryAfterSeconds must be between 1 and 86400"))
	}
	if value.Class == AdapterErrorUnknownOutcome && value.Code != ErrorAdapterOutcomeUnknown {
		problems = append(
			problems,
			errors.New("unknown-outcome class requires ADAPTER_OUTCOME_UNKNOWN"),
		)
	}
	if value.Code == ErrorAdapterOutcomeUnknown && value.Class != AdapterErrorUnknownOutcome {
		problems = append(
			problems,
			errors.New("ADAPTER_OUTCOME_UNKNOWN requires unknown-outcome class"),
		)
	}
	return errors.Join(problems...)
}

func ValidateAdapterResult(value AdapterResult) error {
	var problems []error
	problems = append(problems,
		ValidateID("commandId", string(value.CommandID)),
		ValidateSafeExternalText("receipt", value.Receipt, 2048, false),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if !contains(
		[]AdapterResultState{
			AdapterResultSucceeded,
			AdapterResultInProgress,
			AdapterResultFailed,
			AdapterResultUnknown,
		},
		value.State,
	) {
		problems = append(problems, fmt.Errorf("unknown adapter result state %q", value.State))
	}
	if value.Error != nil {
		problems = append(problems, ValidateNormalizedAdapterError(*value.Error))
	}
	failed := value.State == AdapterResultFailed || value.State == AdapterResultUnknown
	if failed && value.Error == nil {
		problems = append(problems, errors.New("failed or unknown adapter result requires an error"))
	}
	if !failed && value.Error != nil {
		problems = append(problems, errors.New("successful or in-progress adapter result cannot contain an error"))
	}
	if value.State == AdapterResultUnknown &&
		value.Error != nil &&
		value.Error.Class != AdapterErrorUnknownOutcome {
		problems = append(problems, errors.New("unknown adapter result requires unknown-outcome error"))
	}
	if value.State == AdapterResultFailed &&
		value.Error != nil &&
		value.Error.Class == AdapterErrorUnknownOutcome {
		problems = append(problems, errors.New("failed adapter result cannot contain an unknown outcome"))
	}
	for index, evidence := range value.Evidence {
		if err := ValidateEvidence(evidence); err != nil {
			problems = append(problems, fmt.Errorf("evidence[%d]: %w", index, err))
		}
	}
	return errors.Join(problems...)
}

func validateAdapterRef(name string, value AdapterRef, expected AdapterKind) error {
	var problems []error
	if value.Kind != expected {
		problems = append(
			problems,
			fmt.Errorf("%s kind = %q, want %q", name, value.Kind, expected),
		)
	}
	if !namePattern.MatchString(value.Name) {
		problems = append(problems, fmt.Errorf("%s.name must be a DNS label", name))
	}
	if !contractVersionPattern.MatchString(value.ContractVersion) {
		problems = append(problems, fmt.Errorf("%s.contractVersion must be v1 or a later integer version", name))
	}
	return errors.Join(problems...)
}

func validateLabelSelector(name string, value LabelSelector) error {
	return validateLabels(name, value.MatchLabels)
}

// ValidateLabels validates the bounded portable label contract shared by
// public resources and internal adapter observations.
func ValidateLabels(value map[string]string) error {
	return validateLabels("labels", value)
}

func validateLabels(name string, value map[string]string) error {
	var problems []error
	if len(value) > 64 {
		problems = append(problems, fmt.Errorf("%s cannot exceed 64 entries", name))
	}
	for key, item := range value {
		if !namePattern.MatchString(key) {
			problems = append(problems, fmt.Errorf("%s label %q is invalid", name, key))
		}
		if err := ValidateSafeExternalText(name+" label "+key, item, 128, false); err != nil {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

func validateCapacity(name string, value Capacity) error {
	if value.CPUMillis < 0 ||
		value.MemoryBytes < 0 ||
		value.StorageBytes < 0 ||
		value.WorkloadSlots < 0 {
		return fmt.Errorf("%s values cannot be negative", name)
	}
	return nil
}

func exceedsCapacity(allocatable, capacity Capacity) bool {
	return allocatable.CPUMillis > capacity.CPUMillis ||
		allocatable.MemoryBytes > capacity.MemoryBytes ||
		allocatable.StorageBytes > capacity.StorageBytes ||
		allocatable.WorkloadSlots > capacity.WorkloadSlots
}

func validateUniqueKnown[T comparable](
	name string,
	values []T,
	allowed []T,
	required bool,
) error {
	var problems []error
	if required && len(values) == 0 {
		problems = append(problems, fmt.Errorf("%s must not be empty", name))
	}
	seen := make(map[T]struct{}, len(values))
	for index, value := range values {
		if !contains(allowed, value) {
			problems = append(problems, fmt.Errorf("%s[%d] is unknown", name, index))
		}
		if _, found := seen[value]; found {
			problems = append(problems, fmt.Errorf("%s[%d] is duplicated", name, index))
		}
		seen[value] = struct{}{}
	}
	return errors.Join(problems...)
}

func adapterActions() []AdapterAction {
	return []AdapterAction{
		AdapterCapabilities,
		AdapterInspectTarget,
		AdapterObserveTarget,
		AdapterValidateRelease,
		AdapterApply,
		AdapterObserve,
		AdapterStop,
		AdapterRollback,
		AdapterReconcileRoutes,
		AdapterObserveRoutes,
		AdapterDeleteRoutes,
	}
}

func adapterActionsForKind(kind AdapterKind) []AdapterAction {
	switch kind {
	case AdapterInfrastructure:
		return []AdapterAction{
			AdapterCapabilities,
			AdapterInspectTarget,
			AdapterObserveTarget,
		}
	case AdapterRuntime:
		return []AdapterAction{
			AdapterCapabilities,
			AdapterValidateRelease,
			AdapterApply,
			AdapterObserve,
			AdapterStop,
			AdapterRollback,
		}
	case AdapterGateway:
		return []AdapterAction{
			AdapterCapabilities,
			AdapterReconcileRoutes,
			AdapterObserveRoutes,
			AdapterDeleteRoutes,
		}
	default:
		return nil
	}
}

func validateContractTime(name string, value time.Time) error {
	if value.IsZero() ||
		value.Location() != time.UTC ||
		value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf(
			"%s must be UTC with at most microsecond precision and no monotonic component",
			name,
		)
	}
	return nil
}

func validateBoundedText(name, value string, limit int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len([]byte(value)) > limit {
		return fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return nil
}

// ValidateSafeExternalText rejects unsafe text before it can become a public
// problem, evidence value, label, or normalized adapter message.
func ValidateSafeExternalText(
	name string,
	value string,
	maxBytes int,
	required bool,
) error {
	if required && value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if value == "" {
		return nil
	}
	if len([]byte(value)) > maxBytes ||
		!utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be trimmed UTF-8 of at most %d bytes", name, maxBytes)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	normalized := strings.ToLower(value)
	for _, marker := range rawSensitiveMaterialMarkers {
		if strings.Contains(normalized, marker) {
			return fmt.Errorf("%s contains recognizable raw sensitive material", name)
		}
	}
	return nil
}

func contains[T comparable](values []T, target T) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
