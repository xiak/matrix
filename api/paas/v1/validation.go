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
	environmentKeyPattern  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
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

func ValidateReadiness(value Readiness) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Readiness" {
		problems = append(problems, errors.New("readiness type metadata is invalid"))
	}
	if value.State != ReadinessReady && value.State != ReadinessNotReady {
		problems = append(problems, errors.New("readiness state is invalid"))
	}
	if value.SchemaVersion == 0 {
		problems = append(problems, errors.New("readiness schemaVersion must be positive"))
	}
	problems = append(problems, validateContractTime("readiness.checkedAt", value.CheckedAt))
	return errors.Join(problems...)
}

func ValidateExecutionPool(value ExecutionPool) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ExecutionPool" {
		problems = append(problems, errors.New("execution pool type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateLabelSelector(
			"spec.executionTargetSelector",
			value.Spec.ExecutionTargetSelector,
		),
		validateUniqueKnown(
			"spec.allowedIsolationGuarantees",
			value.Spec.AllowedIsolationGuarantees,
			IsolationGuarantees(),
			true,
		),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityPlatform {
		problems = append(problems, errors.New("execution pool must be platform scoped"))
	}
	if !contains(
		[]ExecutionPoolPhase{ExecutionPoolReady, ExecutionPoolDegraded, ExecutionPoolUnavailable},
		value.Status.Phase,
	) {
		problems = append(problems, fmt.Errorf("unknown execution pool phase %q", value.Status.Phase))
	}
	if value.Status.ReadyExecutionTargetCount > value.Status.ExecutionTargetCount {
		problems = append(
			problems,
			errors.New("readyExecutionTargetCount cannot exceed executionTargetCount"),
		)
	}
	return errors.Join(problems...)
}

func ValidateExecutionTarget(value ExecutionTarget) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ExecutionTarget" {
		problems = append(problems, errors.New("execution target type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("spec.executionPoolId", string(value.Spec.ExecutionPoolID)),
		validateAdapterRef(
			"spec.infrastructureAdapter",
			value.Spec.InfrastructureAdapter,
			AdapterInfrastructure,
		),
		validateAdapterRef(
			"spec.deploymentExecutor",
			value.Spec.DeploymentExecutor,
			AdapterDeploymentExecutor,
		),
		validateCapacity("status.capacity", value.Status.Capacity),
		validateCapacity("status.allocatable", value.Status.Allocatable),
		validateUniqueKnown(
			"status.supportedIsolationGuarantees",
			value.Status.SupportedIsolationGuarantees,
			IsolationGuarantees(),
			value.Status.Health == ExecutionTargetHealthReady,
		),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityPlatform {
		problems = append(problems, errors.New("execution target must be platform scoped"))
	}
	if value.Spec.GatewayAdapter != nil {
		problems = append(
			problems,
			validateAdapterRef("spec.gatewayAdapter", *value.Spec.GatewayAdapter, AdapterGateway),
		)
	}
	if !contains([]ExecutionTargetDesiredState{ExecutionTargetActive, ExecutionTargetDraining}, value.Spec.DesiredState) {
		problems = append(problems, fmt.Errorf("unknown target desired state %q", value.Spec.DesiredState))
	}
	if !contains(
		[]ExecutionTargetHealth{
			ExecutionTargetHealthUnknown,
			ExecutionTargetHealthReady,
			ExecutionTargetHealthDegraded,
			ExecutionTargetHealthUnavailable,
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
		validateLabelSelector(
			"spec.executionTargetSelector",
			value.Spec.ExecutionTargetSelector,
		),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("placement policy must be tenant scoped"))
	}
	if !contains(IsolationGuarantees(), value.Spec.RequiredIsolationGuarantee) {
		problems = append(problems, errors.New("required isolation guarantee is invalid"))
	}
	if !contains(
		[]PlacementStrategy{PlacementFirstFit, PlacementSpread, PlacementBinPack},
		value.Spec.Strategy,
	) {
		problems = append(problems, fmt.Errorf("unknown placement strategy %q", value.Spec.Strategy))
	}
	if len(value.Spec.EligibleExecutionPoolIDs) == 0 {
		problems = append(problems, errors.New("eligibleExecutionPoolIds must not be empty"))
	}
	seen := make(map[ResourceID]struct{}, len(value.Spec.EligibleExecutionPoolIDs))
	for index, executionPoolID := range value.Spec.EligibleExecutionPoolIDs {
		problems = append(
			problems,
			ValidateID(
				fmt.Sprintf("spec.eligibleExecutionPoolIds[%d]", index),
				string(executionPoolID),
			),
		)
		if _, found := seen[executionPoolID]; found {
			problems = append(
				problems,
				fmt.Errorf("spec.eligibleExecutionPoolIds[%d] is duplicated", index),
			)
		}
		seen[executionPoolID] = struct{}{}
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
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
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
	if value.DeploymentResourceVersion == 0 {
		problems = append(problems, errors.New("deploymentResourceVersion must be positive"))
	}
	if value.DeploymentGeneration == 0 {
		problems = append(problems, errors.New("deploymentGeneration must be positive"))
	}
	if !contains(IsolationGuarantees(), value.RequestedIsolationGuarantee) {
		problems = append(problems, errors.New("requested isolation guarantee is invalid"))
	}
	switch value.Outcome {
	case PlacementScheduled:
		problems = append(problems, ValidateID("executionTargetId", string(value.ExecutionTargetID)))
		if value.ExecutionTargetResourceVersion == 0 {
			problems = append(
				problems,
				errors.New("executionTargetResourceVersion must be positive for a scheduled decision"),
			)
		}
		if value.GrantedIsolationGuarantee != value.RequestedIsolationGuarantee {
			problems = append(problems, errors.New("granted isolation must exactly equal requested isolation"))
		}
		if value.Reason != nil {
			problems = append(problems, errors.New("scheduled decision cannot contain a reason"))
		}
	case PlacementUnschedulable:
		if value.ExecutionTargetID != "" ||
			value.ExecutionTargetResourceVersion != 0 ||
			value.GrantedIsolationGuarantee != "" {
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

func ValidateApplication(value Application) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Application" {
		problems = append(problems, errors.New("application type metadata is invalid"))
	}
	problems = append(problems, ValidateResourceMetadata(value.Metadata))
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("application must be tenant scoped"))
	}
	return errors.Join(problems...)
}

func ValidateConfiguration(value Configuration) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Configuration" {
		problems = append(problems, errors.New("configuration type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		ValidateID("applicationId", string(value.ApplicationID)),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("configuration must be tenant scoped"))
	}
	return errors.Join(problems...)
}

func ValidateConfigurationRevision(value ConfigurationRevision) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ConfigurationRevision" {
		problems = append(problems, errors.New("configuration revision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateImmutableMetadata("configuration revision", value.Metadata),
		ValidateID("spec.configurationId", string(value.Spec.ConfigurationID)),
		ValidateDigest("spec.contentDigest", value.Spec.ContentDigest),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("configuration revision must be tenant scoped"))
	}
	if len(value.Spec.Values) > 256 {
		problems = append(problems, errors.New("configuration values cannot exceed 256 entries"))
	}
	for key, item := range value.Spec.Values {
		if !environmentKeyPattern.MatchString(key) {
			problems = append(problems, fmt.Errorf("configuration key %q is not a portable environment key", key))
		}
		normalizedKey := strings.ToLower(key)
		for _, fragment := range sensitiveKeyFragments {
			if strings.Contains(normalizedKey, fragment) {
				problems = append(problems, fmt.Errorf("configuration key %q is sensitive and must use a secret", key))
				break
			}
		}
		problems = append(
			problems,
			ValidateSafeExternalText("configuration value "+key, item, 32768, false),
		)
	}
	if digest := ConfigurationValuesDigest(value.Spec.Values); value.Spec.ContentDigest != digest {
		problems = append(problems, errors.New("spec.contentDigest does not match canonical values"))
	}
	return errors.Join(problems...)
}

func ValidateApplicationRevision(value ApplicationRevision) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "ApplicationRevision" {
		problems = append(problems, errors.New("application revision type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateImmutableMetadata("application revision", value.Metadata),
		ValidateID("spec.applicationId", string(value.Spec.ApplicationID)),
		ValidateID("spec.revision", value.Spec.Revision),
		ValidateDigest("spec.contentDigest", value.Spec.ContentDigest),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("application revision must be tenant scoped"))
	}
	if len(value.Spec.Components) == 0 {
		problems = append(problems, errors.New("application revision must contain at least one component"))
	}
	componentNames := make(map[string]struct{}, len(value.Spec.Components))
	for index, component := range value.Spec.Components {
		path := fmt.Sprintf("components[%d]", index)
		if !namePattern.MatchString(component.Name) {
			problems = append(problems, fmt.Errorf("%s.name is invalid", path))
		}
		if _, duplicate := componentNames[component.Name]; duplicate {
			problems = append(problems, fmt.Errorf("%s.name is duplicated", path))
		}
		componentNames[component.Name] = struct{}{}
		if component.Resources.CPUMillis < 0 || component.Resources.MemoryBytes < 0 {
			problems = append(problems, fmt.Errorf("%s.resources cannot be negative", path))
		}
		if !contains(
			[]ArtifactKind{ArtifactOCIImage, ArtifactOCIArtifact, ArtifactReleaseBundle},
			component.Artifact.Kind,
		) {
			problems = append(problems, fmt.Errorf("%s.artifact.kind is invalid", path))
		}
		problems = append(problems,
			ValidateSafeExternalText(path+".artifact.locator", component.Artifact.Locator, 2048, true),
			ValidateDigest(path+".artifact.digest", component.Artifact.Digest),
		)
		endpointNames := make(map[string]struct{}, len(component.Endpoints))
		for endpointIndex, endpoint := range component.Endpoints {
			endpointPath := fmt.Sprintf("%s.endpoints[%d]", path, endpointIndex)
			if !namePattern.MatchString(endpoint.Name) {
				problems = append(problems, fmt.Errorf("%s.name is invalid", endpointPath))
			}
			if _, duplicate := endpointNames[endpoint.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s.name is duplicated", endpointPath))
			}
			endpointNames[endpoint.Name] = struct{}{}
			if endpoint.Port == 0 {
				problems = append(problems, fmt.Errorf("%s.port must be positive", endpointPath))
			}
			if !contains([]EndpointProtocol{EndpointHTTP, EndpointGRPC, EndpointTCP}, endpoint.Protocol) {
				problems = append(problems, fmt.Errorf("%s.protocol is invalid", endpointPath))
			}
			if !contains([]EndpointVisibility{EndpointPrivate, EndpointPublic}, endpoint.Visibility) {
				problems = append(problems, fmt.Errorf("%s.visibility is invalid", endpointPath))
			}
		}
		inputNames := make(map[string]struct{}, len(component.Inputs))
		for inputIndex, input := range component.Inputs {
			inputPath := fmt.Sprintf("%s.inputs[%d]", path, inputIndex)
			if !namePattern.MatchString(input.Name) {
				problems = append(problems, fmt.Errorf("%s.name is invalid", inputPath))
			}
			if _, duplicate := inputNames[input.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s.name is duplicated", inputPath))
			}
			inputNames[input.Name] = struct{}{}
			if !contains([]InputKind{InputConfiguration, InputSecret}, input.Kind) {
				problems = append(problems, fmt.Errorf("%s.kind is invalid", inputPath))
			}
			if !contains([]InjectionMode{InjectionEnvironment, InjectionFile}, input.Injection) {
				problems = append(problems, fmt.Errorf("%s.injection is invalid", inputPath))
			}
			switch input.Kind {
			case InputConfiguration:
				if input.Injection != InjectionEnvironment {
					problems = append(problems, fmt.Errorf("%s CONFIGURATION input must use ENV injection", inputPath))
				}
			case InputSecret:
				if input.Injection != InjectionFile {
					problems = append(problems, fmt.Errorf("%s SECRET input must use FILE injection", inputPath))
				}
			}
		}
	}
	return errors.Join(problems...)
}

func ValidateDeployment(value Deployment) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Deployment" {
		problems = append(problems, errors.New("deployment type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceMetadata(value.Metadata),
		validateDeploymentSpec(value.Spec),
		validateContractTime("status.observedAt", value.Status.ObservedAt),
	)
	if value.Metadata.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("deployment must be tenant scoped"))
	}
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment generation must be positive"))
	}
	if value.Status.ObservedGeneration > value.Generation {
		problems = append(problems, errors.New("observedGeneration cannot exceed generation"))
	}
	if value.Status.ObservedGeneration == 0 {
		if value.Status.ObservedApplicationRevisionID != "" || value.Status.ReadyComponents != 0 {
			problems = append(problems, errors.New("unobserved deployment cannot contain observed revision or ready components"))
		}
	} else if value.Status.ObservedApplicationRevisionID == "" {
		problems = append(problems, errors.New("observed deployment requires observedApplicationRevisionId"))
	}
	if !contains(DeploymentPhases(), value.Status.Phase) {
		problems = append(problems, fmt.Errorf("unknown deployment phase %q", value.Status.Phase))
	}
	if value.Status.ReadyComponents > uint32(len(value.Spec.Components)) {
		problems = append(problems, errors.New("readyComponents cannot exceed component count"))
	}
	if value.Status.PlacementDecisionID != "" {
		problems = append(problems, ValidateID("status.placementDecisionId", string(value.Status.PlacementDecisionID)))
	}
	if value.Status.CurrentOperationID != "" {
		problems = append(problems, ValidateID("status.currentOperationId", string(value.Status.CurrentOperationID)))
	}
	if value.Status.ObservedApplicationRevisionID != "" {
		problems = append(problems, ValidateID("status.observedApplicationRevisionId", string(value.Status.ObservedApplicationRevisionID)))
	}
	if value.Status.Phase == DeploymentReady {
		if value.Status.ObservedGeneration != value.Generation ||
			value.Status.ObservedApplicationRevisionID != value.Spec.ApplicationRevisionID ||
			value.Status.ReadyComponents != uint32(len(value.Spec.Components)) {
			problems = append(problems, errors.New("ready deployment must fully observe its current generation"))
		}
	}
	if value.Status.Phase == DeploymentStopped {
		if value.Status.ObservedGeneration != value.Generation || value.Status.ReadyComponents != 0 {
			problems = append(problems, errors.New("stopped deployment must observe its current generation with no ready components"))
		}
	}
	return errors.Join(problems...)
}

func ValidateDeploymentGeneration(value DeploymentGeneration) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "DeploymentGeneration" {
		problems = append(problems, errors.New("deployment generation type metadata is invalid"))
	}
	problems = append(problems,
		ValidateResourceScope(value.Scope),
		ValidateID("deploymentId", string(value.DeploymentID)),
		validateDeploymentSpec(value.Spec),
		ValidateDigest("contentDigest", value.ContentDigest),
		ValidateID("createdByOperationId", string(value.CreatedByOperationID)),
		validateContractTime("createdAt", value.CreatedAt),
	)
	if value.Scope.Kind != AuthorityTenant {
		problems = append(problems, errors.New("deployment generation must be tenant scoped"))
	}
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment generation must be positive"))
	}
	if value.ContentDigest != DeploymentSpecContentDigest(value.Spec) {
		problems = append(problems, errors.New("contentDigest does not match canonical deployment spec"))
	}
	return errors.Join(problems...)
}

// ValidateDeploymentAgainstRevision checks the cross-resource shape before a
// deployment can enter placement. Repository-level validation separately
// proves tenant and application ownership for every referenced resource.
func ValidateDeploymentAgainstRevision(deployment Deployment, revision ApplicationRevision) error {
	var problems []error
	if err := ValidateDeployment(deployment); err != nil {
		problems = append(problems, err)
	}
	if err := ValidateApplicationRevision(revision); err != nil {
		problems = append(problems, err)
	}
	problems = append(problems, validateDeploymentSpecAgainstRevision(deployment.Spec, revision))
	return errors.Join(problems...)
}

func ValidateDeploymentGenerationAgainstRevision(
	generation DeploymentGeneration,
	revision ApplicationRevision,
) error {
	var problems []error
	if err := ValidateDeploymentGeneration(generation); err != nil {
		problems = append(problems, err)
	}
	if err := ValidateApplicationRevision(revision); err != nil {
		problems = append(problems, err)
	}
	if generation.Scope != revision.Metadata.Scope {
		problems = append(problems, errors.New("deployment generation and application revision scopes differ"))
	}
	problems = append(problems, validateDeploymentSpecAgainstRevision(generation.Spec, revision))
	return errors.Join(problems...)
}

func ValidateDeploymentExecutionRequest(value DeploymentExecutionRequest) error {
	var problems []error
	problems = append(problems,
		ValidateAdapterCommand(value.Command),
		ValidateDeploymentGenerationAgainstRevision(value.Generation, value.ApplicationRevision),
		ValidatePlacementDecision(value.Placement),
	)
	if !contains([]AdapterAction{
		AdapterValidateDeployment,
		AdapterApplyDeployment,
		AdapterStopDeployment,
		AdapterRollbackDeployment,
	}, value.Command.Action) {
		problems = append(problems, fmt.Errorf("deployment execution request action %q is invalid", value.Command.Action))
	}
	if value.Placement.Outcome != PlacementScheduled {
		problems = append(problems, errors.New("deployment execution requires a scheduled placement"))
	}
	if value.Command.Scope != value.Generation.Scope ||
		value.Command.Scope != value.ApplicationRevision.Metadata.Scope ||
		value.Command.Scope != value.Placement.Metadata.Scope {
		problems = append(problems, errors.New("deployment execution resource scopes differ"))
	}
	if value.Command.DeploymentID != value.Generation.DeploymentID ||
		value.Command.DeploymentID != value.Placement.DeploymentID {
		problems = append(problems, errors.New("deployment execution identities differ"))
	}
	if value.Command.ApplicationRevisionID != value.ApplicationRevision.Metadata.ID ||
		value.Command.ApplicationRevisionID != value.Generation.Spec.ApplicationRevisionID ||
		value.Command.ApplicationRevisionID != value.Placement.ApplicationRevisionID {
		problems = append(problems, errors.New("deployment execution application revision identities differ"))
	}
	if value.Command.ApplicationID != value.ApplicationRevision.Spec.ApplicationID {
		problems = append(problems, errors.New("deployment execution application identities differ"))
	}
	if value.Command.OperationID != value.Generation.CreatedByOperationID {
		problems = append(problems, errors.New("deployment execution operation and generation identities differ"))
	}
	if value.Command.ExecutionTargetID != value.Placement.ExecutionTargetID {
		problems = append(problems, errors.New("deployment execution target identities differ"))
	}
	if value.Generation.Generation != value.Placement.DeploymentGeneration ||
		value.Generation.Spec.PlacementPolicyID != value.Placement.PlacementPolicyID {
		problems = append(problems, errors.New("deployment execution generation and placement differ"))
	}

	expectedConfigurations := make(map[ResourceID]struct{})
	for _, component := range value.Generation.Spec.Components {
		for _, binding := range component.Bindings {
			if binding.ConfigurationRevisionID != "" {
				expectedConfigurations[binding.ConfigurationRevisionID] = struct{}{}
			}
		}
	}
	seenConfigurations := make(map[ResourceID]struct{}, len(value.ConfigurationRevisions))
	for index, revision := range value.ConfigurationRevisions {
		if err := ValidateConfigurationRevision(revision); err != nil {
			problems = append(problems, fmt.Errorf("configurationRevisions[%d]: %w", index, err))
		}
		if revision.Metadata.Scope != value.Command.Scope {
			problems = append(problems, fmt.Errorf("configurationRevisions[%d] has another scope", index))
		}
		if _, duplicate := seenConfigurations[revision.Metadata.ID]; duplicate {
			problems = append(problems, fmt.Errorf("configurationRevisions[%d] is duplicated", index))
		}
		seenConfigurations[revision.Metadata.ID] = struct{}{}
		if _, required := expectedConfigurations[revision.Metadata.ID]; !required {
			problems = append(problems, fmt.Errorf("configurationRevisions[%d] is not bound", index))
		}
	}
	for revisionID := range expectedConfigurations {
		if _, found := seenConfigurations[revisionID]; !found {
			problems = append(problems, fmt.Errorf("bound configuration revision %q is missing", revisionID))
		}
	}
	if value.Command.RequestDigest != DeploymentExecutionRequestDigest(value) {
		problems = append(problems, errors.New("command requestDigest does not match canonical execution input"))
	}
	return errors.Join(problems...)
}

func ValidateObserveDeploymentRequest(value ObserveDeploymentRequest) error {
	var problems []error
	problems = append(problems,
		ValidateAdapterCommand(value.Command),
		ValidateDigest("expectedContentDigest", value.ExpectedContentDigest),
	)
	if value.Command.Action != AdapterObserveDeployment {
		problems = append(problems, fmt.Errorf("observe deployment request action = %q, want %q", value.Command.Action, AdapterObserveDeployment))
	}
	if value.Generation == 0 {
		problems = append(problems, errors.New("observe deployment generation must be positive"))
	}
	if value.Command.RequestDigest != ObserveDeploymentRequestDigest(value) {
		problems = append(problems, errors.New("command requestDigest does not match canonical observation input"))
	}
	return errors.Join(problems...)
}

func ValidateDeploymentObservation(value DeploymentObservation) error {
	var problems []error
	problems = append(problems,
		ValidateID("deploymentId", string(value.DeploymentID)),
		ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateDigest("receiptDigest", value.ReceiptDigest),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if value.Generation == 0 {
		problems = append(problems, errors.New("deployment observation generation must be positive"))
	}
	if !contains([]DeploymentPhase{
		DeploymentApplying,
		DeploymentReady,
		DeploymentDegraded,
		DeploymentFailed,
		DeploymentStopping,
		DeploymentStopped,
	}, value.Phase) {
		problems = append(problems, fmt.Errorf("deployment observation phase %q is invalid", value.Phase))
	}
	seenEndpoints := make(map[string]struct{}, len(value.Endpoints))
	for index, endpoint := range value.Endpoints {
		path := fmt.Sprintf("endpoints[%d]", index)
		if !namePattern.MatchString(endpoint.ComponentName) ||
			!namePattern.MatchString(endpoint.EndpointName) ||
			!namePattern.MatchString(endpoint.Address) {
			problems = append(problems, fmt.Errorf("%s contains an invalid network-local name", path))
		}
		if endpoint.Port == 0 {
			problems = append(problems, fmt.Errorf("%s.port must be positive", path))
		}
		if !contains([]EndpointProtocol{EndpointHTTP, EndpointGRPC, EndpointTCP}, endpoint.Protocol) {
			problems = append(problems, fmt.Errorf("%s.protocol is invalid", path))
		}
		identity := endpoint.ComponentName + "\x00" + endpoint.EndpointName
		if _, duplicate := seenEndpoints[identity]; duplicate {
			problems = append(problems, fmt.Errorf("%s is duplicated", path))
		}
		seenEndpoints[identity] = struct{}{}
	}
	for index, evidence := range value.Evidence {
		if err := ValidateEvidence(evidence); err != nil {
			problems = append(problems, fmt.Errorf("evidence[%d]: %w", index, err))
		}
	}
	return errors.Join(problems...)
}

func validateDeploymentSpec(value DeploymentSpec) error {
	var problems []error
	problems = append(problems,
		ValidateID("spec.applicationRevisionId", string(value.ApplicationRevisionID)),
		ValidateID("spec.placementPolicyId", string(value.PlacementPolicyID)),
	)
	if !contains([]DeploymentDesiredState{DeploymentDesiredRunning, DeploymentDesiredStopped}, value.DesiredState) {
		problems = append(problems, fmt.Errorf("unknown deployment desired state %q", value.DesiredState))
	}
	if len(value.Components) == 0 {
		problems = append(problems, errors.New("deployment must contain at least one component"))
	}
	componentNames := make(map[string]struct{}, len(value.Components))
	for componentIndex, component := range value.Components {
		path := fmt.Sprintf("components[%d]", componentIndex)
		if !namePattern.MatchString(component.Name) {
			problems = append(problems, fmt.Errorf("%s.name is invalid", path))
		}
		if _, duplicate := componentNames[component.Name]; duplicate {
			problems = append(problems, fmt.Errorf("%s.name is duplicated", path))
		}
		componentNames[component.Name] = struct{}{}
		if component.Replicas == 0 {
			problems = append(problems, fmt.Errorf("%s.replicas must be positive", path))
		}
		bindingNames := make(map[string]struct{}, len(component.Bindings))
		for bindingIndex, binding := range component.Bindings {
			bindingPath := fmt.Sprintf("%s.bindings[%d]", path, bindingIndex)
			if !namePattern.MatchString(binding.Name) {
				problems = append(problems, fmt.Errorf("%s.name is invalid", bindingPath))
			}
			if _, duplicate := bindingNames[binding.Name]; duplicate {
				problems = append(problems, fmt.Errorf("%s.name is duplicated", bindingPath))
			}
			bindingNames[binding.Name] = struct{}{}
			hasConfiguration := binding.ConfigurationRevisionID != ""
			hasSecret := binding.SecretVersion != nil
			if hasConfiguration == hasSecret {
				problems = append(problems, fmt.Errorf("%s must bind exactly one configuration revision or secret version", bindingPath))
			}
			if hasConfiguration {
				problems = append(problems, ValidateID(bindingPath+".configurationRevisionId", string(binding.ConfigurationRevisionID)))
			}
			if hasSecret {
				problems = append(problems,
					ValidateID(bindingPath+".secretVersion.secretId", string(binding.SecretVersion.SecretID)),
					ValidateID(bindingPath+".secretVersion.version", binding.SecretVersion.Version),
				)
			}
		}
	}
	return errors.Join(problems...)
}

func validateDeploymentSpecAgainstRevision(value DeploymentSpec, revision ApplicationRevision) error {
	var problems []error
	if value.ApplicationRevisionID != revision.Metadata.ID {
		problems = append(problems, errors.New("deployment references another application revision"))
	}
	revisionComponents := make(map[string]ApplicationRevisionComponent, len(revision.Spec.Components))
	for _, component := range revision.Spec.Components {
		revisionComponents[component.Name] = component
	}
	if len(value.Components) != len(revision.Spec.Components) {
		problems = append(problems, errors.New("deployment component set must exactly match application revision"))
	}
	for _, component := range value.Components {
		revisionComponent, found := revisionComponents[component.Name]
		if !found {
			problems = append(problems, fmt.Errorf("deployment component %q is not declared by the application revision", component.Name))
			continue
		}
		inputs := make(map[string]ComponentInput, len(revisionComponent.Inputs))
		for _, input := range revisionComponent.Inputs {
			inputs[input.Name] = input
		}
		bound := make(map[string]struct{}, len(component.Bindings))
		for _, binding := range component.Bindings {
			input, declared := inputs[binding.Name]
			if !declared {
				problems = append(problems, fmt.Errorf("component %q binding %q is not declared", component.Name, binding.Name))
				continue
			}
			bound[binding.Name] = struct{}{}
			if input.Kind == InputConfiguration && binding.ConfigurationRevisionID == "" {
				problems = append(problems, fmt.Errorf("component %q input %q requires a configuration revision", component.Name, input.Name))
			}
			if input.Kind == InputSecret && binding.SecretVersion == nil {
				problems = append(problems, fmt.Errorf("component %q input %q requires a secret version", component.Name, input.Name))
			}
		}
		for _, input := range revisionComponent.Inputs {
			if _, found := bound[input.Name]; input.Required && !found {
				problems = append(problems, fmt.Errorf("component %q required input %q is unbound", component.Name, input.Name))
			}
		}
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
	if !contains(OperationActions(), value.Action) {
		problems = append(problems, fmt.Errorf("unknown operation action %q", value.Action))
	}
	switch value.Action {
	case OperationCreateExecutionPool, OperationRegisterExecutionTarget:
		if value.Scope.Kind != AuthorityPlatform {
			problems = append(problems, errors.New("platform operation action requires platform scope"))
		}
	case OperationCreatePlacement,
		OperationCreateApplication,
		OperationCreateConfiguration,
		OperationCreateConfigurationRevision,
		OperationCreateApplicationRevision,
		OperationDeploy,
		OperationUpdate,
		OperationStop,
		OperationRollback:
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
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
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
	if value.ApplicationID != "" {
		problems = append(problems, ValidateID("applicationId", string(value.ApplicationID)))
	}
	if value.ApplicationRevisionID != "" {
		problems = append(problems, ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)))
	}
	if value.DeploymentID != "" {
		problems = append(problems, ValidateID("deploymentId", string(value.DeploymentID)))
	}
	switch value.Action {
	case AdapterCapabilities, AdapterInspectExecutionTarget, AdapterObserveExecutionTarget:
		if value.Scope.Kind != AuthorityPlatform {
			problems = append(problems, errors.New("infrastructure adapter action requires platform scope"))
		}
		if value.ApplicationID != "" || value.ApplicationRevisionID != "" || value.DeploymentID != "" {
			problems = append(problems, errors.New("infrastructure adapter action cannot contain application or deployment identity"))
		}
	case AdapterValidateDeployment, AdapterApplyDeployment, AdapterObserveDeployment,
		AdapterStopDeployment, AdapterRollbackDeployment, AdapterReconcileRoutes,
		AdapterObserveRoutes, AdapterDeleteRoutes:
		if value.Scope.Kind != AuthorityTenant {
			problems = append(problems, errors.New("deployment adapter action requires tenant scope"))
		}
		if value.ApplicationID == "" || value.ApplicationRevisionID == "" || value.DeploymentID == "" {
			problems = append(problems, errors.New("deployment adapter action requires application, revision, and deployment identity"))
		}
	}
	if value.TraceParent != "" {
		problems = append(
			problems,
			ValidateSafeExternalText("traceparent", value.TraceParent, 55, false),
		)
	}
	return errors.Join(problems...)
}

func ValidateInspectExecutionTargetRequest(value InspectExecutionTargetRequest) error {
	if err := ValidateAdapterCommand(value.Command); err != nil {
		return err
	}
	if value.Command.Action != AdapterInspectExecutionTarget {
		return fmt.Errorf(
			"inspect target request action = %q, want %q",
			value.Command.Action,
			AdapterInspectExecutionTarget,
		)
	}
	if value.Command.Scope.Kind != AuthorityPlatform {
		return errors.New("inspect target request requires platform scope")
	}
	return nil
}

func ValidateObserveExecutionTargetRequest(value ObserveExecutionTargetRequest) error {
	if err := ValidateAdapterCommand(value.Command); err != nil {
		return err
	}
	if value.Command.Action != AdapterObserveExecutionTarget {
		return fmt.Errorf(
			"observe target request action = %q, want %q",
			value.Command.Action,
			AdapterObserveExecutionTarget,
		)
	}
	if value.Command.Scope.Kind != AuthorityPlatform {
		return errors.New("observe target request requires platform scope")
	}
	return nil
}

func ValidateExecutionTargetObservation(value ExecutionTargetObservation) error {
	var problems []error
	problems = append(problems,
		ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		ValidateDigest("identityFingerprint", value.IdentityFingerprint),
		validateLabels("labels", value.Labels),
		validateCapacity("capacity", value.Capacity),
		validateCapacity("allocatable", value.Allocatable),
		validateUniqueKnown(
			"supportedIsolationGuarantees",
			value.SupportedIsolationGuarantees,
			IsolationGuarantees(),
			false,
		),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if !contains(
		[]ExecutionTargetHealth{
			ExecutionTargetHealthUnknown,
			ExecutionTargetHealthReady,
			ExecutionTargetHealthDegraded,
			ExecutionTargetHealthUnavailable,
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
		validateUniqueKnown("isolationGuarantees", value.IsolationGuarantees, IsolationGuarantees(), false),
		validateContractTime("observedAt", value.ObservedAt),
	)
	if !contains(
		[]AdapterKind{AdapterInfrastructure, AdapterDeploymentExecutor, AdapterGateway},
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
		AdapterInspectExecutionTarget,
		AdapterObserveExecutionTarget,
		AdapterValidateDeployment,
		AdapterApplyDeployment,
		AdapterObserveDeployment,
		AdapterStopDeployment,
		AdapterRollbackDeployment,
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
			AdapterInspectExecutionTarget,
			AdapterObserveExecutionTarget,
		}
	case AdapterDeploymentExecutor:
		return []AdapterAction{
			AdapterCapabilities,
			AdapterValidateDeployment,
			AdapterApplyDeployment,
			AdapterObserveDeployment,
			AdapterStopDeployment,
			AdapterRollbackDeployment,
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

func validateImmutableMetadata(name string, value ResourceMetadata) error {
	var problems []error
	if value.ResourceVersion != 1 {
		problems = append(problems, fmt.Errorf("%s resourceVersion must remain 1", name))
	}
	if !value.UpdatedAt.Equal(value.CreatedAt) {
		problems = append(problems, fmt.Errorf("%s updatedAt must equal createdAt", name))
	}
	return errors.Join(problems...)
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
