package paasv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestOpenAPIContractDefinesApplicationPaaSV1(t *testing.T) {
	document := loadOpenAPI(t)
	if got := document["openapi"]; got != "3.1.0" {
		t.Fatalf("openapi version = %v, want 3.1.0", got)
	}
	schemas := openAPISchemas(t, document)
	required := []string{
		"Tenant",
		"Application",
		"CreateApplicationRequest",
		"Configuration",
		"CreateConfigurationRequest",
		"ConfigurationRevision",
		"CreateConfigurationRevisionRequest",
		"ApplicationRevision",
		"CreateApplicationRevisionRequest",
		"Deployment",
		"DeploymentList",
		"DeploymentRuntimeInstance",
		"DeploymentRuntimeObservation",
		"DeploymentResourceInstance",
		"DeploymentResourceObservation",
		"DeploymentResourceSnapshot",
		"DeploymentRuntimeValue",
		"DeploymentRuntimeSnapshot",
		"CreateDeploymentRequest",
		"RollbackDeploymentRequest",
		"DeploymentGeneration",
		"ExecutionPool",
		"ExecutionTarget",
		"ExecutionTargetList",
		"PlacementPolicy",
		"PlacementDecision",
		"Operation",
		"Evidence",
		"Readiness",
		"VerifyInstallationRequest",
		"InstallationVerification",
		"Problem",
		"AdapterCapabilitiesContract",
		"AdapterCommandEnvelope",
		"InspectExecutionTargetRequest",
		"ObserveExecutionTargetRequest",
		"DeploymentExecutionRequest",
		"ObserveDeploymentRequest",
		"ObserveDeploymentRuntimeRequest",
		"DeploymentEndpointObservation",
		"DeploymentObservation",
		"ExecutionTargetObservation",
		"AdapterResult",
	}
	for _, name := range required {
		if _, found := schemas[name]; !found {
			t.Errorf("required schema %q is missing", name)
		}
	}
	readiness := schemaObject(t, schemas, "Readiness")
	properties := object(t, readiness["properties"], "Readiness.properties")
	schemaVersion := object(t, properties["schemaVersion"], "Readiness.schemaVersion")
	if schemaVersion["minimum"] != json.Number("1") {
		t.Fatalf("Readiness.schemaVersion must be positive: %#v", schemaVersion)
	}
	executionTargetList := schemaObject(t, schemas, "ExecutionTargetList")
	listProperties := object(t, executionTargetList["properties"], "ExecutionTargetList.properties")
	listItems := object(t, listProperties["items"], "ExecutionTargetList.items")
	if listItems["maxItems"] != json.Number(fmt.Sprint(MaximumExecutionTargetListItems)) {
		t.Fatalf("ExecutionTargetList.items must be bounded: %#v", listItems)
	}
	deploymentList := schemaObject(t, schemas, "DeploymentList")
	deploymentItems := object(t, object(t, deploymentList["properties"], "DeploymentList.properties")["items"], "DeploymentList.items")
	if deploymentItems["maxItems"] != json.Number(fmt.Sprint(MaximumDeploymentListItems)) {
		t.Fatalf("DeploymentList.items must be bounded: %#v", deploymentItems)
	}
	runtimeObservation := schemaObject(t, schemas, "DeploymentRuntimeObservation")
	runtimeProperties := object(t, runtimeObservation["properties"], "DeploymentRuntimeObservation.properties")
	runtimeInstances := object(t, runtimeProperties["instances"], "DeploymentRuntimeObservation.instances")
	if runtimeInstances["maxItems"] != json.Number(fmt.Sprint(MaximumDeploymentRuntimeInstances)) {
		t.Fatalf("DeploymentRuntimeObservation.instances must be bounded: %#v", runtimeInstances)
	}
	if generation := object(t, runtimeProperties["generation"], "DeploymentRuntimeObservation.generation"); generation["minimum"] != json.Number("1") {
		t.Fatalf("DeploymentRuntimeObservation.generation must be positive: %#v", generation)
	}
	resourceObservation := schemaObject(t, schemas, "DeploymentResourceObservation")
	resourceProperties := object(t, resourceObservation["properties"], "DeploymentResourceObservation.properties")
	resourceInstances := object(t, resourceProperties["instances"], "DeploymentResourceObservation.instances")
	if resourceInstances["maxItems"] != json.Number(fmt.Sprint(MaximumDeploymentRuntimeInstances)) {
		t.Fatalf("DeploymentResourceObservation.instances must be bounded: %#v", resourceInstances)
	}
	request := schemaObject(t, schemas, "ObserveDeploymentRuntimeRequest")
	requestGeneration := object(t, object(t, request["properties"], "ObserveDeploymentRuntimeRequest.properties")["generation"], "ObserveDeploymentRuntimeRequest.generation")
	if requestGeneration["minimum"] != json.Number("1") {
		t.Fatalf("ObserveDeploymentRuntimeRequest.generation must be positive: %#v", requestGeneration)
	}
	snapshot := schemaObject(t, schemas, "DeploymentRuntimeSnapshot")
	snapshotState := object(t, object(t, snapshot["properties"], "DeploymentRuntimeSnapshot.properties")["state"], "DeploymentRuntimeSnapshot.state")
	wantRuntimeStates := []any{string(MeasurementAvailable), string(MeasurementStale), string(MeasurementUnavailable)}
	if !reflect.DeepEqual(snapshotState["enum"], wantRuntimeStates) {
		t.Fatalf("DeploymentRuntimeSnapshot.state must be closed: %#v", snapshotState)
	}
	resourceSnapshot := schemaObject(t, schemas, "DeploymentResourceSnapshot")
	resourceState := object(t, object(t, resourceSnapshot["properties"], "DeploymentResourceSnapshot.properties")["state"], "DeploymentResourceSnapshot.state")
	if !reflect.DeepEqual(resourceState["enum"], wantRuntimeStates) {
		t.Fatalf("DeploymentResourceSnapshot.state must be closed: %#v", resourceState)
	}
	instance := schemaObject(t, schemas, "DeploymentRuntimeInstance")
	if allOf, ok := instance["allOf"].([]any); !ok || len(allOf) != 2 {
		t.Fatalf("DeploymentRuntimeInstance exit-code condition is incomplete: %#v", instance["allOf"])
	}
}

func TestOpenAPINorthboundSurfaceUsesMatrixIAM(t *testing.T) {
	document := loadOpenAPI(t)
	security := document["security"].([]any)
	if len(security) != 1 {
		t.Fatalf("top-level security = %#v, want one MatrixIAM requirement", security)
	}
	requirement := object(t, security[0], "security[0]")
	if scopes, found := requirement["MatrixIAM"]; !found || len(scopes.([]any)) != 0 {
		t.Fatalf("top-level security = %#v, want MatrixIAM bearer requirement", security)
	}
	components := object(t, document["components"], "components")
	schemes := object(t, components["securitySchemes"], "components.securitySchemes")
	matrixIAM := object(t, schemes["MatrixIAM"], "MatrixIAM")
	if matrixIAM["type"] != "http" || matrixIAM["scheme"] != "bearer" {
		t.Fatalf("MatrixIAM = %#v, want HTTP bearer", matrixIAM)
	}

	want := map[string][]string{
		"/v1/execution-pools":                                     {"post"},
		"/v1/execution-pools/{executionPoolId}":                   {"get"},
		"/v1/execution-targets":                                   {"get", "post"},
		"/v1/execution-targets/{executionTargetId}":               {"get"},
		"/v1/platform/operations/{operationId}":                   {"get"},
		"/ready":                                                  {"get"},
		"/v1/applications":                                        {"post"},
		"/v1/applications/{applicationId}":                        {"get"},
		"/v1/configurations":                                      {"post"},
		"/v1/configurations/{configurationId}":                    {"get"},
		"/v1/configuration-revisions":                             {"post"},
		"/v1/configuration-revisions/{configurationRevisionId}":   {"get"},
		"/v1/application-revisions":                               {"post"},
		"/v1/application-revisions/{applicationRevisionId}":       {"get"},
		"/v1/deployments":                                         {"get", "post"},
		"/v1/deployments/{deploymentId}":                          {"get", "put"},
		"/v1/deployments/{deploymentId}/rollback":                 {"post"},
		"/v1/deployments/{deploymentId}/generations/{generation}": {"get"},
		"/v1/deployments/{deploymentId}/runtime":                  {"get"},
		"/v1/operations/{operationId}":                            {"get"},
		"/v1/installation:verify":                                 {"post"},
	}
	paths := object(t, document["paths"], "paths")
	if len(paths) != len(want) {
		t.Fatalf("path count = %d, want %d", len(paths), len(want))
	}
	for path, methods := range want {
		pathItem := object(t, paths[path], path)
		if len(pathItem) != len(methods) {
			t.Errorf("%s methods = %#v, want %v", path, pathItem, methods)
			continue
		}
		for _, method := range methods {
			operation := object(t, pathItem[method], path+" "+method)
			securityOverride, overridesSecurity := operation["security"]
			if path == "/ready" {
				if !overridesSecurity || len(securityOverride.([]any)) != 0 {
					t.Errorf("%s %s must explicitly allow unauthenticated health checks", method, path)
				}
			} else if path == "/v1/installation:verify" {
				if !overridesSecurity {
					t.Errorf("%s %s must override generic MatrixIAM security", method, path)
					continue
				}
				verificationSecurity := securityOverride.([]any)
				if len(verificationSecurity) != 1 {
					t.Errorf("%s %s security = %#v", method, path, verificationSecurity)
					continue
				}
				verificationRequirement := object(t, verificationSecurity[0], "installation verifier security")
				if len(verificationRequirement) != 1 || verificationRequirement["MatrixInstallationVerifier"] == nil {
					t.Errorf("%s %s must require only MatrixInstallationVerifier", method, path)
				}
			} else if overridesSecurity {
				t.Errorf("%s %s must inherit MatrixIAM", method, path)
			}
		}
	}
}

func TestOpenAPIEnumsMatchGoContract(t *testing.T) {
	document := loadOpenAPI(t)
	schemas := openAPISchemas(t, document)
	assertExactEnum(t, schemas, "AuthorityKind", stringify([]AuthorityKind{
		AuthorityPlatform,
		AuthorityTenant,
	}))
	assertExactEnum(t, schemas, "TenantStatus", stringify([]TenantStatus{
		TenantActive,
		TenantSuspended,
		TenantDeactivated,
	}))
	assertExactEnum(t, schemas, "ExecutionPoolPhase", stringify([]ExecutionPoolPhase{
		ExecutionPoolReady,
		ExecutionPoolDegraded,
		ExecutionPoolUnavailable,
	}))
	assertExactEnum(t, schemas, "ExecutionTargetHealth", stringify([]ExecutionTargetHealth{
		ExecutionTargetHealthUnknown,
		ExecutionTargetHealthReady,
		ExecutionTargetHealthDegraded,
		ExecutionTargetHealthUnavailable,
	}))
	assertExactEnum(t, schemas, "ExecutionTargetDesiredState", stringify([]ExecutionTargetDesiredState{
		ExecutionTargetActive,
		ExecutionTargetDraining,
	}))
	assertExactEnum(t, schemas, "IsolationGuarantee", stringify(IsolationGuarantees()))
	assertExactEnum(t, schemas, "PlacementStrategy", stringify([]PlacementStrategy{
		PlacementFirstFit,
		PlacementSpread,
		PlacementBinPack,
	}))
	assertExactEnum(t, schemas, "PlacementOutcome", stringify([]PlacementOutcome{
		PlacementScheduled,
		PlacementUnschedulable,
	}))
	assertExactEnum(t, schemas, "OperationState", stringify(OperationStates()))
	assertExactEnum(t, schemas, "DeploymentPhase", stringify(DeploymentPhases()))
	assertExactEnum(t, schemas, "DeploymentDesiredState", stringify([]DeploymentDesiredState{
		DeploymentDesiredRunning,
		DeploymentDesiredStopped,
	}))
	assertExactEnum(t, schemas, "ReadinessState", stringify([]ReadinessState{
		ReadinessReady,
		ReadinessNotReady,
	}))
	assertExactEnum(t, schemas, "InstallationVerificationState", stringify([]InstallationVerificationState{
		InstallationVerificationPending,
		InstallationVerificationReady,
		InstallationVerificationFailed,
	}))
	assertExactEnum(t, schemas, "ArtifactKind", stringify([]ArtifactKind{
		ArtifactOCIImage,
		ArtifactOCIArtifact,
		ArtifactReleaseBundle,
	}))
	assertExactEnum(t, schemas, "InputKind", stringify([]InputKind{
		InputConfiguration,
		InputSecret,
	}))
	assertExactEnum(t, schemas, "InjectionMode", stringify([]InjectionMode{
		InjectionEnvironment,
		InjectionFile,
	}))
	assertExactEnum(t, schemas, "EndpointProtocol", stringify([]EndpointProtocol{
		EndpointHTTP,
		EndpointGRPC,
		EndpointTCP,
	}))
	assertExactEnum(t, schemas, "EndpointVisibility", stringify([]EndpointVisibility{
		EndpointPrivate,
		EndpointPublic,
	}))
	assertExactEnum(t, schemas, "SubjectType", stringify([]SubjectType{
		SubjectUser,
		SubjectServiceAccount,
		SubjectAgent,
		SubjectSystemUser,
	}))
	assertExactEnum(t, schemas, "OperationAction", stringify(OperationActions()))
	assertExactEnum(t, schemas, "EvidenceType", stringify([]EvidenceType{
		EvidencePolicyDecision,
		EvidencePlacementDecision,
		EvidenceAdapterCommand,
		EvidenceAdapterResult,
		EvidenceObservation,
		EvidenceVerification,
		EvidenceAuditDispatch,
	}))
	assertExactEnum(t, schemas, "EvidenceSeverity", stringify([]EvidenceSeverity{
		EvidenceInfo,
		EvidenceWarning,
		EvidenceError,
	}))
	assertExactEnum(t, schemas, "ErrorCode", stringify(ErrorCodes()))
	assertExactEnum(t, schemas, "AdapterKind", stringify([]AdapterKind{
		AdapterInfrastructure,
		AdapterDeploymentExecutor,
		AdapterGateway,
	}))
	assertExactEnum(t, schemas, "AdapterAction", stringify(adapterActions()))
	assertExactEnum(t, schemas, "AdapterResultState", stringify([]AdapterResultState{
		AdapterResultSucceeded,
		AdapterResultInProgress,
		AdapterResultFailed,
		AdapterResultUnknown,
	}))
	assertExactEnum(t, schemas, "AdapterErrorClass", stringify([]AdapterErrorClass{
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
	}))

	operationState := schemaObject(t, schemas, "OperationState")
	assertExactStrings(
		t,
		"OperationState.x-matrix-terminal-values",
		stringArray(t, operationState["x-matrix-terminal-values"]),
		[]string{
			string(OperationSucceeded),
			string(OperationFailed),
			string(OperationCancelled),
			string(OperationManualIntervention),
		},
	)
}

func TestTimestampSchemaRequiresUTCAndMicrosecondPrecision(t *testing.T) {
	schemas := openAPISchemas(t, loadOpenAPI(t))
	timestamp := schemaObject(t, schemas, "Timestamp")
	const want = `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$`
	if got := timestamp["pattern"]; got != want {
		t.Fatalf("Timestamp.pattern = %q, want %q", got, want)
	}
}

func TestMutationAndConcurrencyHeadersAreNormative(t *testing.T) {
	document := loadOpenAPI(t)
	components := object(t, document["components"], "components")
	parameters := object(t, components["parameters"], "components.parameters")
	idempotency := object(t, parameters["IdempotencyKey"], "IdempotencyKey")
	if idempotency["name"] != "Idempotency-Key" || idempotency["in"] != "header" ||
		idempotency["required"] != true {
		t.Fatalf("Idempotency-Key must be a required header: %#v", idempotency)
	}
	ifMatch := object(t, parameters["IfMatch"], "IfMatch")
	if ifMatch["name"] != "If-Match" || ifMatch["in"] != "header" ||
		ifMatch["required"] != true {
		t.Fatalf("If-Match must be a required header: %#v", ifMatch)
	}
	ifMatchSchema := object(t, ifMatch["schema"], "IfMatch.schema")
	if ifMatchSchema["pattern"] != `^"[1-9][0-9]*"$` {
		t.Fatalf("If-Match must require a strong positive resource ETag: %#v", ifMatchSchema)
	}
	headers := object(t, components["headers"], "components.headers")
	if _, found := headers["ETag"]; !found {
		t.Fatal("ETag response header is missing")
	}
	paths := object(t, document["paths"], "paths")
	verificationPath := object(t, paths["/v1/installation:verify"], "installation verification path")
	verification := object(t, verificationPath["post"], "installation verification operation")
	verificationParameters, ok := verification["parameters"].([]any)
	if !ok || len(verificationParameters) != 1 {
		t.Fatalf("installation verification must require one idempotency header: %#v", verification["parameters"])
	}
	verificationIdempotency := object(t, verificationParameters[0], "installation verification idempotency header")
	if verificationIdempotency["$ref"] != "#/components/parameters/IdempotencyKey" {
		t.Fatalf("installation verification idempotency header = %#v", verificationIdempotency)
	}
	responses := object(t, components["responses"], "components.responses")
	problem := object(t, responses["ProblemResponse"], "ProblemResponse")
	content := object(t, problem["content"], "ProblemResponse.content")
	if _, found := content["application/problem+json"]; !found {
		t.Fatal("ProblemResponse must use application/problem+json")
	}
}

func TestImmutableSchemasAreExplicit(t *testing.T) {
	schemas := openAPISchemas(t, loadOpenAPI(t))
	for _, name := range []string{
		"ConfigurationRevisionSpec",
		"ApplicationRevisionSpec",
		"DeploymentGeneration",
		"PlacementDecision",
	} {
		schema := schemaObject(t, schemas, name)
		if schema["x-matrix-immutable"] != true {
			t.Errorf("%s must declare x-matrix-immutable", name)
		}
	}
}

func TestExecutionAdapterSchemasExposeReferencesNotProviderControls(t *testing.T) {
	schemas := openAPISchemas(t, loadOpenAPI(t))
	for _, name := range []string{
		"DeploymentExecutionRequest",
		"ObserveDeploymentRequest",
		"DeploymentEndpointObservation",
		"DeploymentObservation",
	} {
		schema := schemaObject(t, schemas, name)
		if schema["x-matrix-visibility"] != "internal" {
			t.Errorf("%s must remain internal-visible", name)
		}
	}
	secretReference := schemaObject(t, schemas, "SecretVersionReference")
	properties := object(t, secretReference["properties"], "SecretVersionReference.properties")
	if len(properties) != 2 || properties["secretId"] == nil || properties["version"] == nil {
		t.Fatalf("SecretVersionReference must contain only exact identity fields: %#v", properties)
	}
	if secretReference["additionalProperties"] != false {
		t.Fatal("SecretVersionReference must reject secret material extensions")
	}
}

func TestOpenAPIStructPropertiesAndRequiredFieldsMatchGoTypes(t *testing.T) {
	schemas := openAPISchemas(t, loadOpenAPI(t))
	contracts := map[string]reflect.Type{
		"ResourceScope":                       reflect.TypeOf(ResourceScope{}),
		"ResourceMetadata":                    reflect.TypeOf(ResourceMetadata{}),
		"Tenant":                              reflect.TypeOf(Tenant{}),
		"LabelSelector":                       reflect.TypeOf(LabelSelector{}),
		"ExecutionPoolSpec":                   reflect.TypeOf(ExecutionPoolSpec{}),
		"ExecutionPoolStatus":                 reflect.TypeOf(ExecutionPoolStatus{}),
		"ExecutionPool":                       reflect.TypeOf(ExecutionPool{}),
		"AdapterRef":                          reflect.TypeOf(AdapterRef{}),
		"Capacity":                            reflect.TypeOf(Capacity{}),
		"ExecutionTargetSpec":                 reflect.TypeOf(ExecutionTargetSpec{}),
		"ExecutionTargetStatus":               reflect.TypeOf(ExecutionTargetStatus{}),
		"ExecutionTarget":                     reflect.TypeOf(ExecutionTarget{}),
		"ExecutionTargetList":                 reflect.TypeOf(ExecutionTargetList{}),
		"PlacementPolicySpec":                 reflect.TypeOf(PlacementPolicySpec{}),
		"PlacementPolicy":                     reflect.TypeOf(PlacementPolicy{}),
		"PlacementDecision":                   reflect.TypeOf(PlacementDecision{}),
		"ArtifactRef":                         reflect.TypeOf(ArtifactRef{}),
		"ResourceRequirements":                reflect.TypeOf(ResourceRequirements{}),
		"ApplicationEndpoint":                 reflect.TypeOf(ApplicationEndpoint{}),
		"ComponentInput":                      reflect.TypeOf(ComponentInput{}),
		"SecretVersionReference":              reflect.TypeOf(SecretVersionReference{}),
		"ComponentBinding":                    reflect.TypeOf(ComponentBinding{}),
		"Application":                         reflect.TypeOf(Application{}),
		"CreateApplicationRequest":            reflect.TypeOf(CreateApplicationRequest{}),
		"Configuration":                       reflect.TypeOf(Configuration{}),
		"CreateConfigurationRequest":          reflect.TypeOf(CreateConfigurationRequest{}),
		"ConfigurationRevisionSpec":           reflect.TypeOf(ConfigurationRevisionSpec{}),
		"ConfigurationRevision":               reflect.TypeOf(ConfigurationRevision{}),
		"CreateConfigurationRevisionRequest":  reflect.TypeOf(CreateConfigurationRevisionRequest{}),
		"ApplicationRevisionComponent":        reflect.TypeOf(ApplicationRevisionComponent{}),
		"ApplicationRevisionSpec":             reflect.TypeOf(ApplicationRevisionSpec{}),
		"ApplicationRevision":                 reflect.TypeOf(ApplicationRevision{}),
		"CreateApplicationRevisionRequest":    reflect.TypeOf(CreateApplicationRevisionRequest{}),
		"DeploymentComponent":                 reflect.TypeOf(DeploymentComponent{}),
		"DeploymentSpec":                      reflect.TypeOf(DeploymentSpec{}),
		"DeploymentStatus":                    reflect.TypeOf(DeploymentStatus{}),
		"Deployment":                          reflect.TypeOf(Deployment{}),
		"DeploymentList":                      reflect.TypeOf(DeploymentList{}),
		"DeploymentRuntimeInstance":           reflect.TypeOf(DeploymentRuntimeInstance{}),
		"DeploymentRuntimeObservation":        reflect.TypeOf(DeploymentRuntimeObservation{}),
		"DeploymentInstanceCPUUsage":          reflect.TypeOf(DeploymentInstanceCPUUsage{}),
		"DeploymentInstanceCPUUsageValue":     reflect.TypeOf(DeploymentInstanceCPUUsageValue{}),
		"DeploymentInstanceMemoryUsage":       reflect.TypeOf(DeploymentInstanceMemoryUsage{}),
		"DeploymentInstanceMemoryUsageValue":  reflect.TypeOf(DeploymentInstanceMemoryUsageValue{}),
		"DeploymentInstanceNetworkUsage":      reflect.TypeOf(DeploymentInstanceNetworkUsage{}),
		"DeploymentInstanceNetworkUsageValue": reflect.TypeOf(DeploymentInstanceNetworkUsageValue{}),
		"DeploymentInstanceBlockIOUsage":      reflect.TypeOf(DeploymentInstanceBlockIOUsage{}),
		"DeploymentInstanceBlockIOUsageValue": reflect.TypeOf(DeploymentInstanceBlockIOUsageValue{}),
		"DeploymentInstanceVolumeUsage":       reflect.TypeOf(DeploymentInstanceVolumeUsage{}),
		"DeploymentInstanceStorageUsage":      reflect.TypeOf(DeploymentInstanceStorageUsage{}),
		"DeploymentInstanceStorageUsageValue": reflect.TypeOf(DeploymentInstanceStorageUsageValue{}),
		"DeploymentResourceInstance":          reflect.TypeOf(DeploymentResourceInstance{}),
		"DeploymentResourceObservation":       reflect.TypeOf(DeploymentResourceObservation{}),
		"DeploymentResourceValue":             reflect.TypeOf(DeploymentResourceValue{}),
		"DeploymentResourceSnapshot":          reflect.TypeOf(DeploymentResourceSnapshot{}),
		"DeploymentRuntimeValue":              reflect.TypeOf(DeploymentRuntimeValue{}),
		"DeploymentRuntimeSnapshot":           reflect.TypeOf(DeploymentRuntimeSnapshot{}),
		"CreateDeploymentRequest":             reflect.TypeOf(CreateDeploymentRequest{}),
		"RollbackDeploymentRequest":           reflect.TypeOf(RollbackDeploymentRequest{}),
		"DeploymentGeneration":                reflect.TypeOf(DeploymentGeneration{}),
		"SubjectRef":                          reflect.TypeOf(SubjectRef{}),
		"ResourceRef":                         reflect.TypeOf(ResourceRef{}),
		"FieldViolation":                      reflect.TypeOf(FieldViolation{}),
		"Readiness":                           reflect.TypeOf(Readiness{}),
		"Problem":                             reflect.TypeOf(Problem{}),
		"Operation":                           reflect.TypeOf(Operation{}),
		"Evidence":                            reflect.TypeOf(Evidence{}),
		"AdapterCapabilitiesContract":         reflect.TypeOf(AdapterCapabilitiesContract{}),
		"AdapterCommandEnvelope":              reflect.TypeOf(AdapterCommandEnvelope{}),
		"InspectExecutionTargetRequest":       reflect.TypeOf(InspectExecutionTargetRequest{}),
		"ObserveExecutionTargetRequest":       reflect.TypeOf(ObserveExecutionTargetRequest{}),
		"DeploymentExecutionRequest":          reflect.TypeOf(DeploymentExecutionRequest{}),
		"ObserveDeploymentRequest":            reflect.TypeOf(ObserveDeploymentRequest{}),
		"DeploymentEndpointObservation":       reflect.TypeOf(DeploymentEndpointObservation{}),
		"DeploymentObservation":               reflect.TypeOf(DeploymentObservation{}),
		"ObserveDeploymentRuntimeRequest":     reflect.TypeOf(ObserveDeploymentRuntimeRequest{}),
		"ExecutionTargetObservation":          reflect.TypeOf(ExecutionTargetObservation{}),
		"NormalizedAdapterError":              reflect.TypeOf(NormalizedAdapterError{}),
		"AdapterResult":                       reflect.TypeOf(AdapterResult{}),
	}

	for name, goType := range contracts {
		t.Run(name, func(t *testing.T) {
			assertGoStructMatchesSchema(t, schemas, name, goType)
		})
	}
}

func TestPublicPropertyNamesDoNotLeakAdapterNativeTypes(t *testing.T) {
	schemas := openAPISchemas(t, loadOpenAPI(t))
	forbidden := []string{
		"apisix",
		"kubernetes",
		"docker",
		"ssh",
		"aws",
		"azure",
		"aliyun",
		"cloudflare",
	}
	for schemaName, raw := range schemas {
		walkSchemaProperties(t, schemaName, raw, func(path string) {
			normalized := strings.ToLower(path)
			for _, marker := range forbidden {
				if strings.Contains(normalized, marker) {
					t.Errorf("public property %q leaks adapter-native marker %q", path, marker)
				}
			}
		})
	}
}

func TestExamplesDecodeAndValidate(t *testing.T) {
	tests := []struct {
		path     string
		target   any
		validate func() error
	}{
		{
			path:   "examples/tenant.json",
			target: &Tenant{},
		},
		{
			path:   "examples/execution-pool.json",
			target: &ExecutionPool{},
		},
		{
			path:   "examples/execution-target.json",
			target: &ExecutionTarget{},
		},
		{
			path:   "examples/application.json",
			target: &Application{},
		},
		{
			path:   "examples/configuration.json",
			target: &Configuration{},
		},
		{
			path:   "examples/configuration-revision.json",
			target: &ConfigurationRevision{},
		},
		{
			path:   "examples/placement-policy.json",
			target: &PlacementPolicy{},
		},
		{
			path:   "examples/application-revision.json",
			target: &ApplicationRevision{},
		},
		{
			path:   "examples/deployment.json",
			target: &Deployment{},
		},
		{
			path:   "examples/placement-scheduled.json",
			target: &PlacementDecision{},
		},
		{
			path:   "examples/placement-unschedulable.json",
			target: &PlacementDecision{},
		},
		{
			path:   "examples/operation.json",
			target: &Operation{},
		},
		{
			path:   "examples/readiness.json",
			target: &Readiness{},
		},
		{
			path:   "examples/evidence.json",
			target: &Evidence{},
		},
		{
			path:   "examples/inspect-execution-target-request.json",
			target: &InspectExecutionTargetRequest{},
		},
		{
			path:   "examples/execution-target-observation-ready.json",
			target: &ExecutionTargetObservation{},
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			decodeStrictJSON(t, test.path, test.target)
			var err error
			switch value := test.target.(type) {
			case *Tenant:
				err = ValidateTenant(*value)
			case *ExecutionPool:
				err = ValidateExecutionPool(*value)
			case *ExecutionTarget:
				err = ValidateExecutionTarget(*value)
			case *PlacementPolicy:
				err = ValidatePlacementPolicy(*value)
			case *Application:
				err = ValidateApplication(*value)
			case *Configuration:
				err = ValidateConfiguration(*value)
			case *ConfigurationRevision:
				err = ValidateConfigurationRevision(*value)
			case *ApplicationRevision:
				err = ValidateApplicationRevision(*value)
			case *Deployment:
				err = ValidateDeployment(*value)
			case *PlacementDecision:
				err = ValidatePlacementDecision(*value)
			case *Operation:
				err = ValidateOperation(*value)
			case *Readiness:
				err = ValidateReadiness(*value)
			case *Evidence:
				err = ValidateEvidence(*value)
			case *InspectExecutionTargetRequest:
				err = ValidateInspectExecutionTargetRequest(*value)
			case *ExecutionTargetObservation:
				err = ValidateExecutionTargetObservation(*value)
			default:
				t.Fatalf("unhandled example type %T", test.target)
			}
			if err != nil {
				t.Fatalf("validate example: %v", err)
			}
		})
	}
}

func TestPlacementNeverSilentlyDowngradesIsolation(t *testing.T) {
	var decision PlacementDecision
	decodeStrictJSON(t, "examples/placement-unschedulable.json", &decision)
	decision.Outcome = PlacementScheduled
	decision.ExecutionTargetID = "target-local"
	decision.GrantedIsolationGuarantee = IsolationWorkload
	decision.Reason = nil
	if err := ValidatePlacementDecision(decision); err == nil ||
		!strings.Contains(err.Error(), "exactly equal") {
		t.Fatalf("downgraded isolation must fail closed, got %v", err)
	}
}

func TestEvidenceRejectsSensitiveAttributeKeys(t *testing.T) {
	var evidence Evidence
	decodeStrictJSON(t, "examples/evidence.json", &evidence)
	evidence.Attributes["authorization_token"] = "redacted-is-still-forbidden"
	if err := ValidateEvidence(evidence); err == nil ||
		!strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("sensitive evidence key must be rejected, got %v", err)
	}
}

func loadOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	source, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode openapi.json: %v", err)
	}
	return document
}

func openAPISchemas(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	components := object(t, document["components"], "components")
	return object(t, components["schemas"], "components.schemas")
}

func schemaObject(t *testing.T, schemas map[string]any, name string) map[string]any {
	t.Helper()
	value, found := schemas[name]
	if !found {
		t.Fatalf("schema %q is missing", name)
	}
	return object(t, value, "schema "+name)
}

func assertGoStructMatchesSchema(
	t *testing.T,
	schemas map[string]any,
	name string,
	goType reflect.Type,
) {
	t.Helper()
	schema := schemaObject(t, schemas, name)
	properties := object(t, schema["properties"], name+".properties")
	goProperties := make([]string, 0, goType.NumField())
	goRequired := make([]string, 0, goType.NumField())
	for index := 0; index < goType.NumField(); index++ {
		field := goType.Field(index)
		tag := field.Tag.Get("json")
		parts := strings.Split(tag, ",")
		if tag == "" || parts[0] == "-" {
			t.Fatalf("%s.%s must have a JSON contract tag", goType.Name(), field.Name)
		}
		goProperties = append(goProperties, parts[0])
		if !slices.Contains(parts[1:], "omitempty") {
			goRequired = append(goRequired, parts[0])
		}
	}
	schemaProperties := make([]string, 0, len(properties))
	for property := range properties {
		schemaProperties = append(schemaProperties, property)
	}
	assertExactStrings(t, name+".properties", schemaProperties, goProperties)

	var schemaRequired []string
	if raw, found := schema["required"]; found {
		schemaRequired = stringArray(t, raw)
	}
	assertExactStrings(t, name+".required", schemaRequired, goRequired)
}

func assertExactEnum(t *testing.T, schemas map[string]any, name string, want []string) {
	t.Helper()
	schema := schemaObject(t, schemas, name)
	assertExactStrings(t, name, stringArray(t, schema["enum"]), want)
}

func assertExactStrings(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(uniqueStrings(got)) {
		t.Fatalf("%s contains duplicate values: %v", name, got)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func stringify[T ~string](values []T) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return result
}

func stringArray(t *testing.T, value any) []string {
	t.Helper()
	raw, ok := value.([]any)
	if !ok {
		t.Fatalf("value is %T, want array", value)
	}
	result := make([]string, 0, len(raw))
	for index, item := range raw {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("array[%d] is %T, want string", index, item)
		}
		result = append(result, text)
	}
	return result
}

func object(t *testing.T, value any, name string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want object", name, value)
	}
	return result
}

func walkSchemaProperties(t *testing.T, path string, value any, visit func(string)) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "properties" {
				properties := object(t, child, path+".properties")
				for property, schema := range properties {
					propertyPath := path + "." + property
					visit(propertyPath)
					walkSchemaProperties(t, propertyPath, schema, visit)
				}
				continue
			}
			walkSchemaProperties(t, path, child, visit)
		}
	case []any:
		for _, child := range typed {
			walkSchemaProperties(t, path, child, visit)
		}
	}
}

func decodeStrictJSON(t *testing.T, path string, target any) {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	var remainder any
	if err := decoder.Decode(&remainder); !errors.Is(err, io.EOF) {
		t.Fatalf("%s must contain exactly one JSON value: %v", path, err)
	}
	if reflect.ValueOf(target).Kind() != reflect.Pointer {
		t.Fatalf("example target must be a pointer, got %T", target)
	}
}

func ExampleAPIVersion() {
	fmt.Println(APIVersion)
	// Output: paas.matrix.xiak.com/v1
}
