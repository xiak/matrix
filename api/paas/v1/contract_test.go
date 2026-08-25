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

func TestOpenAPIContractDefinesRuntimeV1(t *testing.T) {
	document := loadOpenAPI(t)
	if got := document["openapi"]; got != "3.1.0" {
		t.Fatalf("openapi version = %v, want 3.1.0", got)
	}
	schemas := openAPISchemas(t, document)
	required := []string{
		"Tenant",
		"ResourcePool",
		"RuntimeTarget",
		"PlacementPolicy",
		"PlacementDecision",
		"WorkloadRelease",
		"Operation",
		"Evidence",
		"Problem",
		"AdapterCapabilitiesContract",
		"AdapterCommandEnvelope",
		"AdapterResult",
	}
	for _, name := range required {
		if _, found := schemas[name]; !found {
			t.Errorf("required schema %q is missing", name)
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
	assertExactEnum(t, schemas, "ResourcePoolPhase", stringify([]ResourcePoolPhase{
		ResourcePoolReady,
		ResourcePoolDegraded,
		ResourcePoolUnavailable,
	}))
	assertExactEnum(t, schemas, "TargetHealth", stringify([]TargetHealth{
		TargetHealthUnknown,
		TargetHealthReady,
		TargetHealthDegraded,
		TargetHealthUnavailable,
	}))
	assertExactEnum(t, schemas, "TargetDesiredState", stringify([]TargetDesiredState{
		TargetActive,
		TargetDraining,
	}))
	assertExactEnum(t, schemas, "IsolationClass", stringify(IsolationClasses()))
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
	assertExactEnum(t, schemas, "ReleasePhase", stringify(ReleasePhases()))
	assertExactEnum(t, schemas, "ArtifactKind", stringify([]ArtifactKind{
		ArtifactOCIImage,
		ArtifactOCIArtifact,
		ArtifactReleaseBundle,
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
	assertExactEnum(t, schemas, "OperationAction", stringify([]OperationAction{
		OperationCreateResourcePool,
		OperationRegisterTarget,
		OperationCreatePlacement,
		OperationDeploy,
		OperationUpdate,
		OperationStop,
		OperationRollback,
	}))
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
		AdapterRuntime,
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
	headers := object(t, components["headers"], "components.headers")
	if _, found := headers["ETag"]; !found {
		t.Fatal("ETag response header is missing")
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
	for _, name := range []string{"WorkloadReleaseSpec", "PlacementDecision"} {
		schema := schemaObject(t, schemas, name)
		if schema["x-matrix-immutable"] != true {
			t.Errorf("%s must declare x-matrix-immutable", name)
		}
	}
}

func TestOpenAPIStructPropertiesAndRequiredFieldsMatchGoTypes(t *testing.T) {
	schemas := openAPISchemas(t, loadOpenAPI(t))
	contracts := map[string]reflect.Type{
		"ResourceScope":               reflect.TypeOf(ResourceScope{}),
		"ResourceMetadata":            reflect.TypeOf(ResourceMetadata{}),
		"Tenant":                      reflect.TypeOf(Tenant{}),
		"LabelSelector":               reflect.TypeOf(LabelSelector{}),
		"ResourcePoolSpec":            reflect.TypeOf(ResourcePoolSpec{}),
		"ResourcePoolStatus":          reflect.TypeOf(ResourcePoolStatus{}),
		"ResourcePool":                reflect.TypeOf(ResourcePool{}),
		"AdapterRef":                  reflect.TypeOf(AdapterRef{}),
		"Capacity":                    reflect.TypeOf(Capacity{}),
		"RuntimeTargetSpec":           reflect.TypeOf(RuntimeTargetSpec{}),
		"RuntimeTargetStatus":         reflect.TypeOf(RuntimeTargetStatus{}),
		"RuntimeTarget":               reflect.TypeOf(RuntimeTarget{}),
		"PlacementPolicySpec":         reflect.TypeOf(PlacementPolicySpec{}),
		"PlacementPolicy":             reflect.TypeOf(PlacementPolicy{}),
		"PlacementDecision":           reflect.TypeOf(PlacementDecision{}),
		"ArtifactRef":                 reflect.TypeOf(ArtifactRef{}),
		"SecretReference":             reflect.TypeOf(SecretReference{}),
		"ResourceRequirements":        reflect.TypeOf(ResourceRequirements{}),
		"WorkloadEndpoint":            reflect.TypeOf(WorkloadEndpoint{}),
		"WorkloadComponent":           reflect.TypeOf(WorkloadComponent{}),
		"WorkloadReleaseSpec":         reflect.TypeOf(WorkloadReleaseSpec{}),
		"WorkloadReleaseStatus":       reflect.TypeOf(WorkloadReleaseStatus{}),
		"WorkloadRelease":             reflect.TypeOf(WorkloadRelease{}),
		"SubjectRef":                  reflect.TypeOf(SubjectRef{}),
		"ResourceRef":                 reflect.TypeOf(ResourceRef{}),
		"FieldViolation":              reflect.TypeOf(FieldViolation{}),
		"Problem":                     reflect.TypeOf(Problem{}),
		"Operation":                   reflect.TypeOf(Operation{}),
		"Evidence":                    reflect.TypeOf(Evidence{}),
		"AdapterCapabilitiesContract": reflect.TypeOf(AdapterCapabilitiesContract{}),
		"AdapterCommandEnvelope":      reflect.TypeOf(AdapterCommandEnvelope{}),
		"NormalizedAdapterError":      reflect.TypeOf(NormalizedAdapterError{}),
		"AdapterResult":               reflect.TypeOf(AdapterResult{}),
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
			path:   "examples/resource-pool.json",
			target: &ResourcePool{},
		},
		{
			path:   "examples/runtime-target.json",
			target: &RuntimeTarget{},
		},
		{
			path:   "examples/placement-policy.json",
			target: &PlacementPolicy{},
		},
		{
			path:   "examples/workload-release.json",
			target: &WorkloadRelease{},
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
			path:   "examples/evidence.json",
			target: &Evidence{},
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			decodeStrictJSON(t, test.path, test.target)
			var err error
			switch value := test.target.(type) {
			case *Tenant:
				err = ValidateTenant(*value)
			case *ResourcePool:
				err = ValidateResourcePool(*value)
			case *RuntimeTarget:
				err = ValidateRuntimeTarget(*value)
			case *PlacementPolicy:
				err = ValidatePlacementPolicy(*value)
			case *WorkloadRelease:
				err = ValidateWorkloadRelease(*value)
			case *PlacementDecision:
				err = ValidatePlacementDecision(*value)
			case *Operation:
				err = ValidateOperation(*value)
			case *Evidence:
				err = ValidateEvidence(*value)
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
	decision.RuntimeTargetID = "target-local"
	decision.GrantedIsolation = IsolationSharedCompose
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
	// Output: matrix.paas.io/paas/v1
}
