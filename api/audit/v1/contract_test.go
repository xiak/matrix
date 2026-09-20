package auditv1

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

func TestCanonicalEventPreservesTenantBytesAndDigest(t *testing.T) {
	event := Event{
		APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-example",
		TenantID: "organization-example", Actor: ActorReference{Type: ActorUser, ID: "principal-example"},
		IAMDecisionID: "decision-example", Action: ActionPaaSDeploymentCreated,
		Target: TargetReference{Kind: TargetDeployment, ID: "deployment-example"}, Result: ResultAccepted,
		RequestDigest: "sha256:" + strings.Repeat("1", 64), RequestID: "request-example",
		CorrelationID: "correlation-example", OperationID: "operation-example",
		OccurredAt: time.Date(2026, 8, 25, 3, 4, 5, 0, time.UTC),
	}
	// This is the accepted tenant canonical wire format, not an implementation snapshot.
	const expected = `{"canonicalVersion":"matrix.audit.canonical-event.v1","source":"PAAS","event":{"apiVersion":"audit.matrix.xiak.com/v1","kind":"AuditEvent","eventId":"event-example","tenantId":"organization-example","actor":{"type":"USER","id":"principal-example"},"iamDecisionId":"decision-example","action":"paas.deployment.created","target":{"kind":"DEPLOYMENT","id":"deployment-example"},"result":"ACCEPTED","requestDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","requestId":"request-example","correlationId":"correlation-example","operationId":"operation-example","occurredAt":"2026-08-25T03:04:05.000000Z"}}`
	document, digest, err := CanonicalizeEvent(SourcePaaS, event)
	expectedDigest := sha256.Sum256([]byte(expected))
	if err != nil || document != expected || digest != "sha256:"+hex.EncodeToString(expectedDigest[:]) {
		t.Fatalf("historical tenant canonical bytes/digest changed: %v", err)
	}
	if _, _, err := CanonicalizeEvent(SourceIAM, event); err == nil {
		t.Fatal("canonical encoder accepted another producer source")
	}
}

func TestNotificationContactFactsRequireTheActualTenantUser(t *testing.T) {
	for _, action := range []Action{
		ActionIAMNotificationContactVerificationStarted,
		ActionIAMNotificationContactVerified,
	} {
		t.Run(string(action), func(t *testing.T) {
			valid := Event{
				APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-notification-contact",
				TenantID: "account-one", Actor: ActorReference{Type: ActorUser, ID: "user-one"},
				Action: action, Target: TargetReference{Kind: TargetUser, ID: "user-one"}, Result: ResultSucceeded,
				RequestDigest: "sha256:" + strings.Repeat("a", 64), RequestID: "request-one", CorrelationID: "request-one",
				OccurredAt: time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC),
			}
			if _, _, err := CanonicalizeEvent(SourceIAM, valid); err != nil {
				t.Fatal(err)
			}
			for _, mutate := range []func(*Event){
				func(value *Event) { value.Actor.Type = ActorSystem },
				func(value *Event) { value.Actor.Type = ActorServiceAccount },
				func(value *Event) { value.Actor.AccessKeyID = "key-one" },
				func(value *Event) { value.Target.ID = "another-user" },
				func(value *Event) { value.Target.Kind = TargetSession },
				func(value *Event) { value.Target.TenantID = value.TenantID },
				func(value *Event) { value.TenantID, value.InstallationID = "", "installation-one" },
				func(value *Event) { value.IAMDecisionID = "invented-permit" },
				func(value *Event) { value.OperationID = "invented-operation" },
				func(value *Event) { value.Result = ResultDenied },
			} {
				forged := valid
				mutate(&forged)
				if ValidateEventForSource(SourceIAM, forged) == nil {
					t.Fatal("unrelated authority accepted as notification contact self-service")
				}
			}
			if ValidateEventForSource(SourcePaaS, valid) == nil {
				t.Fatal("another producer accepted")
			}
		})
	}
}

func TestAccessKeyFactsRequireRealTenantUserDecisions(t *testing.T) {
	event := Event{APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-key", TenantID: "account-a",
		Actor: ActorReference{Type: ActorUser, ID: "manager-a"}, IAMDecisionID: "decision-key", Target: TargetReference{Kind: TargetAccessKey, ID: "key-a"},
		Result: ResultSucceeded, RequestID: "request-key", CorrelationID: "request-key", RequestDigest: "sha256:" + strings.Repeat("1", 64),
		OccurredAt: time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)}
	for _, action := range []Action{ActionIAMAccessKeyCreated, ActionIAMAccessKeyEnabled, ActionIAMAccessKeyDisabled, ActionIAMAccessKeyDeleted} {
		event.Action = action
		if _, _, err := CanonicalizeEvent(SourceIAM, event); err != nil {
			t.Fatal("valid AccessKey fact rejected", err)
		}
		for name, change := range map[string]func(*Event){
			"no decision":      func(e *Event) { e.IAMDecisionID = "" },
			"no tenant":        func(e *Event) { e.TenantID = "" },
			"platform":         func(e *Event) { e.TenantID = ""; e.InstallationID = "installation-a" },
			"target namespace": func(e *Event) { e.Target.TenantID = e.TenantID },
			"user target":      func(e *Event) { e.Target.Kind = TargetUser },
			"failure":          func(e *Event) { e.Result = ResultDenied },
			"system":           func(e *Event) { e.Actor = ActorReference{Type: ActorSystem, ID: "iam"} },
			"service":          func(e *Event) { e.Actor = ActorReference{Type: ActorServiceAccount, ID: "service-a"} },
			"role": func(e *Event) {
				e.Actor = ActorReference{Type: ActorRole, ID: "role-a", RoleSession: &RoleSessionReference{SessionID: "session-a", SourceUserID: "user-a"}}
			},
		} {
			t.Run(string(action)+"/"+name, func(t *testing.T) {
				changed := event
				change(&changed)
				if _, _, err := CanonicalizeEvent(SourceIAM, changed); err == nil {
					t.Fatal("AccessKey fact widened the closed source/actor/target contract")
				}
			})
		}
		if _, _, err := CanonicalizeEvent(SourcePaaS, event); err == nil {
			t.Fatal("another producer asserted IAM credential lifecycle")
		}
	}
}

func TestAdministratorRoleSessionRevocationRequiresItsOwnDecision(t *testing.T) {
	event := Event{APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-admin-revoke", TenantID: "account-a",
		Actor: ActorReference{Type: ActorUser, ID: "admin-a"}, IAMDecisionID: "decision-a", Action: ActionIAMRoleSessionAdminRevoked,
		Target: TargetReference{Kind: TargetRoleSession, ID: "session-a"}, Result: ResultSucceeded,
		RequestID: "request-a", CorrelationID: "request-a", RequestDigest: "sha256:" + strings.Repeat("1", 64),
		OccurredAt: time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)}
	if _, _, err := CanonicalizeEvent(SourceIAM, event); err != nil {
		t.Fatal("valid administrator fact rejected", err)
	}
	for name, change := range map[string]func(*Event){
		"no decision": func(e *Event) { e.IAMDecisionID = "" },
		"system":      func(e *Event) { e.Actor = ActorReference{Type: ActorSystem, ID: "iam"} },
		"service":     func(e *Event) { e.Actor = ActorReference{Type: ActorServiceAccount, ID: "service-a"} },
		"role": func(e *Event) {
			e.Actor = ActorReference{Type: ActorRole, ID: "role-a", RoleSession: &RoleSessionReference{SessionID: "session-a", SourceUserID: "user-a"}}
		},
		"wrong target":  func(e *Event) { e.Target.Kind = TargetRole },
		"target tenant": func(e *Event) { e.Target.TenantID = "account-a" },
		"installation":  func(e *Event) { e.TenantID = ""; e.InstallationID = "installation-a" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := event
			change(&copy)
			if _, _, err := CanonicalizeEvent(SourceIAM, copy); err == nil {
				t.Fatal("administrator fact widened authority")
			}
		})
	}
	event.Action, event.IAMDecisionID = ActionIAMRoleSessionRevoked, ""
	if _, _, err := CanonicalizeEvent(SourceIAM, event); err != nil {
		t.Fatal("source self-revocation gained a decision requirement", err)
	}
}

func TestLegacyOrganizationCreationRetainsItsTenantCanonicalContract(t *testing.T) {
	event := Event{
		APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-legacy-organization",
		TenantID: "organization-original", Actor: ActorReference{Type: ActorUser, ID: "principal-original"},
		IAMDecisionID: "decision-original", Action: ActionIAMOrganizationCreated,
		Target: TargetReference{Kind: TargetOrganization, ID: "organization-created"}, Result: ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("1", 64), RequestID: "request-original",
		CorrelationID: "request-original", OccurredAt: time.Date(2026, 8, 25, 3, 4, 5, 0, time.UTC),
	}
	const expected = `{"canonicalVersion":"matrix.audit.canonical-event.v1","source":"IAM","event":{"apiVersion":"audit.matrix.xiak.com/v1","kind":"AuditEvent","eventId":"event-legacy-organization","tenantId":"organization-original","actor":{"type":"USER","id":"principal-original"},"iamDecisionId":"decision-original","action":"iam.organization.created","target":{"kind":"ORGANIZATION","id":"organization-created"},"result":"SUCCEEDED","requestDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","requestId":"request-original","correlationId":"request-original","occurredAt":"2026-08-25T03:04:05.000000Z"}}`
	document, digest, err := CanonicalizeEvent(SourceIAM, event)
	expectedDigest := sha256.Sum256([]byte(expected))
	if err != nil || document != expected || digest != "sha256:"+hex.EncodeToString(expectedDigest[:]) {
		t.Fatal("legacy organization fact changed its canonical contract")
	}
	event.TenantID, event.InstallationID = "", "installation-original"
	if _, _, err := CanonicalizeEvent(SourceIAM, event); err == nil {
		t.Fatal("legacy organization action was reclassified as a platform lifecycle fact")
	}
}

func TestAuditExamplesPassDomainValidation(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"PaaS event", validAuditEvent("examples/event-paas.json", SourcePaaS)},
		{"denied IAM event", validAuditEvent("examples/event-iam-denied.json", SourceIAM)},
		{"ingestion result", validAuditExample[IngestionResult]("examples/ingestion-result.json", ValidateIngestionResult)},
		{"query request", validAuditExample[QueryRecordsRequest]("examples/query-records-request.json", ValidateQueryRecordsRequest)},
		{"record page", validAuditExample[RecordPage]("examples/record-page.json", ValidateRecordPage)},
		{"verify request", validAuditExample[VerifyChainRequest]("examples/verify-chain-request.json", ValidateVerifyChainRequest)},
		{"chain verification", validAuditExample[ChainVerification]("examples/chain-verification.json", ValidateChainVerification)},
		{"readiness", validAuditExample[Readiness]("examples/readiness.json", ValidateReadiness)},
		{"problem", validAuditExample[Problem]("examples/problem.json", ValidateProblem)},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestAuditInputCannotForgeSourceOrQueryTenant(t *testing.T) {
	event := `{"apiVersion":"audit.matrix.xiak.com/v1","kind":"AuditEvent","source":"IAM","eventId":"event-example","tenantId":"organization-example","actor":{"type":"SYSTEM","id":"paas"},"iamDecisionId":"decision-example","action":"paas.deployment.created","target":{"kind":"DEPLOYMENT","id":"deployment-example"},"result":"ACCEPTED","requestDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","requestId":"request-example","correlationId":"correlation-example","operationId":"operation-example","occurredAt":"2026-08-25T03:04:05.000000Z"}`
	var decodedEvent Event
	if err := DecodeRequest(strings.NewReader(event), &decodedEvent); !errors.Is(err, contractjson.ErrUnknownField) {
		t.Fatalf("forged event source error = %v, want unknown field", err)
	}

	for name, query := range map[string]string{
		"tenant":  `{"pageSize":10,"tenantId":"organization-forged"}`,
		"subject": `{"pageSize":10,"subject":{"type":"USER","id":"principal-forged"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var request QueryRecordsRequest
			if err := DecodeRequest(strings.NewReader(query), &request); !errors.Is(err, contractjson.ErrUnknownField) {
				t.Fatalf("forged query %s error = %v, want unknown field", name, err)
			}
		})
	}

	var request QueryRecordsRequest
	if err := DecodeRequest(strings.NewReader(`{"pageSize":10,"pageSize":20}`), &request); !errors.Is(err, contractjson.ErrDuplicateField) {
		t.Fatalf("duplicate query field error = %v, want duplicate field", err)
	}
	if err := DecodeRequest(strings.NewReader(`{"pageSize":10} {}`), &request); !errors.Is(err, contractjson.ErrTrailingData) {
		t.Fatalf("trailing query document error = %v, want trailing data", err)
	}
	oversized := `{"pageSize":10,"cursor":"` + strings.Repeat("A", int(MaxRequestBytes)) + `"}`
	if err := DecodeRequest(strings.NewReader(oversized), &request); !errors.Is(err, contractjson.ErrDocumentTooLarge) {
		t.Fatalf("oversized query error = %v, want document too large", err)
	}
}

func TestAuditActionCatalogIsClosedAndSourceBound(t *testing.T) {
	for _, action := range AllActions() {
		contract, known := ContractForAction(action)
		if !known || contract.Source == "" || contract.Target == "" || len(contract.Results) == 0 {
			t.Fatalf("action %q has an incomplete contract: %#v", action, contract)
		}
		event := Event{
			APIVersion: APIVersion, Kind: "AuditEvent", EventID: "event-example",
			TenantID: "organization-example", Actor: ActorReference{Type: ActorSystem, ID: "system-example"},
			Action: action, Target: TargetReference{Kind: contract.Target, ID: "target-example"},
			Result:        contract.Results[0],
			RequestDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			RequestID:     "request-example", CorrelationID: "correlation-example",
			OccurredAt: time.Date(2026, 8, 25, 3, 4, 5, 0, time.UTC),
		}
		if contract.IAMDecisionRequired {
			event.IAMDecisionID = "decision-example"
		}
		if action == ActionIAMAuthorizationDecided {
			event.Target.ID = string(event.IAMDecisionID)
		}
		if contract.OperationRequired {
			event.OperationID = "operation-example"
		}
		if contract.PlatformOnly {
			event.TenantID, event.InstallationID = "", "installation-example"
			event.Actor.Type = ActorUser
		}
		if contract.PlatformSystemActorID != "" {
			event.Actor = ActorReference{Type: ActorSystem, ID: contract.PlatformSystemActorID}
		}
		if contract.TargetMatchesInstallation {
			event.Target.ID = event.InstallationID
		}
		if contract.UserActorRequired {
			event.Actor.Type = ActorUser
		}
		if action == ActionIAMNotificationContactVerificationStarted || action == ActionIAMNotificationContactVerified {
			event.Target.ID = string(event.Actor.ID)
		}
		if contract.RoleActorRequired {
			event.Actor = ActorReference{Type: ActorRole, ID: "role-example",
				RoleSession: &RoleSessionReference{SessionID: event.Target.ID, SourceUserID: "source-example"}}
		}
		if action == ActionIAMAccountRootCredentialsRecovered || action == ActionIAMTenantAdministratorRecovered || action == ActionIAMInstallationPrimaryCredentialsRecovered {
			event.Target.TenantID = "organization-recovered"
		}
		if err := ValidateEventForSource(contract.Source, event); err != nil {
			t.Fatalf("valid action contract %q rejected: %v", action, err)
		}
		if contract.PlatformSystemActorID != "" {
			for _, mutation := range []func(*Event){
				func(candidate *Event) { candidate.Actor.Type = ActorUser },
				func(candidate *Event) { candidate.Actor.ID = "another-system" },
			} {
				forged := event
				mutation(&forged)
				if ValidateEvent(forged) == nil {
					t.Fatalf("action %q accepted a forged platform system actor", action)
				}
			}
		}
		if contract.TargetMatchesInstallation {
			forged := event
			forged.Target.ID = "another-installation"
			if ValidateEvent(forged) == nil {
				t.Fatalf("action %q accepted another installation target", action)
			}
		}
		if contract.RoleActorRequired {
			for _, actorType := range []ActorType{ActorUser, ActorSystem, ActorServiceAccount} {
				forged := event
				forged.Actor = ActorReference{Type: actorType, ID: event.Actor.ID}
				if ValidateEvent(forged) == nil {
					t.Fatal("role exit accepted another actor type")
				}
			}
		}
		if contract.UserActorRequired {
			for _, actorType := range []ActorType{ActorSystem, ActorServiceAccount} {
				forged := event
				forged.Actor.Type = actorType
				if ValidateEvent(forged) == nil {
					t.Fatal("attachment fact accepted a non-USER actor")
				}
			}
		}
		if err := ValidateEventForSource(otherAuditSource(contract.Source), event); err == nil {
			t.Fatalf("action %q accepted a forged source", action)
		}
		wrongNamespace := event
		if action == ActionIAMAccountRootCredentialsRecovered || action == ActionIAMTenantAdministratorRecovered || action == ActionIAMInstallationPrimaryCredentialsRecovered {
			wrongNamespace.Target.TenantID = ""
		} else {
			wrongNamespace.Target.TenantID = "organization-forged"
		}
		if ValidateEvent(wrongNamespace) == nil {
			t.Fatalf("action %q accepted an invalid target tenant namespace", action)
		}
		wrongAuthority := event
		if contract.PlatformOnly {
			wrongAuthority.TenantID, wrongAuthority.InstallationID = TenantID(event.InstallationID), ""
		} else {
			wrongAuthority.TenantID, wrongAuthority.InstallationID = "", string(event.TenantID)
		}
		if ValidateEvent(wrongAuthority) == nil {
			t.Fatalf("action %q accepted another authority namespace", action)
		}
	}
	if _, known := ContractForAction(Action("audit.unregistered")); known {
		t.Fatal("unregistered Audit action has a contract")
	}
}

func TestAuditWireTypesHaveNoArbitraryPayloadEscapeHatch(t *testing.T) {
	roots := []reflect.Type{
		reflect.TypeOf(Event{}), reflect.TypeOf(AuditRecord{}), reflect.TypeOf(IngestionResult{}),
		reflect.TypeOf(QueryRecordsRequest{}), reflect.TypeOf(RecordPage{}),
		reflect.TypeOf(VerifyChainRequest{}), reflect.TypeOf(ChainVerification{}),
		reflect.TypeOf(VerifyInstallationRequest{}), reflect.TypeOf(InstallationVerification{}),
	}
	seen := map[reflect.Type]bool{}
	for _, root := range roots {
		assertClosedAuditType(t, root, seen)
	}
}

func TestAuditOpenAPISecurityDerivesSourceAndTenantFromCredentials(t *testing.T) {
	document := loadAuditOpenAPI(t)
	paths := mustAuditObject(t, document["paths"], "paths")
	assertAuditSecurity(t, paths, "/v1/events", "ServiceCredential")
	assertAuditSecurity(t, paths, "/v1/records:query", "UserSession")
	assertAuditSecurity(t, paths, "/v1/integrity:verify", "UserSession")
	assertAuditSecurity(t, paths, "/v1/platform/records:query", "UserSession")
	assertAuditSecurity(t, paths, "/v1/platform/integrity:verify", "UserSession")
	assertAuditSecurity(t, paths, "/v1/installation:verify", "InstallationVerifier")

	schemas := auditOpenAPISchemas(t, document)
	eventProperties := mustAuditObject(t, mustAuditObject(t, schemas["Event"], "event schema")["properties"], "event properties")
	if _, exists := eventProperties["source"]; exists {
		t.Fatal("Audit event request exposes a caller-selected source")
	}
	for _, schemaName := range []string{"QueryRecordsRequest", "VerifyChainRequest"} {
		properties := mustAuditObject(t, mustAuditObject(t, schemas[schemaName], schemaName)["properties"], schemaName+" properties")
		for _, forbidden := range []string{"tenantId", "installationId", "organizationId", "subject", "source"} {
			if _, exists := properties[forbidden]; exists {
				t.Fatalf("%s exposes authority selector %q", schemaName, forbidden)
			}
		}
	}
	assertNoAuditAuthorityHeader(t, document)
}

func validAuditEvent(path string, source Source) func(*testing.T) {
	return func(t *testing.T) {
		value := decodeAuditExample[Event](t, path)
		if err := ValidateEventForSource(source, value); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
	}
}

func validAuditExample[T any](path string, validate func(T) error) func(*testing.T) {
	return func(t *testing.T) {
		value := decodeAuditExample[T](t, path)
		if err := validate(value); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
	}
}

func otherAuditSource(source Source) Source {
	if source == SourceIAM {
		return SourcePaaS
	}
	return SourceIAM
}

func assertClosedAuditType(t *testing.T, contract reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for contract.Kind() == reflect.Pointer || contract.Kind() == reflect.Slice {
		if contract.Kind() == reflect.Slice && contract.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("Audit wire contract contains raw bytes: %s", contract)
		}
		contract = contract.Elem()
	}
	if contract == reflect.TypeOf(time.Time{}) || seen[contract] {
		return
	}
	seen[contract] = true
	switch contract.Kind() {
	case reflect.Map, reflect.Interface:
		t.Fatalf("Audit wire contract contains arbitrary %s: %s", contract.Kind(), contract)
	case reflect.Struct:
		for index := range contract.NumField() {
			field := contract.Field(index)
			jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
			normalized := strings.ToLower(jsonName)
			for _, forbidden := range []string{"attributes", "body", "payload", "credential", "password", "secret", "native", "path"} {
				if normalized == forbidden || strings.HasSuffix(normalized, forbidden) {
					t.Fatalf("Audit wire contract contains forbidden field %s.%s", contract, field.Name)
				}
			}
			assertClosedAuditType(t, field.Type, seen)
		}
	}
}

func assertAuditSecurity(t *testing.T, paths map[string]any, path, scheme string) {
	t.Helper()
	pathObject := mustAuditObject(t, paths[path], path)
	operation := mustAuditObject(t, pathObject["post"], path+" operation")
	security, ok := operation["security"].([]any)
	if !ok || len(security) != 1 {
		t.Fatalf("%s security = %#v, want one requirement", path, operation["security"])
	}
	requirement := mustAuditObject(t, security[0], path+" security requirement")
	if len(requirement) != 1 || requirement[scheme] == nil {
		t.Fatalf("%s security = %#v, want only %s", path, requirement, scheme)
	}
}

func assertNoAuditAuthorityHeader(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			assertNoAuditAuthorityHeader(t, item)
		}
	case map[string]any:
		if typed["in"] == "header" {
			name, _ := typed["name"].(string)
			normalized := strings.ToLower(name)
			if strings.Contains(normalized, "tenant") || strings.Contains(normalized, "organization") ||
				strings.Contains(normalized, "source") || strings.Contains(normalized, "subject") {
				t.Fatalf("Audit OpenAPI exposes authority selector header %q", name)
			}
		}
		for _, child := range typed {
			assertNoAuditAuthorityHeader(t, child)
		}
	}
}
