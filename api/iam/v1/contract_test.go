package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

var removedBuiltinRoleNames = []string{
	"ORGANIZATION_ADMIN",
	"PLATFORM_OPERATOR",
	"PAAS_DEVELOPER",
	"PAAS_VIEWER",
	"AUDIT_READER",
	"INSTALLATION_VERIFIER",
}

func TestAuthorizationProfileTargetsUseExplicitDeclaredModes(t *testing.T) {
	for _, profile := range AllAuthorizationProfiles() {
		before, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		reference := AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
		for _, declared := range profile.Actions {
			t.Run(string(declared.Action), func(t *testing.T) {
				for _, candidate := range []AuthorizationResourceShape{
					{Mode: AuthorizationResourceInstance},
					{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList},
					{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate},
					{Mode: AuthorizationResourceCollection},
					{Mode: AuthorizationResourceInstance, CollectionUsage: AuthorizationCollectionList},
					{Mode: "FILTERED", CollectionUsage: AuthorizationCollectionList},
					{},
				} {
					for _, id := range []string{"real-instance", "collection", "records", "chain", ""} {
						want := false
						for _, shape := range declared.ResourceShapes {
							if shape.Mode == candidate.Mode && shape.CollectionUsage == candidate.CollectionUsage {
								want = id != "" && (shape.Mode == AuthorizationResourceInstance || id == "collection")
							}
						}
						resource := ResourceReference{Kind: declared.ResourceKind, ID: id}
						actual := CheckAuthorizationProfileTarget(profile, reference, declared.Action, resource, candidate.Mode, candidate.CollectionUsage)
						if (actual == nil) != want {
							t.Fatalf("mode=%s usage=%s id=%q accepted=%t want=%t", candidate.Mode, candidate.CollectionUsage, id, actual == nil, want)
						}
						resource.Kind = ResourceKind("UNDECLARED")
						if CheckAuthorizationProfileTarget(profile, reference, declared.Action, resource, candidate.Mode, candidate.CollectionUsage) == nil {
							t.Fatal("wrong resource kind borrowed a declared mode")
						}
					}
				}
				shape := declared.ResourceShapes[0]
				resource := ResourceReference{Kind: declared.ResourceKind, ID: "collection"}
				for _, wrong := range []AuthorizationProfileReference{
					{},
					{Product: "other-product", Revision: reference.Revision, ContentDigest: reference.ContentDigest},
					{Product: reference.Product, Revision: reference.Revision + 1, ContentDigest: reference.ContentDigest},
					{Product: reference.Product, Revision: reference.Revision, ContentDigest: "sha256:" + strings.Repeat("0", 64)},
				} {
					if CheckAuthorizationProfileTarget(profile, wrong, declared.Action, resource, shape.Mode, shape.CollectionUsage) == nil {
						t.Fatal("target admitted without its exact declaration")
					}
				}
				if CheckAuthorizationProfileTarget(profile, reference, "unregistered.inspect", resource, shape.Mode, shape.CollectionUsage) == nil {
					t.Fatal("unregistered action borrowed a known resource shape")
				}
			})
		}
		after, afterDigest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil || before != after || digest != afterDigest {
			t.Fatal("target validation modified immutable declaration content")
		}
	}
}

func TestProfileBoundAuthorizationRequestAndResponse(t *testing.T) {
	request, err := NewAuthorizationRequest(ActionPaaSApplicationRead, ResourceReference{Kind: ResourceApplication, ID: "collection"}, AuthorizationResourceInstance, "", "request-one", "correlation-one")
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []bool{false, true} {
		decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-one",
			Allowed: allowed, Reason: DecisionDenied, Action: request.Action, Resource: request.Resource,
			Profile: &request.Profile, ResourceMode: request.ResourceMode, RequestID: request.RequestID,
			CorrelationID: request.CorrelationID, DecidedAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)}
		if allowed {
			decision.Reason, decision.TenantID = DecisionAllowed, "account-one"
			decision.Subject = &Subject{Type: PrincipalUser, ID: "user-one"}
		}
		if err := CheckAuthorizationDecisionForRequest(decision, request); err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*AuthorizationDecision){
			"profile missing": func(value *AuthorizationDecision) { value.Profile = nil },
			"profile version": func(value *AuthorizationDecision) {
				copy := *value.Profile
				copy.Revision++
				value.Profile = &copy
			},
			"resource":    func(value *AuthorizationDecision) { value.Resource.ID = "another-instance" },
			"mode":        func(value *AuthorizationDecision) { value.ResourceMode = AuthorizationResourceCollection },
			"usage":       func(value *AuthorizationDecision) { value.CollectionUsage = AuthorizationCollectionList },
			"request":     func(value *AuthorizationDecision) { value.RequestID = "other-request" },
			"correlation": func(value *AuthorizationDecision) { value.CorrelationID = "other-correlation" },
		} {
			t.Run(fmt.Sprintf("allowed=%t/%s", allowed, name), func(t *testing.T) {
				changed := decision
				mutate(&changed)
				if CheckAuthorizationDecisionForRequest(changed, request) == nil {
					t.Fatal("response did not bind the full original request")
				}
			})
		}
		legacy := decision
		legacy.Profile, legacy.ResourceMode, legacy.CollectionUsage, legacy.CorrelationID = nil, "", "", ""
		if ValidateAuthorizationDecision(legacy) == nil || ValidateLegacyAuthorizationDecision(legacy) != nil {
			t.Fatal("legacy evidence was either admitted online or lost its explicit read-only validator")
		}
		legacy.CorrelationID = request.CorrelationID
		if ValidateLegacyAuthorizationDecision(legacy) == nil {
			t.Fatal("partial new fields were admitted as legacy")
		}
		encoded, _ := json.Marshal(decision)
		var fields map[string]json.RawMessage
		if json.Unmarshal(encoded, &fields) != nil {
			t.Fatal("decode response fixture")
		}
		for _, field := range []string{"profile", "resourceMode", "correlationId"} {
			changed := make(map[string]json.RawMessage, len(fields))
			for key, value := range fields {
				changed[key] = value
			}
			delete(changed, field)
			raw, _ := json.Marshal(changed)
			var parsed AuthorizationDecision
			if DecodeRequest(bytes.NewReader(raw), &parsed) == nil && ValidateAuthorizationDecision(parsed) == nil {
				t.Fatalf("current response accepted missing %s", field)
			}
		}
	}
	for _, mode := range []AuthorizationResourceMode{"", "BATCH", AuthorizationResourceCollection} {
		if _, err := NewAuthorizationRequest(request.Action, request.Resource, mode, "", request.RequestID, request.CorrelationID); err == nil {
			t.Fatal("constructor inferred a mode or accepted undeclared usage")
		}
	}
}

func TestAuthorizationEncodingRejectsPartialAndPresentEmptyBindings(t *testing.T) {
	for _, shape := range []AuthorizationResourceShape{
		{Mode: AuthorizationResourceInstance},
		{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList},
	} {
		request, err := NewAuthorizationRequest(ActionIAMAccountRead, ResourceReference{Kind: ResourceAccount, ID: "collection"}, shape.Mode, shape.CollectionUsage, "request-encoding", "correlation-encoding")
		if err != nil {
			t.Fatal(err)
		}
		decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-encoding", Reason: DecisionDenied,
			Action: request.Action, Resource: request.Resource, Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage,
			RequestID: request.RequestID, CorrelationID: request.CorrelationID, DecidedAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)}
		for _, input := range []any{request, decision} {
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"profile", "resourceMode", "correlationId", "collectionUsage"} {
				for _, raw := range []json.RawMessage{json.RawMessage("null"), json.RawMessage(`""`)} {
					var document map[string]json.RawMessage
					if json.Unmarshal(encoded, &document) != nil {
						t.Fatal("invalid baseline")
					}
					document[key] = raw
					changed, _ := json.Marshal(document)
					var err error
					if _, ok := input.(AuthorizationRequest); ok {
						var decoded AuthorizationRequest
						err = DecodeRequest(bytes.NewReader(changed), &decoded)
						if err == nil {
							err = ValidateAuthorizationRequest(decoded)
						}
					} else {
						var decoded AuthorizationDecision
						err = DecodeRequest(bytes.NewReader(changed), &decoded)
						if err == nil {
							err = ValidateAuthorizationDecision(decoded)
						}
					}
					if err == nil {
						t.Fatalf("%T/%s accepted %s=%s", input, shape.Mode, key, raw)
					}
				}
			}
		}
	}
}

func TestHistoricalDecisionProfileDoesNotBorrowCurrentHead(t *testing.T) {
	profile, _ := LookupAuthorizationProfile(ProductAudit)
	for index := range profile.Actions {
		profile.Actions[index].ResourceShapes = []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}
	}
	profile.Revision++
	_, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "historical-one",
		Reason: DecisionDenied, Action: ActionAuditIntegrityVerify, Resource: ResourceReference{Kind: ResourceAuditChain, ID: "frozen-instance"},
		Profile:      &AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest},
		ResourceMode: AuthorizationResourceInstance, RequestID: "request-one", CorrelationID: "correlation-one",
		DecidedAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)}
	if ValidateAuthorizationDecisionForProfile(decision, profile) != nil || ValidateAuthorizationDecision(decision) == nil || ValidateLegacyAuthorizationDecision(decision) == nil {
		t.Fatal("frozen evidence borrowed current collection meaning or became legacy")
	}
	current, _ := LookupAuthorizationProfile(ProductAudit)
	if ValidateAuthorizationDecisionForProfile(decision, current) == nil {
		t.Fatal("historical validator selected current head instead of exact supplied content")
	}
}

func TestPaaSProfileDeclaresCompletePlatformProduct(t *testing.T) {
	profile, found := LookupAuthorizationProfile(ProductPaaS)
	if !found || profile.Revision != 1 {
		t.Fatal("unpublished product drafts must converge to one complete first profile")
	}
	expected := map[Action]struct {
		kind       ResourceKind
		collection AuthorizationCollectionUsage
		instance   bool
		result     ResourceKind
	}{
		"paas.execution-pool.create":      {ResourceExecutionPool, "", true, ResourceExecutionPool},
		"paas.execution-pool.read":        {ResourceExecutionPool, AuthorizationCollectionList, true, ""},
		"paas.execution-target.register":  {ResourceExecutionTarget, "", true, ResourceExecutionTarget},
		"paas.execution-target.read":      {ResourceExecutionTarget, AuthorizationCollectionList, true, ""},
		"paas.execution-target.drain":     {ResourceExecutionTarget, "", true, ""},
		"paas.execution-target.activate":  {ResourceExecutionTarget, "", true, ""},
		"paas.execution-target.remove":    {ResourceExecutionTarget, "", true, ""},
		"paas.node-enrollment.create":     {"NODE_ENROLLMENT", AuthorizationCollectionCreate, false, ResourceExecutionTarget},
		"paas.node-enrollment.read":       {"NODE_ENROLLMENT", "", true, ""},
		"paas.node-enrollment.revoke":     {"NODE_ENROLLMENT", "", true, ""},
		"paas.node-enrollment.regenerate": {"NODE_ENROLLMENT", "", true, ""},
		"paas.platform-operation.read":    {ResourceOperation, "", true, ""},
	}
	for _, action := range profile.Actions {
		if action.Scope != AuthorityScopeInstallation {
			continue
		}
		want, ok := expected[action.Action]
		if !ok || action.ResourceKind != want.kind || action.ResultResourceKind != want.result || len(action.Conditions) != 0 {
			t.Fatalf("unexpected platform declaration: %s", action.Action)
		}
		instance, collection := false, AuthorizationCollectionUsage("")
		for _, shape := range action.ResourceShapes {
			if shape.PrefixAllowed {
				t.Fatal("platform action gained prefix permission")
			}
			if shape.Mode == AuthorizationResourceInstance {
				instance = true
			} else {
				collection = shape.CollectionUsage
			}
		}
		definition, known := LookupActionDefinition(action.Action)
		if !known || definition.CallingService != ServicePaaS || definition.ResourceKind != want.kind ||
			definition.AuthorityScope != AuthorityScopeInstallation || instance != want.instance || collection != want.collection {
			t.Fatalf("platform request shape or caller drift: %s", action.Action)
		}
		delete(expected, action.Action)
	}
	if len(expected) != 0 {
		t.Fatalf("platform product is missing declarations: %v", expected)
	}
	_, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil || CheckAuthorizationProfileReference(profile, AuthorizationProfileReference{Product: ProductPaaS, Revision: profile.Revision + 1, ContentDigest: digest}) == nil {
		t.Fatal("numerically newer revision was treated as an exact reference")
	}
}

func TestAuditProfileDeclaresAuthorityWideReadAndVerification(t *testing.T) {
	profile, found := LookupAuthorizationProfile(ProductAudit)
	if !found || profile.Revision != 1 || profile.CallingService != ServiceAudit {
		t.Fatal("invalid first Audit product declaration")
	}
	expected := map[Action]struct {
		kind  ResourceKind
		scope AuthorityScope
	}{
		ActionAuditRecordRead:              {ResourceAuditRecord, AuthorityScopeTenant},
		ActionAuditIntegrityVerify:         {ResourceAuditChain, AuthorityScopeTenant},
		ActionAuditPlatformRecordRead:      {ResourceAuditRecord, AuthorityScopeInstallation},
		ActionAuditPlatformIntegrityVerify: {ResourceAuditChain, AuthorityScopeInstallation},
	}
	for _, action := range profile.Actions {
		want, exists := expected[action.Action]
		if !exists || action.ResourceKind != want.kind || action.Scope != want.scope || action.ResultResourceKind != "" ||
			len(action.ResourceShapes) != 1 || action.ResourceShapes[0] != (AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}) {
			t.Fatal("Audit complete-chain verification cannot select a caller-chosen instance")
		}
		delete(expected, action.Action)
	}
	if len(expected) != 0 {
		t.Fatal("Audit declaration omitted an authority-wide read action")
	}
}

func TestProductProfilesOwnCurrentAdmissionAndDoNotExposeMutableState(t *testing.T) {
	profiles := AllAuthorizationProfiles()
	seen := map[Action]bool{}
	for _, profile := range profiles {
		document, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range profile.Actions {
			if seen[declaration.Action] {
				t.Fatal("action belongs to multiple products")
			}
			seen[declaration.Action] = true
			definition, known := LookupActionDefinition(declaration.Action)
			if !known || definition.Product != profile.Product || definition.CallingService != profile.CallingService || definition.ResourceKind != declaration.ResourceKind || definition.AuthorityScope != declaration.Scope {
				t.Fatal("current admission diverged from the owning profile")
			}
			for _, condition := range declaration.Conditions {
				actual, known := LookupActionConditionDefinition(declaration.Action, condition.Key)
				if !known || actual.ValueType != condition.ValueType || actual.Source != condition.Source {
					t.Fatal("condition capability diverged from its profile")
				}
			}
		}
		copy, known := LookupAuthorizationProfile(profile.Product)
		if !known {
			t.Fatal("declared product cannot be read")
		}
		copy.CallingService = "FORGED"
		copy.Actions[0].ResourceShapes[0].Mode = "FORGED"
		copy.Actions[0].Action = "forged.action"
		for index := range copy.Actions {
			if len(copy.Actions[index].Conditions) > 0 {
				copy.Actions[index].Conditions[0].Source = "CALLER"
			}
		}
		fresh, known := LookupAuthorizationProfile(profile.Product)
		freshDocument, freshDigest, err := CanonicalizeAuthorizationProfile(fresh)
		if !known || err != nil || freshDocument != document || freshDigest != digest {
			t.Fatal("lookup exposed mutable catalog storage", err)
		}
	}
	for _, action := range AllActions() {
		if !seen[action] {
			t.Fatal("current action lacks a product declaration", action)
		}
	}
	if len(seen) != len(AllActions()) {
		t.Fatal("declaration includes an unregistered action")
	}
	profiles[0].Actions[0].Action = "forged.action"
	if actual, known := LookupActionDefinition(ActionIAMAccountCreate); !known || actual.Action != ActionIAMAccountCreate {
		t.Fatal("returned profile changed runtime admission")
	}
	if _, known := LookupAuthorizationProfile("not-registered"); known {
		t.Fatal("unknown product was guessed")
	}
}

func TestProductProfilesDeclareParentInstanceAndCollectionResults(t *testing.T) {
	for _, item := range []struct {
		action           Action
		resource, result ResourceKind
		modes            []AuthorizationResourceShape
	}{
		{ActionIAMUserCreate, ResourceAccount, ResourceUser, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionIAMGroupCreate, ResourceAccount, ResourceGroup, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionIAMPolicyCreate, ResourceAccount, ResourcePolicy, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionIAMGroupMembershipCreate, ResourceGroup, ResourceGroupMembership, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionIAMAccountRead, ResourceAccount, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}},
		{ActionPaaSApplicationCreate, ResourceApplication, ResourceApplication, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}},
		{ActionPaaSApplicationRead, ResourceApplication, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}},
		{ActionPaaSExecutionPoolCreate, ResourceExecutionPool, ResourceExecutionPool, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionPaaSExecutionTargetRegister, ResourceExecutionTarget, ResourceExecutionTarget, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionPaaSExecutionPoolRead, ResourceExecutionPool, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}},
		{ActionPaaSExecutionTargetRead, ResourceExecutionTarget, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}},
		{ActionManagedServiceOfferingRead, ResourceServiceOffering, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}},
	} {
		t.Run(string(item.action), func(t *testing.T) {
			definition, known := LookupActionDefinition(item.action)
			if !known {
				t.Fatal("missing current action")
			}
			profile, known := LookupAuthorizationProfile(definition.Product)
			if !known {
				t.Fatal("missing product")
			}
			for _, action := range profile.Actions {
				if action.Action != item.action {
					continue
				}
				if action.ResourceKind != item.resource || action.ResultResourceKind != item.result || len(action.ResourceShapes) != len(item.modes) {
					t.Fatal("incorrect authorization versus successful resource mapping", action)
				}
				for _, want := range item.modes {
					found := false
					for _, got := range action.ResourceShapes {
						if want == got {
							found = true
						}
					}
					if !found {
						t.Fatal("missing proved target shape", want)
					}
				}
				return
			}
			t.Fatal("action absent from declared product")
		})
	}
	// A child/result kind is not an alternative authorization target.
	request, err := NewAuthorizationRequest(ActionIAMUserCreate, ResourceReference{Kind: ResourceAccount, ID: "account-one"}, AuthorizationResourceInstance, "", "request-one", "request-one")
	if err != nil || ValidateAuthorizationRequest(request) != nil {
		t.Fatal(err)
	}
	request.Resource = ResourceReference{Kind: ResourceUser, ID: "user-child"}
	if ValidateAuthorizationRequest(request) == nil {
		t.Fatal("result resource widened parent authorization")
	}
}

func TestProductProjectionIsIndependentOfProductName(t *testing.T) {
	profile := authorizationProfileFixture()
	profile.Product, profile.CallingService, profile.Actions[0].Action = "observability", "OBSERVABILITY", "observability.sample.inspect"
	definitions := projectActionDefinitions([]AuthorizationProfile{profile})
	if len(definitions) != 1 || definitions[0].Product != profile.Product || definitions[0].CallingService != profile.CallingService {
		t.Fatal("generic product projection requires a product-name branch")
	}
	if _, known := LookupActionDefinition(profile.Actions[0].Action); known {
		t.Fatal("pure projection modified the active registry")
	}
	for name, profiles := range map[string][]AuthorizationProfile{
		"duplicate product": {profile, profile},
		"same revision other content": {profile, func() AuthorizationProfile {
			v := cloneAuthorizationProfile(profile)
			v.Actions[0].ResourceKind = "OTHER"
			return v
		}()},
		"foreign namespace": {func() AuthorizationProfile {
			v := cloneAuthorizationProfile(profile)
			v.Actions[0].Action = ActionIAMUserCreate
			return v
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid compiled registry did not fail closed")
				}
			}()
			projectActionDefinitions(profiles)
		})
	}
}

func TestCurrentProfileCommitmentsDoNotTrustMutableCopies(t *testing.T) {
	for _, source := range AllAuthorizationProfiles() {
		canonical, digest, err := canonicalizeAuthorizationProfile(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []AuthorizationProfile{source, sourceProfileCommitments[source.Product].normalized} {
			actual, actualDigest, err := CanonicalizeAuthorizationProfile(value)
			if err != nil || actual != canonical || actualDigest != digest {
				t.Fatal("immutable source encoding differs from complete encoding")
			}
			changed := cloneAuthorizationProfile(value)
			changed.Actions[0].ResourceKind = "DIFFERENT_KIND"
			if CheckAuthorizationProfileReference(changed, AuthorizationProfileReference{Product: source.Product, Revision: source.Revision, ContentDigest: digest}) == nil {
				t.Fatal("nested content substitution reused a source commitment")
			}
		}
		for _, action := range source.Actions {
			for _, shape := range action.ResourceShapes {
				resource := ResourceReference{Kind: action.ResourceKind, ID: "target-one"}
				if shape.Mode == AuthorizationResourceCollection {
					resource.ID = "collection"
				}
				request, err := NewAuthorizationRequest(action.Action, resource, shape.Mode, shape.CollectionUsage, "request-one", "correlation-one")
				if err != nil || request.Profile != (AuthorizationProfileReference{Product: source.Product, Revision: source.Revision, ContentDigest: digest}) || ValidateAuthorizationRequest(request) != nil {
					t.Fatal("current request differs from its full source commitment")
				}
				variant := cloneAuthorizationProfile(source)
				variant.CallingService = "DIFFERENT_CALLER"
				if CheckAuthorizationProfileTarget(variant, request.Profile, request.Action, resource, shape.Mode, shape.CollectionUsage) == nil {
					t.Fatal("supplied same-tuple bytes bypassed full validation")
				}
				_, variantDigest, err := CanonicalizeAuthorizationProfile(variant)
				if err != nil {
					t.Fatal(err)
				}
				request.Profile.ContentDigest = variantDigest
				if ValidateAuthorizationRequest(request) == nil {
					t.Fatal("valid foreign content changed current source admission")
				}
			}
		}
	}
}

func authorizationProfileFixture() AuthorizationProfile {
	return AuthorizationProfile{
		APIVersion: APIVersion, Kind: "AuthorizationProfile", Product: ProductManagedService,
		Revision: 1, CallingService: ServicePaaS,
		Actions: []AuthorizationProfileAction{{
			Action: ActionManagedServiceOfferingRead, ResourceKind: ResourceServiceOffering, Scope: AuthorityScopeTenant,
			ResourceShapes: []AuthorizationResourceShape{
				{Mode: AuthorizationResourceInstance},
				{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList},
			},
			Conditions: []AuthorizationProfileCondition{
				{Key: ConditionIAMCurrentTime, ValueType: ConditionTime, Source: ConditionIAMTransactionTime},
				{Key: ConditionIAMAccountID, ValueType: ConditionString, Source: ConditionIAMIdentity},
			},
		}},
	}
}

func TestAuthorizationProfileCanonicalSetsAndExactReferences(t *testing.T) {
	profile := authorizationProfileFixture()
	profile.Actions = append(profile.Actions, AuthorizationProfileAction{
		Action: "managedservice.sample.create", ResourceKind: "SAMPLE", Scope: AuthorityScopeTenant,
		ResourceShapes: []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}, ResultResourceKind: "SAMPLE",
	})
	original, _ := json.Marshal(profile)
	document, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(profile)
	if !bytes.Equal(original, after) {
		t.Fatal("canonicalization mutated the caller's nested declaration")
	}
	profile.Actions[0], profile.Actions[1] = profile.Actions[1], profile.Actions[0]
	action := &profile.Actions[1]
	action.ResourceShapes[0], action.ResourceShapes[1] = action.ResourceShapes[1], action.ResourceShapes[0]
	action.Conditions[0], action.Conditions[1] = action.Conditions[1], action.Conditions[0]
	reordered, reorderedDigest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil || reordered != document || reorderedDigest != digest {
		t.Fatal("set order changed the immutable profile identity", err)
	}
	decoded, err := DecodeAuthorizationProfile(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	reference := AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
	if err := CheckAuthorizationProfileReference(decoded, reference); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AuthorizationProfileReference){
		"other product":    func(v *AuthorizationProfileReference) { v.Product = ProductPaaS },
		"newer revision":   func(v *AuthorizationProfileReference) { v.Revision++ },
		"missing digest":   func(v *AuthorizationProfileReference) { v.ContentDigest = "" },
		"different digest": func(v *AuthorizationProfileReference) { v.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			variant := reference
			change(&variant)
			if !errors.Is(CheckAuthorizationProfileReference(decoded, variant), ErrInvalidAuthorizationProfile) {
				t.Fatal("accepted a nonexact profile reference")
			}
		})
	}
}

func TestAuthorizationProfileDigestBindsAuthorizationSemantics(t *testing.T) {
	_, baseline, err := CanonicalizeAuthorizationProfile(authorizationProfileFixture())
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AuthorizationProfile){
		"product": func(v *AuthorizationProfile) {
			v.Product = "otherproduct"
			v.Actions[0].Action = "otherproduct.offering.read"
		},
		"revision":        func(v *AuthorizationProfile) { v.Revision++ },
		"calling service": func(v *AuthorizationProfile) { v.CallingService = "ANOTHER_SERVICE" },
		"action":          func(v *AuthorizationProfile) { v.Actions[0].Action = "managedservice.offering.inspect" },
		"resource kind":   func(v *AuthorizationProfile) { v.Actions[0].ResourceKind = "ANOTHER_KIND" },
		"scope": func(v *AuthorizationProfile) {
			v.Actions[0].Scope = AuthorityScopeInstallation
			v.Actions[0].Conditions = nil
		},
		"prefix":      func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[0].PrefixAllowed = true },
		"target mode": func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes = v.Actions[0].ResourceShapes[:1] },
		"collection semantics": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes[1].CollectionUsage = AuthorizationCollectionCreate
			v.Actions[0].ResultResourceKind = "RESULT"
		},
		"trusted conditions":  func(v *AuthorizationProfile) { v.Actions[0].Conditions = nil },
		"identity source key": func(v *AuthorizationProfile) { v.Actions[0].Conditions[1].Key = ConditionIAMPrincipalID },
	} {
		t.Run(name, func(t *testing.T) {
			variant := authorizationProfileFixture()
			change(&variant)
			_, digest, err := CanonicalizeAuthorizationProfile(variant)
			if err != nil || digest == baseline {
				t.Fatal("authorization semantics missing from digest", err)
			}
		})
	}
}

func TestAuthorizationProfileRejectsUndeclaredOrAmbiguousCapabilities(t *testing.T) {
	for name, change := range map[string]func(*AuthorizationProfile){
		"version":          func(v *AuthorizationProfile) { v.APIVersion = "other/v1" },
		"kind":             func(v *AuthorizationProfile) { v.Kind = "PolicyDocument" },
		"zero revision":    func(v *AuthorizationProfile) { v.Revision = 0 },
		"unsafe revision":  func(v *AuthorizationProfile) { v.Revision = 1 << 53 },
		"product spelling": func(v *AuthorizationProfile) { v.Product = "ManagedService" },
		"service spelling": func(v *AuthorizationProfile) { v.CallingService = "paas" },
		"empty actions":    func(v *AuthorizationProfile) { v.Actions = nil },
		"action wildcard":  func(v *AuthorizationProfile) { v.Actions[0].Action = "managedservice.*" },
		"other namespace":  func(v *AuthorizationProfile) { v.Actions[0].Action = ActionPaaSApplicationRead },
		"duplicate action": func(v *AuthorizationProfile) { v.Actions = append(v.Actions, v.Actions[0]) },
		"oversized action set": func(v *AuthorizationProfile) {
			v.Actions = make([]AuthorizationProfileAction, MaxAuthorizationProfileActions+1)
		},
		"unknown scope": func(v *AuthorizationProfile) { v.Actions[0].Scope = "ANY" },
		"kind spelling": func(v *AuthorizationProfile) { v.Actions[0].ResourceKind = "serviceOffering" },
		"no shape":      func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes = nil },
		"batch":         func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[0].Mode = "BATCH" },
		"duplicate shape": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes = append(v.Actions[0].ResourceShapes, v.Actions[0].ResourceShapes[0])
		},
		"collection prefix": func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[1].PrefixAllowed = true },
		"filtered list":     func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[1].CollectionUsage = "FILTERED" },
		"creation result absent": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes[1].CollectionUsage = AuthorizationCollectionCreate
		},
		"list claiming creation": func(v *AuthorizationProfile) { v.Actions[0].ResultResourceKind = "RESULT" },
		"list and create": func(v *AuthorizationProfile) {
			v.Actions[0].ResultResourceKind = "RESULT"
			v.Actions[0].ResourceShapes = append(v.Actions[0].ResourceShapes, AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate})
		},
		"instance claiming collection": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes[0].CollectionUsage = AuthorizationCollectionCreate
		},
		"result spelling": func(v *AuthorizationProfile) { v.Actions[0].ResultResourceKind = "bad-result" },
		"platform prefix": func(v *AuthorizationProfile) {
			v.Actions[0].Conditions = nil
			v.Actions[0].Scope = AuthorityScopeInstallation
			v.Actions[0].ResourceShapes[0].PrefixAllowed = true
		},
		"probe tenant conditions": func(v *AuthorizationProfile) { v.Actions[0].Scope = AuthorityScopeInstallationProbe },
		"duplicate condition": func(v *AuthorizationProfile) {
			v.Actions[0].Conditions = append(v.Actions[0].Conditions, v.Actions[0].Conditions[0])
		},
		"caller conditions":  func(v *AuthorizationProfile) { v.Actions[0].Conditions[0].Source = "CALLER_ATTRIBUTES" },
		"unknown source key": func(v *AuthorizationProfile) { v.Actions[0].Conditions[0].Key = "paas.arbitrary" },
		"wrong source type":  func(v *AuthorizationProfile) { v.Actions[0].Conditions[0].ValueType = ConditionString },
	} {
		t.Run(name, func(t *testing.T) {
			variant := authorizationProfileFixture()
			change(&variant)
			if !errors.Is(ValidateAuthorizationProfile(variant), ErrInvalidAuthorizationProfile) {
				t.Fatal("accepted invalid declaration")
			}
			if document, digest, err := CanonicalizeAuthorizationProfile(variant); document != "" || digest != "" || !errors.Is(err, ErrInvalidAuthorizationProfile) {
				t.Fatal("invalid declaration produced usable evidence")
			}
		})
	}
}

func TestAuthorizationProfileStrictDecodeAndNonAdmission(t *testing.T) {
	document, _, err := CanonicalizeAuthorizationProfile(authorizationProfileFixture())
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"unknown":                 strings.Replace(document, `"revision":1`, `"revision":1,"permit":true`, 1),
		"duplicate":               strings.Replace(document, `"revision":1`, `"revision":1,"revision":2`, 1),
		"case alias":              strings.Replace(document, `"revision":1`, `"Revision":1`, 1),
		"nested unknown":          strings.Replace(document, `"prefixAllowed":false`, `"prefixAllowed":false,"authority":"ANY"`, 1),
		"nested duplicate":        strings.Replace(document, `"prefixAllowed":false`, `"prefixAllowed":false,"prefixAllowed":true`, 1),
		"result on request shape": strings.Replace(document, `"prefixAllowed":false`, `"prefixAllowed":false,"resultResourceKind":"USER"`, 1),
		"trailing":                document + `{}`,
		"null":                    `null`,
		"oversized":               document + strings.Repeat(" ", int(MaxAuthorizationProfileBytes)),
	} {
		t.Run(name, func(t *testing.T) {
			value, err := DecodeAuthorizationProfile(strings.NewReader(source))
			if !errors.Is(err, ErrInvalidAuthorizationProfile) || value.Product != "" || value.Actions != nil {
				t.Fatal("invalid input returned a usable declaration", err)
			}
		})
	}
	// Product/action spelling cannot enroll a new service or change the active
	// action catalog, even when a prospective declaration is syntactically valid.
	profile := authorizationProfileFixture()
	profile.Product = "observability"
	profile.CallingService = "OBSERVABILITY"
	profile.Actions[0].Action = "observability.sample.inspect"
	if err := ValidateAuthorizationProfile(profile); err != nil {
		t.Fatal("new product syntax must not require a product-name switch", err)
	}
	if _, known := LookupActionDefinition(profile.Actions[0].Action); known {
		t.Fatal("validating a profile registered an action")
	}
	if _, known := LookupActionConditionDefinition(profile.Actions[0].Action, ConditionIAMAccountID); known {
		t.Fatal("source validation granted unknown action capabilities")
	}
	// Absence, null and empty optional condition sets all declare no condition
	// capability. Their canonical form cannot accidentally enable one.
	profile.Actions[0].Conditions = nil
	without, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, empty := range []string{`null`, `[]`} {
		input := strings.Replace(without, `"resourceShapes":`, `"conditions":`+empty+`,"resourceShapes":`, 1)
		decoded, err := DecodeAuthorizationProfile(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		_, decodedDigest, err := CanonicalizeAuthorizationProfile(decoded)
		if err != nil || decodedDigest != digest {
			t.Fatal("empty condition capability changed meaning", err)
		}
	}
}

func FuzzAuthorizationProfileCanonicalRoundTrip(f *testing.F) {
	document, _, err := CanonicalizeAuthorizationProfile(authorizationProfileFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(document)
	for _, profile := range AllAuthorizationProfiles() {
		canonical, _, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(canonical)
	}
	for _, selected := range []Action{ActionIAMUserCreate, ActionPaaSApplicationCreate} {
		definition, known := LookupActionDefinition(selected)
		if !known {
			f.Fatal("missing declared action")
		}
		profile, known := LookupAuthorizationProfile(definition.Product)
		if !known {
			f.Fatal("missing declared product")
		}
		for _, action := range profile.Actions {
			if action.Action != selected {
				continue
			}
			profile.Actions = []AuthorizationProfileAction{action}
			seed, _, err := CanonicalizeAuthorizationProfile(profile)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(seed)
			break
		}
	}
	f.Add(`{"kind":"AuthorizationProfile","actions":null}`)
	f.Add(`{"revision":1,"revision":2}`)
	f.Fuzz(func(t *testing.T, source string) {
		profile, err := DecodeAuthorizationProfile(strings.NewReader(source))
		if err != nil {
			return
		}
		canonical, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeAuthorizationProfile(strings.NewReader(canonical))
		if err != nil {
			t.Fatal(err)
		}
		second, secondDigest, err := CanonicalizeAuthorizationProfile(decoded)
		if err != nil || second != canonical || secondDigest != digest {
			t.Fatal("accepted declaration is not canonically stable", err)
		}
		if err := CheckAuthorizationProfileReference(decoded, AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAuthorizationProfileBoundsTypedDeclarations(t *testing.T) {
	profile := authorizationProfileFixture()
	profile.Actions = make([]AuthorizationProfileAction, MaxAuthorizationProfileActions)
	for index := range profile.Actions {
		action := authorizationProfileFixture().Actions[0]
		action.Action = Action(fmt.Sprintf("managedservice.%s.action%d", strings.Repeat("a", 64), index))
		action.ResourceKind = ResourceKind(strings.Repeat("K", 64))
		action.ResourceShapes = []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}
		action.ResultResourceKind = ResourceKind(strings.Repeat("R", 64))
		profile.Actions[index] = action
	}
	encoded, err := json.Marshal(profile)
	if err != nil || int64(len(encoded)) <= MaxAuthorizationProfileBytes {
		t.Fatal("fixture must exceed the byte budget", err)
	}
	if !errors.Is(ValidateAuthorizationProfile(profile), ErrInvalidAuthorizationProfile) {
		t.Fatal("typed input bypassed the byte budget")
	}
}

func TestLocalRecoveryCapabilityBindsOnePrivateIntent(t *testing.T) {
	secret := func(value string) Secret {
		t.Helper()
		result, err := NewSecret(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	scope := LocalCredentialRecoveryScope{
		InstallationID: "installation-local", BootstrapDigest: "sha256:" + strings.Repeat("a", 64),
		AccountID: "organization-original", PrincipalID: "principal-original",
	}
	local := LocalCredentialRecoveryAuthority{
		APIVersion: APIVersion, Kind: "LocalCredentialRecoveryAuthority", Purpose: LocalCredentialRecoveryPurpose,
		Scope: scope, CapabilityKey: secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x39}, 32))),
	}
	request := LocalCredentialRecoveryRequest{
		APIVersion: APIVersion, Kind: "LocalCredentialRecoveryRequest", Purpose: LocalCredentialRecoveryPurpose,
		CommandID: "command-original", Scope: scope,
		Expected: LocalCredentialRecoveryExpected{OrganizationResourceVersion: 3, PrincipalResourceVersion: 7,
			CredentialGeneration: 4, PlatformBindingID: "binding-original", PlatformBindingResourceVersion: 1},
		NewPassword: secret("Recovery-Private-Password-123!"),
	}
	signed, err := SignLocalCredentialRecoveryRequest(local, request)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := VerifyLocalCredentialRecoveryRequest(local, signed)
	if err != nil || ValidateDigest("commitment", commitment) != nil {
		t.Fatalf("verify capability: %v", err)
	}
	repeated, err := SignLocalCredentialRecoveryRequest(local, request)
	if err != nil || !bytes.Equal(signed.Capability.CopyBytes(), repeated.Capability.CopyBytes()) {
		t.Fatal("same private intent did not reproduce its capability")
	}
	for name, change := range map[string]func(*LocalCredentialRecoveryRequest){
		"purpose":              func(v *LocalCredentialRecoveryRequest) { v.Purpose = "PLATFORM_ROLE_GRANT" },
		"command":              func(v *LocalCredentialRecoveryRequest) { v.CommandID = "command-other" },
		"installation":         func(v *LocalCredentialRecoveryRequest) { v.Scope.InstallationID = "installation-other" },
		"bootstrap":            func(v *LocalCredentialRecoveryRequest) { v.Scope.BootstrapDigest = "sha256:" + strings.Repeat("b", 64) },
		"tenant":               func(v *LocalCredentialRecoveryRequest) { v.Scope.AccountID = "organization-other" },
		"primary":              func(v *LocalCredentialRecoveryRequest) { v.Scope.PrincipalID = "principal-child" },
		"organization version": func(v *LocalCredentialRecoveryRequest) { v.Expected.OrganizationResourceVersion++ },
		"principal version":    func(v *LocalCredentialRecoveryRequest) { v.Expected.PrincipalResourceVersion++ },
		"generation":           func(v *LocalCredentialRecoveryRequest) { v.Expected.CredentialGeneration++ },
		"binding":              func(v *LocalCredentialRecoveryRequest) { v.Expected.PlatformBindingID = "binding-other" },
		"binding version":      func(v *LocalCredentialRecoveryRequest) { v.Expected.PlatformBindingResourceVersion++ },
		"password":             func(v *LocalCredentialRecoveryRequest) { v.NewPassword = secret("Different-Private-Password-123!") },
		"capability": func(v *LocalCredentialRecoveryRequest) {
			v.Capability = secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
		},
		"missing capability":  func(v *LocalCredentialRecoveryRequest) { v.Capability = Secret{} },
		"overflow generation": func(v *LocalCredentialRecoveryRequest) { v.Expected.CredentialGeneration = 9007199254740991 },
	} {
		t.Run(name, func(t *testing.T) {
			forged := signed
			change(&forged)
			if _, err := VerifyLocalCredentialRecoveryRequest(local, forged); !errors.Is(err, ErrInvalidLocalCredentialRecovery) {
				t.Fatalf("substituted intent accepted: %v", err)
			}
		})
	}
	otherKey := local
	otherKey.CapabilityKey = secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32)))
	if _, err := VerifyLocalCredentialRecoveryRequest(otherKey, signed); err == nil {
		t.Fatal("another installation authority key accepted")
	}
	for _, value := range []any{local, signed} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrSecretSerialization) {
			t.Fatalf("ordinary secret serialization error=%v", err)
		}
		formatted := fmt.Sprintf("%+v %#v", value, value)
		for _, sensitive := range []Secret{local.CapabilityKey, signed.NewPassword, signed.Capability} {
			if strings.Contains(formatted, string(sensitive.CopyBytes())) {
				t.Fatal("private material leaked through formatting")
			}
		}
	}
	encodedAuthority, err := EncodeLocalCredentialRecoveryAuthority(local)
	if err != nil {
		t.Fatal(err)
	}
	decodedAuthority, err := DecodeLocalCredentialRecoveryAuthority(bytes.NewReader(encodedAuthority))
	if err != nil || decodedAuthority.Scope != scope {
		t.Fatalf("authority private round trip: %v", err)
	}
	encoded, err := EncodeLocalCredentialRecoveryRequest(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeLocalCredentialRecoveryRequest(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyLocalCredentialRecoveryRequest(decodedAuthority, decoded); err != nil || got != commitment {
		t.Fatalf("private wire changed commitment: %v", err)
	}
	for _, forged := range []string{
		strings.Replace(string(encoded), `"commandId":`, `"commandId":"other","commandId":`, 1),
		strings.TrimSuffix(string(encoded), "}") + `,"databaseDsn":"attacker"}`,
		string(encoded) + `{}`,
		strings.Replace(string(encoded), `"newPassword":`, `"extra":true,"newPassword":`, 1),
	} {
		if _, err := DecodeLocalCredentialRecoveryRequest(strings.NewReader(forged)); err == nil {
			t.Fatal("ambiguous/unknown private request accepted")
		}
	}
}

func TestLocalRecoveryReceiptIsHistoricalNotFreshAuthority(t *testing.T) {
	scope := LocalCredentialRecoveryScope{InstallationID: "installation-original", BootstrapDigest: "sha256:" + strings.Repeat("a", 64), AccountID: "organization-original", PrincipalID: "principal-original"}
	expected := LocalCredentialRecoveryExpected{OrganizationResourceVersion: 1, PrincipalResourceVersion: 4, CredentialGeneration: 3, PlatformBindingID: "binding-original", PlatformBindingResourceVersion: 1}
	result := LocalCredentialRecoveryResult{APIVersion: APIVersion, Kind: "LocalCredentialRecoveryResult", State: "APPLIED", CommandID: "command-original",
		InputCommitment: "sha256:" + strings.Repeat("b", 64), Scope: scope, PreviousCredentialGeneration: 3, CredentialGeneration: 4,
		PrincipalResourceVersion: 5, RevokedSessions: 2, AuditEventID: "event-original", CompletedAt: time.Date(2026, 8, 28, 1, 2, 3, 0, time.UTC)}
	inspection := LocalCredentialRecoveryInspection{APIVersion: APIVersion, Kind: "LocalCredentialRecoveryInspection", Scope: scope, State: "COMPLETED",
		CommandID: result.CommandID, InputCommitment: result.InputCommitment, Expected: &expected, Result: &result}
	if err := ValidateLocalCredentialRecoveryInspection(inspection); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*LocalCredentialRecoveryInspection){
		"wrong command":             func(v *LocalCredentialRecoveryInspection) { v.CommandID = "other" },
		"wrong commitment":          func(v *LocalCredentialRecoveryInspection) { v.InputCommitment = "sha256:" + strings.Repeat("c", 64) },
		"scope":                     func(v *LocalCredentialRecoveryInspection) { v.Scope.PrincipalID = "another-primary" },
		"missing result":            func(v *LocalCredentialRecoveryInspection) { v.Result = nil },
		"missing original expected": func(v *LocalCredentialRecoveryInspection) { v.Expected = nil },
		"missing receipt cannot supply current state": func(v *LocalCredentialRecoveryInspection) { v.State = "NOT_FOUND"; v.Result = nil },
		"eligible cannot assert receipt":              func(v *LocalCredentialRecoveryInspection) { v.State = "ELIGIBLE" },
	} {
		t.Run(name, func(t *testing.T) {
			v := inspection
			mutate(&v)
			if ValidateLocalCredentialRecoveryInspection(v) == nil {
				t.Fatal("invalid historical completion accepted")
			}
		})
	}
	missing := inspection
	missing.State, missing.Expected, missing.Result = "NOT_FOUND", nil, nil
	if err := ValidateLocalCredentialRecoveryInspection(missing); err != nil {
		t.Fatal(err)
	}
	query := LocalCredentialRecoveryReceiptQuery{APIVersion: APIVersion, Kind: "LocalCredentialRecoveryReceiptQuery", CommandID: result.CommandID, InputCommitment: result.InputCommitment}
	if err := ValidateLocalCredentialRecoveryReceiptQuery(query); err != nil {
		t.Fatal(err)
	}
	forgedQuery := `{"apiVersion":"` + APIVersion + `","kind":"LocalCredentialRecoveryReceiptQuery","commandId":"command-original","inputCommitment":"` + result.InputCommitment + `","tenantId":"other"}`
	if DecodeRequest(strings.NewReader(forgedQuery), &query) == nil {
		t.Fatal("receipt query accepted a target selector")
	}
}

func TestPublicBootstrapDigestPreservesTheSealedPrivateBytes(t *testing.T) {
	document := decodeIAMExample[BootstrapDocument](t, "examples/bootstrap-document.json")
	encoded, err := EncodeBootstrapDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	got, err := BootstrapDigest(document)
	if err != nil || got != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatalf("bootstrap byte commitment changed: %v", err)
	}
	if _, err := json.Marshal(document); !errors.Is(err, ErrSecretSerialization) {
		t.Fatal("public digest exposed ordinary bootstrap serialization")
	}
}

func TestPlatformDecisionsCannotMasqueradeAsTenantAuthority(t *testing.T) {
	source, err := os.ReadFile("examples/authorization-decision-allowed.json")
	if err != nil {
		t.Fatal(err)
	}
	var valid AuthorizationDecision
	if err := json.Unmarshal(source, &valid); err != nil {
		t.Fatal(err)
	}
	valid.Action, valid.Resource.Kind = ActionPaaSExecutionTargetRegister, ResourceExecutionTarget
	valid.ResourceMode, valid.CollectionUsage = AuthorizationResourceInstance, ""
	valid.TenantID, valid.InstallationID = "", "installation-example"
	if err := ValidateAuthorizationDecision(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AuthorizationDecision){
		"missing installation": func(value *AuthorizationDecision) { value.InstallationID = "" },
		"mixed authorities":    func(value *AuthorizationDecision) { value.TenantID = "organization-example" },
		"tenant action": func(value *AuthorizationDecision) {
			value.Action, value.Resource.Kind = ActionPaaSApplicationRead, ResourceApplication
		},
		"denial leak": func(value *AuthorizationDecision) {
			value.Allowed, value.Reason, value.Subject = false, DecisionDenied, nil
		},
		"service authority": func(value *AuthorizationDecision) {
			subject := *value.Subject
			subject.Type = PrincipalServiceAccount
			value.Subject = &subject
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if ValidateAuthorizationDecision(value) == nil {
				t.Fatal("invalid platform authority accepted")
			}
		})
	}
}

func TestIAMExamplesPassDomainValidation(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"account", validIAMExample[Account]("examples/account.json", ValidateAccount)},
		{"user", validIAMExample[User]("examples/user.json", ValidateUser)},
		{"bootstrap status", validIAMExample[BootstrapStatus]("examples/bootstrap-status.json", ValidateBootstrapStatus)},
		{"service identity", validIAMExample[ServiceIdentity]("examples/service-identity.json", ValidateServiceIdentity)},
		{"login request", validIAMExample[LoginRequest]("examples/login-request.json", ValidateLoginRequest)},
		{"login response", validIAMExample[LoginResponse]("examples/login-response.json", ValidateLoginResponse)},
		{"logout request", validIAMExample[LogoutRequest]("examples/logout-request.json", ValidateLogoutRequest)},
		{"logout response", validIAMExample[LogoutResponse]("examples/logout-response.json", ValidateLogoutResponse)},
		{"password request", validIAMExample[ChangePasswordRequest]("examples/change-password-request.json", ValidateChangePasswordRequest)},
		{"password response", validIAMExample[ChangePasswordResponse]("examples/change-password-response.json", ValidateChangePasswordResponse)},
		{"create user", validIAMExample[CreateUserRequest]("examples/create-user-request.json", ValidateCreateUserRequest)},
		{"create policy attachment", validIAMExample[CreatePolicyAttachmentRequest]("examples/create-policy-attachment-request.json", ValidateCreatePolicyAttachmentRequest)},
		{"revoke policy attachment", validIAMExample[RevokePolicyAttachmentRequest]("examples/revoke-policy-attachment-request.json", ValidateRevokePolicyAttachmentRequest)},
		{"revoke session", validIAMExample[RevokeSessionRequest]("examples/revoke-session-request.json", ValidateRevokeSessionRequest)},
		{"revocation", validIAMExample[Revocation]("examples/revocation.json", ValidateRevocation)},
		{"authorization request", validIAMExample[AuthorizationRequest]("examples/authorization-request.json", ValidateAuthorizationRequest)},
		{"allowed decision", validIAMExample[AuthorizationDecision]("examples/authorization-decision-allowed.json", ValidateAuthorizationDecision)},
		{"denied decision", validIAMExample[AuthorizationDecision]("examples/authorization-decision-denied.json", ValidateAuthorizationDecision)},
		{"readiness", validIAMExample[Readiness]("examples/readiness.json", ValidateReadiness)},
		{"problem", validIAMExample[Problem]("examples/problem.json", ValidateProblem)},
		{"bootstrap document", func(t *testing.T) {
			file, err := os.Open("examples/bootstrap-document.json")
			if err != nil {
				t.Fatalf("open bootstrap document: %v", err)
			}
			defer file.Close()
			if _, err := DecodeBootstrapDocument(file); err != nil {
				t.Fatalf("decode and validate bootstrap document: %v", err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestIAMAuthorizationInputCannotForgeAuthorityContext(t *testing.T) {
	baseline, err := NewAuthorizationRequest(ActionPaaSDeploymentCreate, ResourceReference{Kind: ResourceDeployment, ID: "collection"}, AuthorizationResourceCollection, AuthorizationCollectionCreate, "request-authorize", "correlation-authorize")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(encoded)
	var baselineDecoded AuthorizationRequest
	if DecodeRequest(strings.NewReader(valid), &baselineDecoded) != nil || ValidateAuthorizationRequest(baselineDecoded) != nil {
		t.Fatal("baseline request is invalid")
	}
	for name, forged := range map[string]string{
		"tenant":  strings.Replace(valid, `"action"`, `"tenantId":"organization-forged","action"`, 1),
		"subject": strings.Replace(valid, `"action"`, `"subject":{"type":"USER","id":"principal-forged"},"action"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var request AuthorizationRequest
			err := DecodeRequest(strings.NewReader(forged), &request)
			if err == nil {
				t.Fatalf("forged %s context was accepted", name)
			}
		})
	}

	duplicate := strings.Replace(valid, `"kind":"DEPLOYMENT"`, `"kind":"DEPLOYMENT","kind":"DEPLOYMENT"`, 1)
	var request AuthorizationRequest
	if err := DecodeRequest(strings.NewReader(duplicate), &request); !errors.Is(err, contractjson.ErrDuplicateField) {
		t.Fatalf("duplicate nested authority field error = %v, want duplicate field", err)
	}
	if err := DecodeRequest(strings.NewReader(valid+` {}`), &request); !errors.Is(err, contractjson.ErrTrailingData) {
		t.Fatalf("trailing authority document error = %v, want trailing data", err)
	}
	oversized := `{"action":"paas.deployment.create","padding":"` +
		strings.Repeat("A", int(MaxRequestBytes)) + `"}`
	if err := DecodeRequest(strings.NewReader(oversized), &request); !errors.Is(err, contractjson.ErrDocumentTooLarge) {
		t.Fatalf("oversized authority document error = %v, want document too large", err)
	}
}

func TestIAMActionCatalogHasOneResourceKind(t *testing.T) {
	for _, action := range AllActions() {
		kind, known := ResourceKindForAction(action)
		if !known || kind == "" {
			t.Fatalf("action %q has no resource kind", action)
		}
		definition, _ := LookupActionDefinition(action)
		profile, _ := LookupAuthorizationProfile(definition.Product)
		for _, declared := range profile.Actions {
			if declared.Action != action {
				continue
			}
			for _, shape := range declared.ResourceShapes {
				request, err := NewAuthorizationRequest(action, ResourceReference{Kind: kind, ID: "collection"}, shape.Mode, shape.CollectionUsage, "request-example", "correlation-example")
				if err != nil || ValidateAuthorizationRequest(request) != nil {
					t.Fatalf("valid catalog entry %q/%q rejected: %v", action, kind, err)
				}
				request.Resource.Kind = ResourceKind("NOT_A_RESOURCE")
				if ValidateAuthorizationRequest(request) == nil {
					t.Fatalf("action %q accepted an unbound resource kind", action)
				}
			}
		}
	}
	if _, known := ResourceKindForAction(Action("paas.unregistered.execute")); known {
		t.Fatal("unregistered action has a resource binding")
	}
}

func TestIAMActionDefinitionsDeclareProductServiceAndScope(t *testing.T) {
	// These cases pin security boundaries, including equal resource kinds in
	// different authority scopes and managedservice's PaaS caller.
	for _, want := range []ActionDefinition{
		{ActionIAMAccountCreate, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation, false},
		{ActionIAMAccountRootCredentialsRecover, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation, false},
		{ActionIAMUserCreate, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeTenant, false},
		{ActionIAMPolicyAttachmentCreate, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeTenant, false},
		{ActionIAMPolicyAttachmentRevoke, ProductIAM, ServiceIAM, ResourcePolicyAttachment, AuthorityScopeTenant, false},
		{ActionIAMPlatformPolicyAttachmentCreate, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeInstallation, false},
		{ActionIAMPlatformPolicyAttachmentRevoke, ProductIAM, ServiceIAM, ResourcePolicyAttachment, AuthorityScopeInstallation, false},
		{ActionIAMSessionRevoke, ProductIAM, ServiceIAM, ResourceSession, AuthorityScopeTenant, false},
		{ActionPaaSApplicationCreate, ProductPaaS, ServicePaaS, ResourceApplication, AuthorityScopeTenant, false},
		{ActionPaaSExecutionPoolCreate, ProductPaaS, ServicePaaS, ResourceExecutionPool, AuthorityScopeInstallation, false},
		{ActionPaaSExecutionTargetRegister, ProductPaaS, ServicePaaS, ResourceExecutionTarget, AuthorityScopeInstallation, false},
		{ActionPaaSOperationRead, ProductPaaS, ServicePaaS, ResourceOperation, AuthorityScopeTenant, false},
		{ActionPaaSPlatformOperationRead, ProductPaaS, ServicePaaS, ResourceOperation, AuthorityScopeInstallation, false},
		{ActionManagedServiceOfferingRead, ProductManagedService, ServicePaaS, ResourceServiceOffering, AuthorityScopeTenant, false},
		{ActionManagedServiceInstallationCreate, ProductManagedService, ServicePaaS, ResourceServiceInstallation, AuthorityScopeTenant, false},
		{ActionAuditRecordRead, ProductAudit, ServiceAudit, ResourceAuditRecord, AuthorityScopeTenant, false},
		{ActionAuditPlatformRecordRead, ProductAudit, ServiceAudit, ResourceAuditRecord, AuthorityScopeInstallation, false},
		{ActionAuditIntegrityVerify, ProductAudit, ServiceAudit, ResourceAuditChain, AuthorityScopeTenant, false},
		{ActionAuditPlatformIntegrityVerify, ProductAudit, ServiceAudit, ResourceAuditChain, AuthorityScopeInstallation, false},
		{ActionInstallationVerify, ProductInstallation, ServiceInstallationVerifier, ResourceInstallation, AuthorityScopeInstallationProbe, false},
	} {
		if got, known := LookupActionDefinition(want.Action); !known || got != want {
			t.Errorf("definition %s = %+v known=%v, want %+v", want.Action, got, known, want)
		}
	}

	callers := map[ProductID]ServicePurpose{
		ProductIAM: ServiceIAM, ProductPaaS: ServicePaaS, ProductManagedService: ServicePaaS,
		ProductAudit: ServiceAudit, ProductInstallation: ServiceInstallationVerifier,
	}
	seen := make(map[Action]bool)
	for _, definition := range AllActionDefinitions() {
		if seen[definition.Action] || definition.Action == "" {
			t.Fatalf("duplicate/empty action definition %q", definition.Action)
		}
		seen[definition.Action] = true
		if caller, known := callers[definition.Product]; !known || caller != definition.CallingService {
			t.Errorf("product caller changed: %+v", definition)
		}
		switch definition.AuthorityScope {
		case AuthorityScopeTenant, AuthorityScopeInstallation:
			if definition.Product == ProductInstallation {
				t.Fatal("installation verifier became a business authorization product")
			}
		case AuthorityScopeInstallationProbe:
			if definition.Action != ActionInstallationVerify || definition.CallingService != ServiceInstallationVerifier {
				t.Fatal("probe scope admitted an unrelated action or service")
			}
		default:
			t.Errorf("missing authority scope: %+v", definition)
		}
		kind, known := ResourceKindForAction(definition.Action)
		if !known || kind != definition.ResourceKind || IsPlatformAction(definition.Action) != (definition.AuthorityScope == AuthorityScopeInstallation) {
			t.Errorf("validators diverge from the definition: %+v", definition)
		}
	}
	actions := AllActions()
	if len(seen) != len(actions) {
		t.Fatal("action inventory and definitions diverge")
	}
	for _, action := range actions {
		if !seen[action] {
			t.Errorf("action %s lacks an explicit definition", action)
		}
	}
	for _, unknown := range []Action{"", "iam.principal.unknown", "paas.unregistered.execute", "installation.verify.other"} {
		if definition, known := LookupActionDefinition(unknown); known || definition != (ActionDefinition{}) || IsPlatformAction(unknown) {
			t.Errorf("unknown action obtained a definition/authority: %q", unknown)
		}
	}
}

func TestIAMCatalogReadsCannotModifyAuthority(t *testing.T) {
	want, known := LookupActionDefinition(ActionIAMAccountCreate)
	if !known {
		t.Fatal("account creation is not registered")
	}
	definitions := AllActionDefinitions()
	for index := range definitions {
		definitions[index] = ActionDefinition{Action: "paas.forged.execute", CallingService: ServicePaaS}
	}
	actions := AllActions()
	for index := range actions {
		actions[index] = "paas.forged.execute"
	}
	copy, _ := LookupActionDefinition(want.Action)
	copy.CallingService, copy.AuthorityScope = ServicePaaS, AuthorityScopeTenant
	if got, known := LookupActionDefinition(want.Action); !known || got != want {
		t.Fatal("caller mutation changed the authority catalog")
	}
	for _, definition := range AllActionDefinitions() {
		if definition.Action == "paas.forged.execute" {
			t.Fatal("definition slice exposed mutable catalog storage")
		}
	}
	for _, action := range AllActions() {
		if action == "paas.forged.execute" {
			t.Fatal("action slice exposed mutable catalog storage")
		}
	}
	for index := range AllRecordedActionDefinitions() {
		copy := AllRecordedActionDefinitions()
		copy[index] = ActionDefinition{Action: "iam.forged.execute"}
	}
	seen := map[Action]bool{}
	for _, definition := range AllRecordedActionDefinitions() {
		if definition.Action == "iam.forged.execute" || seen[definition.Action] {
			t.Fatal("historical catalog was mutable or ambiguous")
		}
		seen[definition.Action] = true
	}
}

func policyDocumentFixture() PolicyDocument {
	return PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant, Statements: []PolicyStatement{
		{SID: "read", Effect: PolicyAllow, Actions: []Action{ActionPaaSDeploymentRead, ActionPaaSApplicationRead}, Resources: []PolicyResourceSelector{
			{Kind: ResourceDeployment, Match: PolicyResourceExact, ID: "deployment-one"},
			{Kind: ResourceApplication, Match: PolicyResourceExact, ID: "application-one"},
		}},
		{SID: "create", Effect: PolicyDeny, Actions: []Action{ActionPaaSApplicationCreate}, Resources: []PolicyResourceSelector{
			{Kind: ResourceApplication, Match: PolicyResourceAnyInAuthority},
		}},
	}}
}

func TestPolicyCompilationBindsMinimalProductsAndEntireAuthorDocument(t *testing.T) {
	document := policyDocumentFixture()
	document.Statements = append(document.Statements, PolicyStatement{SID: "audit", Effect: PolicyAllow,
		Actions: []Action{ActionAuditRecordRead}, Resources: []PolicyResourceSelector{{Kind: ResourceAuditRecord, Match: PolicyResourceAnyInAuthority}}})
	profiles := AllAuthorizationProfiles()
	documentBefore, _ := json.Marshal(document)
	profilesBefore, _ := json.Marshal(profiles)
	legacyCanonical, legacyDigest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	compilation, err := CompilePolicyDocument(document, profiles)
	if err != nil {
		t.Fatal(err)
	}
	if compilation.CompilationVersion != "1" || len(compilation.Profiles) != 2 || compilation.Profiles[0].Product != ProductAudit || compilation.Profiles[1].Product != ProductPaaS {
		t.Fatal("compilation did not select the exact sorted product set")
	}
	canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, profiles)
	if err != nil || ValidateDigest("digest", digest) != nil || digest == legacyDigest {
		t.Fatal("compilation must have a distinct complete content commitment", err)
	}
	var content struct {
		Document json.RawMessage `json:"document"`
		PolicyCompilation
	}
	if err := json.Unmarshal([]byte(canonical), &content); err != nil || string(content.Document) != legacyCanonical {
		t.Fatal("compilation changed the unique canonical author document", err)
	}
	for _, reference := range compilation.Profiles {
		profile, found := LookupAuthorizationProfile(reference.Product)
		if !found || CheckAuthorizationProfileReference(profile, reference) != nil {
			t.Fatal("compiled reference did not bind exact product content")
		}
	}
	documentAfter, _ := json.Marshal(document)
	profilesAfter, _ := json.Marshal(profiles)
	if !bytes.Equal(documentBefore, documentAfter) || !bytes.Equal(profilesBefore, profilesAfter) {
		t.Fatal("compilation mutated the author or declaration inputs")
	}
	compilationBefore, _ := json.Marshal(compilation)
	compilation.Profiles[0], compilation.Profiles[1] = compilation.Profiles[1], compilation.Profiles[0]
	compilation.ResolvedStatements[0], compilation.ResolvedStatements[2] = compilation.ResolvedStatements[2], compilation.ResolvedStatements[0]
	compilation.ResolvedStatements[0].Actions[0], compilation.ResolvedStatements[0].Actions[1] = compilation.ResolvedStatements[0].Actions[1], compilation.ResolvedStatements[0].Actions[0]
	document.Statements[0], document.Statements[2] = document.Statements[2], document.Statements[0]
	profiles[0], profiles[4] = profiles[4], profiles[0]
	before, _ := json.Marshal(compilation)
	if reordered, reorderedDigest, err := CanonicalizePolicyCompilation(document, compilation, profiles); err != nil || reordered != canonical || reorderedDigest != digest {
		t.Fatal("set order changed compilation semantics", err)
	}
	after, _ := json.Marshal(compilation)
	if !bytes.Equal(before, after) || bytes.Equal(compilationBefore, after) {
		t.Fatal("canonicalization must not reorder the caller's compilation in place")
	}
	for _, change := range []func(*PolicyDocument){
		func(v *PolicyDocument) { v.Statements[0].Effect = PolicyDeny },
		func(v *PolicyDocument) { v.Statements[2].Resources[0].ID = "different-resource" },
		func(v *PolicyDocument) {
			v.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMAccountID, Operator: PolicyStringEquals, Values: []string{"account-one"}}}
		},
	} {
		var changed PolicyDocument
		encoded, _ := json.Marshal(document)
		if json.Unmarshal(encoded, &changed) != nil {
			t.Fatal("invalid fixture")
		}
		change(&changed)
		if _, changedDigest, err := CanonicalizePolicyCompilation(changed, compilation, profiles); err != nil || changedDigest == digest {
			t.Fatal("author effect, resource and condition must enter the whole commitment", err)
		}
	}
	if retained, retainedDigest, err := CanonicalizePolicyDocument(document); err != nil || retained != legacyCanonical || retainedDigest != legacyDigest {
		t.Fatal("new compilation changed the retained document-only encoding", err)
	}
	authorBeforeMutation, _ := json.Marshal(document)
	compilation.ResolvedStatements[0].Actions[0] = "tampered.action"
	authorAfterMutation, _ := json.Marshal(document)
	if !bytes.Equal(authorBeforeMutation, authorAfterMutation) {
		t.Fatal("compiler output aliases the author input")
	}
}

func TestPolicyCompilationRejectsForgedOrIncompleteInterpretation(t *testing.T) {
	document := policyDocumentFixture()
	profiles := AllAuthorizationProfiles()
	valid, err := CompilePolicyDocument(document, profiles)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(valid)
	for name, change := range map[string]func(*PolicyCompilation){
		"no version":       func(v *PolicyCompilation) { v.CompilationVersion = "" },
		"unknown version":  func(v *PolicyCompilation) { v.CompilationVersion = "2" },
		"no profiles":      func(v *PolicyCompilation) { v.Profiles = nil },
		"extra profile":    func(v *PolicyCompilation) { v.Profiles = append(v.Profiles, v.Profiles[0]) },
		"wrong product":    func(v *PolicyCompilation) { v.Profiles[0].Product = ProductAudit },
		"wrong revision":   func(v *PolicyCompilation) { v.Profiles[0].Revision++ },
		"wrong digest":     func(v *PolicyCompilation) { v.Profiles[0].ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"no statements":    func(v *PolicyCompilation) { v.ResolvedStatements = nil },
		"duplicate SID":    func(v *PolicyCompilation) { v.ResolvedStatements[0].SID = v.ResolvedStatements[1].SID },
		"unknown SID":      func(v *PolicyCompilation) { v.ResolvedStatements[0].SID = "not-in-author-document" },
		"missing action":   func(v *PolicyCompilation) { v.ResolvedStatements[1].Actions = v.ResolvedStatements[1].Actions[:1] },
		"duplicate action": func(v *PolicyCompilation) { v.ResolvedStatements[1].Actions[1] = v.ResolvedStatements[1].Actions[0] },
		"action moved across SID": func(v *PolicyCompilation) {
			v.ResolvedStatements[0].Actions[0], v.ResolvedStatements[1].Actions[0] = v.ResolvedStatements[1].Actions[0], v.ResolvedStatements[0].Actions[0]
		},
		"unbounded action": func(v *PolicyCompilation) {
			v.ResolvedStatements[0].Actions[0] = Action(strings.Repeat("x", int(MaxPolicyCompilationBytes)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed PolicyCompilation
			if json.Unmarshal(encoded, &changed) != nil {
				t.Fatal("invalid fixture")
			}
			change(&changed)
			if canonical, digest, err := CanonicalizePolicyCompilation(document, changed, profiles); !errors.Is(err, ErrInvalidPolicy) || canonical != "" || digest != "" {
				t.Fatal("forged compilation returned authoritative bytes", err)
			}
		})
	}
	for _, invalid := range []string{
		`{}`, `null`, `[]`, string(encoded) + `{}`,
		strings.Replace(string(encoded), `"compilationVersion":`, `"unknown":true,"compilationVersion":`, 1),
		strings.Replace(string(encoded), `"compilationVersion":"1"`, `"compilationVersion":"1","compilationVersion":"1"`, 1),
		strings.Replace(string(encoded), `"profiles":`, `"Profiles":`, 1),
		strings.Replace(string(encoded), `"revision":`, `"unknown":true,"revision":`, 1),
		strings.Replace(string(encoded), `"sid":`, `"Sid":`, 1),
		strings.Replace(string(encoded), `"sid":`, `"permit":true,"sid":`, 1),
		strings.Repeat(" ", int(MaxPolicyCompilationBytes)) + string(encoded),
	} {
		if _, err := DecodePolicyCompilation(strings.NewReader(invalid), document, profiles); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("strict immutable-content loader accepted malformed compilation", err)
		}
	}
	// This is not an additive caller-selected publication capability.
	canonicalDocument, _, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`"profiles":[]`, `"resolvedStatements":[]`, `"compilationVersion":"1"`} {
		request := `{"displayName":"Example","document":` + canonicalDocument + `,"requestId":"request-one",` + extra + `}`
		var publication CreatePolicyRequest
		if contractjson.DecodeObject(strings.NewReader(request), MaxPolicyBytes, &publication) == nil {
			t.Fatal("author request accepted server-owned profile selection or compilation")
		}
	}
}

func TestPolicyCompilationUsesFrozenDeclarationsNotCurrentCatalog(t *testing.T) {
	profile := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}))
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "read", Effect: PolicyDeny, Actions: []Action{"widgets.item.read"},
			Resources:  []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourcePrefixInAuthority, ID: "widget-"}},
			Conditions: []PolicyCondition{{Key: ConditionIAMAccountID, Operator: PolicyStringNotEquals, Values: []string{"account-one"}}}}}}
	if ValidatePolicyDocument(document) == nil {
		t.Fatal("syntactic declaration registered an unknown product in current authority")
	}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{profile})
	if err != nil {
		t.Fatal("same compiler rejected an explicit non-global product declaration", err)
	}
	canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AuthorizationProfile){
		"next revision": func(v *AuthorizationProfile) { v.Revision++ },
		"new action": func(v *AuthorizationProfile) {
			v.Actions = append(v.Actions, declaredProfileAction("widgets.item.delete", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
		},
		"new shape": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes = append(v.Actions[0].ResourceShapes, AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList})
		},
		"different caller":  func(v *AuthorizationProfile) { v.CallingService = "ANOTHER_SERVICE" },
		"removed prefix":    func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[0].PrefixAllowed = false },
		"removed condition": func(v *AuthorizationProfile) { v.Actions[0].Conditions = nil },
		"wrong source":      func(v *AuthorizationProfile) { v.Actions[0].Conditions[0].Source = "CALLER" },
		"wrong scope":       func(v *AuthorizationProfile) { v.Actions[0].Scope = AuthorityScopeInstallation },
		"wrong kind":        func(v *AuthorizationProfile) { v.Actions[0].ResourceKind = "OTHER_RESOURCE" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneAuthorizationProfile(profile)
			change(&changed)
			if value, commitment, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{changed}); !errors.Is(err, ErrInvalidPolicy) || value != "" || commitment != "" {
				t.Fatal("different declaration reinterpreted a frozen compilation", err)
			}
		})
	}
	for _, supplied := range [][]AuthorizationProfile{nil, {profile, profile}, make([]AuthorizationProfile, MaxPolicyCompilationProfiles+1)} {
		if _, err := CompilePolicyDocument(document, supplied); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("missing, ambiguous or over-budget declarations accepted")
		}
	}
	pattern := document
	pattern.Statements = append([]PolicyStatement(nil), document.Statements...)
	pattern.Statements[0].Actions = []Action{"widgets.item.*"}
	if _, err := CompilePolicyDocument(pattern, []AuthorizationProfile{profile}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("pure binding slice silently enabled runtime action patterns")
	}
	if again, againDigest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile}); err != nil || again != canonical || againDigest != digest {
		t.Fatal("frozen original content no longer validates independently", err)
	}
	if _, registered := LookupAuthorizationProfile(profile.Product); registered {
		t.Fatal("pure compiler modified current product registration")
	}
}

func TestCompiledPolicyVersionHasExplicitCompleteTransportContract(t *testing.T) {
	document := policyDocumentFixture()
	profiles := AllAuthorizationProfiles()
	compilation, err := CompilePolicyDocument(document, profiles)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := CanonicalizePolicyCompilation(document, compilation, profiles)
	if err != nil {
		t.Fatal(err)
	}
	version := PolicyVersion{PolicyID: "policy-one", ID: "version-one", Document: document, ContentDigest: digest,
		ContractVersion: PolicyVersionCompiledContract, Compilation: &compilation}
	if err := ValidatePolicyVersion(version); err != nil {
		t.Fatal("complete compiled transport rejected", err)
	}
	encoded, _ := json.Marshal(version)
	var decoded PolicyVersion
	if json.Unmarshal(encoded, &decoded) != nil || ValidatePolicyVersion(decoded) != nil {
		t.Fatal("compiled version did not round trip")
	}
	for name, mutate := range map[string]func(*PolicyVersion){
		"missing contract":        func(v *PolicyVersion) { v.ContractVersion = 0 },
		"unknown contract":        func(v *PolicyVersion) { v.ContractVersion = 3 },
		"legacy with compilation": func(v *PolicyVersion) { v.ContractVersion = PolicyVersionLegacyContract },
		"missing compilation":     func(v *PolicyVersion) { v.Compilation = nil },
		"changed effect": func(v *PolicyVersion) {
			if v.Document.Statements[0].Effect == PolicyAllow {
				v.Document.Statements[0].Effect = PolicyDeny
			} else {
				v.Document.Statements[0].Effect = PolicyAllow
			}
		},
		"changed digest": func(v *PolicyVersion) { v.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"missing refs":   func(v *PolicyVersion) { v.Compilation.Profiles = nil },
		"duplicate refs": func(v *PolicyVersion) {
			v.Compilation.Profiles = append(v.Compilation.Profiles, v.Compilation.Profiles[0])
		},
		"wrong resolved action": func(v *PolicyVersion) { v.Compilation.ResolvedStatements[0].Actions[0] = "paas.unexpected.action" },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate PolicyVersion
			if json.Unmarshal(encoded, &candidate) != nil {
				t.Fatal("bad fixture")
			}
			mutate(&candidate)
			if ValidatePolicyVersion(candidate) == nil {
				t.Fatal("incomplete or changed compiled version accepted")
			}
		})
	}
	for _, wire := range []string{
		strings.Replace(string(encoded), `,"contractVersion":2`, "", 1),
		strings.Replace(string(encoded), `"contractVersion":2`, `"contractVersion":null`, 1),
		strings.Replace(string(encoded), `"contractVersion":2`, `"contractVersion":2,"contractVersion":2`, 1),
		strings.Replace(string(encoded), `"compilation":`, `"compiled":`, 1),
		strings.Replace(string(encoded), `"policyId":`, `"permit":true,"policyId":`, 1),
	} {
		if json.Unmarshal([]byte(wire), &decoded) == nil {
			t.Fatal("strict version codec accepted absent/aliased/duplicate fields")
		}
	}
	_, legacyDigest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	legacy := PolicyVersion{PolicyID: version.PolicyID, ID: "legacy-version", Document: document, ContentDigest: legacyDigest, ContractVersion: PolicyVersionLegacyContract}
	if ValidatePolicyVersion(legacy) != nil {
		t.Fatal("explicit retained document contract rejected")
	}
	legacyWire, _ := json.Marshal(legacy)
	legacyWire = bytes.Replace(legacyWire, []byte(`"contractVersion":1`), []byte(`"contractVersion":1,"compilation":null`), 1)
	if json.Unmarshal(legacyWire, &decoded) == nil {
		t.Fatal("legacy transport admitted a partial compilation")
	}
}

func TestPolicyCompilationRequestCompatibilityAcrossDeclaredTargets(t *testing.T) {
	for _, frozen := range AllAuthorizationProfiles() {
		current := cloneAuthorizationProfile(frozen)
		current.Revision++ // A new revision with the same meaning is not drift.
		_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range frozen.Actions {
			for _, effect := range []PolicyEffect{PolicyAllow, PolicyDeny} {
				document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: action.Scope,
					Statements: []PolicyStatement{{SID: "one", Effect: effect, Actions: []Action{action.Action},
						Resources: []PolicyResourceSelector{{Kind: action.ResourceKind, Match: PolicyResourceAnyInAuthority}}}}}
				compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
				if err != nil {
					t.Fatal(err)
				}
				_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
				if err != nil {
					t.Fatal(err)
				}
				for _, shape := range action.ResourceShapes {
					request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
						Action: action.Action, Resource: ResourceReference{Kind: action.ResourceKind, ID: "collection"},
						ResourceMode: shape.Mode, CollectionUsage: shape.CollectionUsage, RequestID: "request-one", CorrelationID: "correlation-one"}
					if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request); err != nil {
						t.Fatalf("same explicit meaning rejected: %s/%s/%s: %v", action.Action, effect, shape.Mode, err)
					}
				}
			}
		}
	}
}

func TestPolicyCompilationRequestSameIDDoesNotBridgeTargetModes(t *testing.T) {
	shapes := []AuthorizationResourceShape{
		{Mode: AuthorizationResourceInstance},
		{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList},
		{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate},
	}
	for originalIndex, originalShape := range shapes {
		resultKind := ResourceKind("")
		if originalShape.CollectionUsage == AuthorizationCollectionCreate {
			resultKind = "WIDGET"
		}
		frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
			declaredProfileAction("widgets.item.access", "WIDGET", AuthorityScopeTenant, resultKind, []AuthorizationResourceShape{originalShape}))
		for _, match := range []PolicyResourceMatch{PolicyResourceExact, PolicyResourceAnyInAuthority} {
			selector := PolicyResourceSelector{Kind: "WIDGET", Match: match}
			if match == PolicyResourceExact {
				selector.ID = "collection"
			}
			document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
				Statements: []PolicyStatement{{SID: "one", Effect: PolicyDeny, Actions: []Action{"widgets.item.access"},
					Resources: []PolicyResourceSelector{selector}}}}
			compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
			if err != nil {
				t.Fatal(err)
			}
			_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
			if err != nil {
				t.Fatal(err)
			}
			for currentIndex, shape := range shapes {
				current := cloneAuthorizationProfile(frozen)
				current.Revision++
				current.Actions[0].ResourceShapes = []AuthorizationResourceShape{shape}
				current.Actions[0].ResultResourceKind = ""
				if shape.CollectionUsage == AuthorizationCollectionCreate {
					current.Actions[0].ResultResourceKind = "WIDGET"
				}
				_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
				if err != nil {
					t.Fatal(err)
				}
				request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
					Action: "widgets.item.access", Resource: ResourceReference{Kind: "WIDGET", ID: "collection"},
					ResourceMode: shape.Mode, CollectionUsage: shape.CollectionUsage, RequestID: "request-one", CorrelationID: "correlation-one"}
				err = CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request)
				if (err == nil) != (originalIndex == currentIndex) {
					t.Fatalf("same opaque ID bridged different target modes: %d -> %d, %s: %v", originalIndex, currentIndex, match, err)
				}
			}
		}
	}
}

func TestPolicyCompilationRequestRejectsChangedMeaningBeforeStatementMatching(t *testing.T) {
	frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "",
			[]AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}))
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "guard", Effect: PolicyDeny, Actions: []Action{"widgets.item.read"},
			Resources:  []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourcePrefixInAuthority, ID: "unmatched-"}},
			Conditions: []PolicyCondition{{Key: ConditionIAMAccountID, Operator: PolicyStringNotEquals, Values: []string{"account-one"}}}}}}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AuthorizationProfile, *AuthorizationRequest){
		"caller": func(p *AuthorizationProfile, _ *AuthorizationRequest) { p.CallingService = "OTHER_SERVICE" },
		"kind": func(p *AuthorizationProfile, r *AuthorizationRequest) {
			p.Actions[0].ResourceKind, r.Resource.Kind = "OTHER_WIDGET", "OTHER_WIDGET"
		},
		"scope": func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].Scope, p.Actions[0].Conditions = AuthorityScopeInstallation, nil
			p.Actions[0].ResourceShapes[0].PrefixAllowed = false
		},
		"result kind": func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].ResultResourceKind = "CHILD_WIDGET"
		},
		"new collection shape": func(p *AuthorizationProfile, r *AuthorizationRequest) {
			p.Actions[0].ResourceShapes = append(p.Actions[0].ResourceShapes,
				AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList})
			r.ResourceMode, r.CollectionUsage = AuthorizationResourceCollection, AuthorizationCollectionList
		},
		"prefix removed": func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].ResourceShapes[0].PrefixAllowed = false
		},
		"used condition removed": func(p *AuthorizationProfile, _ *AuthorizationRequest) { p.Actions[0].Conditions = nil },
	} {
		t.Run(name, func(t *testing.T) {
			current := cloneAuthorizationProfile(frozen)
			current.Revision++
			request := AuthorizationRequest{Action: "widgets.item.read", Resource: ResourceReference{Kind: "WIDGET", ID: "collection"},
				ResourceMode: AuthorizationResourceInstance, RequestID: "request-one", CorrelationID: "correlation-one"}
			change(&current, &request)
			_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
			if err != nil {
				t.Fatal("fixture must be a valid new declaration, not a grammar rejection", err)
			}
			request.Profile = AuthorizationProfileReference{current.Product, current.Revision, currentDigest}
			if err := CheckAuthorizationProfileTarget(current, request.Profile, request.Action, request.Resource, request.ResourceMode, request.CollectionUsage); err != nil {
				t.Fatal("fixture must independently be a legal current request", err)
			}
			if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("incompatible old Deny disappeared before resource/condition matching", err)
			}
		})
	}
}

func TestPolicyCompilationRequestDoesNotGrowActionsOrBorrowDeclarations(t *testing.T) {
	frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "read", Effect: PolicyAllow, Actions: []Action{"widgets.item.read"},
			Resources: []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourceExact, ID: "widget-one"}}}}}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	current := cloneAuthorizationProfile(frozen)
	current.Revision++
	current.Actions[0].Conditions = nil // Unused capabilities do not reinterpret this document.
	current.Actions = append(current.Actions, declaredProfileAction("widgets.item.delete", "WIDGET", AuthorityScopeTenant, "",
		[]AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
		Action: "widgets.item.read", Resource: ResourceReference{Kind: "WIDGET", ID: "widget-one"},
		ResourceMode: AuthorizationResourceInstance, RequestID: "request-one", CorrelationID: "correlation-one"}
	for _, action := range []Action{"widgets.item.read", "widgets.item.delete"} {
		request.Action = action
		if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request); err != nil {
			t.Fatal("unrelated action or unused capability should not rewrite exact resolution", err)
		}
	}
	if slices.Contains(compilation.ResolvedStatements[0].Actions, Action("widgets.item.delete")) {
		t.Fatal("compatibility test granted a newly declared action")
	}
	// Even a nonparticipating policy must retain its entire original commitment.
	for name, change := range map[string]func(*PolicyDocument, *PolicyCompilation, *string, *[]AuthorizationProfile, *AuthorizationRequest){
		"different digest": func(_ *PolicyDocument, _ *PolicyCompilation, d *string, _ *[]AuthorizationProfile, _ *AuthorizationRequest) {
			*d = "sha256:" + strings.Repeat("0", 64)
		},
		"author effect": func(d *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, _ *AuthorizationRequest) {
			d.Statements[0].Effect = PolicyDeny
		},
		"no frozen source": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, p *[]AuthorizationProfile, _ *AuthorizationRequest) {
			*p = nil
		},
		"current not original": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, p *[]AuthorizationProfile, _ *AuthorizationRequest) {
			*p = []AuthorizationProfile{current}
		},
		"no compilation": func(_ *PolicyDocument, c *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, _ *AuthorizationRequest) {
			*c = PolicyCompilation{}
		},
		"stale request": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.Profile.Revision--
		},
		"implicit mode": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.ResourceMode = ""
		},
		"instance usage": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.CollectionUsage = AuthorizationCollectionList
		},
		"missing request identity": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.RequestID = ""
		},
		"missing correlation": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.CorrelationID = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changedDocument PolicyDocument
			var changedCompilation PolicyCompilation
			encoded, _ := json.Marshal(document)
			compiled, _ := json.Marshal(compilation)
			if json.Unmarshal(encoded, &changedDocument) != nil || json.Unmarshal(compiled, &changedCompilation) != nil {
				t.Fatal("invalid fixture")
			}
			changedDigest, profiles, changedRequest := digest, []AuthorizationProfile{frozen}, request
			change(&changedDocument, &changedCompilation, &changedDigest, &profiles, &changedRequest)
			if err := CheckPolicyCompilationRequest(changedDocument, changedCompilation, changedDigest, profiles, current, changedRequest); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("malformed commitment/request was ignored for a different action", err)
			}
		})
	}
	if after, afterDigest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen}); err != nil || after != canonical || afterDigest != digest {
		t.Fatal("current compatibility changed frozen content", err)
	}
	if _, registered := LookupAuthorizationProfile("widgets"); registered {
		t.Fatal("pure compatibility check registered a product")
	}
}

func TestPolicyCompilationAndCurrentValidationShareCapabilities(t *testing.T) {
	for _, action := range AllActions() {
		definition, _ := LookupActionDefinition(action)
		for _, effect := range []PolicyEffect{PolicyAllow, PolicyDeny} {
			document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: definition.AuthorityScope,
				Statements: []PolicyStatement{{SID: "one", Effect: effect, Actions: []Action{action}, Resources: []PolicyResourceSelector{{Kind: definition.ResourceKind, Match: PolicyResourceAnyInAuthority}}}}}
			canonical, _, currentErr := CanonicalizePolicyDocument(document)
			compiled, compileErr := CompilePolicyDocument(document, AllAuthorizationProfiles())
			if (currentErr == nil) != (compileErr == nil) {
				t.Fatalf("action %s has two policy grammars: %v / %v", action, currentErr, compileErr)
			}
			if currentErr != nil {
				continue
			}
			encoded, _, err := CanonicalizePolicyCompilation(document, compiled, AllAuthorizationProfiles())
			if err != nil || !strings.Contains(encoded, `"document":`+canonical+`,`) {
				t.Fatal("current and explicit declarations changed document encoding", err)
			}
		}
	}
}

func TestPolicyCompilationCannotBorrowCurrentProfileCapabilities(t *testing.T) {
	profile, _ := LookupAuthorizationProfile(ProductPaaS)
	document := policyDocumentFixture()
	document.Statements = document.Statements[:1]
	document.Statements[0].Actions = []Action{ActionPaaSApplicationRead}
	document.Statements[0].Resources = []PolicyResourceSelector{{Kind: ResourceApplication, Match: PolicyResourcePrefixInAuthority, ID: "app-"}}
	document.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMPrincipalID, Operator: PolicyStringEquals, Values: []string{"user-one"}}}
	if ValidatePolicyDocument(document) != nil {
		t.Fatal("current source must support the fixture capabilities")
	}
	for _, capability := range []string{"prefix", "condition", "action"} {
		t.Run(capability, func(t *testing.T) {
			restricted := cloneAuthorizationProfile(profile)
			for index := range restricted.Actions {
				if restricted.Actions[index].Action != ActionPaaSApplicationRead {
					continue
				}
				switch capability {
				case "prefix":
					restricted.Actions[index].ResourceShapes[0].PrefixAllowed = false
				case "condition":
					restricted.Actions[index].Conditions = nil
				case "action":
					restricted.Actions = append(restricted.Actions[:index], restricted.Actions[index+1:]...)
				}
				break
			}
			if _, err := CompilePolicyDocument(document, []AuthorizationProfile{restricted}); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("explicit historical capability borrowed from global current catalog")
			}
		})
	}
	large := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant}
	for index := 0; index < MaxPolicyStatements; index++ {
		statement := PolicyStatement{SID: fmt.Sprintf("statement-%d", index), Effect: PolicyAllow, Actions: []Action{ActionPaaSApplicationRead}}
		for resource := 0; resource < MaxStatementResources; resource++ {
			statement.Resources = append(statement.Resources, PolicyResourceSelector{Kind: ResourceApplication, Match: PolicyResourceExact, ID: fmt.Sprintf("app-%03d-", resource) + strings.Repeat("x", 112)})
		}
		large.Statements = append(large.Statements, statement)
	}
	if _, err := CompilePolicyDocument(large, []AuthorizationProfile{profile}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("typed compilation bypassed the original author document byte budget")
	}
}

func FuzzPolicyCompilationCanonicalRoundTrip(f *testing.F) {
	document := policyDocumentFixture()
	profiles := AllAuthorizationProfiles()
	current, known := LookupAuthorizationProfile(ProductPaaS)
	request, err := NewAuthorizationRequest(ActionPaaSApplicationRead, ResourceReference{Kind: ResourceApplication, ID: "application-one"},
		AuthorizationResourceInstance, "", "request-one", "correlation-one")
	if !known || err != nil {
		f.Fatal("invalid current request fixture", err)
	}
	compilation, err := CompilePolicyDocument(document, profiles)
	if err != nil {
		f.Fatal(err)
	}
	encoded, _ := json.Marshal(compilation)
	f.Add(string(encoded))
	f.Add(`{"compilationVersion":"1","profiles":[],"resolvedStatements":[]}`)
	f.Fuzz(func(t *testing.T, source string) {
		value, err := DecodePolicyCompilation(strings.NewReader(source), document, profiles)
		if err != nil {
			return
		}
		canonical, digest, err := CanonicalizePolicyCompilation(document, value, profiles)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		repeated, err := DecodePolicyCompilation(bytes.NewReader(wire), document, profiles)
		if err != nil {
			t.Fatal(err)
		}
		if again, againDigest, err := CanonicalizePolicyCompilation(document, repeated, profiles); err != nil || again != canonical || againDigest != digest {
			t.Fatal("immutable compilation changed after round trip", err)
		}
		if err := CheckPolicyCompilationRequest(document, repeated, digest, profiles, current, request); err != nil {
			t.Fatal("valid frozen content became incompatible after strict round trip", err)
		}
		if err := CheckPolicyCompilationRequest(document, repeated, "sha256:"+strings.Repeat("0", 64), profiles, current, request); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("request compatibility ignored the stored whole-content commitment", err)
		}
		version := PolicyVersion{PolicyID: "policy-fuzz", ID: "version-fuzz", Document: document, ContentDigest: digest,
			ContractVersion: PolicyVersionCompiledContract, Compilation: &repeated}
		encodedVersion, err := json.Marshal(version)
		if err != nil {
			t.Fatal(err)
		}
		var decodedVersion PolicyVersion
		if json.Unmarshal(encodedVersion, &decodedVersion) != nil {
			t.Fatal("compiled version wire round trip failed")
		}
		if actual, err := CanonicalizePolicyVersion(decodedVersion); err != nil || actual != canonical {
			t.Fatal("version transport lost its complete author/compilation commitment")
		}
	})
}

func TestPolicyResourcePrefixesAreLiteralAndScopeBounded(t *testing.T) {
	document := policyDocumentFixture()
	document.Statements = document.Statements[:1]
	document.Statements[0].Actions = []Action{ActionPaaSApplicationRead}
	document.Statements[0].Resources = []PolicyResourceSelector{{Kind: ResourceApplication, ID: "application-"}}
	for index := range document.Statements[0].Resources {
		document.Statements[0].Resources[index].Match = PolicyResourceMatch("PREFIX_IN_AUTHORITY")
	}
	canonical, digest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal("declared literal resource prefix rejected", err)
	}
	decoded, err := DecodePolicyDocument(strings.NewReader(canonical))
	if err != nil {
		t.Fatal(err)
	}
	if second, secondDigest, err := CanonicalizePolicyDocument(decoded); err != nil || second != canonical || secondDigest != digest {
		t.Fatal("prefix document round trip changed content")
	}
	document.Statements[0].Actions = []Action{ActionPaaSApplicationRead, ActionPaaSApplicationCreate}
	if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
		t.Fatal("instance read capability admitted collection create prefix")
	}
	document.Statements[0].Actions = []Action{ActionPaaSApplicationRead}
	for _, value := range []string{"a", "app-prod-", "A._:-", strings.Repeat("a", 128)} {
		document.Statements[0].Resources[0].ID = value
		if err := ValidatePolicyDocument(document); err != nil {
			t.Fatal("valid literal prefix rejected", err)
		}
	}
	for _, value := range []string{"", "*", "app-*", "app?", "app[ab]", "app/", "app\\", " app", "app\n", "应用", strings.Repeat("a", 129)} {
		document.Statements[0].Resources[0].ID = value
		if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
			t.Fatal("nonliteral or unbounded prefix admitted")
		}
	}
	for _, action := range AllActionDefinitions() {
		if action.ResourcePrefixAllowed {
			continue
		}
		document.Scope = action.AuthorityScope
		document.Statements[0].Actions = []Action{action.Action}
		document.Statements[0].Resources = []PolicyResourceSelector{{Kind: action.ResourceKind, Match: "PREFIX_IN_AUTHORITY", ID: "resource-"}}
		if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
			t.Fatal("prefix crossed tenant policy scope")
		}
	}
}

func TestPolicyIdentityStringConditionsAreBoundedSets(t *testing.T) {
	plain, _, err := CanonicalizePolicyDocument(policyDocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	withConditions := func(value string) string {
		return strings.Replace(plain, `"resources":`, `"conditions":`+value+`,"resources":`, 1)
	}
	valid := `[{"key":"iam.account-id","operator":"STRING_EQUALS","values":["account-b","account-a"]},{"key":"iam.principal-id","operator":"STRING_EQUALS","values":["principal-z","principal-a"]},{"key":"iam.principal-id","operator":"STRING_NOT_EQUALS","values":["principal-denied"]}]`
	document, err := DecodePolicyDocument(strings.NewReader(withConditions(valid)))
	if err != nil {
		t.Fatal("declared identity conditions rejected", err)
	}
	before, _ := json.Marshal(document)
	canonical, digest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(document)
	if !bytes.Equal(before, after) {
		t.Fatal("string set normalization mutated caller input")
	}
	reordered, err := DecodePolicyDocument(strings.NewReader(withConditions(strings.ReplaceAll(strings.ReplaceAll(valid, `"account-b","account-a"`, `"account-a","account-b"`), `"principal-z","principal-a"`, `"principal-a","principal-z"`))))
	if err != nil {
		t.Fatal(err)
	}
	if other, otherDigest, err := CanonicalizePolicyDocument(reordered); err != nil || canonical != other || digest != otherDigest {
		t.Fatal("string set order changed canonical permission content")
	}
	tooMany := make([]string, 17)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("principal-%d", index)
	}
	tooManyJSON, _ := json.Marshal(tooMany)
	for _, invalid := range []string{
		strings.Replace(valid, "iam.account-id", "caller.account-id", 1),
		strings.Replace(valid, "iam.account-id", "iam.principal-id", 1),
		strings.Replace(valid, "STRING_NOT_EQUALS", "STRING_EQUALS", 1),
		strings.Replace(valid, "STRING_NOT_EQUALS", "DATE_LESS_THAN", 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":[]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":null`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":[1]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":[""]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":["principal-*"]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":[" principal-denied"]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":["principal-denied","principal-denied"]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":`+string(tooManyJSON), 1),
		strings.Replace(valid, `"key":`, `"source":"CALLER","key":`, 1),
	} {
		if _, err := DecodePolicyDocument(strings.NewReader(withConditions(invalid))); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid identity condition admitted")
		}
	}
	for _, action := range AllActionDefinitions() {
		for _, key := range []ConditionKey{"iam.account-id", "iam.principal-id"} {
			definition, found := LookupActionConditionDefinition(action.Action, key)
			if found != (action.AuthorityScope == AuthorityScopeTenant) || found && (definition.Source != "IAM_AUTHENTICATED_IDENTITY" || definition.ValueType != "STRING") {
				t.Fatal("identity condition source crossed a scope")
			}
		}
	}
}

func TestPolicyTimeConditionsAreStrictAndPreserveUnconditionalContent(t *testing.T) {
	for _, action := range AllActionDefinitions() {
		definition, found := LookupActionConditionDefinition(action.Action, ConditionIAMCurrentTime)
		if found != (action.AuthorityScope == AuthorityScopeTenant) || (found && (definition.Source != ConditionIAMTransactionTime || definition.ValueType != ConditionTime)) {
			t.Fatal("time source declaration crossed a scope")
		}
		if _, found := LookupActionConditionDefinition(action.Action, "caller.time"); found {
			t.Fatal("unknown condition declared")
		}
	}
	if _, found := LookupActionConditionDefinition("unknown.action", ConditionIAMCurrentTime); found {
		t.Fatal("unknown action acquired time condition support")
	}
	original, digest, err := CanonicalizePolicyDocument(policyDocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	withConditions := func(conditions string) string {
		return strings.Replace(original, `"resources":`, `"conditions":`+conditions+`,"resources":`, 1)
	}
	valid := `[{"key":"iam.current-time","operator":"DATE_GREATER_THAN_EQUALS","values":["2026-09-14T00:00:00Z"]},{"key":"iam.current-time","operator":"DATE_LESS_THAN","values":["2026-09-15T00:00:00Z"]}]`
	document, err := DecodePolicyDocument(strings.NewReader(withConditions(valid)))
	if err != nil {
		t.Fatal("declared time window rejected", err)
	}
	before, _ := json.Marshal(document)
	encoded, _, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(document)
	if !bytes.Equal(before, after) {
		t.Fatal("condition canonicalization mutated caller input")
	}
	reversed := document
	reversed.Statements = append([]PolicyStatement(nil), document.Statements...)
	reversed.Statements[0].Conditions = append([]PolicyCondition(nil), document.Statements[0].Conditions...)
	reversed.Statements[0].Conditions[0], reversed.Statements[0].Conditions[1] = reversed.Statements[0].Conditions[1], reversed.Statements[0].Conditions[0]
	if normalized, _, err := CanonicalizePolicyDocument(reversed); err != nil || normalized != encoded {
		t.Fatal("condition AND order changed canonical authority")
	}
	roundTrip, err := DecodePolicyDocument(strings.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := CanonicalizePolicyDocument(roundTrip)
	if err != nil || canonical != encoded {
		t.Fatal("condition canonical round trip changed content")
	}
	for _, invalid := range []string{
		`null`, `[]`,
		strings.Replace(valid, "iam.current-time", "request.current-time", 1),
		strings.Replace(valid, "DATE_LESS_THAN", "DATE_NOT_EQUALS", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-09-14T00:00:00Z", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-09-13T00:00:00Z", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-09-15T00:00:00+00:00", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-09-15T00:00:00.0000001Z", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-02-30T00:00:00Z", 1),
		strings.Replace(valid, `"values":["2026-09-14T00:00:00Z"]`, `"values":[]`, 1),
		strings.Replace(valid, `"values":["2026-09-14T00:00:00Z"]`, `"values":[123]`, 1),
		strings.Replace(valid, `"values":["2026-09-14T00:00:00Z"]`, `"values":["2026-09-14T00:00:00Z","2026-09-13T00:00:00Z"]`, 1),
		strings.Replace(valid, `"key":`, `"source":"CALLER","key":`, 1),
		strings.Replace(valid, "DATE_LESS_THAN", "DATE_GREATER_THAN_EQUALS", 1),
	} {
		if _, err := DecodePolicyDocument(strings.NewReader(withConditions(invalid))); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid time condition admitted")
		}
	}
	plain, err := DecodePolicyDocument(strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	retained, retainedDigest, err := CanonicalizePolicyDocument(plain)
	if err != nil || retained != original || retainedDigest != digest || strings.Contains(retained, "conditions") {
		t.Fatal("unconditional canonical content changed")
	}
}

func TestPolicyContentCanonicalizationIsStableAndDoesNotMutateTheDocument(t *testing.T) {
	document := policyDocumentFixture()
	before, _ := json.Marshal(document)
	encoded, digest, err := CanonicalizePolicyDocument(document)
	if err != nil || ValidateDigest("policy digest", digest) != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	after, _ := json.Marshal(document)
	if !bytes.Equal(before, after) {
		t.Fatal("canonicalization mutated caller-owned collections")
	}
	document.Statements[0], document.Statements[1] = document.Statements[1], document.Statements[0]
	document.Statements[1].Actions[0], document.Statements[1].Actions[1] = document.Statements[1].Actions[1], document.Statements[1].Actions[0]
	document.Statements[1].Resources[0], document.Statements[1].Resources[1] = document.Statements[1].Resources[1], document.Statements[1].Resources[0]
	if reordered, reorderedDigest, err := CanonicalizePolicyDocument(document); err != nil || reordered != encoded || reorderedDigest != digest {
		t.Fatalf("set ordering changed canonical policy content: %v", err)
	}
	decoded, err := DecodePolicyDocument(strings.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	version := PolicyVersion{PolicyID: "policy-example", ID: "version-first", Document: decoded, ContentDigest: digest, ContractVersion: PolicyVersionLegacyContract}
	if ValidatePolicyVersion(version) != nil {
		t.Fatal("valid immutable version rejected")
	}
	version.Document.Statements[0].Effect = PolicyAllow
	if ValidatePolicyVersion(version) == nil {
		t.Fatal("changed policy content retained its old digest")
	}
	if _, changedDigest, err := CanonicalizePolicyDocument(version.Document); err != nil || changedDigest == digest {
		t.Fatal("effect change did not change the digest")
	}
}

func TestPolicyLanguageRejectsUnsupportedOrAmbiguousAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*PolicyDocument){
		"language":                   func(v *PolicyDocument) { v.LanguageVersion = "future" },
		"scope":                      func(v *PolicyDocument) { v.Scope = "ACCOUNT_FROM_REQUEST" },
		"empty statements":           func(v *PolicyDocument) { v.Statements = nil },
		"empty sid":                  func(v *PolicyDocument) { v.Statements[0].SID = "" },
		"duplicate sid":              func(v *PolicyDocument) { v.Statements[0].SID = v.Statements[1].SID },
		"unknown effect":             func(v *PolicyDocument) { v.Statements[0].Effect = "PERMIT" },
		"empty actions":              func(v *PolicyDocument) { v.Statements[0].Actions = nil },
		"unknown action":             func(v *PolicyDocument) { v.Statements[0].Actions[0] = "paas.*" },
		"duplicate action":           func(v *PolicyDocument) { v.Statements[0].Actions[0] = v.Statements[0].Actions[1] },
		"mixed scope":                func(v *PolicyDocument) { v.Statements[0].Actions[0] = ActionPaaSExecutionTargetRegister },
		"missing required resource":  func(v *PolicyDocument) { v.Statements[0].Resources = v.Statements[0].Resources[:1] },
		"extra resource kind":        func(v *PolicyDocument) { v.Statements[0].Resources[0].Kind = ResourcePrincipal },
		"unknown match":              func(v *PolicyDocument) { v.Statements[0].Resources[0].Match = "PREFIX" },
		"exact wildcard":             func(v *PolicyDocument) { v.Statements[0].Resources[0].ID = "*" },
		"missing exact id":           func(v *PolicyDocument) { v.Statements[0].Resources[0].ID = "" },
		"authority wildcard with id": func(v *PolicyDocument) { v.Statements[1].Resources[0].ID = "selected-by-caller" },
		"duplicate selector": func(v *PolicyDocument) {
			v.Statements[0].Resources = append(v.Statements[0].Resources, v.Statements[0].Resources[0])
		},
		"too many actions": func(v *PolicyDocument) { v.Statements[0].Actions = make([]Action, MaxStatementActions+1) },
		"too many resources": func(v *PolicyDocument) {
			v.Statements[0].Resources = make([]PolicyResourceSelector, MaxStatementResources+1)
		},
		"too many statements": func(v *PolicyDocument) { v.Statements = make([]PolicyStatement, MaxPolicyStatements+1) },
	} {
		t.Run(name, func(t *testing.T) {
			document := policyDocumentFixture()
			mutate(&document)
			if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
				t.Fatal("invalid policy accepted")
			}
			if encoded, digest, err := CanonicalizePolicyDocument(document); !errors.Is(err, ErrInvalidPolicy) || encoded != "" || digest != "" {
				t.Fatal("invalid policy acquired canonical authority")
			}
		})
	}
	encoded, _, _ := CanonicalizePolicyDocument(policyDocumentFixture())
	for _, forged := range []string{
		strings.Replace(encoded, `"languageVersion":`, `"languageVersion":"future","languageVersion":`, 1),
		strings.Replace(encoded, `"effect":`, `"conditions":{"callerAdmin":true},"effect":`, 1),
		strings.Replace(encoded, `"kind":"APPLICATION"`, `"kind":"PRINCIPAL","kind":"APPLICATION"`, 1),
		strings.Replace(encoded, `"scope":`, `"tenantId":"other","scope":`, 1),
		strings.Replace(encoded, `"actions":[`, `"actions":[null,`, 1),
		strings.Replace(encoded, `"match":"ANY_IN_AUTHORITY"`, `"match":"ANY_IN_AUTHORITY","id":null`, 1),
		strings.Replace(encoded, `"match":"ANY_IN_AUTHORITY"`, `"match":"ANY_IN_AUTHORITY","id":""`, 1),
		encoded + `{}`,
		strings.Repeat(" ", int(MaxPolicyBytes)) + encoded,
	} {
		if _, err := DecodePolicyDocument(strings.NewReader(forged)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("ambiguous/unsupported wire document accepted")
		}
	}
}

func TestPolicyDiagnosticsLocateRejectedAuthorityWithoutEchoingInput(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*PolicyDocument)
		code    PolicyValidationCode
		pointer string
	}{
		{"language", func(v *PolicyDocument) { v.LanguageVersion = "untrusted-private-input" }, PolicyUnsupported, "/languageVersion"},
		{"scope", func(v *PolicyDocument) { v.Scope = "untrusted-private-input" }, PolicyInvalidValue, "/scope"},
		{"empty statements", func(v *PolicyDocument) { v.Statements = nil }, PolicyLimitExceeded, "/statements"},
		{"statement limit", func(v *PolicyDocument) { v.Statements = make([]PolicyStatement, MaxPolicyStatements+1) }, PolicyLimitExceeded, "/statements"},
		{"sid", func(v *PolicyDocument) { v.Statements[0].SID = "bad/input" }, PolicyInvalidValue, "/statements/0/sid"},
		{"duplicate sid", func(v *PolicyDocument) { v.Statements[1].SID = v.Statements[0].SID }, PolicyDuplicate, "/statements/1/sid"},
		{"effect", func(v *PolicyDocument) { v.Statements[0].Effect = "untrusted-private-input" }, PolicyInvalidValue, "/statements/0/effect"},
		{"empty actions", func(v *PolicyDocument) { v.Statements[0].Actions = nil }, PolicyLimitExceeded, "/statements/0/actions"},
		{"action limit", func(v *PolicyDocument) { v.Statements[0].Actions = make([]Action, MaxStatementActions+1) }, PolicyLimitExceeded, "/statements/0/actions"},
		{"empty resources", func(v *PolicyDocument) { v.Statements[0].Resources = nil }, PolicyLimitExceeded, "/statements/0/resources"},
		{"resource limit", func(v *PolicyDocument) {
			v.Statements[0].Resources = make([]PolicyResourceSelector, MaxStatementResources+1)
		}, PolicyLimitExceeded, "/statements/0/resources"},
		{"unknown action", func(v *PolicyDocument) { v.Statements[0].Actions[0] = "untrusted-private-input" }, PolicyUnsupported, "/statements/0/actions/0"},
		{"scope mismatch", func(v *PolicyDocument) { v.Statements[0].Actions[0] = ActionPaaSExecutionTargetRegister }, PolicyScopeMismatch, "/statements/0/actions/0"},
		{"duplicate action", func(v *PolicyDocument) { v.Statements[0].Actions[1] = v.Statements[0].Actions[0] }, PolicyDuplicate, "/statements/0/actions/1"},
		{"resource kind", func(v *PolicyDocument) { v.Statements[0].Resources[0].Kind = ResourceUser }, PolicyResourceMismatch, "/statements/0/resources/0/kind"},
		{"resource match", func(v *PolicyDocument) { v.Statements[0].Resources[0].Match = "untrusted-private-input" }, PolicyUnsupported, "/statements/0/resources/0/match"},
		{"resource id", func(v *PolicyDocument) { v.Statements[0].Resources[0].ID = "bad/input" }, PolicyInvalidValue, "/statements/0/resources/0/id"},
		{"authority id", func(v *PolicyDocument) { v.Statements[1].Resources[0].ID = "untrusted-private-input" }, PolicyInvalidValue, "/statements/1/resources/0/id"},
		{"duplicate resource", func(v *PolicyDocument) {
			v.Statements[0].Resources = append(v.Statements[0].Resources, v.Statements[0].Resources[0])
		}, PolicyDuplicate, "/statements/0/resources/2"},
		{"missing resource", func(v *PolicyDocument) { v.Statements[0].Resources = v.Statements[0].Resources[:1] }, PolicyResourceMismatch, "/statements/0/actions/1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := policyDocumentFixture()
			test.mutate(&document)
			before, _ := json.Marshal(document)
			for range 3 {
				canonical, digest, encodingError := CanonicalizePolicyDocument(document)
				if canonical != "" || digest != "" {
					t.Fatal("rejected document acquired canonical authority")
				}
				for _, err := range []error{ValidatePolicyDocument(document), encodingError} {
					var diagnostic *PolicyValidationError
					if !errors.Is(err, ErrInvalidPolicy) || !errors.As(err, &diagnostic) || diagnostic.Code != test.code || diagnostic.Pointer != test.pointer {
						t.Fatalf("unexpected safe diagnostic: %#v", diagnostic)
					}
					if err.Error() != ErrInvalidPolicy.Error() {
						t.Fatal("ordinary error exposed diagnostic or input")
					}
				}
			}
			after, _ := json.Marshal(document)
			if !bytes.Equal(before, after) {
				t.Fatal("analysis changed the submitted policy")
			}
		})
	}
}

func TestPolicyDecodeDiagnosticsPreserveStrictDocumentRejection(t *testing.T) {
	valid, _, err := CanonicalizePolicyDocument(policyDocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		`null`, `[]`, `{"languageVersion":`, valid + `{}`,
		strings.Replace(valid, `"scope":`, `"scope":"TENANT","scope":`, 1),
		strings.Replace(valid, `"scope":`, `"private-input":"must-not-be-echoed","scope":`, 1),
		strings.Replace(valid, `"actions":[`, `"actions":[{},`, 1),
		strings.Replace(valid, `"match":"ANY_IN_AUTHORITY"`, `"match":"ANY_IN_AUTHORITY","id":null`, 1),
	} {
		_, err := DecodePolicyDocument(strings.NewReader(source))
		var diagnostic *PolicyValidationError
		if !errors.Is(err, ErrInvalidPolicy) || !errors.As(err, &diagnostic) || diagnostic.Code != PolicyInvalidDocument || diagnostic.Pointer != "" {
			t.Fatalf("ambiguous JSON was accepted or mislocated: %#v", diagnostic)
		}
		if err.Error() != ErrInvalidPolicy.Error() {
			t.Fatal("malformed JSON leaked native decoder details")
		}
	}
	_, err = DecodePolicyDocument(strings.NewReader(strings.Repeat(" ", int(MaxPolicyBytes)) + valid))
	var diagnostic *PolicyValidationError
	if !errors.As(err, &diagnostic) || diagnostic.Code != PolicyLimitExceeded || diagnostic.Pointer != "" {
		t.Fatal("raw input size limit did not produce a bounded root diagnostic")
	}
	large := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant}
	for i := range MaxPolicyStatements {
		statement := PolicyStatement{SID: fmt.Sprintf("statement-%d", i), Effect: PolicyAllow, Actions: []Action{ActionPaaSApplicationRead}}
		for j := range MaxStatementResources {
			statement.Resources = append(statement.Resources, PolicyResourceSelector{Kind: ResourceApplication, Match: PolicyResourceExact, ID: strings.Repeat("r", 120) + fmt.Sprintf("%03d", j)})
		}
		large.Statements = append(large.Statements, statement)
	}
	canonical, digest, encodingError := CanonicalizePolicyDocument(large)
	if canonical != "" || digest != "" {
		t.Fatal("oversized typed document acquired canonical authority")
	}
	for _, err := range []error{ValidatePolicyDocument(large), encodingError} {
		if !errors.As(err, &diagnostic) || diagnostic.Code != PolicyLimitExceeded || diagnostic.Pointer != "" {
			t.Fatal("typed document size limit did not produce a root diagnostic")
		}
	}
}

func FuzzPolicyDocumentCanonicalRoundTrip(f *testing.F) {
	valid, _, _ := CanonicalizePolicyDocument(policyDocumentFixture())
	f.Add(valid)
	timed := policyDocumentFixture()
	timed.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMCurrentTime, Operator: PolicyDateLessThan, Values: []string{"2026-09-15T00:00:00Z"}}}
	timedCanonical, _, err := CanonicalizePolicyDocument(timed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(timedCanonical)
	identity := policyDocumentFixture()
	identity.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMPrincipalID, Operator: PolicyStringNotEquals, Values: []string{"user-z", "user-a"}}}
	identityCanonical, _, err := CanonicalizePolicyDocument(identity)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(identityCanonical)
	prefix := policyDocumentFixture()
	prefix.Statements = prefix.Statements[:1]
	prefix.Statements[0].Actions = []Action{ActionPaaSApplicationRead}
	prefix.Statements[0].Resources = []PolicyResourceSelector{{Kind: ResourceApplication, Match: PolicyResourcePrefixInAuthority, ID: "application-"}}
	prefixCanonical, _, err := CanonicalizePolicyDocument(prefix)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(prefixCanonical)
	f.Add(`{"languageVersion":"1","scope":"TENANT","statements":[]}`)
	f.Add(`{"statements":null}`)
	f.Fuzz(func(t *testing.T, source string) {
		document, err := DecodePolicyDocument(strings.NewReader(source))
		if err != nil {
			var diagnostic *PolicyValidationError
			if !errors.Is(err, ErrInvalidPolicy) || !errors.As(err, &diagnostic) || err.Error() != ErrInvalidPolicy.Error() {
				t.Fatal("rejected input lacks a safe policy diagnostic")
			}
			return
		}
		canonical, digest, err := CanonicalizePolicyDocument(document)
		if err != nil {
			t.Fatal(err)
		}
		repeated, err := DecodePolicyDocument(strings.NewReader(canonical))
		if err != nil {
			t.Fatal(err)
		}
		if again, againDigest, err := CanonicalizePolicyDocument(repeated); err != nil || canonical != again || digest != againDigest {
			t.Fatal("accepted policy has unstable canonical content")
		}
	})
}

func TestPolicyMetadataAndAttachmentOwnershipContracts(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	policy := Policy{APIVersion: APIVersion, Kind: "Policy", ID: "policy-example", Management: PolicyCustomerManaged,
		AccountID: "account-a", DisplayName: "Application reader", Scope: AuthorityScopeTenant, Status: PolicyActive,
		DefaultVersionID: "version-one", ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	attachment := PolicyAttachment{APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-example", AccountID: "account-a",
		Target: PolicyAttachmentTarget{Kind: PolicyTargetUser, ID: "user-example"}, PolicyID: policy.ID,
		Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	if ValidatePolicy(policy) != nil || ValidatePolicyAttachment(attachment) != nil {
		t.Fatal("valid policy relationship rejected")
	}
	document := policyDocumentFixture()
	_, digest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	detail := PolicyDetail{APIVersion: APIVersion, Kind: "PolicyDetail", Policy: policy,
		Version: PolicyVersion{PolicyID: policy.ID, ID: policy.DefaultVersionID, Document: document, ContentDigest: digest, ContractVersion: PolicyVersionLegacyContract}}
	if ValidatePolicyDetail(detail) != nil {
		t.Fatal("valid policy detail rejected")
	}
	for name, mutate := range map[string]func(*PolicyDetail){
		"wrong version owner": func(v *PolicyDetail) { v.Version.PolicyID = "another-policy" },
		"wrong default":       func(v *PolicyDetail) { v.Policy.DefaultVersionID = "another-version" },
		"wrong digest":        func(v *PolicyDetail) { v.Version.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"retired detail":      func(v *PolicyDetail) { v.Policy.Status = PolicyRetired },
		"unknown wrapper":     func(v *PolicyDetail) { v.Kind = "PolicyPermit" },
	} {
		t.Run(name, func(t *testing.T) {
			value := detail
			mutate(&value)
			if ValidatePolicyDetail(value) == nil {
				t.Fatal("inconsistent policy detail accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Policy){
		"missing owner":             func(v *Policy) { v.AccountID = "" },
		"customer system namespace": func(v *Policy) { v.ID = SystemPolicyPlatformOperator },
		"customer platform scope":   func(v *Policy) { v.Scope = AuthorityScopeInstallation },
		"customer probe scope":      func(v *Policy) { v.Scope = AuthorityScopeInstallationProbe },
		"unknown manager":           func(v *Policy) { v.Management = "PUBLIC" },
		"unknown status":            func(v *Policy) { v.Status = "DELETED" },
		"no default":                func(v *Policy) { v.DefaultVersionID = "" },
		"zero revision":             func(v *Policy) { v.ResourceVersion = 0 },
		"invalid chronology":        func(v *Policy) { v.UpdatedAt = now.Add(-time.Second) },
		"unsafe display name":       func(v *Policy) { v.DisplayName = "reader\nowner" },
	} {
		t.Run(name, func(t *testing.T) {
			value := policy
			mutate(&value)
			if !errors.Is(ValidatePolicy(value), ErrInvalidPolicy) {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	system := policy
	system.Management, system.ID, system.AccountID, system.Scope = PolicySystemManaged, SystemPolicyPlatformOperator, "", AuthorityScopeInstallation
	if ValidatePolicy(system) != nil {
		t.Fatal("system metadata rejected")
	}
	system.AccountID = "account-a"
	if ValidatePolicy(system) == nil {
		t.Fatal("system metadata accepted a customer owner")
	}
	for name, mutate := range map[string]func(*PolicyAttachment){
		"missing account":               func(v *PolicyAttachment) { v.AccountID = "" },
		"unknown target":                func(v *PolicyAttachment) { v.Target.Kind = "ROOT" },
		"missing target":                func(v *PolicyAttachment) { v.Target.ID = "" },
		"mixed scope":                   func(v *PolicyAttachment) { v.InstallationID = "installation-a" },
		"platform without installation": func(v *PolicyAttachment) { v.Scope = AuthorityScopeInstallation },
		"unknown scope":                 func(v *PolicyAttachment) { v.Scope = "GLOBAL" },
		"unversioned revocation":        func(v *PolicyAttachment) { v.RevokedAt = &now },
		"revocation time differs":       func(v *PolicyAttachment) { at := now.Add(time.Second); v.RevokedAt, v.ResourceVersion = &at, 2 },
	} {
		t.Run(name, func(t *testing.T) {
			value := attachment
			mutate(&value)
			if ValidatePolicyAttachment(value) == nil {
				t.Fatal("invalid attachment accepted")
			}
		})
	}
	for _, kind := range []PolicyAttachmentTargetKind{PolicyTargetUser, PolicyTargetService, PolicyTargetGroup, PolicyTargetRole} {
		value := attachment
		value.Target.Kind = kind
		if ValidatePolicyAttachment(value) != nil {
			t.Fatal("tenant target contract rejected")
		}
		value.Scope, value.InstallationID = AuthorityScopeInstallation, "installation-a"
		if (ValidatePolicyAttachment(value) == nil) != (kind == PolicyTargetUser) {
			t.Fatal("platform attachment must target a USER")
		}
		value.Scope = AuthorityScopeInstallationProbe
		if (ValidatePolicyAttachment(value) == nil) != (kind == PolicyTargetService) {
			t.Fatal("probe attachment must target a service")
		}
	}
	attachment.RevokedAt, attachment.ResourceVersion = &now, 2
	if ValidatePolicyAttachment(attachment) != nil {
		t.Fatal("immutable revoked relationship rejected")
	}
	policy.Status = PolicyRetired
	if ValidatePolicy(policy) != nil {
		t.Fatal("retired metadata rejected")
	}
	policyJSON, _ := json.Marshal(policy)
	attachmentJSON, _ := json.Marshal(attachment)
	if got, err := DecodePolicy(bytes.NewReader(policyJSON)); err != nil || got.ID != policy.ID {
		t.Fatal("metadata round trip failed")
	}
	if got, err := DecodePolicyAttachment(bytes.NewReader(attachmentJSON)); err != nil || got.RevokedAt == nil {
		t.Fatal("revocation round trip failed")
	}
	for _, prefix := range []string{`{"unknown":true,`, `{"id":"injected",`} {
		if _, err := DecodePolicy(strings.NewReader(prefix + string(policyJSON[1:]))); err == nil {
			t.Fatal("policy accepted unknown/duplicate input")
		}
		if _, err := DecodePolicyAttachment(strings.NewReader(prefix + string(attachmentJSON[1:]))); err == nil {
			t.Fatal("attachment accepted unknown/duplicate input")
		}
	}
}

func TestCurrentIdentityUsesOnlyItsLivePolicyGrantSources(t *testing.T) {
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	blocked := func(action Action, kind ResourceKind, id string) ActionCapability {
		return ActionCapability{Action: action, Resource: ResourceReference{Kind: kind, ID: id}, RestrictionReason: CapabilityAuthorityRequired}
	}
	identity := CurrentIdentity{APIVersion: APIVersion, Kind: "CurrentIdentity",
		PermissionBoundary: UserPermissionBoundary{APIVersion: APIVersion, Kind: "UserPermissionBoundary", AccountID: "account-a", UserID: "user-a", ResourceVersion: 1},
		Account: Account{APIVersion: APIVersion, Kind: "Account", ID: "account-a", DisplayName: "Account A",
			Status: AccountActive, RootIdentity: RootIdentity{PrincipalID: "user-a", LoginName: "admin"},
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		User: User{APIVersion: APIVersion, Kind: "User", ID: "user-a", AccountID: "account-a",
			LoginName: "admin", DisplayName: "Administrator", Status: PrincipalActive,
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		IdentityKind: IdentityRoot,
		PolicySources: []PolicyGrantSource{{Kind: PolicyGrantDirect, Attachment: PolicyAttachment{
			APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-a",
			AccountID: "account-a", Target: PolicyAttachmentTarget{Kind: PolicyTargetUser, ID: "user-a"},
			PolicyID: SystemPolicyAccountAdministrator, Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}}},
		Capabilities: []ActionCapability{
			blocked(ActionIAMAccountCreate, ResourceAccount, "collection"),
			blocked(ActionIAMAccountRead, ResourceAccount, "collection"),
			blocked(ActionIAMAccountAliasSet, ResourceAccount, "account-a"),
			blocked(ActionIAMUserList, ResourceAccount, "account-a"),
			blocked(ActionIAMUserCreate, ResourceAccount, "account-a"),
			blocked(ActionIAMPolicyList, ResourceAccount, "account-a"),
			blocked(ActionIAMGroupList, ResourceAccount, "account-a"),
			blocked(ActionIAMGroupCreate, ResourceAccount, "account-a"),
		}}
	if ValidateCurrentIdentity(identity) != nil {
		t.Fatal("current policy identity rejected")
	}
	for name, mutate := range map[string]func(*CurrentIdentity){
		"missing snapshot":        func(v *CurrentIdentity) { v.PolicySources = nil },
		"missing boundary":        func(v *CurrentIdentity) { v.PermissionBoundary = UserPermissionBoundary{} },
		"foreign boundary":        func(v *CurrentIdentity) { v.PermissionBoundary.AccountID = "account-b" },
		"stale boundary revision": func(v *CurrentIdentity) { v.PermissionBoundary.ResourceVersion++ },
		"another account":         func(v *CurrentIdentity) { v.PolicySources[0].Attachment.AccountID = "account-b" },
		"another user":            func(v *CurrentIdentity) { v.PolicySources[0].Attachment.Target.ID = "user-b" },
		"service carrier":         func(v *CurrentIdentity) { v.PolicySources[0].Attachment.Target.Kind = PolicyTargetService },
		"duplicate attachment":    func(v *CurrentIdentity) { v.PolicySources = append(v.PolicySources, v.PolicySources[0]) },
		"revoked attachment": func(v *CurrentIdentity) {
			v.PolicySources[0].Attachment.RevokedAt = &now
			v.PolicySources[0].Attachment.ResourceVersion = 2
		},
		"missing capability": func(v *CurrentIdentity) { v.Capabilities = v.Capabilities[1:] },
		"wrong capability target": func(v *CurrentIdentity) {
			v.Capabilities[0].Resource.ID = "account-a"
		},
		"available with restriction": func(v *CurrentIdentity) {
			v.Capabilities[0].Available = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := identity
			value.PolicySources = append([]PolicyGrantSource{}, identity.PolicySources...)
			value.Capabilities = append([]ActionCapability{}, identity.Capabilities...)
			mutate(&value)
			if ValidateCurrentIdentity(value) == nil {
				t.Fatal("invalid current attachment relationship accepted")
			}
		})
	}
	membership := GroupMembership{APIVersion: APIVersion, Kind: "GroupMembership", ID: "membership-a",
		AccountID: "account-a", GroupID: "group-a", UserID: "user-a", CreatedBy: "user-admin",
		ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	groupIdentity := identity
	groupIdentity.PolicySources = []PolicyGrantSource{{Kind: PolicyGrantGroup, Attachment: PolicyAttachment{
		APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-group", AccountID: "account-a",
		Target: PolicyAttachmentTarget{Kind: PolicyTargetGroup, ID: "group-a"}, PolicyID: SystemPolicyPaaSViewer,
		Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}, Membership: &membership}}
	if ValidateCurrentIdentity(groupIdentity) == nil {
		t.Fatal("root identity accepted a group inheritance path")
	}
	groupIdentity.Account.RootIdentity = RootIdentity{PrincipalID: "root-user", LoginName: "owner"}
	groupIdentity.IdentityKind = IdentityUser
	if ValidateCurrentIdentity(groupIdentity) != nil {
		t.Fatal("current group policy source rejected")
	}
	wrongMembership := membership
	wrongMembership.UserID = "user-b"
	groupIdentity.PolicySources[0].Membership = &wrongMembership
	if ValidateCurrentIdentity(groupIdentity) == nil {
		t.Fatal("group source for another user accepted")
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(encoded, &wire) != nil {
		t.Fatal("decode identity fixture")
	}
	wire["roles"] = json.RawMessage(`[]`)
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CurrentIdentity
	if DecodeRequest(bytes.NewReader(encoded), &decoded) == nil {
		t.Fatal("old roles field remained as a parallel current identity contract")
	}
	delete(wire, "roles")
	wire["policyAttachments"] = json.RawMessage(`[]`)
	encoded, err = json.Marshal(wire)
	if err != nil || DecodeRequest(bytes.NewReader(encoded), &decoded) == nil {
		t.Fatal("old direct-only policy attachments remained as a parallel current identity contract")
	}
	delete(wire, "policyAttachments")
	wire["canCreateAccounts"] = json.RawMessage(`true`)
	encoded, err = json.Marshal(wire)
	if err != nil || DecodeRequest(bytes.NewReader(encoded), &decoded) == nil {
		t.Fatal("old account creation hint remained as a parallel capability contract")
	}
}

func TestGroupAccessRequiresExactRelationsAndCapabilities(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	group := Group{APIVersion: APIVersion, Kind: "Group", AccountID: "account-a", ID: "group-a", Name: "Operators",
		ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	attachment := PolicyAttachment{APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-a", AccountID: group.AccountID,
		Target: PolicyAttachmentTarget{Kind: PolicyTargetGroup, ID: string(group.ID)}, PolicyID: SystemPolicyPaaSViewer,
		Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	access := GroupAccess{Group: group, PolicyAttachments: []PolicyAttachment{attachment}}
	for _, action := range []Action{ActionIAMGroupDelete, ActionIAMGroupMembershipCreate, ActionIAMGroupMembershipList,
		ActionIAMGroupPolicyAttachmentCreate, ActionIAMGroupRead, ActionIAMGroupUpdate} {
		access.Capabilities = append(access.Capabilities, ActionCapability{Action: action, Resource: ResourceReference{Kind: ResourceGroup, ID: string(group.ID)}, Available: true})
	}
	access.Capabilities = append(access.Capabilities, ActionCapability{Action: ActionIAMGroupPolicyAttachmentRevoke,
		Resource: ResourceReference{Kind: ResourcePolicyAttachment, ID: string(attachment.ID)}, RestrictionReason: CapabilityAuthorityRequired})
	if ValidateGroupAccess(access) != nil {
		t.Fatal("valid mixed available/unavailable group capabilities rejected")
	}
	for name, mutate := range map[string]func(*GroupAccess){
		"missing capability":          func(v *GroupAccess) { v.Capabilities = v.Capabilities[1:] },
		"duplicate capability":        func(v *GroupAccess) { v.Capabilities = append(v.Capabilities, v.Capabilities[0]) },
		"unrelated capability":        func(v *GroupAccess) { v.Capabilities[0].Action = ActionIAMUserDelete },
		"wrong target":                func(v *GroupAccess) { v.Capabilities[0].Resource.ID = "other-group" },
		"missing restriction":         func(v *GroupAccess) { v.Capabilities[len(v.Capabilities)-1].RestrictionReason = "" },
		"missing attachment snapshot": func(v *GroupAccess) { v.PolicyAttachments = nil },
		"foreign attachment":          func(v *GroupAccess) { v.PolicyAttachments[0].AccountID = "account-b" },
		"user attachment":             func(v *GroupAccess) { v.PolicyAttachments[0].Target.Kind = PolicyTargetUser },
		"different group":             func(v *GroupAccess) { v.PolicyAttachments[0].Target.ID = "group-b" },
		"revoked attachment": func(v *GroupAccess) {
			v.PolicyAttachments[0].RevokedAt = &now
			v.PolicyAttachments[0].ResourceVersion = 2
		},
		"platform attachment": func(v *GroupAccess) {
			v.PolicyAttachments[0].Scope = AuthorityScopeInstallation
			v.PolicyAttachments[0].InstallationID = "installation-a"
		},
		"invalid group revision": func(v *GroupAccess) { v.Group.ResourceVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			value := access
			value.PolicyAttachments = append([]PolicyAttachment{}, access.PolicyAttachments...)
			value.Capabilities = append([]ActionCapability{}, access.Capabilities...)
			mutate(&value)
			if ValidateGroupAccess(value) == nil {
				t.Fatal("invalid group authority projection accepted")
			}
		})
	}
	membership := GroupMembership{APIVersion: APIVersion, Kind: "GroupMembership", AccountID: group.AccountID,
		ID: "membership-a", GroupID: group.ID, UserID: "user-a", CreatedBy: "user-admin", ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	page := GroupMembershipList{APIVersion: APIVersion, Kind: "GroupMembershipList", AccountID: group.AccountID, GroupID: group.ID,
		Items: []GroupMembershipAccess{{Membership: membership, Capabilities: []ActionCapability{{Action: ActionIAMGroupMembershipRemove,
			Resource: ResourceReference{Kind: ResourceGroupMembership, ID: string(membership.ID)}, Available: true}}}}}
	if ValidateGroupMembershipList(page) != nil {
		t.Fatal("valid membership page rejected")
	}
	for name, mutate := range map[string]func(*GroupMembershipList){
		"foreign account": func(v *GroupMembershipList) { v.AccountID = "account-b" },
		"different group": func(v *GroupMembershipList) { v.GroupID = "group-b" },
		"removed relation": func(v *GroupMembershipList) {
			v.Items[0].Membership.RemovedAt = &now
			v.Items[0].Membership.ResourceVersion = 2
		},
		"wrong continuation": func(v *GroupMembershipList) { v.NextAfter = "membership-b" },
		"user as removal target": func(v *GroupMembershipList) {
			v.Items[0].Capabilities[0].Resource = ResourceReference{Kind: ResourceUser, ID: "user-a"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := page
			value.Items = append([]GroupMembershipAccess{}, page.Items...)
			value.Items[0].Capabilities = append([]ActionCapability{}, page.Items[0].Capabilities...)
			mutate(&value)
			if ValidateGroupMembershipList(value) == nil {
				t.Fatal("invalid membership page accepted")
			}
		})
	}
}

func TestPolicyCanonicalizationEnforcesByteBudgetForTypedInputs(t *testing.T) {
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant}
	for i := 0; i < MaxPolicyStatements; i++ {
		statement := PolicyStatement{SID: fmt.Sprintf("statement-%d", i), Effect: PolicyAllow, Actions: []Action{ActionPaaSApplicationRead}}
		for j := 0; j < MaxStatementResources; j++ {
			statement.Resources = append(statement.Resources, PolicyResourceSelector{Kind: ResourceApplication, Match: PolicyResourceExact, ID: fmt.Sprintf("application-%d", j)})
		}
		document.Statements = append(document.Statements, statement)
	}
	if validatePolicyStructure(document) != nil {
		t.Fatal("fixture must obey structural limits")
	}
	if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
		t.Fatal("typed document bypassed byte budget")
	}
	if encoded, digest, err := CanonicalizePolicyDocument(document); !errors.Is(err, ErrInvalidPolicy) || encoded != "" || digest != "" {
		t.Fatal("oversized typed document acquired a digest")
	}
}

func TestQualifiedLoginIsAnAccountNamespaceNotAnEmail(t *testing.T) {
	for _, name := range []string{"admin", "developer@acme", "developer@123456789", "developer@tenant-prod", "developer@tenant.example", "dev.user@tenant:region-1"} {
		if err := ValidateLoginIdentifier(name); err != nil {
			t.Errorf("valid login %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"developer@", "@acme", "developer@@acme", "developer@acme@other", "developer@ acme", " developer@acme", "developer@acme ", "Dev@acme", "developer@主账号", "developer@acme/other"} {
		if ValidateLoginIdentifier(name) == nil {
			t.Errorf("invalid login %q accepted", name)
		}
	}
	for _, alias := range []string{"acme", "team-42", "a" + strings.Repeat("b", 61) + "9"} {
		if ValidateAccountAlias(alias) != nil {
			t.Errorf("valid alias %q rejected", alias)
		}
	}
	for _, alias := range []string{"", "ab", "Acme", "123", "team-", "-team", "team.example", "team_name", strings.Repeat("a", 64)} {
		if ValidateAccountAlias(alias) == nil {
			t.Errorf("invalid alias %q accepted", alias)
		}
	}
	create := decodeIAMExample[CreateUserRequest](t, "examples/create-user-request.json")
	create.LoginName = "developer@acme"
	if ValidateCreateUserRequest(create) == nil {
		t.Fatal("user creation accepted a qualified local username")
	}
	create.LoginName = "developer"
	if ValidateCreateUserRequest(create) != nil {
		t.Fatal("creation without implicit authority must be accepted")
	}
	for _, role := range removedBuiltinRoleNames {
		encoded, err := json.Marshal(map[string]any{"loginName": "developer", "displayName": "Developer", "initialPassword": "Initial-Password-49!", "requestId": "initial-role-rejected", "initialRole": role})
		if err != nil {
			t.Fatal(err)
		}
		if DecodeRequest(bytes.NewReader(encoded), &create) == nil {
			t.Fatalf("removed initialRole field accepted %s", role)
		}
	}
}

func TestAccountDirectoryContractsRejectCrossTenantAuthority(t *testing.T) {
	user := decodeIAMExample[User](t, "examples/user.json")
	attachment := PolicyAttachment{APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-directory",
		AccountID: user.AccountID, Target: PolicyAttachmentTarget{Kind: PolicyTargetUser, ID: string(user.ID)},
		PolicyID: SystemPolicyPaaSViewer, Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: user.CreatedAt, UpdatedAt: user.CreatedAt}
	blocked := func(action Action, kind ResourceKind, id string) ActionCapability {
		return ActionCapability{Action: action, Resource: ResourceReference{Kind: kind, ID: id}, RestrictionReason: CapabilityAuthorityRequired}
	}
	list := UserList{APIVersion: APIVersion, Kind: "UserList", Items: []UserAccess{{User: user, PolicyAttachments: []PolicyAttachment{attachment},
		Capabilities: []ActionCapability{
			blocked(ActionIAMUserRead, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserUpdate, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserDelete, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserPermissionBoundarySet, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserPermissionBoundaryRemove, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserSetStatus, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserPasswordReset, ResourceUser, string(user.ID)),
			blocked(ActionIAMPolicyAttachmentCreate, ResourceUser, string(user.ID)),
			blocked(ActionIAMPlatformPolicyAttachmentCreate, ResourceUser, string(user.ID)),
			blocked(ActionIAMPolicyAttachmentRevoke, ResourcePolicyAttachment, string(attachment.ID)),
		}}}}
	if err := ValidateUserList(list); err != nil {
		t.Fatalf("valid directory: %v", err)
	}
	for _, action := range []Action{ActionIAMUserPermissionBoundarySet, ActionIAMUserPermissionBoundaryRemove} {
		changed := list.Items[0]
		changed.Capabilities = nil
		for _, capability := range list.Items[0].Capabilities {
			if capability.Action != action {
				changed.Capabilities = append(changed.Capabilities, capability)
			}
		}
		if ValidateUserAccess(changed) == nil {
			t.Fatal("user projection omitted a boundary management capability")
		}
	}
	for name, mutate := range map[string]func(*PolicyAttachment){
		"wrong subject": func(a *PolicyAttachment) { a.Target.ID = "other-user" },
		"wrong carrier": func(a *PolicyAttachment) { a.Target.Kind = PolicyTargetService },
		"revoked":       func(a *PolicyAttachment) { a.ResourceVersion = 2; a.RevokedAt = &a.UpdatedAt },
	} {
		t.Run(name, func(t *testing.T) {
			changed := attachment
			mutate(&changed)
			list.Items[0].PolicyAttachments = []PolicyAttachment{changed}
			if ValidateUserList(list) == nil {
				t.Fatal("invalid directory attachment accepted")
			}
		})
	}
	list.Items[0].PolicyAttachments = []PolicyAttachment{attachment, attachment}
	if ValidateUserList(list) == nil {
		t.Fatal("duplicate attachment accepted")
	}
	list.Items[0].PolicyAttachments[1].ID = "another-attachment"
	if ValidateUserList(list) == nil {
		t.Fatal("duplicate active policy accepted")
	}
	list.Items[0].PolicyAttachments = []PolicyAttachment{attachment}
	list.Items[0].PolicyAttachments[0].AccountID = "organization-other"
	if ValidateUserList(list) == nil {
		t.Fatal("directory accepted a cross-tenant policy attachment")
	}
	list.Items[0].PolicyAttachments = []PolicyAttachment{}
	list.NextAfter = "different-principal"
	if ValidateUserList(list) == nil {
		t.Fatal("directory accepted an unrelated cursor")
	}
	list.NextAfter = ""
	list.Items = append(list.Items, list.Items[0])
	if ValidateUserList(list) == nil {
		t.Fatal("directory accepted duplicate principals")
	}
	if ValidateSetAccountAliasRequest(SetAccountAliasRequest{Alias: "acme", RequestID: "request-alias"}) == nil {
		t.Fatal("alias mutation accepted no concurrency version")
	}
	if ValidateSetUserStatusRequest(SetUserStatusRequest{Status: "REMOVED", ResourceVersion: 1, RequestID: "request-status"}) == nil {
		t.Fatal("unsupported status accepted")
	}
}

func TestUserProfileAndDeletionContractsAreStrictAndNonSecret(t *testing.T) {
	update := UpdateUserRequest{DisplayName: "Renamed user", ResourceVersion: 7, RequestID: "request-user-update"}
	if ValidateUpdateUserRequest(update) != nil || ValidateDeleteUserRequest(DeleteUserRequest{ResourceVersion: 8, RequestID: "request-user-delete"}) != nil {
		t.Fatal("valid user lifecycle request rejected")
	}
	for _, invalid := range []UpdateUserRequest{
		{DisplayName: "", ResourceVersion: 7, RequestID: "request-user-update"},
		{DisplayName: " padded ", ResourceVersion: 7, RequestID: "request-user-update"},
		{DisplayName: "Renamed user", ResourceVersion: 0, RequestID: "request-user-update"},
	} {
		if ValidateUpdateUserRequest(invalid) == nil {
			t.Fatal("invalid user profile update accepted")
		}
	}
	for _, encoded := range []string{
		`{"displayName":"Renamed user","resourceVersion":7,"requestId":"request-user-update","loginName":"replacement"}`,
		`{"resourceVersion":8,"requestId":"request-user-delete","accountId":"forged"}`,
	} {
		var target any = &UpdateUserRequest{}
		if strings.Contains(encoded, "accountId") {
			target = &DeleteUserRequest{}
		}
		if DecodeRequest(strings.NewReader(encoded), target) == nil {
			t.Fatal("user lifecycle request accepted an authority or identity selector")
		}
	}
	deletedAt := time.Date(2026, 9, 11, 9, 10, 11, 123000, time.UTC)
	receipt := UserDeletion{APIVersion: APIVersion, Kind: "UserDeletion", AccountID: "account-a", ID: "user-a",
		LoginName: "member.a", ResourceVersion: 9, DeletedAt: deletedAt}
	if ValidateUserDeletion(receipt) != nil {
		t.Fatal("valid user deletion receipt rejected")
	}
	receipt.DeletedAt = time.Time{}
	if ValidateUserDeletion(receipt) == nil {
		t.Fatal("deletion receipt without an authoritative timestamp accepted")
	}
}

func TestIAMCredentialsRequireExplicitEncoding(t *testing.T) {
	plaintext := "Example-Only-Secret-49!"
	secret, err := NewSecret(plaintext)
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	login := decodeIAMExample[LoginResponse](t, "examples/login-response.json")
	bootstrap := decodeIAMExample[BootstrapDocument](t, "examples/bootstrap-document.json")
	values := []any{
		secret,
		LoginRequest{LoginName: "admin", Password: secret, RequestID: "request-login"},
		login,
		bootstrap,
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if !errors.Is(err, ErrSecretSerialization) {
			t.Fatalf("json.Marshal(%T) error = %v, want forbidden credential serialization", value, err)
		}
		if bytes.Contains(encoded, []byte(plaintext)) {
			t.Fatalf("json.Marshal(%T) leaked credential material", value)
		}
	}
	if rendered := fmt.Sprintf("%s %#v", secret, secret); strings.Contains(rendered, plaintext) || !strings.Contains(rendered, "REDACTED") {
		t.Fatalf("formatted secret was not redacted: %q", rendered)
	}

	bootstrapJSON, err := EncodeBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatalf("explicitly encode bootstrap document: %v", err)
	}
	decodedBootstrap, err := DecodeBootstrapDocument(bytes.NewReader(bootstrapJSON))
	if err != nil {
		t.Fatalf("decode explicitly encoded bootstrap document: %v", err)
	}
	if !bytes.Equal(decodedBootstrap.Administrator.Password.CopyBytes(), bootstrap.Administrator.Password.CopyBytes()) {
		t.Fatal("explicit bootstrap encoding changed administrator credential")
	}

	loginJSON, err := EncodeLoginResponse(login)
	if err != nil {
		t.Fatalf("explicitly encode login response: %v", err)
	}
	var decodedLogin LoginResponse
	if err := DecodeRequest(bytes.NewReader(loginJSON), &decodedLogin); err != nil {
		t.Fatalf("decode explicitly encoded login response: %v", err)
	}
	if !bytes.Equal(decodedLogin.Credential.CopyBytes(), login.Credential.CopyBytes()) {
		t.Fatal("explicit login response encoding changed session credential")
	}
	if decodedLogin.MustChangePassword != login.MustChangePassword {
		t.Fatal("explicit login response encoding changed the password-change requirement")
	}
}

func TestIAMLoginResponsePublishesPasswordChangeRequirement(t *testing.T) {
	document := loadIAMOpenAPI(t)
	login := mustIAMObject(t, iamOpenAPISchemas(t, document)["LoginResponse"], "login response schema")
	properties := mustIAMObject(t, login["properties"], "login response properties")
	if _, exists := properties["mustChangePassword"]; !exists {
		t.Fatal("login response does not publish the password-change requirement")
	}
	required, ok := login["required"].([]any)
	if !ok {
		t.Fatalf("login response required fields = %#v", login["required"])
	}
	found := false
	for _, field := range required {
		if field == "mustChangePassword" {
			found = true
		}
	}
	if !found {
		t.Fatal("login response password-change requirement is optional")
	}
}

func TestIAMOpenAPICredentialBoundaries(t *testing.T) {
	document := loadIAMOpenAPI(t)
	paths := mustIAMObject(t, document["paths"], "paths")
	authorizePath := mustIAMObject(t, paths["/v1/authorize"], "authorize path")
	authorize := mustIAMObject(t, authorizePath["post"], "authorize operation")
	security, ok := authorize["security"].([]any)
	if !ok || len(security) != 1 {
		t.Fatalf("authorize security = %#v, want one AND requirement", authorize["security"])
	}
	requirement := mustIAMObject(t, security[0], "authorize security requirement")
	if len(requirement) != 2 || requirement["ServiceCredential"] == nil || requirement["SubjectCredential"] == nil {
		t.Fatalf("authorize security = %#v, want service and subject credentials", requirement)
	}
	verificationPath := mustIAMObject(t, paths["/v1/installation:verify"], "installation verification path")
	verification := mustIAMObject(t, verificationPath["post"], "installation verification operation")
	verificationSecurity, ok := verification["security"].([]any)
	if !ok || len(verificationSecurity) != 1 {
		t.Fatalf("installation verification security = %#v, want one requirement", verification["security"])
	}
	verificationRequirement := mustIAMObject(
		t, verificationSecurity[0], "installation verification security requirement",
	)
	if len(verificationRequirement) != 1 || verificationRequirement["ServiceCredential"] == nil {
		t.Fatalf(
			"installation verification security = %#v, want only verifier service credential",
			verificationRequirement,
		)
	}

	identityPath := mustIAMObject(t, paths["/v1/service-identity"], "service identity path")
	identity := mustIAMObject(t, identityPath["get"], "service identity operation")
	identitySecurity, ok := identity["security"].([]any)
	if !ok || len(identitySecurity) != 1 {
		t.Fatalf("service identity security = %#v, want one requirement", identity["security"])
	}
	identityRequirement := mustIAMObject(t, identitySecurity[0], "service identity security requirement")
	if len(identityRequirement) != 1 || identityRequirement["ServiceCredential"] == nil {
		t.Fatalf("service identity security = %#v, want only current service credential", identityRequirement)
	}
	if _, exists := identity["requestBody"]; exists {
		t.Fatal("service identity endpoint accepts a request body selector")
	}
	if parameters, exists := identity["parameters"]; exists {
		t.Fatalf("service identity endpoint exposes selector parameters: %#v", parameters)
	}

	authorizationRequest := mustIAMObject(t, iamOpenAPISchemas(t, document)["AuthorizationRequest"], "authorization request schema")
	properties := mustIAMObject(t, authorizationRequest["properties"], "authorization request properties")
	for _, forbidden := range []string{"tenantId", "organizationId", "subject"} {
		if _, exists := properties[forbidden]; exists {
			t.Fatalf("authorization request exposes forged authority field %q", forbidden)
		}
	}
	assertNoAuthoritySelectorHeader(t, document)
}

func TestUserPermissionBoundaryContractIsExplicitAndRevisionBound(t *testing.T) {
	set := SetUserPermissionBoundaryRequest{PolicyID: "policy-boundary", PolicyResourceVersion: 2, ResourceVersion: 3, RequestID: "set-boundary"}
	if err := ValidateSetUserPermissionBoundaryRequest(set); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SetUserPermissionBoundaryRequest){
		func(v *SetUserPermissionBoundaryRequest) { v.PolicyID = "" },
		func(v *SetUserPermissionBoundaryRequest) { v.PolicyResourceVersion = 0 },
		func(v *SetUserPermissionBoundaryRequest) { v.ResourceVersion = 0 },
		func(v *SetUserPermissionBoundaryRequest) { v.ResourceVersion = 9007199254740991 },
		func(v *SetUserPermissionBoundaryRequest) { v.RequestID = "" },
	} {
		invalid := set
		mutate(&invalid)
		if ValidateSetUserPermissionBoundaryRequest(invalid) == nil {
			t.Fatal("invalid boundary mutation accepted")
		}
	}
	remove := RemoveUserPermissionBoundaryRequest{ResourceVersion: 3, RequestID: "remove-boundary"}
	if ValidateRemoveUserPermissionBoundaryRequest(remove) != nil {
		t.Fatal("valid removal rejected")
	}
	remove.ResourceVersion = 9007199254740991
	if ValidateRemoveUserPermissionBoundaryRequest(remove) == nil {
		t.Fatal("nonincrementable removal revision accepted")
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"accountId":"other",`, `"userId":"other",`, `"scope":"INSTALLATION",`, `"versionId":"other",`, `"policyId":"duplicate",`} {
		var decoded SetUserPermissionBoundaryRequest
		if DecodeRequest(strings.NewReader("{"+field+string(encoded[1:])), &decoded) == nil {
			t.Fatal("boundary selector or duplicate accepted")
		}
	}
	view := UserPermissionBoundary{APIVersion: APIVersion, Kind: "UserPermissionBoundary", AccountID: "account-example", UserID: "user-example", ResourceVersion: 3}
	for _, reference := range []*PolicyVersionReference{nil, {PolicyID: "policy-boundary", VersionID: "version-boundary", ContentDigest: "sha256:" + strings.Repeat("a", 64)}} {
		view.Policy = reference
		if ValidateUserPermissionBoundary(view) != nil {
			t.Fatal("valid boundary projection rejected")
		}
		encoded, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		var decoded UserPermissionBoundary
		if DecodeRequest(bytes.NewReader(encoded), &decoded) != nil || ValidateUserPermissionBoundary(decoded) != nil {
			t.Fatal("boundary round trip failed")
		}
	}
	for _, invalid := range []string{
		`{"apiVersion":"` + APIVersion + `","kind":"UserPermissionBoundary","accountId":"account-example","userId":"user-example","resourceVersion":3}`,
		`{"apiVersion":"` + APIVersion + `","kind":"UserPermissionBoundary","accountId":"account-example","userId":"user-example","resourceVersion":3,"policy":{}}`,
	} {
		var decoded UserPermissionBoundary
		if DecodeRequest(strings.NewReader(invalid), &decoded) == nil && ValidateUserPermissionBoundary(decoded) == nil {
			t.Fatal("missing or corrupt boundary projection treated as unbounded")
		}
	}
}

func validIAMExample[T any](path string, validate func(T) error) func(*testing.T) {
	return func(t *testing.T) {
		value := decodeIAMExample[T](t, path)
		if err := validate(value); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
	}
}

func mustIAMObject(t *testing.T, value any, name string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s contains %T, want object", name, value)
	}
	return object
}

func assertNoAuthoritySelectorHeader(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			assertNoAuthoritySelectorHeader(t, item)
		}
	case map[string]any:
		if typed["in"] == "header" {
			name, _ := typed["name"].(string)
			normalized := strings.ToLower(name)
			if strings.Contains(normalized, "tenant") || strings.Contains(normalized, "organization") ||
				(strings.Contains(normalized, "subject") && name != "Matrix-Subject-Credential") {
				t.Fatalf("OpenAPI exposes authority selector header %q", name)
			}
		}
		for _, child := range typed {
			assertNoAuthoritySelectorHeader(t, child)
		}
	}
}
