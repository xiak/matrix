package iamv1

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/xiak/matrix/api/contractjson"
)

// This contract owns immutable product-declaration bytes. It is not an
// enrollment, permission, trusted signature, or caller-supplied authority.
type AuthorizationProfile struct {
	APIVersion     string                       `json:"apiVersion"`
	Kind           string                       `json:"kind"`
	Product        ProductID                    `json:"product"`
	Revision       uint64                       `json:"revision"`
	CallingService ServicePurpose               `json:"callingService"`
	Actions        []AuthorizationProfileAction `json:"actions"`
}

type AuthorizationProfileAction struct {
	Action         Action                          `json:"action"`
	ResourceKind   ResourceKind                    `json:"resourceKind"`
	Scope          AuthorityScope                  `json:"scope"`
	ResourceShapes []AuthorizationResourceShape    `json:"resourceShapes"`
	Conditions     []AuthorizationProfileCondition `json:"conditions,omitempty"`
	// The successful fact may concern a child/new resource. This declaration
	// never changes the resource against which IAM makes its decision.
	ResultResourceKind ResourceKind `json:"resultResourceKind,omitempty"`
}

type AuthorizationResourceMode string
type AuthorizationCollectionUsage string

const (
	AuthorizationResourceInstance   AuthorizationResourceMode    = "INSTANCE"
	AuthorizationResourceCollection AuthorizationResourceMode    = "COLLECTION"
	AuthorizationCollectionList     AuthorizationCollectionUsage = "COLLECTION_LIST"
	AuthorizationCollectionCreate   AuthorizationCollectionUsage = "COLLECTION_CREATE"
	MaxAuthorizationProfileActions                               = 128
	MaxAuthorizationProfileBytes    int64                        = 64 * 1024
)

// Prefix support belongs to the instance shape, not every use of an Action.
// Successful resource production is declared separately on the action:
// both collection and parent-instance authorization may create a resource.
type AuthorizationResourceShape struct {
	Mode            AuthorizationResourceMode    `json:"mode"`
	PrefixAllowed   bool                         `json:"prefixAllowed"`
	CollectionUsage AuthorizationCollectionUsage `json:"collectionUsage,omitempty"`
}

type AuthorizationProfileCondition struct {
	Key       ConditionKey       `json:"key"`
	ValueType ConditionValueType `json:"valueType"`
	Source    ConditionSource    `json:"source"`
}

type AuthorizationProfileReference struct {
	Product       ProductID `json:"product"`
	Revision      uint64    `json:"revision"`
	ContentDigest string    `json:"contentDigest"`
}

// AuthorizationProfileList is complete current product metadata, not the
// requesting user's permissions. AccountID binds the read context only.
type AuthorizationProfileList struct {
	APIVersion string                      `json:"apiVersion"`
	Kind       string                      `json:"kind"`
	AccountID  AccountID                   `json:"accountId"`
	Items      []AuthorizationProfileEntry `json:"items"`
}

// Keep the declaration whole: filtering actions would invalidate its digest.
type AuthorizationProfileEntry struct {
	Profile       AuthorizationProfile `json:"profile"`
	ContentDigest string               `json:"contentDigest"`
}

const MaxAuthorizationProfileListItems = 16

func DecodeAuthorizationProfileList(reader io.Reader) (AuthorizationProfileList, error) {
	var value AuthorizationProfileList
	if contractjson.DecodeObject(reader, MaxRequestBytes, &value) != nil || ValidateAuthorizationProfileList(value) != nil {
		return AuthorizationProfileList{}, ErrInvalidAuthorizationProfile
	}
	return value, nil
}

func ValidateAuthorizationProfileList(value AuthorizationProfileList) error {
	if value.APIVersion != APIVersion || value.Kind != "AuthorizationProfileList" ||
		ValidateID("accountId", string(value.AccountID)) != nil || len(value.Items) < 1 || len(value.Items) > MaxAuthorizationProfileListItems {
		return ErrInvalidAuthorizationProfile
	}
	var previous ProductID
	for _, entry := range value.Items {
		if entry.Profile.Product <= previous || CheckAuthorizationProfileReference(entry.Profile,
			AuthorizationProfileReference{Product: entry.Profile.Product, Revision: entry.Profile.Revision, ContentDigest: entry.ContentDigest}) != nil {
			return ErrInvalidAuthorizationProfile
		}
		previous = entry.Profile.Product
	}
	// This endpoint uses the existing ordinary contract/HTTP decode budget,
	// not the much larger sum of every individual declaration's maximum.
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxRequestBytes {
		return ErrInvalidAuthorizationProfile
	}
	return nil
}

type authorizationProfileCommitment struct {
	profile    AuthorizationProfile
	normalized AuthorizationProfile
	canonical  string
	reference  AuthorizationProfileReference
}

func sourceAuthorizationProfileCommitment(profile AuthorizationProfile) authorizationProfileCommitment {
	canonical, digest, err := canonicalizeAuthorizationProfile(profile)
	var normalized AuthorizationProfile
	if err != nil || json.Unmarshal([]byte(canonical), &normalized) != nil {
		panic("invalid release-owned IAM product declaration")
	}
	return authorizationProfileCommitment{cloneAuthorizationProfile(profile), normalized, canonical,
		AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}}
}

var ErrInvalidAuthorizationProfile = errors.New("invalid IAM authorization profile")

func DecodeAuthorizationProfile(reader io.Reader) (AuthorizationProfile, error) {
	if reader == nil {
		return AuthorizationProfile{}, ErrInvalidAuthorizationProfile
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaxAuthorizationProfileBytes+1))
	if err != nil || int64(len(encoded)) > MaxAuthorizationProfileBytes {
		return AuthorizationProfile{}, ErrInvalidAuthorizationProfile
	}
	// Full byte equality with an already validated source constant proves the
	// same syntax/content, not registration or authority. Return a deep copy;
	// no caller can mutate the source. All other bytes use the strict decoder.
	for _, source := range sourceProfileCommitments {
		if string(encoded) == source.canonical {
			return cloneAuthorizationProfile(source.normalized), nil
		}
	}
	var value AuthorizationProfile
	if contractjson.DecodeObject(bytes.NewReader(encoded), MaxAuthorizationProfileBytes, &value) != nil || ValidateAuthorizationProfile(value) != nil {
		return AuthorizationProfile{}, ErrInvalidAuthorizationProfile
	}
	return value, nil
}

func ValidateAuthorizationProfile(value AuthorizationProfile) error {
	_, _, err := CanonicalizeAuthorizationProfile(value)
	return err
}

// Product and service identifiers are syntactic namespaces here, not enums of
// products known to today's executable. Only trusted registration may admit a
// declaration; a well-formed unfamiliar product gets no runtime permission.
func profileIdentifier(value string, upper bool) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range []byte(value) {
		letter := character >= 'a' && character <= 'z'
		if upper {
			letter = character >= 'A' && character <= 'Z'
		}
		if !letter && (index == 0 || !(character >= '0' && character <= '9' || character == '_' || character == '-')) {
			return false
		}
	}
	return true
}

func validateAuthorizationProfileStructure(value AuthorizationProfile) error {
	if value.APIVersion != APIVersion || value.Kind != "AuthorizationProfile" ||
		!profileIdentifier(string(value.Product), false) || !profileIdentifier(string(value.CallingService), true) ||
		validatePositiveVersion(value.Revision) != nil || len(value.Actions) == 0 || len(value.Actions) > MaxAuthorizationProfileActions {
		return ErrInvalidAuthorizationProfile
	}
	seen := make(map[Action]bool, len(value.Actions))
	for _, action := range value.Actions {
		product, _, _ := strings.Cut(string(action.Action), ".")
		if !authorizationActionIdentifier(action.Action) || product != string(value.Product) || seen[action.Action] ||
			!profileIdentifier(string(action.ResourceKind), true) || len(action.ResourceShapes) == 0 || len(action.ResourceShapes) > 3 || len(action.Conditions) > 3 {
			return ErrInvalidAuthorizationProfile
		}
		seen[action.Action] = true
		if action.Scope != AuthorityScopeTenant && action.Scope != AuthorityScopeInstallation && action.Scope != AuthorityScopeInstallationProbe {
			return ErrInvalidAuthorizationProfile
		}
		if action.ResultResourceKind != "" && !profileIdentifier(string(action.ResultResourceKind), true) {
			return ErrInvalidAuthorizationProfile
		}
		shapes := make(map[string]bool, len(action.ResourceShapes))
		for _, shape := range action.ResourceShapes {
			key := string(shape.Mode) + ":" + string(shape.CollectionUsage)
			if shapes[key] {
				return ErrInvalidAuthorizationProfile
			}
			shapes[key] = true
			switch shape.Mode {
			case AuthorizationResourceInstance:
				if shape.CollectionUsage != "" || shape.PrefixAllowed && action.Scope != AuthorityScopeTenant {
					return ErrInvalidAuthorizationProfile
				}
			case AuthorizationResourceCollection:
				if shape.PrefixAllowed {
					return ErrInvalidAuthorizationProfile
				}
				switch shape.CollectionUsage {
				case AuthorizationCollectionList:
					if action.ResultResourceKind != "" {
						return ErrInvalidAuthorizationProfile
					}
				case AuthorizationCollectionCreate:
					if action.ResultResourceKind == "" {
						return ErrInvalidAuthorizationProfile
					}
				default:
					return ErrInvalidAuthorizationProfile
				}
			default:
				return ErrInvalidAuthorizationProfile
			}
		}
		conditions := make(map[ConditionKey]bool, len(action.Conditions))
		for _, condition := range action.Conditions {
			if action.Scope != AuthorityScopeTenant || conditions[condition.Key] {
				return ErrInvalidAuthorizationProfile
			}
			conditions[condition.Key] = true
			// Reuse the source owner's closed definitions without borrowing an
			// unrelated action's permission or inferring a source from its name.
			definition, known := lookupConditionDefinition(condition.Key)
			if !known || condition.ValueType != definition.ValueType || condition.Source != definition.Source {
				return ErrInvalidAuthorizationProfile
			}
		}
	}
	return nil
}

func authorizationActionIdentifier(action Action) bool {
	parts := strings.Split(string(action), ".")
	if len(parts) < 2 || len(parts) > 5 || len(action) > 128 {
		return false
	}
	for _, part := range parts {
		if !profileIdentifier(part, false) {
			return false
		}
	}
	return true
}

// CanonicalizeAuthorizationProfile normalizes declaration sets without
// mutating inputs. Its domain-separated digest is not a Policy or Audit hash.
func CanonicalizeAuthorizationProfile(value AuthorizationProfile) (string, string, error) {
	// Equality covers every supplied byte-bearing field, including nested
	// shapes and conditions. A tuple match alone is never sufficient. Unknown,
	// reordered or changed declarations use the complete validator/encoder.
	if source, known := sourceProfileCommitments[value.Product]; known &&
		(equalAuthorizationProfile(value, source.profile) || equalAuthorizationProfile(value, source.normalized)) {
		return source.canonical, source.reference.ContentDigest, nil
	}
	return canonicalizeAuthorizationProfile(value)
}

// Compare every declaration field without reflective pointer traversal on each
// capability projection. This checks content, not just the reference tuple;
// unknown/changed declarations still use the complete canonical encoder.
func equalAuthorizationProfile(left, right AuthorizationProfile) bool {
	if left.APIVersion != right.APIVersion || left.Kind != right.Kind || left.Product != right.Product ||
		left.Revision != right.Revision || left.CallingService != right.CallingService ||
		len(left.Actions) != len(right.Actions) || (left.Actions == nil) != (right.Actions == nil) {
		return false
	}
	for index, action := range left.Actions {
		other := right.Actions[index]
		if action.Action != other.Action || action.ResourceKind != other.ResourceKind || action.Scope != other.Scope ||
			action.ResultResourceKind != other.ResultResourceKind ||
			(action.ResourceShapes == nil) != (other.ResourceShapes == nil) || !slices.Equal(action.ResourceShapes, other.ResourceShapes) ||
			(action.Conditions == nil) != (other.Conditions == nil) || !slices.Equal(action.Conditions, other.Conditions) {
			return false
		}
	}
	return true
}

func canonicalizeAuthorizationProfile(value AuthorizationProfile) (string, string, error) {
	if validateAuthorizationProfileStructure(value) != nil {
		return "", "", ErrInvalidAuthorizationProfile
	}
	value = cloneAuthorizationProfile(value)
	for index := range value.Actions {
		action := &value.Actions[index]
		slices.SortFunc(action.ResourceShapes, func(left, right AuthorizationResourceShape) int {
			if order := cmp.Compare(left.Mode, right.Mode); order != 0 {
				return order
			}
			return cmp.Compare(left.CollectionUsage, right.CollectionUsage)
		})
		slices.SortFunc(action.Conditions, func(left, right AuthorizationProfileCondition) int { return cmp.Compare(left.Key, right.Key) })
	}
	slices.SortFunc(value.Actions, func(left, right AuthorizationProfileAction) int { return cmp.Compare(left.Action, right.Action) })
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxAuthorizationProfileBytes {
		return "", "", ErrInvalidAuthorizationProfile
	}
	digest := sha256.Sum256(append([]byte("matrix.iam.authorization-profile.v1\x00"), encoded...))
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func cloneAuthorizationProfile(value AuthorizationProfile) AuthorizationProfile {
	value.Actions = slices.Clone(value.Actions)
	for index := range value.Actions {
		value.Actions[index].ResourceShapes = slices.Clone(value.Actions[index].ResourceShapes)
		value.Actions[index].Conditions = slices.Clone(value.Actions[index].Conditions)
	}
	return value
}

// All current and immutable policy lookups project the same capability shape.
// This is derived data, never an independently editable action registry.
func authorizationProfileActionDefinition(profile AuthorizationProfile, action AuthorizationProfileAction) ActionDefinition {
	definition := ActionDefinition{Action: action.Action, Product: profile.Product, CallingService: profile.CallingService, ResourceKind: action.ResourceKind, AuthorityScope: action.Scope}
	for _, shape := range action.ResourceShapes {
		if shape.Mode == AuthorizationResourceInstance {
			definition.ResourcePrefixAllowed = shape.PrefixAllowed
		}
	}
	return definition
}

// CheckAuthorizationProfileReference compares the exact tuple, never a
// numerically newer revision. It does not authenticate the profile publisher.
func CheckAuthorizationProfileReference(value AuthorizationProfile, reference AuthorizationProfileReference) error {
	_, digest, err := CanonicalizeAuthorizationProfile(value)
	if err != nil || reference.Product != value.Product || reference.Revision != value.Revision || reference.ContentDigest != digest {
		return ErrInvalidAuthorizationProfile
	}
	return nil
}

// CheckAuthorizationProfileTarget validates an explicitly selected target mode
// against immutable declaration bytes. The caller must separately establish
// trusted registration, current service identity and account/installation scope.
// Neither an ID spelled "collection" nor an action name selects the mode.
func CheckAuthorizationProfileTarget(
	profile AuthorizationProfile,
	reference AuthorizationProfileReference,
	action Action,
	resource ResourceReference,
	mode AuthorizationResourceMode,
	usage AuthorizationCollectionUsage,
) error {
	if CheckAuthorizationProfileReference(profile, reference) != nil {
		return ErrInvalidAuthorizationProfile
	}
	return checkValidatedProfileTarget(profile, action, resource, mode, usage)
}

// Private: only call after this exact profile's complete canonical commitment
// has already been validated in the same stack. Never expose an unchecked PEP
// entrypoint or retain this as an authorization result.
func checkValidatedProfileTarget(profile AuthorizationProfile, action Action, resource ResourceReference,
	mode AuthorizationResourceMode, usage AuthorizationCollectionUsage) error {
	if ValidateID("resource.id", resource.ID) != nil {
		return ErrInvalidAuthorizationProfile
	}
	switch mode {
	case AuthorizationResourceInstance:
		if usage != "" {
			return ErrInvalidAuthorizationProfile
		}
	case AuthorizationResourceCollection:
		if resource.ID != "collection" || (usage != AuthorizationCollectionList && usage != AuthorizationCollectionCreate) {
			return ErrInvalidAuthorizationProfile
		}
	default:
		return ErrInvalidAuthorizationProfile
	}
	for _, declared := range profile.Actions {
		if declared.Action != action || declared.ResourceKind != resource.Kind {
			continue
		}
		for _, shape := range declared.ResourceShapes {
			if shape.Mode == mode && shape.CollectionUsage == usage {
				return nil
			}
		}
	}
	return ErrInvalidAuthorizationProfile
}

// Only select the private, immutable executable declaration here. A caller-
// supplied Profile with an equal tuple must never enter this fast path.
func checkSourceProfileTarget(reference AuthorizationProfileReference, action Action, resource ResourceReference,
	mode AuthorizationResourceMode, usage AuthorizationCollectionUsage) error {
	expected, known := sourceProfileCommitments[reference.Product]
	if !known || expected.reference != reference {
		return ErrInvalidAuthorizationProfile
	}
	for _, profile := range authorizationProfiles {
		if profile.Product == reference.Product {
			return checkValidatedProfileTarget(profile, action, resource, mode, usage)
		}
	}
	return ErrInvalidAuthorizationProfile
}

// NewAuthorizationRequest is a current-source transport constructor. The PEP
// explicitly chooses the target mode; this function never infers list/create
// from a resource ID and does not authenticate or authorize the caller.
func NewAuthorizationRequest(action Action, resource ResourceReference, mode AuthorizationResourceMode, usage AuthorizationCollectionUsage, requestID, correlationID string) (AuthorizationRequest, error) {
	definition, known := LookupActionDefinition(action)
	if !known {
		return AuthorizationRequest{}, ErrInvalidAuthorizationProfile
	}
	source, known := sourceProfileCommitments[definition.Product]
	if !known {
		return AuthorizationRequest{}, ErrInvalidAuthorizationProfile
	}
	request := AuthorizationRequest{Action: action, Resource: resource,
		Profile:      source.reference,
		ResourceMode: mode, CollectionUsage: usage, RequestID: requestID, CorrelationID: correlationID}
	if err := ValidateAuthorizationRequest(request); err != nil {
		return AuthorizationRequest{}, err
	}
	return request, nil
}

// CheckAuthorizationDecisionForRequest is the shared response-binding contract
// used by PEPs before consuming either an Allow or a Deny.
func CheckAuthorizationDecisionForRequest(decision AuthorizationDecision, request AuthorizationRequest) error {
	if ValidateAuthorizationRequest(request) != nil || ValidateAuthorizationDecision(decision) != nil || decision.Profile == nil ||
		*decision.Profile != request.Profile || decision.Action != request.Action || decision.Resource != request.Resource ||
		decision.ResourceMode != request.ResourceMode || decision.CollectionUsage != request.CollectionUsage ||
		decision.RequestID != request.RequestID || decision.CorrelationID != request.CorrelationID {
		return ErrInvalidAuthorizationProfile
	}
	return nil
}
