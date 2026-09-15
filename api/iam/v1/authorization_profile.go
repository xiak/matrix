package iamv1

import (
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

var ErrInvalidAuthorizationProfile = errors.New("invalid IAM authorization profile")

func DecodeAuthorizationProfile(reader io.Reader) (AuthorizationProfile, error) {
	var value AuthorizationProfile
	if contractjson.DecodeObject(reader, MaxAuthorizationProfileBytes, &value) != nil || ValidateAuthorizationProfile(value) != nil {
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
		parts := strings.Split(string(action.Action), ".")
		if len(parts) < 2 || len(parts) > 5 || parts[0] != string(value.Product) || len(action.Action) > 128 || seen[action.Action] ||
			!profileIdentifier(string(action.ResourceKind), true) || len(action.ResourceShapes) == 0 || len(action.ResourceShapes) > 3 || len(action.Conditions) > 3 {
			return ErrInvalidAuthorizationProfile
		}
		for _, part := range parts {
			if !profileIdentifier(part, false) {
				return ErrInvalidAuthorizationProfile
			}
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

// CanonicalizeAuthorizationProfile normalizes declaration sets without
// mutating inputs. Its domain-separated digest is not a Policy or Audit hash.
func CanonicalizeAuthorizationProfile(value AuthorizationProfile) (string, string, error) {
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
	if CheckAuthorizationProfileReference(profile, reference) != nil || ValidateID("resource.id", resource.ID) != nil {
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

// NewAuthorizationRequest is a current-source transport constructor. The PEP
// explicitly chooses the target mode; this function never infers list/create
// from a resource ID and does not authenticate or authorize the caller.
func NewAuthorizationRequest(action Action, resource ResourceReference, mode AuthorizationResourceMode, usage AuthorizationCollectionUsage, requestID, correlationID string) (AuthorizationRequest, error) {
	definition, known := LookupActionDefinition(action)
	if !known {
		return AuthorizationRequest{}, ErrInvalidAuthorizationProfile
	}
	profile, known := LookupAuthorizationProfile(definition.Product)
	if !known {
		return AuthorizationRequest{}, ErrInvalidAuthorizationProfile
	}
	_, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	request := AuthorizationRequest{Action: action, Resource: resource,
		Profile:      AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest},
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
