package iamv1

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/xiak/matrix/api/contractjson"
)

type PolicyID string
type PolicyVersionID string
type PolicyEffect string
type PolicyResourceMatch string

const (
	SystemPolicyAccountAdministrator PolicyID = "system.account-administrator"
	SystemPolicyPlatformOperator     PolicyID = "system.platform-operator"
	SystemPolicyPaaSDeveloper        PolicyID = "system.paas-developer"
	SystemPolicyPaaSViewer           PolicyID = "system.paas-viewer"
	SystemPolicyAuditReader          PolicyID = "system.audit-reader"
	SystemPolicyInstallationVerifier PolicyID = "system.installation-verifier"
)

const (
	PolicyLanguageVersion                            = "1"
	MaxPolicyBytes               int64               = 64 * 1024
	MaxPolicyStatements                              = 64
	MaxStatementActions                              = 128
	MaxStatementResources                            = 64
	PolicyAllow                  PolicyEffect        = "ALLOW"
	PolicyDeny                   PolicyEffect        = "DENY"
	PolicyResourceExact          PolicyResourceMatch = "EXACT"
	PolicyResourceAnyInAuthority PolicyResourceMatch = "ANY_IN_AUTHORITY"
)

var ErrInvalidPolicy = errors.New("IAM policy is invalid")

// PolicyDocument is a closed permission language, not a request-supplied
// authority. Valid syntax does not confer permission to publish or attach it.
type PolicyDocument struct {
	LanguageVersion string            `json:"languageVersion"`
	Scope           AuthorityScope    `json:"scope"`
	Statements      []PolicyStatement `json:"statements"`
}

type PolicyStatement struct {
	SID       string                   `json:"sid"`
	Effect    PolicyEffect             `json:"effect"`
	Actions   []Action                 `json:"actions"`
	Resources []PolicyResourceSelector `json:"resources"`
}

// ANY_IN_AUTHORITY does not assert ownership of a resource. Product PEPs must
// still bind the actual resource to the credential-derived authority.
type PolicyResourceSelector struct {
	Kind  ResourceKind        `json:"kind"`
	Match PolicyResourceMatch `json:"match"`
	ID    string              `json:"id,omitempty"`
}

func (selector *PolicyResourceSelector) UnmarshalJSON(source []byte) error {
	type wire PolicyResourceSelector
	var decoded wire
	if err := contractjson.DecodeObjectBytes(source, MaxPolicyBytes, &decoded); err != nil {
		return ErrInvalidPolicy
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(source, &fields); err != nil {
		return ErrInvalidPolicy
	}
	if _, hasID := fields["id"]; hasID && decoded.Match == PolicyResourceAnyInAuthority {
		return ErrInvalidPolicy
	}
	*selector = PolicyResourceSelector(decoded)
	return nil
}

type PolicyVersion struct {
	PolicyID      PolicyID        `json:"policyId"`
	ID            PolicyVersionID `json:"versionId"`
	Document      PolicyDocument  `json:"document"`
	ContentDigest string          `json:"contentDigest"`
}

type PolicyVersionReference struct {
	PolicyID      PolicyID        `json:"policyId"`
	VersionID     PolicyVersionID `json:"versionId"`
	ContentDigest string          `json:"contentDigest"`
}

func DecodePolicyDocument(reader io.Reader) (PolicyDocument, error) {
	var document PolicyDocument
	if err := contractjson.DecodeObject(reader, MaxPolicyBytes, &document); err != nil {
		return PolicyDocument{}, ErrInvalidPolicy
	}
	if err := ValidatePolicyDocument(document); err != nil {
		return PolicyDocument{}, err
	}
	return document, nil
}

func ValidatePolicyDocument(document PolicyDocument) error {
	if err := validatePolicyStructure(document); err != nil {
		return err
	}
	encoded, err := json.Marshal(document)
	if err != nil || int64(len(encoded)) > MaxPolicyBytes {
		return ErrInvalidPolicy
	}
	return nil
}

func validatePolicyStructure(document PolicyDocument) error {
	if document.LanguageVersion != PolicyLanguageVersion ||
		len(document.Statements) == 0 || len(document.Statements) > MaxPolicyStatements {
		return ErrInvalidPolicy
	}
	switch document.Scope {
	case AuthorityScopeTenant, AuthorityScopeInstallation, AuthorityScopeInstallationProbe:
	default:
		return ErrInvalidPolicy
	}
	seenStatements := make(map[string]bool, len(document.Statements))
	for _, statement := range document.Statements {
		if ValidateID("sid", statement.SID) != nil || seenStatements[statement.SID] ||
			(statement.Effect != PolicyAllow && statement.Effect != PolicyDeny) ||
			len(statement.Actions) == 0 || len(statement.Actions) > MaxStatementActions ||
			len(statement.Resources) == 0 || len(statement.Resources) > MaxStatementResources {
			return ErrInvalidPolicy
		}
		seenStatements[statement.SID] = true
		seenActions := make(map[Action]bool, len(statement.Actions))
		requiredKinds := make(map[ResourceKind]bool)
		for _, action := range statement.Actions {
			definition, known := LookupActionDefinition(action)
			if !known || definition.AuthorityScope != document.Scope || seenActions[action] {
				return ErrInvalidPolicy
			}
			seenActions[action] = true
			requiredKinds[definition.ResourceKind] = false
		}
		seenResources := make(map[PolicyResourceSelector]bool, len(statement.Resources))
		for _, resource := range statement.Resources {
			if _, needed := requiredKinds[resource.Kind]; !needed || seenResources[resource] {
				return ErrInvalidPolicy
			}
			switch resource.Match {
			case PolicyResourceExact:
				if ValidateID("resource.id", resource.ID) != nil {
					return ErrInvalidPolicy
				}
			case PolicyResourceAnyInAuthority:
				if resource.ID != "" {
					return ErrInvalidPolicy
				}
			default:
				return ErrInvalidPolicy
			}
			seenResources[resource] = true
			requiredKinds[resource.Kind] = true
		}
		for _, covered := range requiredKinds {
			if !covered {
				return ErrInvalidPolicy
			}
		}
	}
	return nil
}

// CanonicalizePolicyDocument is the single policy-content encoding owner.
// Collection ordering is normalized without mutating caller-owned slices.
// This digest is not an Audit event digest and cannot replace its encoding.
func CanonicalizePolicyDocument(document PolicyDocument) (string, string, error) {
	if err := validatePolicyStructure(document); err != nil {
		return "", "", err
	}
	document.Statements = append([]PolicyStatement(nil), document.Statements...)
	for index := range document.Statements {
		statement := &document.Statements[index]
		statement.Actions = append([]Action(nil), statement.Actions...)
		statement.Resources = append([]PolicyResourceSelector(nil), statement.Resources...)
		slices.Sort(statement.Actions)
		slices.SortFunc(statement.Resources, func(left, right PolicyResourceSelector) int {
			if order := cmp.Compare(left.Kind, right.Kind); order != 0 {
				return order
			}
			if order := cmp.Compare(left.Match, right.Match); order != 0 {
				return order
			}
			return cmp.Compare(left.ID, right.ID)
		})
	}
	slices.SortFunc(document.Statements, func(left, right PolicyStatement) int { return cmp.Compare(left.SID, right.SID) })
	encoded, err := json.Marshal(document)
	if err != nil || int64(len(encoded)) > MaxPolicyBytes {
		return "", "", ErrInvalidPolicy
	}
	digest := sha256.Sum256(append([]byte("matrix.iam.policy.v1\x00"), encoded...))
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidatePolicyVersion(version PolicyVersion) error {
	if ValidateID("policyId", string(version.PolicyID)) != nil || ValidateID("versionId", string(version.ID)) != nil ||
		ValidateDigest("contentDigest", version.ContentDigest) != nil {
		return ErrInvalidPolicy
	}
	_, digest, err := CanonicalizePolicyDocument(version.Document)
	if err != nil || digest != version.ContentDigest {
		return ErrInvalidPolicy
	}
	return nil
}
