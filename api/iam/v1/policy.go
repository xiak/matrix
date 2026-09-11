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
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

type PolicyID string
type PolicyVersionID string
type PolicyEffect string
type PolicyResourceMatch string
type PolicyManagement string
type PolicyStatus string
type PolicyAttachmentID string
type PolicyAttachmentTargetKind string

const (
	PolicySystemManaged   PolicyManagement           = "SYSTEM"
	PolicyCustomerManaged PolicyManagement           = "CUSTOMER"
	PolicyActive          PolicyStatus               = "ACTIVE"
	PolicyRetired         PolicyStatus               = "RETIRED"
	PolicyTargetUser      PolicyAttachmentTargetKind = "USER"
	PolicyTargetService   PolicyAttachmentTargetKind = "SERVICE_ACCOUNT"
	PolicyTargetGroup     PolicyAttachmentTargetKind = "GROUP"
	PolicyTargetRole      PolicyAttachmentTargetKind = "ROLE"
)

// Policy is mutable metadata pointing to one immutable content version. It
// never contains subjects or constitutes permission to attach the policy.
type Policy struct {
	APIVersion       string           `json:"apiVersion"`
	Kind             string           `json:"kind"`
	ID               PolicyID         `json:"id"`
	Management       PolicyManagement `json:"management"`
	AccountID        OrganizationID   `json:"accountId,omitempty"`
	DisplayName      string           `json:"displayName"`
	Scope            AuthorityScope   `json:"scope"`
	Status           PolicyStatus     `json:"status"`
	DefaultVersionID PolicyVersionID  `json:"defaultVersionId"`
	ResourceVersion  uint64           `json:"resourceVersion"`
	CreatedAt        time.Time        `json:"createdAt"`
	UpdatedAt        time.Time        `json:"updatedAt"`
}

const MaxPolicyListItems = 256

// PolicyList is a complete bounded metadata snapshot, not an authorization
// permit. The scope is derived from the separately authorized route.
type PolicyList struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	AccountID      OrganizationID `json:"accountId"`
	Scope          AuthorityScope `json:"scope"`
	InstallationID string         `json:"installationId,omitempty"`
	Items          []Policy       `json:"items"`
}

func ValidatePolicyList(value PolicyList) error {
	if value.APIVersion != APIVersion || value.Kind != "PolicyList" || ValidateID("accountId", string(value.AccountID)) != nil ||
		value.Items == nil || len(value.Items) > MaxPolicyListItems {
		return ErrInvalidPolicy
	}
	if (value.Scope != AuthorityScopeTenant && value.Scope != AuthorityScopeInstallation) ||
		(value.Scope == AuthorityScopeTenant && value.InstallationID != "") ||
		(value.Scope == AuthorityScopeInstallation && ValidateID("installationId", value.InstallationID) != nil) {
		return ErrInvalidPolicy
	}
	var previous PolicyID
	for _, item := range value.Items {
		if ValidatePolicy(item) != nil || item.Scope != value.Scope || (item.AccountID != "" && item.AccountID != value.AccountID) || item.ID <= previous {
			return ErrInvalidPolicy
		}
		previous = item.ID
	}
	return nil
}

// Target kinds describe authorization carriers, not authenticatable principal
// types. A group cannot become a login identity by appearing in this contract.
type PolicyAttachmentTarget struct {
	Kind PolicyAttachmentTargetKind `json:"kind"`
	ID   string                     `json:"id"`
}

type PolicyAttachment struct {
	APIVersion      string                 `json:"apiVersion"`
	Kind            string                 `json:"kind"`
	ID              PolicyAttachmentID     `json:"id"`
	AccountID       OrganizationID         `json:"accountId"`
	Target          PolicyAttachmentTarget `json:"target"`
	PolicyID        PolicyID               `json:"policyId"`
	Scope           AuthorityScope         `json:"scope"`
	InstallationID  string                 `json:"installationId,omitempty"`
	ResourceVersion uint64                 `json:"resourceVersion"`
	CreatedAt       time.Time              `json:"createdAt"`
	UpdatedAt       time.Time              `json:"updatedAt"`
	RevokedAt       *time.Time             `json:"revokedAt,omitempty"`
}

// The requested policy revision is a concurrency precondition, not permission
// to attach it. Account, installation and scope come from current authority.
type CreatePolicyAttachmentRequest struct {
	Target                PolicyAttachmentTarget `json:"target"`
	PolicyID              PolicyID               `json:"policyId"`
	PolicyResourceVersion uint64                 `json:"policyResourceVersion"`
	RequestID             string                 `json:"requestId"`
}

type RevokePolicyAttachmentRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

func ValidateCreatePolicyAttachmentRequest(value CreatePolicyAttachmentRequest) error {
	// This direct-user management slice does not admit unimplemented group,
	// role or service-credential workflows through a permissive target enum.
	if value.Target.Kind != PolicyTargetUser {
		return ErrInvalidPolicy
	}
	return errors.Join(ValidateID("target.id", value.Target.ID), ValidateID("policyId", string(value.PolicyID)),
		validatePositiveVersion(value.PolicyResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateRevokePolicyAttachmentRequest(value RevokePolicyAttachmentRequest) error {
	return errors.Join(validatePositiveVersion(value.ResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidatePolicy(policy Policy) error {
	if policy.APIVersion != APIVersion || policy.Kind != "Policy" ||
		ValidateID("policyId", string(policy.ID)) != nil ||
		validateText("displayName", policy.DisplayName, 1, 128) != nil ||
		ValidateID("defaultVersionId", string(policy.DefaultVersionID)) != nil ||
		validatePositiveVersion(policy.ResourceVersion) != nil ||
		validateChronology(policy.CreatedAt, policy.UpdatedAt) != nil ||
		(policy.Status != PolicyActive && policy.Status != PolicyRetired) {
		return ErrInvalidPolicy
	}
	switch policy.Management {
	case PolicySystemManaged:
		if policy.AccountID != "" || !strings.HasPrefix(string(policy.ID), "system.") || policy.ID == "system." || !validPolicyScope(policy.Scope) {
			return ErrInvalidPolicy
		}
	case PolicyCustomerManaged:
		if ValidateID("accountId", string(policy.AccountID)) != nil ||
			strings.HasPrefix(string(policy.ID), "system.") || policy.Scope != AuthorityScopeTenant {
			return ErrInvalidPolicy
		}
	default:
		return ErrInvalidPolicy
	}
	return nil
}

func ValidatePolicyAttachment(attachment PolicyAttachment) error {
	if attachment.APIVersion != APIVersion || attachment.Kind != "PolicyAttachment" ||
		ValidateID("attachmentId", string(attachment.ID)) != nil ||
		ValidateID("accountId", string(attachment.AccountID)) != nil ||
		ValidateID("target.id", attachment.Target.ID) != nil ||
		ValidateID("policyId", string(attachment.PolicyID)) != nil ||
		validatePositiveVersion(attachment.ResourceVersion) != nil ||
		validateChronology(attachment.CreatedAt, attachment.UpdatedAt) != nil {
		return ErrInvalidPolicy
	}
	switch attachment.Target.Kind {
	case PolicyTargetUser, PolicyTargetService, PolicyTargetGroup, PolicyTargetRole:
	default:
		return ErrInvalidPolicy
	}
	switch attachment.Scope {
	case AuthorityScopeTenant:
		if attachment.InstallationID != "" {
			return ErrInvalidPolicy
		}
	case AuthorityScopeInstallation:
		if attachment.Target.Kind != PolicyTargetUser || ValidateID("installationId", attachment.InstallationID) != nil {
			return ErrInvalidPolicy
		}
	case AuthorityScopeInstallationProbe:
		if attachment.Target.Kind != PolicyTargetService || ValidateID("installationId", attachment.InstallationID) != nil {
			return ErrInvalidPolicy
		}
	default:
		return ErrInvalidPolicy
	}
	if attachment.RevokedAt != nil && (validateTime("revokedAt", *attachment.RevokedAt) != nil ||
		attachment.RevokedAt.Before(attachment.CreatedAt) || !attachment.RevokedAt.Equal(attachment.UpdatedAt) || attachment.ResourceVersion < 2) {
		return ErrInvalidPolicy
	}
	return nil
}

func DecodePolicy(reader io.Reader) (Policy, error) {
	var value Policy
	if contractjson.DecodeObject(reader, MaxPolicyBytes, &value) != nil || ValidatePolicy(value) != nil {
		return Policy{}, ErrInvalidPolicy
	}
	return value, nil
}

func DecodePolicyAttachment(reader io.Reader) (PolicyAttachment, error) {
	var value PolicyAttachment
	if contractjson.DecodeObject(reader, MaxPolicyBytes, &value) != nil || ValidatePolicyAttachment(value) != nil {
		return PolicyAttachment{}, ErrInvalidPolicy
	}
	return value, nil
}

func validPolicyScope(scope AuthorityScope) bool {
	return scope == AuthorityScopeTenant || scope == AuthorityScopeInstallation || scope == AuthorityScopeInstallationProbe
}

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
	if !validPolicyScope(document.Scope) {
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
