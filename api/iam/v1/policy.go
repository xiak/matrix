package iamv1

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
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
type PolicyGrantSourceKind string
type PolicyConditionOperator string

const (
	PolicyDateGreaterThanEquals PolicyConditionOperator = "DATE_GREATER_THAN_EQUALS"
	PolicyDateLessThan          PolicyConditionOperator = "DATE_LESS_THAN"
	MaxStatementConditions                              = 16
)

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

const (
	PolicyGrantDirect PolicyGrantSourceKind = "DIRECT"
	PolicyGrantGroup  PolicyGrantSourceKind = "GROUP"
)

// Policy is mutable metadata pointing to one immutable content version. It
// never contains subjects or constitutes permission to attach the policy.
type Policy struct {
	APIVersion       string           `json:"apiVersion"`
	Kind             string           `json:"kind"`
	ID               PolicyID         `json:"id"`
	Management       PolicyManagement `json:"management"`
	AccountID        AccountID        `json:"accountId,omitempty"`
	DisplayName      string           `json:"displayName"`
	Scope            AuthorityScope   `json:"scope"`
	Status           PolicyStatus     `json:"status"`
	DefaultVersionID PolicyVersionID  `json:"defaultVersionId"`
	ResourceVersion  uint64           `json:"resourceVersion"`
	CreatedAt        time.Time        `json:"createdAt"`
	UpdatedAt        time.Time        `json:"updatedAt"`
}

const MaxPolicyListItems = 256
const MaxCustomerPolicies = 128
const MaxPolicyVersions = 5

// PolicyDetail joins metadata to its current immutable default content. It is
// a read result, not proof that the reader may publish or attach that content.
type PolicyDetail struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Policy     Policy        `json:"policy"`
	Version    PolicyVersion `json:"version"`
}

type CreatePolicyRequest struct {
	DisplayName string         `json:"displayName"`
	Document    PolicyDocument `json:"document"`
	RequestID   string         `json:"requestId"`
}

type UpdatePolicyRequest struct {
	DisplayName     string `json:"displayName"`
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

type DeletePolicyRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

func ValidateDeletePolicyRequest(value DeletePolicyRequest) error {
	if validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return ValidateID("requestId", value.RequestID)
}

func ValidateUpdatePolicyRequest(value UpdatePolicyRequest) error {
	if validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return errors.Join(validateText("displayName", value.DisplayName, 1, 128), ValidateID("requestId", value.RequestID))
}

// The selected version need not be the default. This is distinct from the
// current-default PolicyDetail contract and is never an authorization permit.
type PolicyVersionDetail struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Policy     Policy        `json:"policy"`
	Version    PolicyVersion `json:"version"`
}

type PolicyVersionList struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Policy     Policy          `json:"policy"`
	Items      []PolicyVersion `json:"items"`
}

type CreatePolicyVersionRequest struct {
	Document        PolicyDocument `json:"document"`
	ResourceVersion uint64         `json:"resourceVersion"`
	RequestID       string         `json:"requestId"`
}

type SetDefaultPolicyVersionRequest struct {
	VersionID       PolicyVersionID `json:"versionId"`
	ResourceVersion uint64          `json:"resourceVersion"`
	RequestID       string          `json:"requestId"`
}

type DeletePolicyVersionRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

func ValidateDeletePolicyVersionRequest(value DeletePolicyVersionRequest) error {
	if validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return ValidateID("requestId", value.RequestID)
}

func ValidateCreatePolicyVersionRequest(value CreatePolicyVersionRequest) error {
	if value.Document.Scope != AuthorityScopeTenant || validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return errors.Join(ValidateID("requestId", value.RequestID), ValidatePolicyDocument(value.Document))
}

func ValidateSetDefaultPolicyVersionRequest(value SetDefaultPolicyVersionRequest) error {
	if validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return errors.Join(ValidateID("requestId", value.RequestID), ValidateID("versionId", string(value.VersionID)))
}

func ValidatePolicyVersionDetail(value PolicyVersionDetail) error {
	if value.APIVersion != APIVersion || value.Kind != "PolicyVersionDetail" || ValidatePolicy(value.Policy) != nil ||
		value.Policy.Management != PolicyCustomerManaged || value.Policy.Status != PolicyActive ||
		ValidatePolicyVersion(value.Version) != nil || value.Version.PolicyID != value.Policy.ID || value.Version.Document.Scope != value.Policy.Scope {
		return ErrInvalidPolicy
	}
	return nil
}

func ValidatePolicyVersionList(value PolicyVersionList) error {
	if value.APIVersion != APIVersion || value.Kind != "PolicyVersionList" || ValidatePolicy(value.Policy) != nil ||
		value.Policy.Management != PolicyCustomerManaged || value.Policy.Status != PolicyActive || len(value.Items) == 0 || len(value.Items) > MaxPolicyVersions {
		return ErrInvalidPolicy
	}
	var previous PolicyVersionID
	defaultFound := false
	for _, version := range value.Items {
		if ValidatePolicyVersion(version) != nil || version.PolicyID != value.Policy.ID || version.Document.Scope != value.Policy.Scope || version.ID <= previous {
			return ErrInvalidPolicy
		}
		previous = version.ID
		defaultFound = defaultFound || version.ID == value.Policy.DefaultVersionID
	}
	if !defaultFound {
		return ErrInvalidPolicy
	}
	return nil
}

func ValidateCreatePolicyRequest(value CreatePolicyRequest) error {
	if value.Document.Scope != AuthorityScopeTenant {
		return ErrInvalidPolicy
	}
	return errors.Join(validateText("displayName", value.DisplayName, 1, 128),
		ValidateID("requestId", value.RequestID), ValidatePolicyDocument(value.Document))
}

func ValidatePolicyDetail(value PolicyDetail) error {
	if value.APIVersion != APIVersion || value.Kind != "PolicyDetail" ||
		ValidatePolicy(value.Policy) != nil || ValidatePolicyVersion(value.Version) != nil ||
		value.Policy.Status != PolicyActive || value.Policy.Scope != AuthorityScopeTenant ||
		value.Version.PolicyID != value.Policy.ID || value.Version.ID != value.Policy.DefaultVersionID ||
		value.Version.Document.Scope != value.Policy.Scope {
		return ErrInvalidPolicy
	}
	return nil
}

// PolicyList is a complete bounded metadata snapshot, not an authorization
// permit. The scope is derived from the separately authorized route.
type PolicyList struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	AccountID      AccountID      `json:"accountId"`
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
		if ValidatePolicy(item) != nil || item.Status != PolicyActive || item.Scope != value.Scope || (item.AccountID != "" && item.AccountID != value.AccountID) || item.ID <= previous {
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
	AccountID       AccountID              `json:"accountId"`
	Target          PolicyAttachmentTarget `json:"target"`
	PolicyID        PolicyID               `json:"policyId"`
	Scope           AuthorityScope         `json:"scope"`
	InstallationID  string                 `json:"installationId,omitempty"`
	ResourceVersion uint64                 `json:"resourceVersion"`
	CreatedAt       time.Time              `json:"createdAt"`
	UpdatedAt       time.Time              `json:"updatedAt"`
	RevokedAt       *time.Time             `json:"revokedAt,omitempty"`
}

// PolicyGrantSource describes one current authority path. It is a read-only
// snapshot and never a reusable authorization permit.
type PolicyGrantSource struct {
	Kind       PolicyGrantSourceKind `json:"kind"`
	Attachment PolicyAttachment      `json:"attachment"`
	Membership *GroupMembership      `json:"membership,omitempty"`
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
	// Group is the only inherited carrier implemented in this slice. Role and
	// service-credential management remain closed until their own workflows.
	if value.Target.Kind != PolicyTargetUser && value.Target.Kind != PolicyTargetGroup {
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

func ValidatePolicyGrantSource(source PolicyGrantSource) error {
	if ValidatePolicyAttachment(source.Attachment) != nil || source.Attachment.RevokedAt != nil {
		return ErrInvalidPolicy
	}
	switch source.Kind {
	case PolicyGrantDirect:
		if source.Membership != nil || source.Attachment.Target.Kind != PolicyTargetUser {
			return ErrInvalidPolicy
		}
	case PolicyGrantGroup:
		if source.Membership == nil || ValidateGroupMembership(*source.Membership) != nil || source.Membership.RemovedAt != nil ||
			source.Attachment.Scope != AuthorityScopeTenant || source.Attachment.Target.Kind != PolicyTargetGroup ||
			source.Attachment.AccountID != source.Membership.AccountID ||
			source.Attachment.Target.ID != string(source.Membership.GroupID) {
			return ErrInvalidPolicy
		}
	default:
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

type PolicyValidationCode string

const (
	PolicyInvalidDocument  PolicyValidationCode = "INVALID_DOCUMENT"
	PolicyInvalidValue     PolicyValidationCode = "INVALID_VALUE"
	PolicyUnsupported      PolicyValidationCode = "UNSUPPORTED"
	PolicyDuplicate        PolicyValidationCode = "DUPLICATE"
	PolicyLimitExceeded    PolicyValidationCode = "LIMIT_EXCEEDED"
	PolicyScopeMismatch    PolicyValidationCode = "SCOPE_MISMATCH"
	PolicyResourceMismatch PolicyValidationCode = "RESOURCE_MISMATCH"
)

// PolicyValidationError locates a rejected field without echoing input values.
// Pointer is a JSON Pointer; the empty string denotes the entire document.
// Ordinary errors remain sanitized and compatible with ErrInvalidPolicy.
type PolicyValidationError struct {
	Code    PolicyValidationCode
	Pointer string
}

func (err *PolicyValidationError) Error() string { return ErrInvalidPolicy.Error() }
func (err *PolicyValidationError) Unwrap() error { return ErrInvalidPolicy }

func invalidPolicyAt(code PolicyValidationCode, pointer string) error {
	return &PolicyValidationError{Code: code, Pointer: pointer}
}

// PolicyDocument is a closed permission language, not a request-supplied
// authority. Valid syntax does not confer permission to publish or attach it.
type PolicyDocument struct {
	LanguageVersion string            `json:"languageVersion"`
	Scope           AuthorityScope    `json:"scope"`
	Statements      []PolicyStatement `json:"statements"`
}

type PolicyStatement struct {
	SID        string                   `json:"sid"`
	Effect     PolicyEffect             `json:"effect"`
	Actions    []Action                 `json:"actions"`
	Resources  []PolicyResourceSelector `json:"resources"`
	Conditions []PolicyCondition        `json:"conditions,omitempty"`
}

type PolicyCondition struct {
	Key      ConditionKey            `json:"key"`
	Operator PolicyConditionOperator `json:"operator"`
	Values   []string                `json:"values"`
}

func (statement *PolicyStatement) UnmarshalJSON(source []byte) error {
	type wire PolicyStatement
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxPolicyBytes, &decoded) != nil {
		return ErrInvalidPolicy
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(source, &fields) != nil {
		return ErrInvalidPolicy
	}
	if _, present := fields["conditions"]; present && len(decoded.Conditions) == 0 {
		return ErrInvalidPolicy
	}
	*statement = PolicyStatement(decoded)
	return nil
}

// ParsePolicyTime accepts a single canonical UTC representation with at most
// microsecond precision. It never accepts a timezone or a local clock fallback.
func ParsePolicyTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || validateTime("conditionTime", parsed) != nil || parsed.Year() < 1 || parsed.Year() > 9999 || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, ErrInvalidPolicy
	}
	return parsed, nil
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
		code := PolicyInvalidDocument
		if errors.Is(err, contractjson.ErrDocumentTooLarge) || errors.Is(err, contractjson.ErrDocumentTooDeep) {
			code = PolicyLimitExceeded
		}
		return PolicyDocument{}, invalidPolicyAt(code, "")
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
		return invalidPolicyAt(PolicyLimitExceeded, "")
	}
	return nil
}

func validatePolicyStructure(document PolicyDocument) error {
	if document.LanguageVersion != PolicyLanguageVersion {
		return invalidPolicyAt(PolicyUnsupported, "/languageVersion")
	}
	if !validPolicyScope(document.Scope) {
		return invalidPolicyAt(PolicyInvalidValue, "/scope")
	}
	if len(document.Statements) == 0 || len(document.Statements) > MaxPolicyStatements {
		return invalidPolicyAt(PolicyLimitExceeded, "/statements")
	}
	seenStatements := make(map[string]bool, len(document.Statements))
	for index, statement := range document.Statements {
		pointer := "/statements/" + strconv.Itoa(index)
		if ValidateID("sid", statement.SID) != nil {
			return invalidPolicyAt(PolicyInvalidValue, pointer+"/sid")
		}
		if seenStatements[statement.SID] {
			return invalidPolicyAt(PolicyDuplicate, pointer+"/sid")
		}
		seenStatements[statement.SID] = true
		if statement.Effect != PolicyAllow && statement.Effect != PolicyDeny {
			return invalidPolicyAt(PolicyInvalidValue, pointer+"/effect")
		}
		if len(statement.Actions) == 0 || len(statement.Actions) > MaxStatementActions {
			return invalidPolicyAt(PolicyLimitExceeded, pointer+"/actions")
		}
		if len(statement.Resources) == 0 || len(statement.Resources) > MaxStatementResources {
			return invalidPolicyAt(PolicyLimitExceeded, pointer+"/resources")
		}
		if err := validatePolicyConditions(statement, pointer); err != nil {
			return err
		}
		seenActions := make(map[Action]bool, len(statement.Actions))
		requiredKinds := make(map[ResourceKind]bool)
		for index, action := range statement.Actions {
			actionPointer := pointer + "/actions/" + strconv.Itoa(index)
			definition, known := LookupActionDefinition(action)
			if !known {
				return invalidPolicyAt(PolicyUnsupported, actionPointer)
			}
			if definition.AuthorityScope != document.Scope {
				return invalidPolicyAt(PolicyScopeMismatch, actionPointer)
			}
			if seenActions[action] {
				return invalidPolicyAt(PolicyDuplicate, actionPointer)
			}
			seenActions[action] = true
			requiredKinds[definition.ResourceKind] = false
		}
		seenResources := make(map[PolicyResourceSelector]bool, len(statement.Resources))
		for index, resource := range statement.Resources {
			resourcePointer := pointer + "/resources/" + strconv.Itoa(index)
			if _, needed := requiredKinds[resource.Kind]; !needed {
				return invalidPolicyAt(PolicyResourceMismatch, resourcePointer+"/kind")
			}
			if seenResources[resource] {
				return invalidPolicyAt(PolicyDuplicate, resourcePointer)
			}
			switch resource.Match {
			case PolicyResourceExact:
				if ValidateID("resource.id", resource.ID) != nil {
					return invalidPolicyAt(PolicyInvalidValue, resourcePointer+"/id")
				}
			case PolicyResourceAnyInAuthority:
				if resource.ID != "" {
					return invalidPolicyAt(PolicyInvalidValue, resourcePointer+"/id")
				}
			default:
				return invalidPolicyAt(PolicyUnsupported, resourcePointer+"/match")
			}
			seenResources[resource] = true
			requiredKinds[resource.Kind] = true
		}
		// Select the first uncovered action in input order, not map iteration
		// order, so repeated analysis always identifies the same field.
		for index, action := range statement.Actions {
			definition, _ := LookupActionDefinition(action)
			if !requiredKinds[definition.ResourceKind] {
				return invalidPolicyAt(PolicyResourceMismatch, pointer+"/actions/"+strconv.Itoa(index))
			}
		}
	}
	return nil
}

func validatePolicyConditions(statement PolicyStatement, pointer string) error {
	if statement.Conditions != nil && (len(statement.Conditions) == 0 || len(statement.Conditions) > MaxStatementConditions) {
		return invalidPolicyAt(PolicyLimitExceeded, pointer+"/conditions")
	}
	seen := make(map[PolicyConditionOperator]bool)
	var start, end time.Time
	for index, condition := range statement.Conditions {
		location := pointer + "/conditions/" + strconv.Itoa(index)
		if condition.Key != ConditionIAMCurrentTime {
			return invalidPolicyAt(PolicyUnsupported, location+"/key")
		}
		for _, action := range statement.Actions {
			if _, supported := LookupActionConditionDefinition(action, condition.Key); !supported {
				return invalidPolicyAt(PolicyUnsupported, location+"/key")
			}
		}
		if condition.Operator != PolicyDateGreaterThanEquals && condition.Operator != PolicyDateLessThan {
			return invalidPolicyAt(PolicyUnsupported, location+"/operator")
		}
		if seen[condition.Operator] {
			return invalidPolicyAt(PolicyDuplicate, location)
		}
		seen[condition.Operator] = true
		if len(condition.Values) != 1 {
			return invalidPolicyAt(PolicyLimitExceeded, location+"/values")
		}
		value, err := ParsePolicyTime(condition.Values[0])
		if err != nil {
			return invalidPolicyAt(PolicyInvalidValue, location+"/values/0")
		}
		if condition.Operator == PolicyDateGreaterThanEquals {
			start = value
		} else {
			end = value
		}
		if !start.IsZero() && !end.IsZero() && !start.Before(end) {
			return invalidPolicyAt(PolicyInvalidValue, location+"/values/0")
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
		statement.Conditions = append([]PolicyCondition(nil), statement.Conditions...)
		slices.SortFunc(statement.Conditions, func(left, right PolicyCondition) int {
			if order := cmp.Compare(left.Key, right.Key); order != 0 {
				return order
			}
			return cmp.Compare(left.Operator, right.Operator)
		})
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
		return "", "", invalidPolicyAt(PolicyLimitExceeded, "")
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
