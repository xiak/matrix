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
	PolicyStringEquals          PolicyConditionOperator = "STRING_EQUALS"
	PolicyStringNotEquals       PolicyConditionOperator = "STRING_NOT_EQUALS"
	MaxStatementConditions                              = 16
	MaxStringConditionValues                            = 16
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
	PolicyLanguageVersion                               = "1"
	MaxPolicyBytes                  int64               = 64 * 1024
	MaxPolicyStatements                                 = 64
	MaxStatementActions                                 = 128
	MaxStatementResources                               = 64
	PolicyAllow                     PolicyEffect        = "ALLOW"
	PolicyDeny                      PolicyEffect        = "DENY"
	PolicyResourceExact             PolicyResourceMatch = "EXACT"
	PolicyResourceAnyInAuthority    PolicyResourceMatch = "ANY_IN_AUTHORITY"
	PolicyResourcePrefixInAuthority PolicyResourceMatch = "PREFIX_IN_AUTHORITY"
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

// Authority-scoped matching never asserts resource ownership. Product PEPs
// must bind the actual resource to the credential-derived authority. For
// PREFIX_IN_AUTHORITY, ID is a literal, nonempty prefix, not a glob or a path.
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

const (
	PolicyCompilationVersion           = "1"
	MaxPolicyCompilationProfiles       = 16
	MaxPolicyCompilationBytes    int64 = 128 * 1024
)

// PolicyCompilation freezes how one author document was resolved against
// explicit product declarations. It is not accepted from policy publishers,
// does not authenticate those declarations, and is not an authorization permit.
// The current PolicyVersion wire remains separate until its storage cutover.
type PolicyCompilation struct {
	CompilationVersion string                          `json:"compilationVersion"`
	Profiles           []AuthorizationProfileReference `json:"profiles"`
	ResolvedStatements []PolicyResolvedStatement       `json:"resolvedStatements"`
}

type PolicyResolvedStatement struct {
	SID     string   `json:"sid"`
	Actions []Action `json:"actions"`
}

// UserPermissionBoundary describes a limit, never a positive grant. A null
// Policy explicitly means no tenant boundary at this User revision.
type UserPermissionBoundary struct {
	APIVersion      string                  `json:"apiVersion"`
	Kind            string                  `json:"kind"`
	AccountID       AccountID               `json:"accountId"`
	UserID          PrincipalID             `json:"userId"`
	ResourceVersion uint64                  `json:"resourceVersion"`
	Policy          *PolicyVersionReference `json:"policy"`
}

type SetUserPermissionBoundaryRequest struct {
	PolicyID              PolicyID `json:"policyId"`
	PolicyResourceVersion uint64   `json:"policyResourceVersion"`
	ResourceVersion       uint64   `json:"resourceVersion"`
	RequestID             string   `json:"requestId"`
}

type RemoveUserPermissionBoundaryRequest struct {
	ResourceVersion uint64 `json:"resourceVersion"`
	RequestID       string `json:"requestId"`
}

func ValidateSetUserPermissionBoundaryRequest(value SetUserPermissionBoundaryRequest) error {
	if validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return errors.Join(ValidateID("policyId", string(value.PolicyID)),
		validatePositiveVersion(value.PolicyResourceVersion), ValidateID("requestId", value.RequestID))
}

func ValidateRemoveUserPermissionBoundaryRequest(value RemoveUserPermissionBoundaryRequest) error {
	if validatePositiveVersion(value.ResourceVersion) != nil || value.ResourceVersion == 9007199254740991 {
		return ErrInvalidPolicy
	}
	return ValidateID("requestId", value.RequestID)
}

func ValidateUserPermissionBoundary(value UserPermissionBoundary) error {
	if value.APIVersion != APIVersion || value.Kind != "UserPermissionBoundary" ||
		ValidateID("accountId", string(value.AccountID)) != nil || ValidateID("userId", string(value.UserID)) != nil ||
		validatePositiveVersion(value.ResourceVersion) != nil {
		return ErrInvalidPolicy
	}
	if value.Policy != nil {
		return errors.Join(ValidateID("policyId", string(value.Policy.PolicyID)),
			ValidateID("versionId", string(value.Policy.VersionID)), ValidateDigest("contentDigest", value.Policy.ContentDigest))
	}
	return nil
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
	return validatePolicyStructureWithCapabilities(document, currentPolicyCapabilities)
}

// Both current publication validation and immutable compilation use this
// validator. Only the source of declared capabilities differs; there is no
// second policy grammar or permissive historical-policy parser.
type policyCapabilityLookup struct {
	action    func(Action) (ActionDefinition, bool)
	condition func(Action, ConditionKey) (ConditionKeyDefinition, bool)
}

var currentPolicyCapabilities = policyCapabilityLookup{LookupActionDefinition, LookupActionConditionDefinition}

func validatePolicyStructureWithCapabilities(document PolicyDocument, capabilities policyCapabilityLookup) error {
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
		if err := validatePolicyConditions(statement, pointer, capabilities); err != nil {
			return err
		}
		seenActions := make(map[Action]bool, len(statement.Actions))
		requiredKinds := make(map[ResourceKind]bool)
		prefixUnsupportedKinds := make(map[ResourceKind]bool)
		for index, action := range statement.Actions {
			actionPointer := pointer + "/actions/" + strconv.Itoa(index)
			definition, known := capabilities.action(action)
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
			if !definition.ResourcePrefixAllowed {
				prefixUnsupportedKinds[definition.ResourceKind] = true
			}
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
			case PolicyResourcePrefixInAuthority:
				if document.Scope != AuthorityScopeTenant {
					return invalidPolicyAt(PolicyScopeMismatch, resourcePointer+"/match")
				}
				if prefixUnsupportedKinds[resource.Kind] {
					return invalidPolicyAt(PolicyUnsupported, resourcePointer+"/match")
				}
				if ValidateID("resource.id", resource.ID) != nil {
					return invalidPolicyAt(PolicyInvalidValue, resourcePointer+"/id")
				}
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
			definition, _ := capabilities.action(action)
			if !requiredKinds[definition.ResourceKind] {
				return invalidPolicyAt(PolicyResourceMismatch, pointer+"/actions/"+strconv.Itoa(index))
			}
		}
	}
	return nil
}

func validatePolicyConditions(statement PolicyStatement, pointer string, capabilities policyCapabilityLookup) error {
	if statement.Conditions != nil && (len(statement.Conditions) == 0 || len(statement.Conditions) > MaxStatementConditions) {
		return invalidPolicyAt(PolicyLimitExceeded, pointer+"/conditions")
	}
	seen := make(map[struct {
		key      ConditionKey
		operator PolicyConditionOperator
	}]bool)
	var start, end time.Time
	for index, condition := range statement.Conditions {
		location := pointer + "/conditions/" + strconv.Itoa(index)
		if condition.Key != ConditionIAMCurrentTime && condition.Key != ConditionIAMAccountID && condition.Key != ConditionIAMPrincipalID {
			return invalidPolicyAt(PolicyUnsupported, location+"/key")
		}
		for _, action := range statement.Actions {
			if _, supported := capabilities.condition(action, condition.Key); !supported {
				return invalidPolicyAt(PolicyUnsupported, location+"/key")
			}
		}
		identity := struct {
			key      ConditionKey
			operator PolicyConditionOperator
		}{condition.Key, condition.Operator}
		if seen[identity] {
			return invalidPolicyAt(PolicyDuplicate, location)
		}
		seen[identity] = true
		if condition.Key != ConditionIAMCurrentTime {
			if condition.Operator != PolicyStringEquals && condition.Operator != PolicyStringNotEquals {
				return invalidPolicyAt(PolicyUnsupported, location+"/operator")
			}
			if len(condition.Values) < 1 || len(condition.Values) > MaxStringConditionValues {
				return invalidPolicyAt(PolicyLimitExceeded, location+"/values")
			}
			values := make(map[string]bool, len(condition.Values))
			for valueIndex, value := range condition.Values {
				valuePointer := location + "/values/" + strconv.Itoa(valueIndex)
				if ValidateID("condition.value", value) != nil {
					return invalidPolicyAt(PolicyInvalidValue, valuePointer)
				}
				if values[value] {
					return invalidPolicyAt(PolicyDuplicate, valuePointer)
				}
				values[value] = true
			}
			continue
		}
		if condition.Operator != PolicyDateGreaterThanEquals && condition.Operator != PolicyDateLessThan {
			return invalidPolicyAt(PolicyUnsupported, location+"/operator")
		}
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
	encoded, err := canonicalPolicyDocument(document, currentPolicyCapabilities)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(append([]byte("matrix.iam.policy.v1\x00"), encoded...))
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func canonicalPolicyDocument(document PolicyDocument, capabilities policyCapabilityLookup) ([]byte, error) {
	if err := validatePolicyStructureWithCapabilities(document, capabilities); err != nil {
		return nil, err
	}
	document.Statements = append([]PolicyStatement(nil), document.Statements...)
	for index := range document.Statements {
		statement := &document.Statements[index]
		statement.Actions = append([]Action(nil), statement.Actions...)
		statement.Resources = append([]PolicyResourceSelector(nil), statement.Resources...)
		statement.Conditions = append([]PolicyCondition(nil), statement.Conditions...)
		for index := range statement.Conditions {
			condition := &statement.Conditions[index]
			condition.Values = append([]string(nil), condition.Values...)
			slices.Sort(condition.Values)
		}
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
		return nil, invalidPolicyAt(PolicyLimitExceeded, "")
	}
	return encoded, nil
}

// CompilePolicyDocument resolves exact actions using only the supplied
// declarations, never today's global catalog. The owning transaction must
// authenticate and select its current registry heads before invoking it.
// Pattern syntax is deliberately not enabled by this contract slice.
func CompilePolicyDocument(document PolicyDocument, profiles []AuthorizationProfile) (PolicyCompilation, error) {
	compilation, _, err := compilePolicyDocument(document, profiles)
	return compilation, err
}

func compilePolicyDocument(document PolicyDocument, profiles []AuthorizationProfile) (PolicyCompilation, []byte, error) {
	if len(profiles) == 0 || len(profiles) > MaxPolicyCompilationProfiles {
		return PolicyCompilation{}, nil, invalidPolicyAt(PolicyLimitExceeded, "/profiles")
	}
	references := make(map[ProductID]AuthorizationProfileReference, len(profiles))
	definitions := make(map[Action]ActionDefinition)
	conditions := make(map[Action][]AuthorizationProfileCondition)
	for _, profile := range profiles {
		_, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			return PolicyCompilation{}, nil, invalidPolicyAt(PolicyInvalidValue, "/profiles")
		}
		if _, duplicate := references[profile.Product]; duplicate {
			return PolicyCompilation{}, nil, invalidPolicyAt(PolicyDuplicate, "/profiles")
		}
		references[profile.Product] = AuthorizationProfileReference{profile.Product, profile.Revision, digest}
		for _, action := range profile.Actions {
			if _, duplicate := definitions[action.Action]; duplicate {
				return PolicyCompilation{}, nil, invalidPolicyAt(PolicyDuplicate, "/profiles")
			}
			definitions[action.Action] = authorizationProfileActionDefinition(profile, action)
			conditions[action.Action] = action.Conditions
		}
	}
	capabilities := policyCapabilityLookup{
		action: func(action Action) (ActionDefinition, bool) {
			definition, known := definitions[action]
			return definition, known
		},
		condition: func(action Action, key ConditionKey) (ConditionKeyDefinition, bool) {
			for _, condition := range conditions[action] {
				if condition.Key == key {
					return ConditionKeyDefinition{condition.Key, condition.ValueType, condition.Source}, true
				}
			}
			return ConditionKeyDefinition{}, false
		},
	}
	canonical, err := canonicalPolicyDocument(document, capabilities)
	if err != nil {
		return PolicyCompilation{}, nil, err
	}
	compilation := PolicyCompilation{CompilationVersion: PolicyCompilationVersion}
	used := make(map[ProductID]bool)
	for _, statement := range document.Statements {
		actions := slices.Clone(statement.Actions)
		slices.Sort(actions)
		compilation.ResolvedStatements = append(compilation.ResolvedStatements, PolicyResolvedStatement{statement.SID, actions})
		for _, action := range actions {
			used[definitions[action].Product] = true
		}
	}
	for product := range used {
		compilation.Profiles = append(compilation.Profiles, references[product])
	}
	slices.SortFunc(compilation.Profiles, func(left, right AuthorizationProfileReference) int { return cmp.Compare(left.Product, right.Product) })
	slices.SortFunc(compilation.ResolvedStatements, func(left, right PolicyResolvedStatement) int { return cmp.Compare(left.SID, right.SID) })
	content := struct {
		Document json.RawMessage `json:"document"`
		PolicyCompilation
	}{json.RawMessage(canonical), compilation}
	encoded, err := json.Marshal(content)
	if err != nil || int64(len(encoded)) > MaxPolicyCompilationBytes {
		return PolicyCompilation{}, nil, invalidPolicyAt(PolicyLimitExceeded, "")
	}
	return compilation, encoded, nil
}

// CanonicalizePolicyCompilation commits the author document and its exact
// interpretation together. SID equality binds statements without an independent
// statement digest/ordinal. The supplied profiles must later be verified against
// immutable registry records, not caller claims or a newer compatible revision.
func CanonicalizePolicyCompilation(document PolicyDocument, compilation PolicyCompilation, profiles []AuthorizationProfile) (string, string, error) {
	expected, encoded, err := compilePolicyDocument(document, profiles)
	if err != nil {
		return "", "", err
	}
	if compilation.CompilationVersion != PolicyCompilationVersion ||
		len(compilation.Profiles) != len(expected.Profiles) || len(compilation.ResolvedStatements) != len(expected.ResolvedStatements) {
		return "", "", ErrInvalidPolicy
	}
	// Copy all mutable sets before normalization. Equality with the compiler's
	// exact output also rejects duplicates, unused refs and unbound statements.
	compilation.Profiles = slices.Clone(compilation.Profiles)
	compilation.ResolvedStatements = slices.Clone(compilation.ResolvedStatements)
	for _, reference := range compilation.Profiles {
		if !profileIdentifier(string(reference.Product), false) || validatePositiveVersion(reference.Revision) != nil ||
			ValidateDigest("contentDigest", reference.ContentDigest) != nil {
			return "", "", ErrInvalidPolicy
		}
	}
	for index := range compilation.ResolvedStatements {
		statement := &compilation.ResolvedStatements[index]
		if ValidateID("sid", statement.SID) != nil || len(statement.Actions) == 0 || len(statement.Actions) > MaxStatementActions {
			return "", "", ErrInvalidPolicy
		}
		for _, action := range statement.Actions {
			if len(action) == 0 || len(action) > 128 {
				return "", "", ErrInvalidPolicy
			}
		}
		statement.Actions = slices.Clone(statement.Actions)
		slices.Sort(statement.Actions)
	}
	slices.SortFunc(compilation.Profiles, func(left, right AuthorizationProfileReference) int { return cmp.Compare(left.Product, right.Product) })
	slices.SortFunc(compilation.ResolvedStatements, func(left, right PolicyResolvedStatement) int { return cmp.Compare(left.SID, right.SID) })
	if !slices.Equal(compilation.Profiles, expected.Profiles) {
		return "", "", ErrInvalidPolicy
	}
	for index, statement := range compilation.ResolvedStatements {
		if statement.SID != expected.ResolvedStatements[index].SID || !slices.Equal(statement.Actions, expected.ResolvedStatements[index].Actions) {
			return "", "", ErrInvalidPolicy
		}
	}
	digest := sha256.Sum256(append([]byte("matrix.iam.policy-compilation.v1\x00"), encoded...))
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

// DecodePolicyCompilation is for owner-loaded immutable content, not a new
// northbound publication API. Incomplete or forged compilation never falls
// back to the document-only version contract.
func DecodePolicyCompilation(reader io.Reader, document PolicyDocument, profiles []AuthorizationProfile) (PolicyCompilation, error) {
	var compilation PolicyCompilation
	if contractjson.DecodeObject(reader, MaxPolicyCompilationBytes, &compilation) != nil {
		return PolicyCompilation{}, ErrInvalidPolicy
	}
	if _, _, err := CanonicalizePolicyCompilation(document, compilation, profiles); err != nil {
		return PolicyCompilation{}, err
	}
	return compilation, nil
}

// CheckPolicyCompilationRequest checks the compatibility of frozen content
// with one explicitly supplied current request declaration. It is not an Allow:
// callers still authenticate the current head/subject and evaluate all grants,
// boundaries and selectors. Historical proofs must not call this current check.
// Neither supplied declaration is authenticated by this pure contract function.
func CheckPolicyCompilationRequest(document PolicyDocument, compilation PolicyCompilation, contentDigest string,
	frozenProfiles []AuthorizationProfile, current AuthorizationProfile, request AuthorizationRequest,
) error {
	_, digest, err := CanonicalizePolicyCompilation(document, compilation, frozenProfiles)
	if err != nil || digest != contentDigest || ValidateID("requestId", request.RequestID) != nil ||
		ValidateID("correlationId", request.CorrelationID) != nil ||
		CheckAuthorizationProfileTarget(current, request.Profile, request.Action, request.Resource, request.ResourceMode, request.CollectionUsage) != nil {
		return ErrInvalidPolicy
	}
	participatingStatements := make(map[string]bool)
	for _, statement := range compilation.ResolvedStatements {
		if slices.Contains(statement.Actions, request.Action) {
			participatingStatements[statement.SID] = true
		}
	}
	if len(participatingStatements) == 0 {
		// New actions cannot enter the immutable resolved set. This policy
		// contributes no statement, but its complete integrity was still checked.
		return nil
	}
	var currentAction AuthorizationProfileAction
	for _, action := range current.Actions {
		if action.Action == request.Action {
			currentAction = action
			break
		}
	}
	var frozenAction AuthorizationProfileAction
	for _, profile := range frozenProfiles {
		if profile.Product != current.Product {
			continue
		}
		if profile.CallingService != current.CallingService {
			return ErrInvalidPolicy
		}
		for _, reference := range compilation.Profiles {
			if reference.Product == profile.Product &&
				CheckAuthorizationProfileTarget(profile, reference, request.Action, request.Resource, request.ResourceMode, request.CollectionUsage) != nil {
				return ErrInvalidPolicy
			}
		}
		for _, action := range profile.Actions {
			if action.Action == request.Action {
				frozenAction = action
				break
			}
		}
	}
	if frozenAction.Action != request.Action || frozenAction.ResourceKind != currentAction.ResourceKind ||
		frozenAction.Scope != currentAction.Scope || frozenAction.ResultResourceKind != currentAction.ResultResourceKind {
		return ErrInvalidPolicy
	}
	for _, statement := range document.Statements {
		if !participatingStatements[statement.SID] {
			continue
		}
		// Check before evaluating values, selectors or Effect. An old Deny
		// cannot disappear merely because its meaning is no longer understood.
		for _, condition := range statement.Conditions {
			var original, present AuthorizationProfileCondition
			for _, declared := range frozenAction.Conditions {
				if declared.Key == condition.Key {
					original = declared
				}
			}
			for _, declared := range currentAction.Conditions {
				if declared.Key == condition.Key {
					present = declared
				}
			}
			if original.Key != condition.Key || original != present {
				return ErrInvalidPolicy
			}
		}
		if request.ResourceMode == AuthorizationResourceInstance {
			for _, selector := range statement.Resources {
				if selector.Kind != request.Resource.Kind || selector.Match != PolicyResourcePrefixInAuthority {
					continue
				}
				prefixAllowed := false
				for _, shape := range currentAction.ResourceShapes {
					prefixAllowed = prefixAllowed || shape.Mode == AuthorizationResourceInstance && shape.PrefixAllowed
				}
				if !prefixAllowed {
					return ErrInvalidPolicy
				}
			}
		}
	}
	return nil
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
