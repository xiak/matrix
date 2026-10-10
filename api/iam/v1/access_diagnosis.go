package iamv1

import (
	"cmp"
	"errors"
	"slices"
	"time"
)

// AccessDiagnosisOutcome is an observation of the current policy snapshot. It
// is not an AuthorizationDecision and can never be used as a permit.
type AccessDiagnosisOutcome string

const (
	AccessDiagnosisAllowed AccessDiagnosisOutcome = "ALLOWED"
	AccessDiagnosisDenied  AccessDiagnosisOutcome = "DENIED"
)

type AccessDiagnosisReason string

const (
	AccessDiagnosisExplicitDeny               AccessDiagnosisReason = "EXPLICIT_DENY"
	AccessDiagnosisNoMatchingAllow            AccessDiagnosisReason = "NO_MATCHING_ALLOW"
	AccessDiagnosisUserPermissionBoundary     AccessDiagnosisReason = "USER_PERMISSION_BOUNDARY"
	AccessDiagnosisRolePermissionBoundary     AccessDiagnosisReason = "ROLE_PERMISSION_BOUNDARY"
	AccessDiagnosisSessionPolicy              AccessDiagnosisReason = "SESSION_POLICY"
	AccessDiagnosisCredentialRestricted       AccessDiagnosisReason = "CREDENTIAL_RESTRICTED"
	AccessDiagnosisSubjectUnsupported         AccessDiagnosisReason = "SUBJECT_UNSUPPORTED"
	AccessDiagnosisCallingServiceUnsupported  AccessDiagnosisReason = "CALLING_SERVICE_UNSUPPORTED"
	AccessDiagnosisResourceContextUnsupported AccessDiagnosisReason = "RESOURCE_CONTEXT_UNSUPPORTED"
)

type AccessDiagnosisSourceKind string

const (
	AccessDiagnosisSourceDirect      AccessDiagnosisSourceKind = "DIRECT"
	AccessDiagnosisSourceGroup       AccessDiagnosisSourceKind = "GROUP"
	AccessDiagnosisSourceRole        AccessDiagnosisSourceKind = "ROLE"
	AccessDiagnosisSourceServiceRole AccessDiagnosisSourceKind = "SERVICE_ROLE"
)

type AccessDiagnosisEffect string

const (
	AccessDiagnosisEffectAllow AccessDiagnosisEffect = "ALLOW"
	AccessDiagnosisEffectDeny  AccessDiagnosisEffect = "DENY"
)

type AccessDiagnosisRestrictionKind string

const (
	AccessDiagnosisRestrictionUserBoundary  AccessDiagnosisRestrictionKind = "USER_BOUNDARY"
	AccessDiagnosisRestrictionRoleBoundary  AccessDiagnosisRestrictionKind = "ROLE_BOUNDARY"
	AccessDiagnosisRestrictionSessionPolicy AccessDiagnosisRestrictionKind = "SESSION_POLICY"
)

type AccessDiagnosisRestrictionState string

const (
	AccessDiagnosisRestrictionMatched       AccessDiagnosisRestrictionState = "MATCHED"
	AccessDiagnosisRestrictionBlocked       AccessDiagnosisRestrictionState = "BLOCKED"
	AccessDiagnosisRestrictionNotApplicable AccessDiagnosisRestrictionState = "NOT_APPLICABLE"
)

const AccessDiagnosisNotEvaluated = "NOT_EVALUATED"

// One policy can match both Allow and Deny statements, so the bounded public
// projection is twice the authority evaluator's 256-policy input ceiling.
const MaxAccessDiagnosisSources = 512

// AccessDiagnosisSource is a sanitized provenance projection. It deliberately
// omits policy documents, compiled statements and condition values.
type AccessDiagnosisSource struct {
	Kind         AccessDiagnosisSourceKind `json:"kind"`
	Effect       AccessDiagnosisEffect     `json:"effect"`
	Version      PolicyVersionReference    `json:"version"`
	AttachmentID PolicyAttachmentID        `json:"attachmentId,omitempty"`
	MembershipID GroupMembershipID         `json:"membershipId,omitempty"`
}

// AccessDiagnosisRestriction identifies one upper-bound layer. SessionPolicy
// has a digest but no fabricated PolicyVersion identity.
type AccessDiagnosisRestriction struct {
	Kind          AccessDiagnosisRestrictionKind  `json:"kind"`
	State         AccessDiagnosisRestrictionState `json:"state"`
	Version       *PolicyVersionReference         `json:"version,omitempty"`
	ContentDigest string                          `json:"contentDigest,omitempty"`
}

// CurrentAccessDiagnosis explains one current, credential-bound authorization
// evaluation. It carries no decision ID, nonce, bearer or replay authority.
type CurrentAccessDiagnosis struct {
	APIVersion        string                        `json:"apiVersion"`
	Kind              string                        `json:"kind"`
	Outcome           AccessDiagnosisOutcome        `json:"outcome"`
	Reasons           []AccessDiagnosisReason       `json:"reasons"`
	TenantID          AccountID                     `json:"tenantId,omitempty"`
	InstallationID    string                        `json:"installationId,omitempty"`
	Subject           Subject                       `json:"subject"`
	Action            Action                        `json:"action"`
	Resource          ResourceReference             `json:"resource"`
	Profile           AuthorizationProfileReference `json:"profile"`
	ResourceMode      AuthorizationResourceMode     `json:"resourceMode"`
	CollectionUsage   AuthorizationCollectionUsage  `json:"collectionUsage,omitempty"`
	NetworkContext    *AuthorizationNetworkContext  `json:"networkContext,omitempty"`
	RequestTags       []AuthorizationTag            `json:"requestTags,omitempty"`
	ResourceTags      []AuthorizationTag            `json:"resourceTags,omitempty"`
	RequestID         string                        `json:"requestId"`
	CorrelationID     string                        `json:"correlationId"`
	EvaluatedAt       time.Time                     `json:"evaluatedAt"`
	Sources           []AccessDiagnosisSource       `json:"sources"`
	Restrictions      []AccessDiagnosisRestriction  `json:"restrictions"`
	ResourceExistence string                        `json:"resourceExistence"`
	BusinessOutcome   string                        `json:"businessOutcome"`
}

func ValidateCurrentAccessDiagnosis(value CurrentAccessDiagnosis) error {
	profile, known := LookupAuthorizationProfile(value.Profile.Product)
	if !known {
		return errors.New("current access diagnosis profile is invalid")
	}
	return ValidateCurrentAccessDiagnosisForProfile(value, profile)
}

// ValidateCurrentAccessDiagnosisForProfile checks one observation against the
// exact declaration used for its private evaluation. It does not make the
// observation an authorization decision or reusable permit.
func ValidateCurrentAccessDiagnosisForProfile(value CurrentAccessDiagnosis, profile AuthorizationProfile) error {
	if value.APIVersion != APIVersion || value.Kind != "CurrentAccessDiagnosis" ||
		(value.Outcome != AccessDiagnosisAllowed && value.Outcome != AccessDiagnosisDenied) ||
		ValidateSubject(value.Subject) != nil || validateTime("evaluatedAt", value.EvaluatedAt) != nil ||
		value.ResourceExistence != AccessDiagnosisNotEvaluated || value.BusinessOutcome != AccessDiagnosisNotEvaluated {
		return errors.New("current access diagnosis is invalid")
	}
	request := AuthorizationRequest{Action: value.Action, Resource: value.Resource, Profile: value.Profile,
		ResourceMode: value.ResourceMode, CollectionUsage: value.CollectionUsage, NetworkContext: value.NetworkContext,
		RequestTags: value.RequestTags, ResourceTags: value.ResourceTags, RequestID: value.RequestID, CorrelationID: value.CorrelationID}
	if ValidateAuthorizationRequestForProfile(request, profile) != nil || len(value.Reasons) > 9 || len(value.Sources) > MaxAccessDiagnosisSources || len(value.Restrictions) > 3 {
		return errors.New("current access diagnosis binding is invalid")
	}
	definition, known := LookupAuthorizationProfileActionDefinition(profile, value.Action)
	if !known {
		return errors.New("current access diagnosis action is invalid")
	}
	if definition.AuthorityScope == AuthorityScopeTenant {
		if ValidateID("tenantId", string(value.TenantID)) != nil || value.InstallationID != "" {
			return errors.New("current access diagnosis tenant scope is invalid")
		}
	} else if ValidateID("installationId", value.InstallationID) != nil || value.TenantID != "" {
		return errors.New("current access diagnosis installation scope is invalid")
	}
	if value.Outcome == AccessDiagnosisAllowed && len(value.Reasons) != 0 || value.Outcome == AccessDiagnosisDenied && len(value.Reasons) == 0 ||
		!slices.IsSorted(value.Reasons) || hasDuplicateComparable(value.Reasons) {
		return errors.New("current access diagnosis reasons are invalid")
	}
	for _, reason := range value.Reasons {
		if !knownAccessDiagnosisReason(reason) {
			return errors.New("current access diagnosis reason is invalid")
		}
	}
	for index, source := range value.Sources {
		if validateAccessDiagnosisSource(source) != nil || index > 0 && compareAccessDiagnosisSource(value.Sources[index-1], source) >= 0 {
			return errors.New("current access diagnosis sources are invalid")
		}
	}
	for index, restriction := range value.Restrictions {
		if validateAccessDiagnosisRestriction(restriction) != nil || index > 0 && cmp.Compare(value.Restrictions[index-1].Kind, restriction.Kind) >= 0 {
			return errors.New("current access diagnosis restrictions are invalid")
		}
	}
	return nil
}

func knownAccessDiagnosisReason(value AccessDiagnosisReason) bool {
	switch value {
	case AccessDiagnosisExplicitDeny, AccessDiagnosisNoMatchingAllow, AccessDiagnosisUserPermissionBoundary,
		AccessDiagnosisRolePermissionBoundary, AccessDiagnosisSessionPolicy, AccessDiagnosisCredentialRestricted,
		AccessDiagnosisSubjectUnsupported, AccessDiagnosisCallingServiceUnsupported, AccessDiagnosisResourceContextUnsupported:
		return true
	default:
		return false
	}
}

func validateAccessDiagnosisSource(value AccessDiagnosisSource) error {
	if value.Kind != AccessDiagnosisSourceDirect && value.Kind != AccessDiagnosisSourceGroup &&
		value.Kind != AccessDiagnosisSourceRole && value.Kind != AccessDiagnosisSourceServiceRole {
		return errors.New("access diagnosis source kind is invalid")
	}
	if value.Effect != AccessDiagnosisEffectAllow && value.Effect != AccessDiagnosisEffectDeny ||
		validateAccessDiagnosisPolicyVersion(value.Version) != nil {
		return errors.New("access diagnosis source is invalid")
	}
	switch value.Kind {
	case AccessDiagnosisSourceGroup:
		if ValidateID("attachmentId", string(value.AttachmentID)) != nil || ValidateID("membershipId", string(value.MembershipID)) != nil {
			return errors.New("access diagnosis group source is invalid")
		}
	case AccessDiagnosisSourceDirect, AccessDiagnosisSourceRole:
		if ValidateID("attachmentId", string(value.AttachmentID)) != nil || value.MembershipID != "" {
			return errors.New("access diagnosis attachment source is invalid")
		}
	case AccessDiagnosisSourceServiceRole:
		if value.AttachmentID != "" || value.MembershipID != "" {
			return errors.New("access diagnosis service role source is invalid")
		}
	}
	return nil
}

func validateAccessDiagnosisRestriction(value AccessDiagnosisRestriction) error {
	if value.Kind != AccessDiagnosisRestrictionUserBoundary && value.Kind != AccessDiagnosisRestrictionRoleBoundary &&
		value.Kind != AccessDiagnosisRestrictionSessionPolicy || value.State != AccessDiagnosisRestrictionMatched &&
		value.State != AccessDiagnosisRestrictionBlocked && value.State != AccessDiagnosisRestrictionNotApplicable {
		return errors.New("access diagnosis restriction is invalid")
	}
	if value.Kind == AccessDiagnosisRestrictionSessionPolicy {
		if value.Version != nil || value.State == AccessDiagnosisRestrictionNotApplicable && value.ContentDigest != "" ||
			value.State != AccessDiagnosisRestrictionNotApplicable && ValidateDigest("contentDigest", value.ContentDigest) != nil {
			return errors.New("access diagnosis session restriction is invalid")
		}
		return nil
	}
	if value.ContentDigest != "" || value.State == AccessDiagnosisRestrictionNotApplicable && value.Version != nil ||
		value.State != AccessDiagnosisRestrictionNotApplicable && (value.Version == nil || validateAccessDiagnosisPolicyVersion(*value.Version) != nil) {
		return errors.New("access diagnosis boundary restriction is invalid")
	}
	return nil
}

func validateAccessDiagnosisPolicyVersion(value PolicyVersionReference) error {
	return errors.Join(
		ValidateID("policyId", string(value.PolicyID)),
		ValidateID("versionId", string(value.VersionID)),
		ValidateDigest("contentDigest", value.ContentDigest),
	)
}

func compareAccessDiagnosisSource(left, right AccessDiagnosisSource) int {
	if result := cmp.Compare(left.Kind, right.Kind); result != 0 {
		return result
	}
	if result := cmp.Compare(left.Effect, right.Effect); result != 0 {
		return result
	}
	if result := cmp.Compare(left.Version.PolicyID, right.Version.PolicyID); result != 0 {
		return result
	}
	if result := cmp.Compare(left.Version.VersionID, right.Version.VersionID); result != 0 {
		return result
	}
	if result := cmp.Compare(left.AttachmentID, right.AttachmentID); result != 0 {
		return result
	}
	return cmp.Compare(left.MembershipID, right.MembershipID)
}

func hasDuplicateComparable[T comparable](values []T) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}
