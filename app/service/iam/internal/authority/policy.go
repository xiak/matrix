package authority

import (
	"cmp"
	"errors"
	"slices"
	"strings"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const MaxEvaluationPolicies = 256
const MaxEvaluationStatements = 4096

var ErrInvalidPolicyState = errors.New("IAM policy authority state is invalid")

// AttachedPolicy is one database-resolved relationship, not a caller-provided
// permission document. A non-nil Membership proves one live group inheritance
// path; both direct and inherited authority enter the same evaluator.
type AttachedPolicy struct {
	Policy     iamv1.Policy                 `json:"policy"`
	Version    iamv1.PolicyVersion          `json:"version"`
	Attachment iamv1.PolicyAttachment       `json:"attachment"`
	Membership *iamv1.GroupMembership       `json:"membership,omitempty"`
	Profiles   []iamv1.AuthorizationProfile `json:"-"`
}

type PolicyAttachmentEvidence struct {
	AttachmentID              iamv1.PolicyAttachmentID     `json:"attachmentId"`
	ResourceVersion           uint64                       `json:"resourceVersion"`
	MembershipID              iamv1.GroupMembershipID      `json:"membershipId,omitempty"`
	MembershipResourceVersion uint64                       `json:"membershipResourceVersion,omitempty"`
	Version                   iamv1.PolicyVersionReference `json:"version"`
	ContractVersion           uint64                       `json:"contractVersion"`
	Compilation               *iamv1.PolicyCompilation     `json:"compilation,omitempty"`
}

// ResolvedUserBoundary is a current database snapshot, never a request field
// or an attachment. NONE is explicit so a missing row/decoder result fails
// closed rather than silently dropping an upper bound.
type ResolvedUserBoundary struct {
	State               string                       `json:"state"`
	AccountID           iamv1.AccountID              `json:"accountId"`
	UserID              iamv1.PrincipalID            `json:"userId"`
	UserResourceVersion uint64                       `json:"userResourceVersion"`
	BoundaryID          string                       `json:"boundaryId,omitempty"`
	ResourceVersion     uint64                       `json:"resourceVersion,omitempty"`
	Policy              *iamv1.Policy                `json:"policy,omitempty"`
	Version             *iamv1.PolicyVersion         `json:"version,omitempty"`
	Profiles            []iamv1.AuthorizationProfile `json:"-"`
}

type UserBoundaryEvidence struct {
	State               string                        `json:"state"`
	UserResourceVersion uint64                        `json:"userResourceVersion,omitempty"`
	BoundaryID          string                        `json:"boundaryId,omitempty"`
	ResourceVersion     uint64                        `json:"resourceVersion,omitempty"`
	Version             *iamv1.PolicyVersionReference `json:"version,omitempty"`
	ContractVersion     uint64                        `json:"contractVersion,omitempty"`
	Compilation         *iamv1.PolicyCompilation      `json:"compilation,omitempty"`
}

func ValidateUserBoundary(value *ResolvedUserBoundary, account iamv1.AccountID, user iamv1.PrincipalID, revision uint64) error {
	if iamv1.ValidateID("accountId", string(account)) != nil || iamv1.ValidateID("userId", string(user)) != nil ||
		value == nil || value.AccountID != account || value.UserID != user ||
		value.UserResourceVersion != revision || revision == 0 || revision > 9007199254740991 {
		return ErrInvalidPolicyState
	}
	switch value.State {
	case "NONE":
		if value.BoundaryID != "" || value.ResourceVersion != 0 || value.Policy != nil || value.Version != nil {
			return ErrInvalidPolicyState
		}
	case "BOUND":
		if iamv1.ValidateID("boundaryId", value.BoundaryID) != nil || value.ResourceVersion == 0 || value.ResourceVersion > 9007199254740991 ||
			value.Policy == nil || value.Version == nil || iamv1.ValidatePolicy(*value.Policy) != nil ||
			iamv1.ValidatePolicyVersion(*value.Version) != nil {
			return ErrInvalidPolicyState
		}
		policy, version := value.Policy, value.Version
		if policy.Status != iamv1.PolicyActive || policy.Scope != iamv1.AuthorityScopeTenant ||
			(policy.Management == iamv1.PolicyCustomerManaged && policy.AccountID != account) ||
			version.PolicyID != policy.ID || version.ID != policy.DefaultVersionID || version.Document.Scope != policy.Scope {
			return ErrInvalidPolicyState
		}
	default:
		return ErrInvalidPolicyState
	}
	return nil
}

// Boundary statements use the same evaluator and current typed context as
// grants; their result and provenance must not be merged into grant sources.
func evaluateUserBoundary(value *ResolvedUserBoundary, context policyEvaluationContext, request iamv1.AuthorizationRequest) (PolicyEvaluation, UserBoundaryEvidence, error) {
	evidence := UserBoundaryEvidence{State: value.State, UserResourceVersion: value.UserResourceVersion}
	if value.State == "NONE" {
		return PolicyEvaluation{Allowed: true}, evidence, nil
	}
	context.profiles = make(map[iamv1.AuthorizationProfileReference]iamv1.AuthorizationProfile)
	if context.includeProfiles(value.Profiles) != nil {
		return PolicyEvaluation{}, UserBoundaryEvidence{}, ErrInvalidPolicyState
	}
	result, err := evaluatePolicies(context, []iamv1.PolicyVersion{*value.Version}, request)
	if err != nil {
		return PolicyEvaluation{}, UserBoundaryEvidence{}, err
	}
	evidence.BoundaryID, evidence.ResourceVersion = value.BoundaryID, value.ResourceVersion
	evidence.Version = &iamv1.PolicyVersionReference{PolicyID: value.Policy.ID, VersionID: value.Version.ID, ContentDigest: value.Version.ContentDigest}
	evidence.ContractVersion, evidence.Compilation = value.Version.ContractVersion, value.Version.Compilation
	return result, evidence, nil
}

type PolicyEvaluation struct {
	Allowed         bool
	ExplicitDeny    bool
	MatchedVersions []iamv1.PolicyVersionReference
}

// Constructed from the owner-validated snapshot, never decoded from a request.
// Keep condition sources typed rather than admitting a caller attribute map.
type policyEvaluationContext struct {
	databaseTime time.Time
	accountID    iamv1.AccountID
	subject      iamv1.Subject
	profiles     map[iamv1.AuthorizationProfileReference]iamv1.AuthorizationProfile
}

func (context *policyEvaluationContext) includeProfiles(profiles []iamv1.AuthorizationProfile) error {
	for _, profile := range profiles {
		_, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			return ErrInvalidPolicyState
		}
		reference := iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
		context.profiles[reference] = profile
	}
	return nil
}

// LegacySystemPolicyReferences describes only the exact source-owned seeds at
// the supported interpretation baseline. It is NOT proof of a row's binary
// provenance, a CUSTOMER compatibility path or a migration backfill.
func LegacySystemPolicyReferences(version iamv1.PolicyVersion) ([]iamv1.AuthorizationProfileReference, bool) {
	if version.ContractVersion != iamv1.PolicyVersionLegacyContract || iamv1.ValidatePolicyVersion(version) != nil {
		return nil, false
	}
	seeds := map[iamv1.PolicyID]string{
		iamv1.SystemPolicyAccountAdministrator: "2202a829e32905bb3d522996f01b4b5141430a25d0733fa1c75ad620deb24273",
		iamv1.SystemPolicyPlatformOperator:     "3f4d1db89d94ef13aca81c5da190bf67d03f1c24d217387981f983ec911de3b7",
		iamv1.SystemPolicyPaaSDeveloper:        "a3483d842d049b77a7406f8ba068ad74147b75e6a27d7a53d1e475090c59949c",
		iamv1.SystemPolicyPaaSViewer:           "f50cb1247177f209740ac2b8487b12be62c7d00d575ae382be1e64af0aed1305",
		iamv1.SystemPolicyAuditReader:          "51ac082ac0e5053510ae920a4af9b870f0b08c4c8854b28d59650e695625f890",
		iamv1.SystemPolicyInstallationVerifier: "230e3de1d9a19cd85b53e268f1f3fc7680489e52e05fb1ac362fa62724451823",
	}
	hex, found := seeds[version.PolicyID]
	if !found || version.ContentDigest != "sha256:"+hex || version.ID != iamv1.PolicyVersionID("version-"+hex) {
		return nil, false
	}
	// Exact archive keys, never a lookup of today's head or a guessed revision.
	return []iamv1.AuthorizationProfileReference{
		{Product: iamv1.ProductIAM, Revision: 1, ContentDigest: "sha256:9e6176c37a0b1566987e6c666c1fef9da1f81b90078c6d7fb8a91473ae666a44"},
		{Product: iamv1.ProductPaaS, Revision: 1, ContentDigest: "sha256:f2409682d451b564cbd55b2b315543c2f4b333e3f027f3b4377b103ecc1e2876"},
		{Product: iamv1.ProductManagedService, Revision: 1, ContentDigest: "sha256:5b728c9d7cdd97cc7eeb4cc095d9e053bbf5dab74ca2c08a239b25a6a4c99e2f"},
		{Product: iamv1.ProductAudit, Revision: 1, ContentDigest: "sha256:6bae9c16c05ad781662190c02ab2adb1e552ef2889c0a05d78de7d4553147052"},
		{Product: iamv1.ProductInstallation, Revision: 1, ContentDigest: "sha256:04493b4c1dfacebbb6a2ed0d47b38c686c6d56a5526acdcf2a886d00ac45b730"},
	}, true
}

func (context policyEvaluationContext) policyInterpretation(version iamv1.PolicyVersion) (iamv1.PolicyCompilation, string, []iamv1.AuthorizationProfile, error) {
	var references []iamv1.AuthorizationProfileReference
	if version.ContractVersion == iamv1.PolicyVersionCompiledContract && version.Compilation != nil {
		references = version.Compilation.Profiles
	} else {
		var supported bool
		references, supported = LegacySystemPolicyReferences(version)
		if !supported {
			return iamv1.PolicyCompilation{}, "", nil, ErrInvalidPolicyState
		}
	}
	profiles := make([]iamv1.AuthorizationProfile, 0, len(references))
	for _, reference := range references {
		profile, found := context.profiles[reference]
		if !found {
			return iamv1.PolicyCompilation{}, "", nil, ErrInvalidPolicyState
		}
		profiles = append(profiles, profile)
	}
	if version.ContractVersion == iamv1.PolicyVersionCompiledContract {
		return *version.Compilation, version.ContentDigest, profiles, nil
	}
	// Interpret the fixed legacy SYSTEM bytes against their explicit ceiling
	// using the sole grammar. Nothing is written back or presented as the
	// author's compilation; the original version/digest remains the evidence.
	compilation, err := iamv1.CompilePolicyDocument(version.Document, profiles)
	if err != nil {
		return iamv1.PolicyCompilation{}, "", nil, ErrInvalidPolicyState
	}
	_, digest, err := iamv1.CanonicalizePolicyCompilation(version.Document, compilation, profiles)
	return compilation, digest, profiles, err
}

// EvaluateAttachedPolicies joins current policy metadata, immutable content and
// a live attachment inside an already authenticated authority snapshot. It
// invokes the sole statement evaluator only after every ownership link agrees.
func EvaluateAttachedPolicies(databaseTime time.Time, accountID iamv1.AccountID, installationID string, subject iamv1.Subject,
	attached []AttachedPolicy, request iamv1.AuthorizationRequest,
) (PolicyEvaluation, []PolicyAttachmentEvidence, error) {
	if iamv1.ValidateID("accountId", string(accountID)) != nil ||
		iamv1.ValidateID("subject.id", string(subject.ID)) != nil ||
		(subject.Type != iamv1.PrincipalUser && subject.Type != iamv1.PrincipalServiceAccount) ||
		(installationID != "" && iamv1.ValidateID("installationId", installationID) != nil) ||
		len(attached) > MaxEvaluationPolicies {
		return PolicyEvaluation{}, nil, ErrInvalidPolicyState
	}
	versions := make([]iamv1.PolicyVersion, 0, len(attached))
	context := policyEvaluationContext{databaseTime: databaseTime, accountID: accountID, subject: subject,
		profiles: make(map[iamv1.AuthorizationProfileReference]iamv1.AuthorizationProfile)}
	seen := make(map[iamv1.PolicyAttachmentID]bool, len(attached))
	for _, row := range attached {
		policy, attachment := row.Policy, row.Attachment
		directSource := row.Membership == nil && attachment.Target.ID == string(subject.ID) &&
			string(attachment.Target.Kind) == string(subject.Type)
		groupSource := row.Membership != nil && subject.Type == iamv1.PrincipalUser &&
			iamv1.ValidateGroupMembership(*row.Membership) == nil && row.Membership.RemovedAt == nil &&
			attachment.Scope == iamv1.AuthorityScopeTenant && attachment.Target.Kind == iamv1.PolicyTargetGroup &&
			row.Membership.AccountID == accountID && row.Membership.UserID == subject.ID &&
			string(row.Membership.GroupID) == attachment.Target.ID
		if iamv1.ValidatePolicy(policy) != nil || iamv1.ValidatePolicyAttachment(attachment) != nil ||
			policy.Status != iamv1.PolicyActive || attachment.RevokedAt != nil || seen[attachment.ID] ||
			attachment.AccountID != accountID || (!directSource && !groupSource) ||
			(policy.Management == iamv1.PolicyCustomerManaged && policy.AccountID != accountID) ||
			attachment.PolicyID != policy.ID || row.Version.PolicyID != policy.ID ||
			row.Version.ID != policy.DefaultVersionID || row.Version.Document.Scope != policy.Scope ||
			attachment.Scope != policy.Scope ||
			(attachment.Scope != iamv1.AuthorityScopeTenant && attachment.InstallationID != installationID) {
			return PolicyEvaluation{}, nil, ErrInvalidPolicyState
		}
		seen[attachment.ID] = true
		if err := context.includeProfiles(row.Profiles); err != nil {
			return PolicyEvaluation{}, nil, err
		}
		if subject.Type != iamv1.PrincipalUser {
			for _, statement := range row.Version.Document.Statements {
				if len(statement.Conditions) != 0 {
					return PolicyEvaluation{}, nil, ErrInvalidPolicyState
				}
			}
		}
		versions = append(versions, row.Version)
	}
	result, err := evaluatePolicies(context, versions, request)
	if err != nil {
		return PolicyEvaluation{}, nil, err
	}
	matched := make(map[iamv1.PolicyID]iamv1.PolicyVersionReference, len(result.MatchedVersions))
	for _, version := range result.MatchedVersions {
		matched[version.PolicyID] = version
	}
	evidence := make([]PolicyAttachmentEvidence, 0, len(result.MatchedVersions))
	for _, row := range attached {
		if version, found := matched[row.Policy.ID]; found {
			item := PolicyAttachmentEvidence{AttachmentID: row.Attachment.ID,
				ResourceVersion: row.Attachment.ResourceVersion, Version: version,
				ContractVersion: row.Version.ContractVersion, Compilation: row.Version.Compilation}
			if row.Membership != nil {
				item.MembershipID = row.Membership.ID
				item.MembershipResourceVersion = row.Membership.ResourceVersion
			}
			evidence = append(evidence, item)
		}
	}
	slices.SortFunc(evidence, func(left, right PolicyAttachmentEvidence) int {
		return cmp.Compare(left.AttachmentID, right.AttachmentID)
	})
	return result, evidence, nil
}

// evaluatePolicies evaluates a current, owner-validated policy snapshot. It
// does not authenticate a subject, resolve ownership, or authorize attachment
// management. Those checks surround it in the existing authority transaction.
func evaluatePolicies(context policyEvaluationContext, versions []iamv1.PolicyVersion, request iamv1.AuthorizationRequest) (PolicyEvaluation, error) {
	if validateAuthorityTime(context.databaseTime) != nil || iamv1.ValidateID("accountId", string(context.accountID)) != nil ||
		iamv1.ValidateID("subject.id", string(context.subject.ID)) != nil ||
		(context.subject.Type != iamv1.PrincipalUser && context.subject.Type != iamv1.PrincipalServiceAccount) {
		return PolicyEvaluation{}, ErrInvalidPolicyState
	}
	if iamv1.ValidateAuthorizationRequest(request) != nil {
		return PolicyEvaluation{}, ErrInvalidAuthorizationRequest
	}
	action, resource := request.Action, request.Resource
	definition, _ := iamv1.LookupActionDefinition(action)
	currentProfile, found := iamv1.LookupAuthorizationProfile(request.Profile.Product)
	if !found {
		return PolicyEvaluation{}, ErrInvalidAuthorizationRequest
	}
	if len(versions) > MaxEvaluationPolicies {
		return PolicyEvaluation{}, ErrInvalidPolicyState
	}
	seen := make(map[iamv1.PolicyID]iamv1.PolicyVersionReference, len(versions))
	statementCount := 0
	result := PolicyEvaluation{}
	hasAllow := false
	for _, version := range versions {
		statementCount += len(version.Document.Statements)
		if statementCount > MaxEvaluationStatements || iamv1.ValidateID("policyId", string(version.PolicyID)) != nil ||
			iamv1.ValidateID("versionId", string(version.ID)) != nil {
			return PolicyEvaluation{}, ErrInvalidPolicyState
		}
		compilation, digest, profiles, err := context.policyInterpretation(version)
		if err != nil || iamv1.CheckPolicyCompilationRequest(version.Document, compilation, digest, profiles, currentProfile, request) != nil {
			return PolicyEvaluation{}, ErrInvalidPolicyState
		}
		reference := iamv1.PolicyVersionReference{PolicyID: version.PolicyID, VersionID: version.ID, ContentDigest: version.ContentDigest}
		if previous, duplicate := seen[version.PolicyID]; duplicate {
			if previous != reference {
				return PolicyEvaluation{}, ErrInvalidPolicyState
			}
			continue
		}
		seen[version.PolicyID] = reference
		if version.Document.Scope != definition.AuthorityScope {
			continue
		}
		matched := false
		for _, statement := range version.Document.Statements {
			if !slices.Contains(statement.Actions, action) {
				continue
			}
			conditionMatch, err := policyConditionsMatch(statement.Conditions, action, context)
			if err != nil {
				return PolicyEvaluation{}, err
			}
			if !conditionMatch {
				continue
			}
			for _, selector := range statement.Resources {
				if selector.Kind != resource.Kind {
					continue
				}
				resourceMatches := false
				switch selector.Match {
				case iamv1.PolicyResourceExact:
					resourceMatches = selector.ID == resource.ID
				case iamv1.PolicyResourceAnyInAuthority:
					resourceMatches = true
				case iamv1.PolicyResourcePrefixInAuthority:
					resourceMatches = request.ResourceMode == iamv1.AuthorizationResourceInstance && strings.HasPrefix(resource.ID, selector.ID)
				default:
					return PolicyEvaluation{}, ErrInvalidPolicyState
				}
				if !resourceMatches {
					continue
				}
				matched = true
				if statement.Effect == iamv1.PolicyDeny {
					result.ExplicitDeny = true
				} else {
					hasAllow = true
				}
				break
			}
		}
		if matched {
			result.MatchedVersions = append(result.MatchedVersions, reference)
		}
	}
	// Do not return early for ALLOW or DENY: another record may reveal a corrupt
	// snapshot or an explicit denial. Source order never changes the outcome.
	result.Allowed = hasAllow && !result.ExplicitDeny
	slices.SortFunc(result.MatchedVersions, func(left, right iamv1.PolicyVersionReference) int { return cmp.Compare(left.PolicyID, right.PolicyID) })
	return result, nil
}

func policyConditionsMatch(conditions []iamv1.PolicyCondition, action iamv1.Action, context policyEvaluationContext) (bool, error) {
	matched := true
	for _, condition := range conditions {
		definition, supported := iamv1.LookupActionConditionDefinition(action, condition.Key)
		if !supported || context.subject.Type != iamv1.PrincipalUser {
			return false, ErrInvalidPolicyState
		}
		if definition.Source == iamv1.ConditionIAMIdentity {
			if definition.ValueType != iamv1.ConditionString || len(condition.Values) < 1 || len(condition.Values) > iamv1.MaxStringConditionValues {
				return false, ErrInvalidPolicyState
			}
			var actual string
			switch condition.Key {
			case iamv1.ConditionIAMAccountID:
				actual = string(context.accountID)
			case iamv1.ConditionIAMPrincipalID:
				actual = string(context.subject.ID)
			default:
				return false, ErrInvalidPolicyState
			}
			if iamv1.ValidateID("condition.actual", actual) != nil {
				return false, ErrInvalidPolicyState
			}
			equals := slices.Contains(condition.Values, actual)
			switch condition.Operator {
			case iamv1.PolicyStringEquals:
				matched = matched && equals
			case iamv1.PolicyStringNotEquals:
				matched = matched && !equals
			default:
				return false, ErrInvalidPolicyState
			}
			continue
		}
		if definition.Source != iamv1.ConditionIAMTransactionTime || definition.ValueType != iamv1.ConditionTime || len(condition.Values) != 1 {
			return false, ErrInvalidPolicyState
		}
		boundary, err := iamv1.ParsePolicyTime(condition.Values[0])
		if err != nil {
			return false, ErrInvalidPolicyState
		}
		switch condition.Operator {
		case iamv1.PolicyDateGreaterThanEquals:
			matched = matched && !context.databaseTime.Before(boundary)
		case iamv1.PolicyDateLessThan:
			matched = matched && context.databaseTime.Before(boundary)
		default:
			return false, ErrInvalidPolicyState
		}
	}
	return matched, nil
}

// SystemPolicyVersion publishes the code-owned permission documents used by
// the evaluator and, at the storage cutover, the policy seed. The version ID
// follows the canonical content; adding a permitted action cannot silently
// change the document under an existing version ID.
func SystemPolicyVersion(id iamv1.PolicyID) (iamv1.PolicyVersion, error) {
	var actions []iamv1.Action
	scope := iamv1.AuthorityScopeTenant
	switch id {
	case iamv1.SystemPolicyAccountAdministrator:
		actions = []iamv1.Action{
			iamv1.ActionIAMAccountAliasSet, iamv1.ActionIAMUserList, iamv1.ActionIAMPolicyList,
			iamv1.ActionIAMPolicyCreate, iamv1.ActionIAMPolicyRead,
			iamv1.ActionIAMPolicyVersionList, iamv1.ActionIAMPolicyVersionRead, iamv1.ActionIAMPolicyVersionCreate, iamv1.ActionIAMPolicySetDefaultVersion,
			iamv1.ActionIAMPolicyVersionDelete,
			iamv1.ActionIAMPolicyUpdate,
			iamv1.ActionIAMPolicyDelete,
			iamv1.ActionIAMUserSetStatus, iamv1.ActionIAMUserPasswordReset,
			iamv1.ActionIAMUserCreate, iamv1.ActionIAMUserRead,
			iamv1.ActionIAMUserUpdate, iamv1.ActionIAMUserDelete,
			iamv1.ActionIAMUserPermissionBoundarySet, iamv1.ActionIAMUserPermissionBoundaryRemove,
			iamv1.ActionIAMPolicyAttachmentCreate, iamv1.ActionIAMPolicyAttachmentRevoke,
			iamv1.ActionIAMGroupList, iamv1.ActionIAMGroupCreate, iamv1.ActionIAMGroupRead,
			iamv1.ActionIAMGroupUpdate, iamv1.ActionIAMGroupDelete,
			iamv1.ActionIAMGroupMembershipList, iamv1.ActionIAMGroupMembershipCreate, iamv1.ActionIAMGroupMembershipRemove,
			iamv1.ActionIAMGroupPolicyAttachmentCreate, iamv1.ActionIAMGroupPolicyAttachmentRevoke,
			iamv1.ActionIAMSessionRevoke,
			iamv1.ActionPaaSApplicationCreate, iamv1.ActionPaaSApplicationRead,
			iamv1.ActionPaaSConfigurationCreate, iamv1.ActionPaaSConfigurationRead,
			iamv1.ActionPaaSConfigurationRevisionCreate, iamv1.ActionPaaSConfigurationRevisionRead,
			iamv1.ActionPaaSApplicationRevisionCreate, iamv1.ActionPaaSApplicationRevisionRead,
			iamv1.ActionPaaSDeploymentCreate, iamv1.ActionPaaSDeploymentUpdate,
			iamv1.ActionPaaSDeploymentRollback, iamv1.ActionPaaSDeploymentStop,
			iamv1.ActionPaaSDeploymentRead, iamv1.ActionPaaSOperationRead,
			iamv1.ActionManagedServiceOfferingRead, iamv1.ActionManagedServiceRegionRead,
			iamv1.ActionManagedServiceQuotaEntitlementActivate, iamv1.ActionManagedServiceQuotaEntitlementRead,
			iamv1.ActionManagedServiceInstallationCreate, iamv1.ActionManagedServiceInstallationRead,
			iamv1.ActionAuditRecordRead, iamv1.ActionAuditIntegrityVerify,
		}
	case iamv1.SystemPolicyPlatformOperator:
		scope = iamv1.AuthorityScopeInstallation
		actions = []iamv1.Action{
			iamv1.ActionIAMAccountCreate, iamv1.ActionIAMAccountRead, iamv1.ActionIAMPlatformPolicyList,
			iamv1.ActionIAMAccountSetStatus, iamv1.ActionIAMAccountRootCredentialsRecover,
			iamv1.ActionIAMPlatformPolicyAttachmentCreate, iamv1.ActionIAMPlatformPolicyAttachmentRevoke,
			iamv1.ActionPaaSExecutionPoolCreate, iamv1.ActionPaaSExecutionPoolRead,
			iamv1.ActionPaaSExecutionTargetRegister, iamv1.ActionPaaSExecutionTargetRead,
			iamv1.ActionPaaSExecutionTargetDrain, iamv1.ActionPaaSExecutionTargetActivate, iamv1.ActionPaaSExecutionTargetRemove,
			iamv1.ActionPaaSNodeEnrollmentCreate, iamv1.ActionPaaSNodeEnrollmentRead,
			iamv1.ActionPaaSNodeEnrollmentRevoke, iamv1.ActionPaaSNodeEnrollmentRegenerate,
			iamv1.ActionPaaSPlatformOperationRead,
			iamv1.ActionAuditPlatformRecordRead, iamv1.ActionAuditPlatformIntegrityVerify,
		}
	case iamv1.SystemPolicyPaaSDeveloper:
		actions = []iamv1.Action{
			iamv1.ActionPaaSApplicationCreate, iamv1.ActionPaaSApplicationRead,
			iamv1.ActionPaaSConfigurationCreate, iamv1.ActionPaaSConfigurationRead,
			iamv1.ActionPaaSConfigurationRevisionCreate, iamv1.ActionPaaSConfigurationRevisionRead,
			iamv1.ActionPaaSApplicationRevisionCreate, iamv1.ActionPaaSApplicationRevisionRead,
			iamv1.ActionPaaSDeploymentCreate, iamv1.ActionPaaSDeploymentUpdate,
			iamv1.ActionPaaSDeploymentRollback, iamv1.ActionPaaSDeploymentStop,
			iamv1.ActionPaaSDeploymentRead, iamv1.ActionPaaSOperationRead,
			iamv1.ActionManagedServiceOfferingRead, iamv1.ActionManagedServiceRegionRead,
			iamv1.ActionManagedServiceQuotaEntitlementActivate, iamv1.ActionManagedServiceQuotaEntitlementRead,
			iamv1.ActionManagedServiceInstallationCreate, iamv1.ActionManagedServiceInstallationRead,
		}
	case iamv1.SystemPolicyPaaSViewer:
		actions = []iamv1.Action{
			iamv1.ActionPaaSApplicationRead, iamv1.ActionPaaSConfigurationRead,
			iamv1.ActionPaaSConfigurationRevisionRead, iamv1.ActionPaaSApplicationRevisionRead,
			iamv1.ActionPaaSDeploymentRead, iamv1.ActionPaaSOperationRead,
			iamv1.ActionManagedServiceOfferingRead, iamv1.ActionManagedServiceRegionRead,
			iamv1.ActionManagedServiceQuotaEntitlementRead, iamv1.ActionManagedServiceInstallationRead,
		}
	case iamv1.SystemPolicyAuditReader:
		actions = []iamv1.Action{iamv1.ActionAuditRecordRead, iamv1.ActionAuditIntegrityVerify}
	case iamv1.SystemPolicyInstallationVerifier:
		scope = iamv1.AuthorityScopeInstallationProbe
		actions = []iamv1.Action{iamv1.ActionInstallationVerify}
	default:
		return iamv1.PolicyVersion{}, ErrInvalidPolicyState
	}
	resources := make([]iamv1.PolicyResourceSelector, 0)
	seen := make(map[iamv1.ResourceKind]bool)
	for _, action := range actions {
		definition, known := iamv1.LookupActionDefinition(action)
		if !known || definition.AuthorityScope != scope {
			return iamv1.PolicyVersion{}, ErrInvalidPolicyState
		}
		if !seen[definition.ResourceKind] {
			resources = append(resources, iamv1.PolicyResourceSelector{Kind: definition.ResourceKind, Match: iamv1.PolicyResourceAnyInAuthority})
			seen[definition.ResourceKind] = true
		}
	}
	document := iamv1.PolicyDocument{LanguageVersion: iamv1.PolicyLanguageVersion, Scope: scope,
		Statements: []iamv1.PolicyStatement{{SID: "permissions", Effect: iamv1.PolicyAllow, Actions: actions, Resources: resources}}}
	compilation, err := iamv1.CompilePolicyDocument(document, iamv1.AllAuthorizationProfiles())
	if err != nil {
		return iamv1.PolicyVersion{}, ErrInvalidPolicyState
	}
	_, digest, err := iamv1.CanonicalizePolicyCompilation(document, compilation, iamv1.AllAuthorizationProfiles())
	if err != nil {
		return iamv1.PolicyVersion{}, ErrInvalidPolicyState
	}
	return iamv1.PolicyVersion{PolicyID: id, ID: iamv1.PolicyVersionID("version-" + digest[len("sha256:"):]), Document: document, ContentDigest: digest,
		ContractVersion: iamv1.PolicyVersionCompiledContract, Compilation: &compilation}, nil
}
