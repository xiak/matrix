package authority

import (
	"cmp"
	"errors"
	"slices"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const MaxEvaluationPolicies = 256
const MaxEvaluationStatements = 4096

var ErrInvalidPolicyState = errors.New("IAM policy authority state is invalid")

// AttachedPolicy is one database-resolved relationship, not a caller-provided
// permission document. Group/role inheritance needs its own proven source path
// before it can enter the direct-subject evaluation below.
type AttachedPolicy struct {
	Policy     iamv1.Policy
	Version    iamv1.PolicyVersion
	Attachment iamv1.PolicyAttachment
}

type PolicyAttachmentEvidence struct {
	AttachmentID    iamv1.PolicyAttachmentID
	ResourceVersion uint64
	Version         iamv1.PolicyVersionReference
}

type PolicyEvaluation struct {
	Allowed         bool
	ExplicitDeny    bool
	MatchedVersions []iamv1.PolicyVersionReference
}

// EvaluateAttachedPolicies joins current policy metadata, immutable content and
// a live attachment inside an already authenticated authority snapshot. It
// invokes the sole statement evaluator only after every ownership link agrees.
func EvaluateAttachedPolicies(accountID iamv1.OrganizationID, installationID string, subject iamv1.Subject,
	attached []AttachedPolicy, action iamv1.Action, resource iamv1.ResourceReference,
) (PolicyEvaluation, []PolicyAttachmentEvidence, error) {
	if iamv1.ValidateID("accountId", string(accountID)) != nil ||
		iamv1.ValidateID("subject.id", string(subject.ID)) != nil ||
		(subject.Type != iamv1.PrincipalUser && subject.Type != iamv1.PrincipalServiceAccount) ||
		(installationID != "" && iamv1.ValidateID("installationId", installationID) != nil) ||
		len(attached) > MaxEvaluationPolicies {
		return PolicyEvaluation{}, nil, ErrInvalidPolicyState
	}
	versions := make([]iamv1.PolicyVersion, 0, len(attached))
	seen := make(map[iamv1.PolicyAttachmentID]bool, len(attached))
	for _, row := range attached {
		policy, attachment := row.Policy, row.Attachment
		if iamv1.ValidatePolicy(policy) != nil || iamv1.ValidatePolicyAttachment(attachment) != nil ||
			policy.Status != iamv1.PolicyActive || attachment.RevokedAt != nil || seen[attachment.ID] ||
			attachment.AccountID != accountID || attachment.Target.ID != string(subject.ID) ||
			string(attachment.Target.Kind) != string(subject.Type) ||
			(policy.Management == iamv1.PolicyCustomerManaged && policy.AccountID != accountID) ||
			attachment.PolicyID != policy.ID || row.Version.PolicyID != policy.ID ||
			row.Version.ID != policy.DefaultVersionID || row.Version.Document.Scope != policy.Scope ||
			attachment.Scope != policy.Scope ||
			(attachment.Scope != iamv1.AuthorityScopeTenant && attachment.InstallationID != installationID) {
			return PolicyEvaluation{}, nil, ErrInvalidPolicyState
		}
		seen[attachment.ID] = true
		versions = append(versions, row.Version)
	}
	result, err := EvaluatePolicies(versions, action, resource)
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
			evidence = append(evidence, PolicyAttachmentEvidence{AttachmentID: row.Attachment.ID,
				ResourceVersion: row.Attachment.ResourceVersion, Version: version})
		}
	}
	slices.SortFunc(evidence, func(left, right PolicyAttachmentEvidence) int {
		return cmp.Compare(left.AttachmentID, right.AttachmentID)
	})
	return result, evidence, nil
}

// EvaluatePolicies evaluates a current, owner-validated policy snapshot. It
// does not authenticate a subject, resolve ownership, or authorize attachment
// management. Those checks surround it in the existing authority transaction.
func EvaluatePolicies(versions []iamv1.PolicyVersion, action iamv1.Action, resource iamv1.ResourceReference) (PolicyEvaluation, error) {
	definition, known := iamv1.LookupActionDefinition(action)
	if !known || resource.Kind != definition.ResourceKind || iamv1.ValidateID("resource.id", resource.ID) != nil {
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
		if statementCount > MaxEvaluationStatements || iamv1.ValidatePolicyVersion(version) != nil {
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
			for _, selector := range statement.Resources {
				if selector.Kind != resource.Kind || (selector.Match == iamv1.PolicyResourceExact && selector.ID != resource.ID) {
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
			iamv1.ActionIAMAccountAliasSet, iamv1.ActionIAMPrincipalList,
			iamv1.ActionIAMPrincipalSetStatus, iamv1.ActionIAMPasswordReset,
			iamv1.ActionIAMPrincipalCreate, iamv1.ActionIAMPrincipalRead,
			iamv1.ActionIAMRoleBindingPut, iamv1.ActionIAMRoleBindingRevoke,
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
			iamv1.ActionIAMOrganizationCreate, iamv1.ActionIAMOrganizationRead,
			iamv1.ActionIAMOrganizationSetStatus, iamv1.ActionIAMOrganizationAdministratorRecover,
			iamv1.ActionIAMPlatformRoleBindingPut, iamv1.ActionIAMPlatformRoleBindingRevoke,
			iamv1.ActionPaaSExecutionPoolCreate, iamv1.ActionPaaSExecutionPoolRead,
			iamv1.ActionPaaSExecutionTargetRegister, iamv1.ActionPaaSExecutionTargetRead,
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
	_, digest, err := iamv1.CanonicalizePolicyDocument(document)
	if err != nil {
		return iamv1.PolicyVersion{}, ErrInvalidPolicyState
	}
	return iamv1.PolicyVersion{PolicyID: id, ID: iamv1.PolicyVersionID("version-" + digest[len("sha256:"):]), Document: document, ContentDigest: digest}, nil
}
