package iamv1

type AccountStatus string
type PrincipalType string

// SubjectType describes authorization capability, not a stored principal. A
// Role is an effective identity and never acquires a login/password by appearing
// in a product declaration.
type SubjectType string
type PrincipalStatus string
type SessionStatus string
type AccessKeyStatus string
type AccessKeyCredentialState string
type Action string
type ResourceKind string
type DecisionReason string
type BootstrapState string
type ServicePurpose string
type ReadinessState string
type ProductID string
type AuthorityScope string
type IdentityKind string
type CapabilityRestriction string
type ConditionKey string
type ConditionValueType string
type ConditionSource string

const (
	ConditionIAMCurrentTime            ConditionKey       = "iam.current-time"
	ConditionIAMAccountID              ConditionKey       = "iam.account-id"
	ConditionIAMPrincipalID            ConditionKey       = "iam.principal-id"
	ConditionRequestSourceIP           ConditionKey       = "request.source-ip"
	ConditionRequestTagPrefix                             = "request.tag/"
	ConditionResourceTagPrefix                            = "resource.tag/"
	ConditionTime                      ConditionValueType = "TIME"
	ConditionString                    ConditionValueType = "STRING"
	ConditionIP                        ConditionValueType = "IP"
	ConditionIAMTransactionTime        ConditionSource    = "IAM_TRANSACTION_TIME"
	ConditionIAMIdentity               ConditionSource    = "IAM_AUTHENTICATED_IDENTITY"
	ConditionCallingServiceNetwork     ConditionSource    = "CALLING_SERVICE_NETWORK"
	ConditionCallingServiceRequestTag  ConditionSource    = "CALLING_SERVICE_REQUEST_TAG"
	ConditionCallingServiceResourceTag ConditionSource    = "CALLING_SERVICE_RESOURCE_TAG"
)

// This is a source declaration, not caller-supplied context or a complete
// AuthorizationProfile. Tenant conditions use IAM's own authoritative sources.
type ConditionKeyDefinition struct {
	Key       ConditionKey
	ValueType ConditionValueType
	Source    ConditionSource
}

func LookupActionConditionDefinition(action Action, key ConditionKey) (ConditionKeyDefinition, bool) {
	for _, profile := range authorizationProfiles {
		for _, declaration := range profile.Actions {
			if declaration.Action != action {
				continue
			}
			for _, condition := range declaration.Conditions {
				if condition.Key == key {
					return ConditionKeyDefinition{Key: condition.Key, ValueType: condition.ValueType, Source: condition.Source}, true
				}
			}
			return ConditionKeyDefinition{}, false
		}
	}
	return ConditionKeyDefinition{}, false
}

// A source declaration is not an action capability or permission. Admission
// must additionally check the action's explicitly declared scope/capabilities.
func lookupConditionDefinition(key ConditionKey) (ConditionKeyDefinition, bool) {
	switch key {
	case ConditionIAMCurrentTime:
		return ConditionKeyDefinition{key, ConditionTime, ConditionIAMTransactionTime}, true
	case ConditionIAMAccountID, ConditionIAMPrincipalID:
		return ConditionKeyDefinition{key, ConditionString, ConditionIAMIdentity}, true
	case ConditionRequestSourceIP:
		return ConditionKeyDefinition{key, ConditionIP, ConditionCallingServiceNetwork}, true
	default:
		if _, ok := requestTagName(key); ok {
			return ConditionKeyDefinition{key, ConditionString, ConditionCallingServiceRequestTag}, true
		}
		if _, ok := resourceTagName(key); ok {
			return ConditionKeyDefinition{key, ConditionString, ConditionCallingServiceResourceTag}, true
		}
		return ConditionKeyDefinition{}, false
	}
}

// ActionDefinition binds a product operation to its only authorization caller,
// resource kind and authority scope. It describes a registered operation; it
// does not grant permission, attest a resource's owner, or imply instance-level
// filtering. These value-only records are not caller-editable profiles.
type ActionDefinition struct {
	Action         Action
	Product        ProductID
	CallingService ServicePurpose
	ResourceKind   ResourceKind
	AuthorityScope AuthorityScope
	// An explicitly proved instance-resource capability, not inferred from
	// action spelling or resource kind. Undeclared/new actions default closed.
	ResourcePrefixAllowed bool
}

const (
	ProductIAM            ProductID = "iam"
	ProductPaaS           ProductID = "paas"
	ProductManagedService ProductID = "managedservice"
	ProductAudit          ProductID = "audit"
	ProductInstallation   ProductID = "installation"
)

const (
	AuthorityScopeTenant       AuthorityScope = "TENANT"
	AuthorityScopeInstallation AuthorityScope = "INSTALLATION"
	// The existing verifier probe yields a home-tenant-bound service decision,
	// not a platform USER decision or a permit for any business operation.
	AuthorityScopeInstallationProbe AuthorityScope = "INSTALLATION_PROBE"
)

const (
	AccountActive   AccountStatus = "ACTIVE"
	AccountDisabled AccountStatus = "DISABLED"
)

const (
	PrincipalUser           PrincipalType = "USER"
	PrincipalServiceAccount PrincipalType = "SERVICE_ACCOUNT"
)

const (
	SubjectUser           SubjectType = "USER"
	SubjectServiceAccount SubjectType = "SERVICE_ACCOUNT"
	SubjectRole           SubjectType = "ROLE"
)

const (
	PrincipalActive   PrincipalStatus = "ACTIVE"
	PrincipalDisabled PrincipalStatus = "DISABLED"
)

const (
	IdentityRoot IdentityKind = "ROOT_IDENTITY"
	IdentityUser IdentityKind = "USER"
)

const (
	CapabilityAuthorityRequired               CapabilityRestriction = "AUTHORITY_REQUIRED"
	CapabilityCurrentCredentialChangeRequired CapabilityRestriction = "CURRENT_CREDENTIAL_CHANGE_REQUIRED"
	CapabilitySelfProtected                   CapabilityRestriction = "SELF_PROTECTED"
	CapabilityRootIdentityProtected           CapabilityRestriction = "ROOT_IDENTITY_PROTECTED"
	CapabilityInstallationAuthorityProtected  CapabilityRestriction = "INSTALLATION_AUTHORITY_PROTECTED"
	CapabilitySystemAccountProtected          CapabilityRestriction = "SYSTEM_ACCOUNT_PROTECTED"
	CapabilityTargetDisabled                  CapabilityRestriction = "TARGET_DISABLED"
	CapabilityTargetCredentialChangeRequired  CapabilityRestriction = "TARGET_CREDENTIAL_CHANGE_REQUIRED"
	CapabilityTargetMustBeDisabled            CapabilityRestriction = "TARGET_MUST_BE_DISABLED"
	CapabilitySessionNotRevocable             CapabilityRestriction = "SESSION_NOT_REVOCABLE"
	CapabilityAccessKeyLimitReached           CapabilityRestriction = "ACCESS_KEY_LIMIT_REACHED"
	CapabilityResourceVersionExhausted        CapabilityRestriction = "RESOURCE_VERSION_EXHAUSTED"
)

var allCapabilityRestrictions = [...]CapabilityRestriction{
	CapabilityAuthorityRequired,
	CapabilityCurrentCredentialChangeRequired,
	CapabilitySelfProtected,
	CapabilityRootIdentityProtected,
	CapabilityInstallationAuthorityProtected,
	CapabilitySystemAccountProtected,
	CapabilityTargetDisabled,
	CapabilityTargetCredentialChangeRequired,
	CapabilityTargetMustBeDisabled,
	CapabilitySessionNotRevocable,
	CapabilityAccessKeyLimitReached,
	CapabilityResourceVersionExhausted,
}

func AllCapabilityRestrictions() []CapabilityRestriction {
	return append([]CapabilityRestriction(nil), allCapabilityRestrictions[:]...)
}

const (
	SessionActive  SessionStatus = "ACTIVE"
	SessionRevoked SessionStatus = "REVOKED"
	SessionExpired SessionStatus = "EXPIRED"
)

const (
	AccessKeyEnabled  AccessKeyStatus = "ENABLED"
	AccessKeyDisabled AccessKeyStatus = "DISABLED"
	// AccessKeyCredentialCurrent means only that the secret lineage has not
	// been permanently fenced by a supported authentication recovery. It is
	// never proof that the key can authenticate a current request.
	AccessKeyCredentialCurrent        AccessKeyCredentialState = "CURRENT"
	AccessKeyCredentialRecoveryFenced AccessKeyCredentialState = "RECOVERY_FENCED"
	MaxUserAccessKeys                                          = 2
	MaxAccessKeySourceCIDRs                                    = 16
)

const (
	ActionIAMAccountCreate                 Action = "iam.account.create"
	ActionIAMAccountRead                   Action = "iam.account.read"
	ActionIAMAccountSetStatus              Action = "iam.account.set-status"
	ActionIAMAccountRootCredentialsRecover Action = "iam.account.recover-root-credentials"
	ActionIAMAccountAliasSet               Action = "iam.account.alias-set"
	ActionIAMUserList                      Action = "iam.user.list"
	ActionIAMSecuritySettingsRead          Action = "iam.security-settings.read"
	ActionIAMSecuritySettingsUpdate        Action = "iam.security-settings.update"
	ActionIAMPolicyList                    Action = "iam.policy.list"
	ActionIAMPolicyCreate                  Action = "iam.policy.create"
	ActionIAMPolicyRead                    Action = "iam.policy.read"
	ActionIAMPolicyVersionList             Action = "iam.policy-version.list"
	ActionIAMPolicyVersionRead             Action = "iam.policy-version.read"
	ActionIAMPolicyVersionCreate           Action = "iam.policy-version.create"
	ActionIAMPolicyVersionDelete           Action = "iam.policy-version.delete"
	ActionIAMPolicySetDefaultVersion       Action = "iam.policy.set-default-version"
	ActionIAMPolicyUpdate                  Action = "iam.policy.update"
	ActionIAMPolicyDelete                  Action = "iam.policy.delete"
	ActionIAMPlatformPolicyList            Action = "iam.platform-policy.list"
	ActionIAMUserSetStatus                 Action = "iam.user.set-status"
	ActionIAMUserPasswordReset             Action = "iam.user.reset-password"

	ActionIAMUserCreate                         Action = "iam.user.create"
	ActionIAMUserRead                           Action = "iam.user.read"
	ActionIAMUserUpdate                         Action = "iam.user.update"
	ActionIAMUserDelete                         Action = "iam.user.delete"
	ActionIAMUserPermissionBoundarySet          Action = "iam.user.permission-boundary.set"
	ActionIAMUserPermissionBoundaryRemove       Action = "iam.user.permission-boundary.remove"
	ActionIAMGroupList                          Action = "iam.group.list"
	ActionIAMGroupCreate                        Action = "iam.group.create"
	ActionIAMGroupRead                          Action = "iam.group.read"
	ActionIAMGroupUpdate                        Action = "iam.group.update"
	ActionIAMGroupDelete                        Action = "iam.group.delete"
	ActionIAMGroupMembershipList                Action = "iam.group-membership.list"
	ActionIAMGroupMembershipCreate              Action = "iam.group-membership.create"
	ActionIAMGroupMembershipRemove              Action = "iam.group-membership.remove"
	ActionIAMGroupPolicyAttachmentCreate        Action = "iam.group-policy-attachment.create"
	ActionIAMGroupPolicyAttachmentRevoke        Action = "iam.group-policy-attachment.revoke"
	ActionIAMRoleList                           Action = "iam.role.list"
	ActionIAMRoleCreate                         Action = "iam.role.create"
	ActionIAMRoleRead                           Action = "iam.role.read"
	ActionIAMRoleUpdate                         Action = "iam.role.update"
	ActionIAMRoleSetStatus                      Action = "iam.role.set-status"
	ActionIAMRoleDelete                         Action = "iam.role.delete"
	ActionIAMRoleTrustSet                       Action = "iam.role-trust.set"
	ActionIAMRolePolicyAttachmentCreate         Action = "iam.role-policy-attachment.create"
	ActionIAMRolePolicyAttachmentRevoke         Action = "iam.role-policy-attachment.revoke"
	ActionIAMRolePermissionBoundarySet          Action = "iam.role.permission-boundary.set"
	ActionIAMRolePermissionBoundaryRemove       Action = "iam.role.permission-boundary.remove"
	ActionIAMRoleAssume                         Action = "iam.role.assume"
	ActionIAMRoleSessionList                    Action = "iam.role-session.list"
	ActionIAMRoleSessionRead                    Action = "iam.role-session.read"
	ActionIAMRoleSessionRevoke                  Action = "iam.role-session.revoke"
	ActionIAMServiceRoleTemplateList            Action = "iam.service-role-template.list"
	ActionIAMServiceLinkedRoleList              Action = "iam.service-linked-role.list"
	ActionIAMServiceLinkedRoleRead              Action = "iam.service-linked-role.read"
	ActionIAMServiceLinkedRoleCreate            Action = "iam.service-linked-role.create"
	ActionIAMRolePass                           Action = "iam.role.pass"
	ActionIAMWorkloadRoleBindingRevoke          Action = "iam.workload-role-binding.revoke"
	ActionIAMSessionRevoke                      Action = "iam.session.revoke"
	ActionIAMAccessKeyList                      Action = "iam.access-key.list"
	ActionIAMAccessKeyCreate                    Action = "iam.access-key.create"
	ActionIAMAccessKeyRead                      Action = "iam.access-key.read"
	ActionIAMAccessKeySetStatus                 Action = "iam.access-key.set-status"
	ActionIAMAccessKeySetNetworkRestrictions    Action = "iam.access-key.set-network-restrictions"
	ActionIAMAccessKeyDelete                    Action = "iam.access-key.delete"
	ActionIAMSecurityReportCreate               Action = "iam.security-report.create"
	ActionIAMSecurityReportRead                 Action = "iam.security-report.read"
	ActionIAMSecurityReportDownload             Action = "iam.security-report.download"
	ActionIAMAccessAnalyzerCreate               Action = "iam.access-analyzer.create"
	ActionIAMAccessAnalyzerList                 Action = "iam.access-analyzer.list"
	ActionIAMAccessAnalyzerRead                 Action = "iam.access-analyzer.read"
	ActionIAMAccessAnalyzerUpdate               Action = "iam.access-analyzer.update"
	ActionIAMAccessAnalyzerSetDisposition       Action = "iam.access-analyzer.set-disposition"
	ActionIAMAccessFindingList                  Action = "iam.access-finding.list"
	ActionIAMAccessFindingRead                  Action = "iam.access-finding.read"
	ActionIAMAccessFindingArchive               Action = "iam.access-finding.archive"
	ActionIAMAccessFindingUnarchive             Action = "iam.access-finding.unarchive"
	ActionIAMPolicyAttachmentCreate             Action = "iam.policy-attachment.create"
	ActionIAMPolicyAttachmentRevoke             Action = "iam.policy-attachment.revoke"
	ActionIAMPolicyAttachmentChangeRead         Action = "iam.policy-attachment-change.read"
	ActionIAMPlatformPolicyAttachmentCreate     Action = "iam.platform-policy-attachment.create"
	ActionIAMPlatformPolicyAttachmentRevoke     Action = "iam.platform-policy-attachment.revoke"
	ActionIAMPlatformPolicyAttachmentChangeRead Action = "iam.platform-policy-attachment-change.read"

	ActionPaaSExecutionPoolCreate      Action = "paas.execution-pool.create"
	ActionPaaSExecutionPoolRead        Action = "paas.execution-pool.read"
	ActionPaaSExecutionTargetRegister  Action = "paas.execution-target.register"
	ActionPaaSExecutionTargetRead      Action = "paas.execution-target.read"
	ActionPaaSExecutionTargetDrain     Action = "paas.execution-target.drain"
	ActionPaaSExecutionTargetActivate  Action = "paas.execution-target.activate"
	ActionPaaSExecutionTargetRemove    Action = "paas.execution-target.remove"
	ActionPaaSNodeEnrollmentCreate     Action = "paas.node-enrollment.create"
	ActionPaaSNodeEnrollmentRead       Action = "paas.node-enrollment.read"
	ActionPaaSNodeEnrollmentRevoke     Action = "paas.node-enrollment.revoke"
	ActionPaaSNodeEnrollmentRegenerate Action = "paas.node-enrollment.regenerate"
	ActionPaaSPlatformOperationRead    Action = "paas.platform-operation.read"

	ActionPaaSApplicationCreate           Action = "paas.application.create"
	ActionPaaSApplicationRead             Action = "paas.application.read"
	ActionPaaSApplicationLabelSet         Action = "paas.application-label.set"
	ActionPaaSApplicationLabelDelete      Action = "paas.application-label.delete"
	ActionPaaSConfigurationCreate         Action = "paas.configuration.create"
	ActionPaaSConfigurationRead           Action = "paas.configuration.read"
	ActionPaaSConfigurationRevisionCreate Action = "paas.configuration-revision.create"
	ActionPaaSConfigurationRevisionRead   Action = "paas.configuration-revision.read"
	ActionPaaSApplicationRevisionCreate   Action = "paas.application-revision.create"
	ActionPaaSApplicationRevisionRead     Action = "paas.application-revision.read"
	ActionPaaSDeploymentCreate            Action = "paas.deployment.create"
	ActionPaaSDeploymentUpdate            Action = "paas.deployment.update"
	ActionPaaSDeploymentRollback          Action = "paas.deployment.rollback"
	ActionPaaSDeploymentStop              Action = "paas.deployment.stop"
	ActionPaaSDeploymentRead              Action = "paas.deployment.read"
	ActionPaaSOperationRead               Action = "paas.operation.read"

	ActionManagedServiceOfferingRead             Action = "managedservice.offering.read"
	ActionManagedServiceRegionRead               Action = "managedservice.region.read"
	ActionManagedServiceQuotaEntitlementActivate Action = "managedservice.quota-entitlement.activate"
	ActionManagedServiceQuotaEntitlementRead     Action = "managedservice.quota-entitlement.read"
	ActionManagedServiceInstallationCreate       Action = "managedservice.service-installation.create"
	ActionManagedServiceInstallationRead         Action = "managedservice.service-installation.read"
	ActionManagedServiceInstallationRoleBind     Action = "managedservice.service-installation.service-role.bind"
	ActionManagedServiceInstallationRoleUnbind   Action = "managedservice.service-installation.service-role.unbind"

	ActionAuditRecordRead              Action = "audit.record.read"
	ActionAuditIntegrityVerify         Action = "audit.integrity.verify"
	ActionAuditPlatformRecordRead      Action = "audit.platform-record.read"
	ActionAuditPlatformIntegrityVerify Action = "audit.platform-integrity.verify"
	ActionInstallationVerify           Action = "installation.verify"
)

// Published historical decisions retain these literals; no active action
// definition or policy may use them.
const (
	ActionIAMOrganizationCreate               Action = "iam.organization.create"
	ActionIAMOrganizationRead                 Action = "iam.organization.read"
	ActionIAMOrganizationSetStatus            Action = "iam.organization.set-status"
	ActionIAMOrganizationAdministratorRecover Action = "iam.organization-administrator.recover"
	ActionIAMLegacyAccountAliasSet            Action = "iam.account-alias.set"
	ActionIAMPrincipalList                    Action = "iam.principal.list"
	ActionIAMPrincipalSetStatus               Action = "iam.principal.set-status"
	ActionIAMPasswordReset                    Action = "iam.password.reset"
	ActionIAMPrincipalCreate                  Action = "iam.principal.create"
	ActionIAMPrincipalRead                    Action = "iam.principal.read"
	ActionIAMRoleBindingPut                   Action = "iam.role-binding.put"
	ActionIAMRoleBindingRevoke                Action = "iam.role-binding.revoke"
	ActionIAMPlatformRoleBindingPut           Action = "iam.platform-role-binding.put"
	ActionIAMPlatformRoleBindingRevoke        Action = "iam.platform-role-binding.revoke"
)

const (
	ResourceAccount               ResourceKind = "ACCOUNT"
	ResourceUser                  ResourceKind = "USER"
	ResourceAccessKey             ResourceKind = "ACCESS_KEY"
	ResourceGroup                 ResourceKind = "GROUP"
	ResourceRole                  ResourceKind = "ROLE"
	ResourceRoleSession           ResourceKind = "ROLE_SESSION"
	ResourceGroupMembership       ResourceKind = "GROUP_MEMBERSHIP"
	ResourceOrganization          ResourceKind = "ORGANIZATION"
	ResourcePrincipal             ResourceKind = "PRINCIPAL"
	ResourceRoleBinding           ResourceKind = "ROLE_BINDING"
	ResourceWorkloadRoleBinding   ResourceKind = "WORKLOAD_ROLE_BINDING"
	ResourcePolicyAttachment      ResourceKind = "POLICY_ATTACHMENT"
	ResourcePolicy                ResourceKind = "POLICY"
	ResourceSession               ResourceKind = "SESSION"
	ResourceSecurityReport        ResourceKind = "SECURITY_REPORT"
	ResourceAccessAnalyzer        ResourceKind = "ACCESS_ANALYZER"
	ResourceAccessFinding         ResourceKind = "ACCESS_FINDING"
	ResourceApplication           ResourceKind = "APPLICATION"
	ResourceConfiguration         ResourceKind = "CONFIGURATION"
	ResourceConfigurationRevision ResourceKind = "CONFIGURATION_REVISION"
	ResourceApplicationRevision   ResourceKind = "APPLICATION_REVISION"
	ResourceDeployment            ResourceKind = "DEPLOYMENT"
	ResourceOperation             ResourceKind = "OPERATION"
	ResourceServiceOffering       ResourceKind = "SERVICE_OFFERING"
	ResourceRegion                ResourceKind = "REGION"
	ResourceQuotaEntitlement      ResourceKind = "QUOTA_ENTITLEMENT"
	ResourceServiceInstallation   ResourceKind = "SERVICE_INSTALLATION"
	ResourceAuditRecord           ResourceKind = "AUDIT_RECORD"
	ResourceAuditChain            ResourceKind = "AUDIT_CHAIN"
	ResourceInstallation          ResourceKind = "INSTALLATION"
	ResourceExecutionPool         ResourceKind = "EXECUTION_POOL"
	ResourceExecutionTarget       ResourceKind = "EXECUTION_TARGET"
	ResourceNodeEnrollment        ResourceKind = "NODE_ENROLLMENT"
)

const (
	DecisionAllowed DecisionReason = "ALLOWED"
	DecisionDenied  DecisionReason = "DENIED"
)

const (
	BootstrapUninitialized BootstrapState = "UNINITIALIZED"
	BootstrapReady         BootstrapState = "READY"
)

const (
	ServiceIAM                  ServicePurpose = "IAM"
	ServicePaaS                 ServicePurpose = "PAAS"
	ServiceAudit                ServicePurpose = "AUDIT"
	ServiceInstallationVerifier ServicePurpose = "INSTALLATION_VERIFIER"
)

const (
	ReadinessReady    ReadinessState = "READY"
	ReadinessNotReady ReadinessState = "NOT_READY"
)

func AllActions() []Action {
	actions := make([]Action, len(actionDefinitions))
	for index, definition := range actionDefinitions {
		actions[index] = definition.Action
	}
	return actions
}

// AllActionDefinitions returns copies in the established contract-generation
// order. No caller can mutate the shared catalog through these values.
func AllActionDefinitions() []ActionDefinition {
	return append([]ActionDefinition(nil), actionDefinitions[:]...)
}

func LookupActionDefinition(action Action) (ActionDefinition, bool) {
	for _, definition := range actionDefinitions {
		if definition.Action == action {
			return definition, true
		}
	}
	return ActionDefinition{}, false
}

// AllRecordedActionDefinitions describes only the strict decoding of immutable
// decisions. Retired entries are NOT callable operations: requests, policies,
// service admission and new decision writes use the current catalog instead.
// Current definitions are derived, not maintained as a second authority.
func AllRecordedActionDefinitions() []ActionDefinition {
	return append(AllActionDefinitions(), retiredActionDefinitions[:]...)
}

func lookupRecordedActionDefinition(action Action) (ActionDefinition, bool) {
	if definition, known := LookupActionDefinition(action); known {
		return definition, true
	}
	for _, definition := range retiredActionDefinitions {
		if definition.Action == action {
			return definition, true
		}
	}
	return ActionDefinition{}, false
}

// Only published decision vocabulary is retained. Do not add aliases, infer
// unknown actions from prefixes, or pass these entries to policy evaluation.
var retiredActionDefinitions = [...]ActionDefinition{
	{ActionIAMOrganizationCreate, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation, false},
	{ActionIAMOrganizationRead, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation, false},
	{ActionIAMOrganizationSetStatus, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation, false},
	{ActionIAMOrganizationAdministratorRecover, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeInstallation, false},
	{ActionIAMLegacyAccountAliasSet, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant, false},
	{ActionIAMPrincipalList, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant, false},
	{ActionIAMPrincipalSetStatus, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant, false},
	{ActionIAMPasswordReset, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant, false},
	{ActionIAMPrincipalCreate, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant, false},
	{ActionIAMPrincipalRead, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant, false},
	{ActionIAMRoleBindingPut, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant, false},
	{ActionIAMRoleBindingRevoke, ProductIAM, ServiceIAM, ResourceRoleBinding, AuthorityScopeTenant, false},
	{ActionIAMPlatformRoleBindingPut, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeInstallation, false},
	{ActionIAMPlatformRoleBindingRevoke, ProductIAM, ServiceIAM, ResourceRoleBinding, AuthorityScopeInstallation, false},
}

// AllServicePurposes returns the exact installer bootstrap order. The order is
// part of the IAMBootstrap wire contract, not merely an enum inventory.
func AllServicePurposes() []ServicePurpose {
	return append([]ServicePurpose(nil), allServicePurposes...)
}

// These release-owned declarations are the only current action catalog.
// ActionDefinition and contract enum order are derived projections, not a second
// editable source. Product revision changes must accompany changed declarations.
var authorizationProfiles = authorizationProfilesForBuild([]AuthorizationProfile{
	iamPolicyAttachmentChangeProfile(),
	paasProfileRevisionThirteen,
	managedServiceProfileRevisionFour,
	auditProfileRevisionFour,
	declaredProductProfile(ProductInstallation, ServiceInstallationVerifier, 1,
		declaredProfileAction(ActionInstallationVerify, ResourceInstallation, AuthorityScopeInstallationProbe, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	),
})

// Revision one is required to interpret already sealed policy/decision content.
// It is not selected as current and cannot be edited to add Role permissions.
var iamProfileRevisionOne = declaredProductProfile(ProductIAM, ServiceIAM, 1,
	declaredProfileAction(ActionIAMAccountCreate, ResourceAccount, AuthorityScopeInstallation, ResourceAccount, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionIAMAccountRead, ResourceAccount, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionIAMAccountSetStatus, ResourceAccount, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMAccountRootCredentialsRecover, ResourceAccount, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMAccountAliasSet, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserList, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyList, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyCreate, ResourceAccount, AuthorityScopeTenant, ResourcePolicy, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyRead, ResourcePolicy, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyVersionList, ResourcePolicy, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyVersionRead, ResourcePolicy, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyVersionCreate, ResourcePolicy, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyVersionDelete, ResourcePolicy, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicySetDefaultVersion, ResourcePolicy, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyUpdate, ResourcePolicy, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyDelete, ResourcePolicy, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPlatformPolicyList, ResourceInstallation, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserSetStatus, ResourceUser, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserPasswordReset, ResourceUser, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserCreate, ResourceAccount, AuthorityScopeTenant, ResourceUser, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserRead, ResourceUser, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserUpdate, ResourceUser, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserDelete, ResourceUser, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserPermissionBoundarySet, ResourceUser, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMUserPermissionBoundaryRemove, ResourceUser, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupList, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupCreate, ResourceAccount, AuthorityScopeTenant, ResourceGroup, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupRead, ResourceGroup, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupUpdate, ResourceGroup, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupDelete, ResourceGroup, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupMembershipList, ResourceGroup, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupMembershipCreate, ResourceGroup, AuthorityScopeTenant, ResourceGroupMembership, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupMembershipRemove, ResourceGroupMembership, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupPolicyAttachmentCreate, ResourceGroup, AuthorityScopeTenant, ResourcePolicyAttachment, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMGroupPolicyAttachmentRevoke, ResourcePolicyAttachment, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyAttachmentCreate, ResourceUser, AuthorityScopeTenant, ResourcePolicyAttachment, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPolicyAttachmentRevoke, ResourcePolicyAttachment, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMSessionRevoke, ResourceSession, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPlatformPolicyAttachmentCreate, ResourceUser, AuthorityScopeInstallation, ResourcePolicyAttachment, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionIAMPlatformPolicyAttachmentRevoke, ResourcePolicyAttachment, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
)

func HistoricalAuthorizationProfiles() []AuthorizationProfile {
	return []AuthorizationProfile{cloneAuthorizationProfile(iamProfileRevisionOne), iamRoleManagementProfile(), iamRoleSessionProfile(), iamRoleSessionManagementProfile(), iamAccessKeyManagementProfile(), iamSecuritySettingsReadProfile(), iamSecuritySettingsProfile(), iamServiceRoleProfile(), iamSecurityReportProfile(), iamAccessAnalyzerProfile(), iamAccessFindingProfile(), iamAccessDispositionProfile(), cloneAuthorizationProfile(paasProfileRevisionOne), cloneAuthorizationProfile(paasProfileRevisionTwo), cloneAuthorizationProfile(paasProfileRevisionThree), cloneAuthorizationProfile(paasProfileRevisionFour), cloneAuthorizationProfile(paasProfileRevisionFive), cloneAuthorizationProfile(paasProfileRevisionSix), cloneAuthorizationProfile(paasProfileRevisionSeven), cloneAuthorizationProfile(paasProfileRevisionEight), cloneAuthorizationProfile(paasProfileRevisionNine), cloneAuthorizationProfile(paasProfileRevisionTen), cloneAuthorizationProfile(paasProfileRevisionEleven), cloneAuthorizationProfile(paasProfileRevisionTwelve), cloneAuthorizationProfile(managedServiceProfileRevisionOne), cloneAuthorizationProfile(managedServiceProfileRevisionTwo), cloneAuthorizationProfile(managedServiceProfileRevisionThree), cloneAuthorizationProfile(auditProfileRevisionOne), cloneAuthorizationProfile(auditProfileRevisionTwo), cloneAuthorizationProfile(auditProfileRevisionThree)}
}

// Revision one remains archived because compiled policy content and decisions
// already commit to it. Revision two grants ROLE only the one action required
// by the first service-linked role; it does not make every managedservice
// action assumable or admit SERVICE_ACCOUNT directly.
var managedServiceProfileRevisionOne = declaredProductProfile(ProductManagedService, ServicePaaS, 1,
	declaredProfileAction(ActionManagedServiceOfferingRead, ResourceServiceOffering, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionManagedServiceRegionRead, ResourceRegion, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionManagedServiceQuotaEntitlementActivate, ResourceQuotaEntitlement, AuthorityScopeTenant, ResourceQuotaEntitlement, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionManagedServiceQuotaEntitlementRead, ResourceQuotaEntitlement, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionManagedServiceInstallationCreate, ResourceServiceInstallation, AuthorityScopeTenant, ResourceServiceInstallation, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionManagedServiceInstallationRead, ResourceServiceInstallation, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
)

var managedServiceProfileRevisionTwo = managedServiceInstallationRoleProfile(managedServiceProfileRevisionOne)
var managedServiceProfileRevisionThree = managedServiceRoleConsentProfile(managedServiceProfileRevisionTwo)
var managedServiceProfileRevisionFour = managedServiceOfferingListBatchProfile(managedServiceProfileRevisionThree)

var paasProfileRevisionOne = declaredProductProfile(ProductPaaS, ServicePaaS, 1,
	declaredProfileAction(ActionPaaSExecutionPoolCreate, ResourceExecutionPool, AuthorityScopeInstallation, ResourceExecutionPool, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSExecutionPoolRead, ResourceExecutionPool, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionPaaSExecutionTargetRegister, ResourceExecutionTarget, AuthorityScopeInstallation, ResourceExecutionTarget, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSExecutionTargetRead, ResourceExecutionTarget, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionPaaSExecutionTargetDrain, ResourceExecutionTarget, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSExecutionTargetActivate, ResourceExecutionTarget, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSExecutionTargetRemove, ResourceExecutionTarget, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSNodeEnrollmentCreate, ResourceNodeEnrollment, AuthorityScopeInstallation, ResourceExecutionTarget, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionPaaSNodeEnrollmentRead, ResourceNodeEnrollment, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSNodeEnrollmentRevoke, ResourceNodeEnrollment, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSNodeEnrollmentRegenerate, ResourceNodeEnrollment, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSPlatformOperationRead, ResourceOperation, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSApplicationCreate, ResourceApplication, AuthorityScopeTenant, ResourceApplication, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionPaaSApplicationRead, ResourceApplication, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}),
	declaredProfileAction(ActionPaaSConfigurationCreate, ResourceConfiguration, AuthorityScopeTenant, ResourceConfiguration, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionPaaSConfigurationRead, ResourceConfiguration, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSConfigurationRevisionCreate, ResourceConfigurationRevision, AuthorityScopeTenant, ResourceConfigurationRevision, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionPaaSConfigurationRevisionRead, ResourceConfigurationRevision, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSApplicationRevisionCreate, ResourceApplicationRevision, AuthorityScopeTenant, ResourceApplicationRevision, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionPaaSApplicationRevisionRead, ResourceApplicationRevision, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSDeploymentCreate, ResourceDeployment, AuthorityScopeTenant, ResourceDeployment, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}),
	declaredProfileAction(ActionPaaSDeploymentUpdate, ResourceDeployment, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSDeploymentRollback, ResourceDeployment, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSDeploymentStop, ResourceDeployment, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSDeploymentRead, ResourceDeployment, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	declaredProfileAction(ActionPaaSOperationRead, ResourceOperation, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
)

var paasProfileRevisionTwo = roleBusinessProfile(paasProfileRevisionOne)
var paasProfileRevisionThree = networkConditionProfile(paasProfileRevisionTwo)
var paasProfileRevisionFour = applicationRequestTagProfile(paasProfileRevisionThree)
var paasProfileRevisionFive = applicationResourceTagProfile(paasProfileRevisionFour)
var paasProfileRevisionSix = applicationLabelMutationProfile(paasProfileRevisionFive)
var paasProfileRevisionSeven = applicationCreateAccessKeyProfile(paasProfileRevisionSix)
var paasProfileRevisionEight = applicationGraphCreateAccessKeyProfile(paasProfileRevisionSeven)
var paasProfileRevisionNine = applicationReadAccessKeyProfile(paasProfileRevisionEight)
var paasProfileRevisionTen = paasInstanceReadAccessKeyProfile(paasProfileRevisionNine)
var paasProfileRevisionEleven = paasDeploymentMutationAccessKeyProfile(paasProfileRevisionTen)
var paasProfileRevisionTwelve = applicationLabelAccessKeyProfile(paasProfileRevisionEleven)
var paasProfileRevisionThirteen = applicationListBatchProfile(paasProfileRevisionTwelve)

func applicationListBatchProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	for index := range profile.Actions {
		if profile.Actions[index].Action != ActionPaaSApplicationRead {
			continue
		}
		profile.Actions[index].ResourceShapes = append(profile.Actions[index].ResourceShapes,
			AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList})
		profile.Actions[index].InstanceListBatch = true
		return profile
	}
	panic("PaaS application read declaration is missing")
}

func applicationCreateAccessKeyProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	for index := range profile.Actions {
		if profile.Actions[index].Action == ActionPaaSApplicationCreate {
			profile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{
				UserAuthenticationAccessKey, UserAuthenticationLoginSession,
			}
			return profile
		}
	}
	panic("PaaS Application create declaration is missing")
}

func applicationGraphCreateAccessKeyProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	pending := map[Action]struct{}{
		ActionPaaSConfigurationCreate:         {},
		ActionPaaSConfigurationRevisionCreate: {},
		ActionPaaSApplicationRevisionCreate:   {},
		ActionPaaSDeploymentCreate:            {},
	}
	for index := range profile.Actions {
		if _, expected := pending[profile.Actions[index].Action]; !expected {
			continue
		}
		profile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{
			UserAuthenticationAccessKey, UserAuthenticationLoginSession,
		}
		delete(pending, profile.Actions[index].Action)
	}
	if len(pending) != 0 {
		panic("PaaS immutable resource graph declaration is missing")
	}
	return profile
}

func applicationReadAccessKeyProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	for index := range profile.Actions {
		if profile.Actions[index].Action != ActionPaaSApplicationRead {
			continue
		}
		profile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{
			UserAuthenticationAccessKey, UserAuthenticationLoginSession,
		}
		return profile
	}
	panic("PaaS Application read declaration is missing")
}

func paasInstanceReadAccessKeyProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	pending := map[Action]struct{}{
		ActionPaaSConfigurationRead:         {},
		ActionPaaSConfigurationRevisionRead: {},
		ActionPaaSApplicationRevisionRead:   {},
		ActionPaaSDeploymentRead:            {},
		ActionPaaSOperationRead:             {},
	}
	for index := range profile.Actions {
		if _, expected := pending[profile.Actions[index].Action]; !expected {
			continue
		}
		profile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{
			UserAuthenticationAccessKey, UserAuthenticationLoginSession,
		}
		delete(pending, profile.Actions[index].Action)
	}
	if len(pending) != 0 {
		panic("PaaS instance read declaration is missing")
	}
	return profile
}

func paasDeploymentMutationAccessKeyProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	pending := map[Action]struct{}{
		ActionPaaSDeploymentUpdate:   {},
		ActionPaaSDeploymentStop:     {},
		ActionPaaSDeploymentRollback: {},
	}
	for index := range profile.Actions {
		if _, expected := pending[profile.Actions[index].Action]; !expected {
			continue
		}
		profile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{
			UserAuthenticationAccessKey, UserAuthenticationLoginSession,
		}
		delete(pending, profile.Actions[index].Action)
	}
	if len(pending) != 0 {
		panic("PaaS Deployment mutation declaration is missing")
	}
	return profile
}

func applicationLabelAccessKeyProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	pending := map[Action]struct{}{
		ActionPaaSApplicationLabelSet:    {},
		ActionPaaSApplicationLabelDelete: {},
	}
	for index := range profile.Actions {
		if _, expected := pending[profile.Actions[index].Action]; !expected {
			continue
		}
		profile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{
			UserAuthenticationAccessKey, UserAuthenticationLoginSession,
		}
		delete(pending, profile.Actions[index].Action)
	}
	if len(pending) != 0 {
		panic("PaaS Application label mutation declaration is missing")
	}
	return profile
}

var auditProfileRevisionOne = declaredProductProfile(ProductAudit, ServiceAudit, 1,
	declaredProfileAction(ActionAuditRecordRead, ResourceAuditRecord, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionAuditIntegrityVerify, ResourceAuditChain, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionAuditPlatformRecordRead, ResourceAuditRecord, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
	declaredProfileAction(ActionAuditPlatformIntegrityVerify, ResourceAuditChain, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}),
)

var auditProfileRevisionTwo = roleBusinessProfile(auditProfileRevisionOne)
var auditProfileRevisionThree = auditAccessKeyProfile(auditProfileRevisionTwo)
var auditProfileRevisionFour = networkConditionProfile(auditProfileRevisionThree)

func auditAccessKeyProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	pending := map[Action]struct{}{
		ActionAuditRecordRead:      {},
		ActionAuditIntegrityVerify: {},
	}
	for index := range profile.Actions {
		if _, expected := pending[profile.Actions[index].Action]; !expected {
			continue
		}
		profile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{
			UserAuthenticationAccessKey, UserAuthenticationLoginSession,
		}
		delete(pending, profile.Actions[index].Action)
	}
	if len(pending) != 0 {
		panic("Audit tenant query declaration is missing")
	}
	return profile
}

func roleBusinessProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision = 2
	for index := range profile.Actions {
		profile.Actions[index].SubjectTypes = []SubjectType{SubjectUser}
		if profile.Actions[index].Scope == AuthorityScopeTenant {
			profile.Actions[index].SubjectTypes = []SubjectType{SubjectRole, SubjectUser}
		}
	}
	return profile
}

func managedServiceInstallationRoleProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	for index := range profile.Actions {
		profile.Actions[index].SubjectTypes = []SubjectType{SubjectUser}
		if profile.Actions[index].Action == ActionManagedServiceInstallationRead {
			profile.Actions[index].SubjectTypes = []SubjectType{SubjectRole, SubjectUser}
		}
	}
	return profile
}

func managedServiceRoleConsentProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	for _, action := range []Action{ActionManagedServiceInstallationRoleBind, ActionManagedServiceInstallationRoleUnbind} {
		declaration := declaredProfileAction(action, ResourceServiceInstallation, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}})
		declaration.SubjectTypes = []SubjectType{SubjectUser}
		profile.Actions = append(profile.Actions, declaration)
	}
	return profile
}

func managedServiceOfferingListBatchProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	for index := range profile.Actions {
		if profile.Actions[index].Action == ActionManagedServiceOfferingRead {
			profile.Actions[index].InstanceListBatch = true
			return profile
		}
	}
	panic("managed-service offering read declaration is missing")
}

// networkConditionProfile explicitly advances one product declaration. It does
// not infer capability from action names or make this condition available to
// another product. Each product owner must opt in with a new revision and a PEP
// that derives the value from its trusted network boundary.
func networkConditionProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	definition, known := lookupConditionDefinition(ConditionRequestSourceIP)
	if !known {
		panic("invalid release-owned network condition declaration")
	}
	for index := range profile.Actions {
		if profile.Actions[index].Scope != AuthorityScopeTenant {
			continue
		}
		profile.Actions[index].Conditions = append(profile.Actions[index].Conditions,
			AuthorizationProfileCondition{Key: definition.Key, ValueType: definition.ValueType, Source: definition.Source})
	}
	return profile
}

// applicationRequestTagProfile declares one real authorization label owned by
// the PaaS application-create PEP. Other labels remain product metadata and
// cannot be referenced by Policy merely because their names exist in storage.
func applicationRequestTagProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	key, err := NewRequestTagConditionKey("environment")
	if err != nil {
		panic("invalid release-owned application request tag")
	}
	definition, known := lookupConditionDefinition(key)
	if !known {
		panic("invalid release-owned application request tag declaration")
	}
	for index := range profile.Actions {
		if profile.Actions[index].Action != ActionPaaSApplicationCreate {
			continue
		}
		profile.Actions[index].Conditions = append(profile.Actions[index].Conditions,
			AuthorizationProfileCondition{Key: definition.Key, ValueType: definition.ValueType, Source: definition.Source})
		return profile
	}
	panic("PaaS application create declaration is missing")
}

// applicationResourceTagProfile adds one resource-owned fact to the one read
// operation whose PEP can load and revalidate that fact under the authenticated
// Account. It does not turn arbitrary stored labels into Policy inputs.
func applicationResourceTagProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	key, err := NewResourceTagConditionKey("environment")
	if err != nil {
		panic("invalid release-owned application resource tag")
	}
	definition, known := lookupConditionDefinition(key)
	if !known {
		panic("invalid release-owned application resource tag declaration")
	}
	for index := range profile.Actions {
		if profile.Actions[index].Action != ActionPaaSApplicationRead {
			continue
		}
		profile.Actions[index].Conditions = append(profile.Actions[index].Conditions,
			AuthorizationProfileCondition{Key: definition.Key, ValueType: definition.ValueType, Source: definition.Source})
		return profile
	}
	panic("PaaS application read declaration is missing")
}

// applicationLabelMutationProfile declares two write operations over the
// product-owned Application. Both operations bind the current resource label
// and the exact requested label pair; the PEP, not IAM or the caller, derives
// the pair being removed for delete.
func applicationLabelMutationProfile(previous AuthorizationProfile) AuthorizationProfile {
	profile := cloneAuthorizationProfile(previous)
	profile.Revision++
	requestKey, err := NewRequestTagConditionKey("environment")
	if err != nil {
		panic("invalid release-owned application label request tag")
	}
	resourceKey, err := NewResourceTagConditionKey("environment")
	if err != nil {
		panic("invalid release-owned application label resource tag")
	}
	requestDefinition, requestKnown := lookupConditionDefinition(requestKey)
	resourceDefinition, resourceKnown := lookupConditionDefinition(resourceKey)
	networkDefinition, networkKnown := lookupConditionDefinition(ConditionRequestSourceIP)
	if !requestKnown || !resourceKnown || !networkKnown {
		panic("invalid release-owned application label conditions")
	}
	for _, action := range []Action{ActionPaaSApplicationLabelSet, ActionPaaSApplicationLabelDelete} {
		declaration := declaredProfileAction(action, ResourceApplication, AuthorityScopeTenant, "",
			[]AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}})
		declaration.SubjectTypes = []SubjectType{SubjectRole, SubjectUser}
		declaration.Conditions = append(declaration.Conditions,
			AuthorizationProfileCondition{Key: networkDefinition.Key, ValueType: networkDefinition.ValueType, Source: networkDefinition.Source},
			AuthorizationProfileCondition{Key: resourceDefinition.Key, ValueType: resourceDefinition.ValueType, Source: resourceDefinition.Source},
			AuthorizationProfileCondition{Key: requestDefinition.Key, ValueType: requestDefinition.ValueType, Source: requestDefinition.Source})
		profile.Actions = append(profile.Actions, declaration)
	}
	return profile
}

func iamRoleManagementProfile() AuthorizationProfile {
	profile := cloneAuthorizationProfile(iamProfileRevisionOne)
	profile.Revision = 2
	profile.Actions = append(profile.Actions,
		declaredProfileAction(ActionIAMRoleList, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleCreate, ResourceAccount, AuthorityScopeTenant, ResourceRole, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleRead, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleUpdate, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleSetStatus, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleDelete, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleTrustSet, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRolePolicyAttachmentCreate, ResourceRole, AuthorityScopeTenant, ResourcePolicyAttachment, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRolePolicyAttachmentRevoke, ResourcePolicyAttachment, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	)
	return profile
}

func iamRoleSessionProfile() AuthorizationProfile {
	profile := iamRoleManagementProfile()
	profile.Revision = 3
	profile.Actions = append(profile.Actions,
		declaredProfileAction(ActionIAMRolePermissionBoundarySet, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRolePermissionBoundaryRemove, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleAssume, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	)
	for index := range profile.Actions {
		profile.Actions[index].SubjectTypes = []SubjectType{SubjectUser}
	}
	return profile
}

func iamRoleSessionManagementProfile() AuthorizationProfile {
	profile := iamRoleSessionProfile()
	profile.Revision = 4
	profile.Actions = append(profile.Actions,
		declaredProfileAction(ActionIAMRoleSessionList, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleSessionRead, ResourceRoleSession, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRoleSessionRevoke, ResourceRoleSession, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	)
	for index := range profile.Actions {
		profile.Actions[index].SubjectTypes = []SubjectType{SubjectUser}
	}
	return profile
}

func iamAccessKeyManagementProfile() AuthorizationProfile {
	profile := iamRoleSessionManagementProfile()
	profile.Revision = 5
	profile.Actions = append(profile.Actions,
		declaredProfileAction(ActionIAMAccessKeyList, ResourceUser, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessKeyCreate, ResourceUser, AuthorityScopeTenant, ResourceAccessKey, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessKeyRead, ResourceAccessKey, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessKeySetStatus, ResourceAccessKey, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessKeyDelete, ResourceAccessKey, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	)
	for index := range profile.Actions {
		profile.Actions[index].SubjectTypes = []SubjectType{SubjectUser}
	}
	return profile
}

func iamSecuritySettingsReadProfile() AuthorizationProfile {
	profile := iamAccessKeyManagementProfile()
	profile.Revision = 6
	read := declaredProfileAction(ActionIAMSecuritySettingsRead, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}})
	read.SubjectTypes = []SubjectType{SubjectUser}
	read.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
	profile.Actions = append(profile.Actions, read)
	return profile
}

func iamSecuritySettingsProfile() AuthorizationProfile {
	profile := iamSecuritySettingsReadProfile()
	profile.Revision = 7
	update := declaredProfileAction(ActionIAMSecuritySettingsUpdate, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}})
	update.SubjectTypes = []SubjectType{SubjectUser}
	update.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
	profile.Actions = append(profile.Actions, update)
	return profile
}

func iamServiceRoleProfile() AuthorizationProfile {
	profile := iamSecuritySettingsProfile()
	profile.Revision = 8
	for _, declaration := range []AuthorizationProfileAction{
		declaredProfileAction(ActionIAMServiceRoleTemplateList, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMServiceLinkedRoleList, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMServiceLinkedRoleRead, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMServiceLinkedRoleCreate, ResourceAccount, AuthorityScopeTenant, ResourceRole, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMRolePass, ResourceRole, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMWorkloadRoleBindingRevoke, ResourceWorkloadRoleBinding, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	} {
		declaration.SubjectTypes = []SubjectType{SubjectUser}
		declaration.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
		profile.Actions = append(profile.Actions, declaration)
	}
	return profile
}

func iamAccessKeyNetworkProfile() AuthorizationProfile {
	profile := iamServiceRoleProfile()
	profile.Revision = 9
	update := declaredProfileAction(ActionIAMAccessKeySetNetworkRestrictions, ResourceAccessKey, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}})
	update.SubjectTypes = []SubjectType{SubjectUser}
	update.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
	profile.Actions = append(profile.Actions, update)
	return profile
}

func iamSecurityReportProfile() AuthorizationProfile {
	profile := iamAccessKeyNetworkProfile()
	profile.Revision = 10
	for _, declaration := range []AuthorizationProfileAction{
		declaredProfileAction(ActionIAMSecurityReportCreate, ResourceAccount, AuthorityScopeTenant, ResourceSecurityReport, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMSecurityReportRead, ResourceSecurityReport, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMSecurityReportDownload, ResourceSecurityReport, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	} {
		declaration.SubjectTypes = []SubjectType{SubjectUser}
		declaration.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
		profile.Actions = append(profile.Actions, declaration)
	}
	return profile
}

func iamAccessAnalyzerProfile() AuthorizationProfile {
	profile := iamSecurityReportProfile()
	profile.Revision = 11
	for _, declaration := range []AuthorizationProfileAction{
		declaredProfileAction(ActionIAMAccessAnalyzerCreate, ResourceAccount, AuthorityScopeTenant, ResourceAccessAnalyzer, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessAnalyzerList, ResourceAccount, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessAnalyzerRead, ResourceAccessAnalyzer, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessAnalyzerUpdate, ResourceAccessAnalyzer, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessFindingList, ResourceAccessAnalyzer, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	} {
		declaration.SubjectTypes = []SubjectType{SubjectUser}
		declaration.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
		profile.Actions = append(profile.Actions, declaration)
	}
	return profile
}

func iamAccessFindingProfile() AuthorizationProfile {
	profile := iamAccessAnalyzerProfile()
	profile.Revision = 12
	for _, declaration := range []AuthorizationProfileAction{
		declaredProfileAction(ActionIAMAccessFindingRead, ResourceAccessFinding, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessFindingArchive, ResourceAccessFinding, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMAccessFindingUnarchive, ResourceAccessFinding, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	} {
		declaration.SubjectTypes = []SubjectType{SubjectUser}
		declaration.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
		profile.Actions = append(profile.Actions, declaration)
	}
	return profile
}

func iamAccessDispositionProfile() AuthorizationProfile {
	profile := iamAccessFindingProfile()
	profile.Revision = 13
	declaration := declaredProfileAction(ActionIAMAccessAnalyzerSetDisposition, ResourceAccessAnalyzer, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}})
	declaration.SubjectTypes = []SubjectType{SubjectUser}
	declaration.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
	profile.Actions = append(profile.Actions, declaration)
	return profile
}

func iamPolicyAttachmentChangeProfile() AuthorizationProfile {
	profile := iamAccessDispositionProfile()
	profile.Revision = 14
	for _, declaration := range []AuthorizationProfileAction{
		declaredProfileAction(ActionIAMPolicyAttachmentChangeRead, ResourcePolicyAttachment, AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction(ActionIAMPlatformPolicyAttachmentChangeRead, ResourcePolicyAttachment, AuthorityScopeInstallation, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
	} {
		declaration.SubjectTypes = []SubjectType{SubjectUser}
		declaration.UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession}
		profile.Actions = append(profile.Actions, declaration)
	}
	return profile
}

var actionDefinitions = projectActionDefinitions(authorizationProfiles)

// Source declarations cannot change during this executable's lifetime. Compute
// their commitments once, not for every projected capability. This contains no
// database head, subject, attachment, decision or permission cache. Supplied
// archive/profile values still go through the full public commitment checker.
var sourceProfileCommitments = func() map[ProductID]authorizationProfileCommitment {
	result := make(map[ProductID]authorizationProfileCommitment, len(authorizationProfiles))
	for _, profile := range authorizationProfiles {
		result[profile.Product] = sourceAuthorizationProfileCommitment(profile)
	}
	return result
}()

// Current source declarations have one revision per product. This is release
// registration, not a tenant-writable registry or an authorization result.
func AllAuthorizationProfiles() []AuthorizationProfile {
	result := make([]AuthorizationProfile, len(authorizationProfiles))
	for index, profile := range authorizationProfiles {
		result[index] = cloneAuthorizationProfile(profile)
	}
	return result
}

func LookupAuthorizationProfile(product ProductID) (AuthorizationProfile, bool) {
	for _, profile := range authorizationProfiles {
		if profile.Product == product {
			return cloneAuthorizationProfile(profile), true
		}
	}
	return AuthorizationProfile{}, false
}

func declaredProductProfile(product ProductID, caller ServicePurpose, revision uint64, actions ...AuthorizationProfileAction) AuthorizationProfile {
	return AuthorizationProfile{APIVersion: APIVersion, Kind: "AuthorizationProfile", Product: product, Revision: revision, CallingService: caller, Actions: actions}
}

func declaredProfileAction(action Action, resource ResourceKind, scope AuthorityScope, result ResourceKind, shapes []AuthorizationResourceShape) AuthorizationProfileAction {
	value := AuthorizationProfileAction{Action: action, ResourceKind: resource, Scope: scope, ResourceShapes: shapes, ResultResourceKind: result}
	if scope == AuthorityScopeTenant {
		for _, key := range []ConditionKey{ConditionIAMCurrentTime, ConditionIAMAccountID, ConditionIAMPrincipalID} {
			definition, known := lookupConditionDefinition(key)
			if !known {
				panic("invalid release-owned IAM condition declaration")
			}
			value.Conditions = append(value.Conditions, AuthorizationProfileCondition{Key: key, ValueType: definition.ValueType, Source: definition.Source})
		}
	}
	return value
}

func projectActionDefinitions(profiles []AuthorizationProfile) []ActionDefinition {
	var result []ActionDefinition
	products := make(map[ProductID]bool, len(profiles))
	actions := make(map[Action]bool)
	for _, profile := range profiles {
		if products[profile.Product] || ValidateAuthorizationProfile(profile) != nil {
			panic("invalid release-owned IAM product declaration")
		}
		products[profile.Product] = true
		for _, declaration := range profile.Actions {
			if actions[declaration.Action] {
				panic("duplicate release-owned IAM action declaration")
			}
			actions[declaration.Action] = true
			result = append(result, authorizationProfileActionDefinition(profile, declaration))
		}
	}
	return result
}

var allServicePurposes = []ServicePurpose{
	ServiceIAM,
	ServicePaaS,
	ServiceAudit,
	ServiceInstallationVerifier,
}

// IsPlatformAction identifies installation authority, never the subject's
// organization membership. Unknown actions grant neither kind of authority.
func IsPlatformAction(action Action) bool {
	definition, known := LookupActionDefinition(action)
	return known && definition.AuthorityScope == AuthorityScopeInstallation
}
