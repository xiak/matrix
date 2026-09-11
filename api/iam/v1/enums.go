package iamv1

type AccountStatus string
type PrincipalType string
type PrincipalStatus string
type SessionStatus string
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
)

const (
	SessionActive  SessionStatus = "ACTIVE"
	SessionRevoked SessionStatus = "REVOKED"
	SessionExpired SessionStatus = "EXPIRED"
)

const (
	ActionIAMAccountCreate                 Action = "iam.account.create"
	ActionIAMAccountRead                   Action = "iam.account.read"
	ActionIAMAccountSetStatus              Action = "iam.account.set-status"
	ActionIAMAccountRootCredentialsRecover Action = "iam.account.recover-root-credentials"
	ActionIAMAccountAliasSet               Action = "iam.account.alias-set"
	ActionIAMUserList                      Action = "iam.user.list"
	ActionIAMPolicyList                    Action = "iam.policy.list"
	ActionIAMPlatformPolicyList            Action = "iam.platform-policy.list"
	ActionIAMUserSetStatus                 Action = "iam.user.set-status"
	ActionIAMUserPasswordReset             Action = "iam.user.reset-password"

	ActionIAMUserCreate                     Action = "iam.user.create"
	ActionIAMUserRead                       Action = "iam.user.read"
	ActionIAMSessionRevoke                  Action = "iam.session.revoke"
	ActionIAMPolicyAttachmentCreate         Action = "iam.policy-attachment.create"
	ActionIAMPolicyAttachmentRevoke         Action = "iam.policy-attachment.revoke"
	ActionIAMPlatformPolicyAttachmentCreate Action = "iam.platform-policy-attachment.create"
	ActionIAMPlatformPolicyAttachmentRevoke Action = "iam.platform-policy-attachment.revoke"

	ActionPaaSExecutionPoolCreate     Action = "paas.execution-pool.create"
	ActionPaaSExecutionPoolRead       Action = "paas.execution-pool.read"
	ActionPaaSExecutionTargetRegister Action = "paas.execution-target.register"
	ActionPaaSExecutionTargetRead     Action = "paas.execution-target.read"
	ActionPaaSPlatformOperationRead   Action = "paas.platform-operation.read"

	ActionPaaSApplicationCreate           Action = "paas.application.create"
	ActionPaaSApplicationRead             Action = "paas.application.read"
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
	ResourceOrganization          ResourceKind = "ORGANIZATION"
	ResourcePrincipal             ResourceKind = "PRINCIPAL"
	ResourceRoleBinding           ResourceKind = "ROLE_BINDING"
	ResourcePolicyAttachment      ResourceKind = "POLICY_ATTACHMENT"
	ResourceSession               ResourceKind = "SESSION"
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
	{ActionIAMOrganizationCreate, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation},
	{ActionIAMOrganizationRead, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation},
	{ActionIAMOrganizationSetStatus, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation},
	{ActionIAMOrganizationAdministratorRecover, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeInstallation},
	{ActionIAMLegacyAccountAliasSet, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant},
	{ActionIAMPrincipalList, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant},
	{ActionIAMPrincipalSetStatus, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant},
	{ActionIAMPasswordReset, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant},
	{ActionIAMPrincipalCreate, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant},
	{ActionIAMPrincipalRead, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant},
	{ActionIAMRoleBindingPut, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant},
	{ActionIAMRoleBindingRevoke, ProductIAM, ServiceIAM, ResourceRoleBinding, AuthorityScopeTenant},
	{ActionIAMPlatformRoleBindingPut, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeInstallation},
	{ActionIAMPlatformRoleBindingRevoke, ProductIAM, ServiceIAM, ResourceRoleBinding, AuthorityScopeInstallation},
}

// AllServicePurposes returns the exact installer bootstrap order. The order is
// part of the IAMBootstrap wire contract, not merely an enum inventory.
func AllServicePurposes() []ServicePurpose {
	return append([]ServicePurpose(nil), allServicePurposes...)
}

// This is the sole action/resource/caller/scope catalog. Preserve its order:
// existing generated contracts use AllActions.
var actionDefinitions = [...]ActionDefinition{
	{ActionIAMAccountCreate, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation},
	{ActionIAMAccountRead, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation},
	{ActionIAMAccountSetStatus, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation},
	{ActionIAMAccountRootCredentialsRecover, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation},
	{ActionIAMAccountAliasSet, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeTenant},
	{ActionIAMUserList, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeTenant},
	{ActionIAMPolicyList, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeTenant},
	{ActionIAMPlatformPolicyList, ProductIAM, ServiceIAM, ResourceInstallation, AuthorityScopeInstallation},
	{ActionIAMUserSetStatus, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeTenant},
	{ActionIAMUserPasswordReset, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeTenant},
	{ActionIAMUserCreate, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeTenant},
	{ActionIAMUserRead, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeTenant},
	{ActionIAMPolicyAttachmentCreate, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeTenant},
	{ActionIAMPolicyAttachmentRevoke, ProductIAM, ServiceIAM, ResourcePolicyAttachment, AuthorityScopeTenant},
	{ActionIAMSessionRevoke, ProductIAM, ServiceIAM, ResourceSession, AuthorityScopeTenant},
	{ActionIAMPlatformPolicyAttachmentCreate, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeInstallation},
	{ActionIAMPlatformPolicyAttachmentRevoke, ProductIAM, ServiceIAM, ResourcePolicyAttachment, AuthorityScopeInstallation},
	{ActionPaaSExecutionPoolCreate, ProductPaaS, ServicePaaS, ResourceExecutionPool, AuthorityScopeInstallation},
	{ActionPaaSExecutionPoolRead, ProductPaaS, ServicePaaS, ResourceExecutionPool, AuthorityScopeInstallation},
	{ActionPaaSExecutionTargetRegister, ProductPaaS, ServicePaaS, ResourceExecutionTarget, AuthorityScopeInstallation},
	{ActionPaaSExecutionTargetRead, ProductPaaS, ServicePaaS, ResourceExecutionTarget, AuthorityScopeInstallation},
	{ActionPaaSPlatformOperationRead, ProductPaaS, ServicePaaS, ResourceOperation, AuthorityScopeInstallation},
	{ActionPaaSApplicationCreate, ProductPaaS, ServicePaaS, ResourceApplication, AuthorityScopeTenant},
	{ActionPaaSApplicationRead, ProductPaaS, ServicePaaS, ResourceApplication, AuthorityScopeTenant},
	{ActionPaaSConfigurationCreate, ProductPaaS, ServicePaaS, ResourceConfiguration, AuthorityScopeTenant},
	{ActionPaaSConfigurationRead, ProductPaaS, ServicePaaS, ResourceConfiguration, AuthorityScopeTenant},
	{ActionPaaSConfigurationRevisionCreate, ProductPaaS, ServicePaaS, ResourceConfigurationRevision, AuthorityScopeTenant},
	{ActionPaaSConfigurationRevisionRead, ProductPaaS, ServicePaaS, ResourceConfigurationRevision, AuthorityScopeTenant},
	{ActionPaaSApplicationRevisionCreate, ProductPaaS, ServicePaaS, ResourceApplicationRevision, AuthorityScopeTenant},
	{ActionPaaSApplicationRevisionRead, ProductPaaS, ServicePaaS, ResourceApplicationRevision, AuthorityScopeTenant},
	{ActionPaaSDeploymentCreate, ProductPaaS, ServicePaaS, ResourceDeployment, AuthorityScopeTenant},
	{ActionPaaSDeploymentUpdate, ProductPaaS, ServicePaaS, ResourceDeployment, AuthorityScopeTenant},
	{ActionPaaSDeploymentRollback, ProductPaaS, ServicePaaS, ResourceDeployment, AuthorityScopeTenant},
	{ActionPaaSDeploymentStop, ProductPaaS, ServicePaaS, ResourceDeployment, AuthorityScopeTenant},
	{ActionPaaSDeploymentRead, ProductPaaS, ServicePaaS, ResourceDeployment, AuthorityScopeTenant},
	{ActionPaaSOperationRead, ProductPaaS, ServicePaaS, ResourceOperation, AuthorityScopeTenant},
	{ActionManagedServiceOfferingRead, ProductManagedService, ServicePaaS, ResourceServiceOffering, AuthorityScopeTenant},
	{ActionManagedServiceRegionRead, ProductManagedService, ServicePaaS, ResourceRegion, AuthorityScopeTenant},
	{ActionManagedServiceQuotaEntitlementActivate, ProductManagedService, ServicePaaS, ResourceQuotaEntitlement, AuthorityScopeTenant},
	{ActionManagedServiceQuotaEntitlementRead, ProductManagedService, ServicePaaS, ResourceQuotaEntitlement, AuthorityScopeTenant},
	{ActionManagedServiceInstallationCreate, ProductManagedService, ServicePaaS, ResourceServiceInstallation, AuthorityScopeTenant},
	{ActionManagedServiceInstallationRead, ProductManagedService, ServicePaaS, ResourceServiceInstallation, AuthorityScopeTenant},
	{ActionAuditRecordRead, ProductAudit, ServiceAudit, ResourceAuditRecord, AuthorityScopeTenant},
	{ActionAuditIntegrityVerify, ProductAudit, ServiceAudit, ResourceAuditChain, AuthorityScopeTenant},
	{ActionAuditPlatformRecordRead, ProductAudit, ServiceAudit, ResourceAuditRecord, AuthorityScopeInstallation},
	{ActionAuditPlatformIntegrityVerify, ProductAudit, ServiceAudit, ResourceAuditChain, AuthorityScopeInstallation},
	{ActionInstallationVerify, ProductInstallation, ServiceInstallationVerifier, ResourceInstallation, AuthorityScopeInstallationProbe},
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
