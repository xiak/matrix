package iamv1

type OrganizationStatus string
type PrincipalType string
type PrincipalStatus string
type SessionStatus string
type BuiltinRole string
type Action string
type ResourceKind string
type DecisionReason string
type BootstrapState string
type ServicePurpose string
type ReadinessState string
type ProductID string
type AuthorityScope string

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
	OrganizationActive   OrganizationStatus = "ACTIVE"
	OrganizationDisabled OrganizationStatus = "DISABLED"
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
	SessionActive  SessionStatus = "ACTIVE"
	SessionRevoked SessionStatus = "REVOKED"
	SessionExpired SessionStatus = "EXPIRED"
)

const (
	RoleOrganizationAdmin    BuiltinRole = "ORGANIZATION_ADMIN"
	RolePlatformOperator     BuiltinRole = "PLATFORM_OPERATOR"
	RolePaaSDeveloper        BuiltinRole = "PAAS_DEVELOPER"
	RolePaaSViewer           BuiltinRole = "PAAS_VIEWER"
	RoleAuditReader          BuiltinRole = "AUDIT_READER"
	RoleInstallationVerifier BuiltinRole = "INSTALLATION_VERIFIER"
)

const (
	ActionIAMOrganizationCreate               Action = "iam.organization.create"
	ActionIAMOrganizationRead                 Action = "iam.organization.read"
	ActionIAMOrganizationSetStatus            Action = "iam.organization.set-status"
	ActionIAMOrganizationAdministratorRecover Action = "iam.organization-administrator.recover"
	ActionIAMAccountAliasSet                  Action = "iam.account-alias.set"
	ActionIAMPrincipalList                    Action = "iam.principal.list"
	ActionIAMPrincipalSetStatus               Action = "iam.principal.set-status"
	ActionIAMPasswordReset                    Action = "iam.password.reset"

	ActionIAMPrincipalCreate           Action = "iam.principal.create"
	ActionIAMPrincipalRead             Action = "iam.principal.read"
	ActionIAMRoleBindingPut            Action = "iam.role-binding.put"
	ActionIAMRoleBindingRevoke         Action = "iam.role-binding.revoke"
	ActionIAMSessionRevoke             Action = "iam.session.revoke"
	ActionIAMPlatformRoleBindingPut    Action = "iam.platform-role-binding.put"
	ActionIAMPlatformRoleBindingRevoke Action = "iam.platform-role-binding.revoke"

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

const (
	ResourceOrganization          ResourceKind = "ORGANIZATION"
	ResourcePrincipal             ResourceKind = "PRINCIPAL"
	ResourceRoleBinding           ResourceKind = "ROLE_BINDING"
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

func AllBuiltinRoles() []BuiltinRole {
	return append([]BuiltinRole(nil), allBuiltinRoles...)
}

// AllServicePurposes returns the exact installer bootstrap order. The order is
// part of the IAMBootstrap wire contract, not merely an enum inventory.
func AllServicePurposes() []ServicePurpose {
	return append([]ServicePurpose(nil), allServicePurposes...)
}

// This is the sole action/resource/caller/scope catalog. Preserve its order:
// existing generated contracts use AllActions.
var actionDefinitions = [...]ActionDefinition{
	{ActionIAMOrganizationCreate, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation},
	{ActionIAMOrganizationRead, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation},
	{ActionIAMOrganizationSetStatus, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeInstallation},
	{ActionIAMOrganizationAdministratorRecover, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeInstallation},
	{ActionIAMAccountAliasSet, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant},
	{ActionIAMPrincipalList, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant},
	{ActionIAMPrincipalSetStatus, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant},
	{ActionIAMPasswordReset, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant},
	{ActionIAMPrincipalCreate, ProductIAM, ServiceIAM, ResourceOrganization, AuthorityScopeTenant},
	{ActionIAMPrincipalRead, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant},
	{ActionIAMRoleBindingPut, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeTenant},
	{ActionIAMRoleBindingRevoke, ProductIAM, ServiceIAM, ResourceRoleBinding, AuthorityScopeTenant},
	{ActionIAMSessionRevoke, ProductIAM, ServiceIAM, ResourceSession, AuthorityScopeTenant},
	{ActionIAMPlatformRoleBindingPut, ProductIAM, ServiceIAM, ResourcePrincipal, AuthorityScopeInstallation},
	{ActionIAMPlatformRoleBindingRevoke, ProductIAM, ServiceIAM, ResourceRoleBinding, AuthorityScopeInstallation},
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

var allBuiltinRoles = []BuiltinRole{
	RoleOrganizationAdmin,
	RolePlatformOperator,
	RolePaaSDeveloper,
	RolePaaSViewer,
	RoleAuditReader,
	RoleInstallationVerifier,
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
