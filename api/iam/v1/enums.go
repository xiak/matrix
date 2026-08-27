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
	ActionIAMOrganizationCreate Action = "iam.organization.create"
	ActionIAMOrganizationRead   Action = "iam.organization.read"
	ActionIAMAccountAliasSet    Action = "iam.account-alias.set"
	ActionIAMPrincipalList      Action = "iam.principal.list"
	ActionIAMPrincipalSetStatus Action = "iam.principal.set-status"
	ActionIAMPasswordReset      Action = "iam.password.reset"

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

	ActionAuditRecordRead      Action = "audit.record.read"
	ActionAuditIntegrityVerify Action = "audit.integrity.verify"
	ActionInstallationVerify   Action = "installation.verify"
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
	return append([]Action(nil), allActions...)
}

func AllBuiltinRoles() []BuiltinRole {
	return append([]BuiltinRole(nil), allBuiltinRoles...)
}

// AllServicePurposes returns the exact installer bootstrap order. The order is
// part of the IAMBootstrap wire contract, not merely an enum inventory.
func AllServicePurposes() []ServicePurpose {
	return append([]ServicePurpose(nil), allServicePurposes...)
}

var allActions = []Action{
	ActionIAMOrganizationCreate,
	ActionIAMOrganizationRead,
	ActionIAMAccountAliasSet,
	ActionIAMPrincipalList,
	ActionIAMPrincipalSetStatus,
	ActionIAMPasswordReset,
	ActionIAMPrincipalCreate,
	ActionIAMPrincipalRead,
	ActionIAMRoleBindingPut,
	ActionIAMRoleBindingRevoke,
	ActionIAMSessionRevoke,
	ActionIAMPlatformRoleBindingPut,
	ActionIAMPlatformRoleBindingRevoke,
	ActionPaaSExecutionPoolCreate,
	ActionPaaSExecutionPoolRead,
	ActionPaaSExecutionTargetRegister,
	ActionPaaSExecutionTargetRead,
	ActionPaaSPlatformOperationRead,
	ActionPaaSApplicationCreate,
	ActionPaaSApplicationRead,
	ActionPaaSConfigurationCreate,
	ActionPaaSConfigurationRead,
	ActionPaaSConfigurationRevisionCreate,
	ActionPaaSConfigurationRevisionRead,
	ActionPaaSApplicationRevisionCreate,
	ActionPaaSApplicationRevisionRead,
	ActionPaaSDeploymentCreate,
	ActionPaaSDeploymentUpdate,
	ActionPaaSDeploymentRollback,
	ActionPaaSDeploymentStop,
	ActionPaaSDeploymentRead,
	ActionPaaSOperationRead,
	ActionManagedServiceOfferingRead,
	ActionManagedServiceRegionRead,
	ActionManagedServiceQuotaEntitlementActivate,
	ActionManagedServiceQuotaEntitlementRead,
	ActionManagedServiceInstallationCreate,
	ActionManagedServiceInstallationRead,
	ActionAuditRecordRead,
	ActionAuditIntegrityVerify,
	ActionInstallationVerify,
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
	switch action {
	case ActionIAMPlatformRoleBindingPut, ActionIAMPlatformRoleBindingRevoke,
		ActionPaaSExecutionPoolCreate, ActionPaaSExecutionPoolRead,
		ActionPaaSExecutionTargetRegister, ActionPaaSExecutionTargetRead,
		ActionPaaSPlatformOperationRead:
		return true
	default:
		return false
	}
}
