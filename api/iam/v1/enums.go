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
	RolePaaSDeveloper        BuiltinRole = "PAAS_DEVELOPER"
	RolePaaSViewer           BuiltinRole = "PAAS_VIEWER"
	RoleDevOpsAdmin          BuiltinRole = "DEVOPS_ADMIN"
	RoleDevOpsDeveloper      BuiltinRole = "DEVOPS_DEVELOPER"
	RoleDevOpsViewer         BuiltinRole = "DEVOPS_VIEWER"
	RoleAuditReader          BuiltinRole = "AUDIT_READER"
	RoleInstallationVerifier BuiltinRole = "INSTALLATION_VERIFIER"
)

const (
	ActionIAMPrincipalCreate   Action = "iam.principal.create"
	ActionIAMPrincipalRead     Action = "iam.principal.read"
	ActionIAMRoleBindingPut    Action = "iam.role-binding.put"
	ActionIAMRoleBindingRevoke Action = "iam.role-binding.revoke"
	ActionIAMSessionRevoke     Action = "iam.session.revoke"

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

	ActionDevOpsProjectCreate           Action = "devops.project.create"
	ActionDevOpsProjectRead             Action = "devops.project.read"
	ActionDevOpsSourceConnectionCreate  Action = "devops.source-connection.create"
	ActionDevOpsSourceConnectionRead    Action = "devops.source-connection.read"
	ActionDevOpsSourceConnectionUpdate  Action = "devops.source-connection.update"
	ActionDevOpsRepositoryBindingCreate Action = "devops.repository-binding.create"
	ActionDevOpsRepositoryBindingRead   Action = "devops.repository-binding.read"
	ActionDevOpsRepositoryBindingUpdate Action = "devops.repository-binding.update"
	ActionDevOpsPipelineCreate          Action = "devops.pipeline.create"
	ActionDevOpsPipelineRead            Action = "devops.pipeline.read"
	ActionDevOpsPipelineUpdate          Action = "devops.pipeline.update"
	ActionDevOpsPipelineActivate        Action = "devops.pipeline.activate"
	ActionDevOpsRunRead                 Action = "devops.run.read"
	ActionDevOpsRunReplay               Action = "devops.run.replay"
	ActionDevOpsRunCancel               Action = "devops.run.cancel"
	ActionDevOpsLogRead                 Action = "devops.log.read"

	ActionAuditRecordRead         Action = "audit.record.read"
	ActionAuditIntegrityVerify    Action = "audit.integrity.verify"
	ActionInstallationProductRead Action = "installation.product.read"
	ActionInstallationVerify      Action = "installation.verify"
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
	ResourceDevOpsProject         ResourceKind = "DEVOPS_PROJECT"
	ResourceSourceConnection      ResourceKind = "SOURCE_CONNECTION"
	ResourceRepositoryBinding     ResourceKind = "REPOSITORY_BINDING"
	ResourcePipeline              ResourceKind = "PIPELINE"
	ResourcePipelineRun           ResourceKind = "PIPELINE_RUN"
	ResourcePipelineLog           ResourceKind = "PIPELINE_LOG"
	ResourceAuditRecord           ResourceKind = "AUDIT_RECORD"
	ResourceAuditChain            ResourceKind = "AUDIT_CHAIN"
	ResourceInstallation          ResourceKind = "INSTALLATION"
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
	ServicePlatform             ServicePurpose = "PLATFORM"
	ServicePaaS                 ServicePurpose = "PAAS"
	ServiceDevOps               ServicePurpose = "DEVOPS"
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

// AllServicePurposes returns the closed service identity catalog. Optional
// product services are included even though Foundation bootstrap does not
// provision their credentials.
func AllServicePurposes() []ServicePurpose {
	return append([]ServicePurpose(nil), allServicePurposes...)
}

// BootstrapServicePurposes returns the exact Foundation installer bootstrap
// order. The order is part of the IAMBootstrap wire contract.
func BootstrapServicePurposes() []ServicePurpose {
	return append([]ServicePurpose(nil), bootstrapServicePurposes...)
}

var allActions = []Action{
	ActionIAMPrincipalCreate,
	ActionIAMPrincipalRead,
	ActionIAMRoleBindingPut,
	ActionIAMRoleBindingRevoke,
	ActionIAMSessionRevoke,
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
	ActionDevOpsProjectCreate,
	ActionDevOpsProjectRead,
	ActionDevOpsSourceConnectionCreate,
	ActionDevOpsSourceConnectionRead,
	ActionDevOpsSourceConnectionUpdate,
	ActionDevOpsRepositoryBindingCreate,
	ActionDevOpsRepositoryBindingRead,
	ActionDevOpsRepositoryBindingUpdate,
	ActionDevOpsPipelineCreate,
	ActionDevOpsPipelineRead,
	ActionDevOpsPipelineUpdate,
	ActionDevOpsPipelineActivate,
	ActionDevOpsRunRead,
	ActionDevOpsRunReplay,
	ActionDevOpsRunCancel,
	ActionDevOpsLogRead,
	ActionAuditRecordRead,
	ActionAuditIntegrityVerify,
	ActionInstallationProductRead,
	ActionInstallationVerify,
}

var allBuiltinRoles = []BuiltinRole{
	RoleOrganizationAdmin,
	RolePaaSDeveloper,
	RolePaaSViewer,
	RoleDevOpsAdmin,
	RoleDevOpsDeveloper,
	RoleDevOpsViewer,
	RoleAuditReader,
	RoleInstallationVerifier,
}

var allServicePurposes = []ServicePurpose{
	ServiceIAM,
	ServicePlatform,
	ServicePaaS,
	ServiceDevOps,
	ServiceAudit,
	ServiceInstallationVerifier,
}

var bootstrapServicePurposes = []ServicePurpose{
	ServiceIAM,
	ServicePlatform,
	ServicePaaS,
	ServiceAudit,
	ServiceInstallationVerifier,
}

// legacyBootstrapServicePurposes is the fixed v0.1 inventory retained only so
// an accepted installation can replay its original signed-in-place authority
// seed while upgrading. It is deliberately excluded from public enumeration.
var legacyBootstrapServicePurposes = []ServicePurpose{
	ServiceIAM,
	ServicePaaS,
	ServiceAudit,
	ServiceInstallationVerifier,
}
