package auditv1

type Source string
type ActorType string
type Action string
type TargetKind string
type Result string
type IngestionOutcome string
type RetentionPolicy string
type VerificationState string
type ReadinessState string
type InstallationVerificationState string

const (
	SourceIAM   Source = "IAM"
	SourcePaaS  Source = "PAAS"
	SourceAudit Source = "AUDIT"
)

const (
	ActorUser           ActorType = "USER"
	ActorServiceAccount ActorType = "SERVICE_ACCOUNT"
	ActorSystem         ActorType = "SYSTEM"
)

const (
	ActionIAMOrganizationCreated  Action = "iam.organization.created"
	ActionIAMAccountAliasSet      Action = "iam.account-alias.set"
	ActionIAMPrincipalStatusSet   Action = "iam.principal.status-set"
	ActionIAMPasswordReset        Action = "iam.password.reset"
	ActionIAMBootstrapApplied     Action = "iam.bootstrap.applied"
	ActionIAMSessionIssued        Action = "iam.session.issued"
	ActionIAMSessionRevoked       Action = "iam.session.revoked"
	ActionIAMPasswordChanged      Action = "iam.password.changed"
	ActionIAMPrincipalCreated     Action = "iam.principal.created"
	ActionIAMRoleBindingPut       Action = "iam.role-binding.put"
	ActionIAMRoleBindingRevoked   Action = "iam.role-binding.revoked"
	ActionIAMAuthorizationDecided Action = "iam.authorization.decided"

	ActionPaaSApplicationCreated                  Action = "paas.application.created"
	ActionPaaSConfigurationCreated                Action = "paas.configuration.created"
	ActionPaaSConfigurationRevisionCreated        Action = "paas.configuration-revision.created"
	ActionPaaSApplicationRevisionCreated          Action = "paas.application-revision.created"
	ActionPaaSDeploymentCreated                   Action = "paas.deployment.created"
	ActionPaaSDeploymentUpdated                   Action = "paas.deployment.updated"
	ActionPaaSDeploymentStopped                   Action = "paas.deployment.stopped"
	ActionPaaSDeploymentRolledBack                Action = "paas.deployment.rolled-back"
	ActionManagedServiceQuotaEntitlementActivated Action = "managedservice.quota-entitlement.activated"
	ActionManagedServiceInstallationCreated       Action = "managedservice.service-installation.created"
	ActionManagedServiceInstallationReady         Action = "managedservice.service-installation.ready"

	ActionAuditRecordsRead       Action = "audit.records.read"
	ActionAuditIntegrityVerified Action = "audit.integrity.verified"
)

const (
	TargetOrganization          TargetKind = "ORGANIZATION"
	TargetInstallation          TargetKind = "INSTALLATION"
	TargetPrincipal             TargetKind = "PRINCIPAL"
	TargetRoleBinding           TargetKind = "ROLE_BINDING"
	TargetSession               TargetKind = "SESSION"
	TargetAuthorizationDecision TargetKind = "AUTHORIZATION_DECISION"
	TargetApplication           TargetKind = "APPLICATION"
	TargetConfiguration         TargetKind = "CONFIGURATION"
	TargetConfigurationRevision TargetKind = "CONFIGURATION_REVISION"
	TargetApplicationRevision   TargetKind = "APPLICATION_REVISION"
	TargetDeployment            TargetKind = "DEPLOYMENT"
	TargetQuotaEntitlement      TargetKind = "QUOTA_ENTITLEMENT"
	TargetServiceInstallation   TargetKind = "SERVICE_INSTALLATION"
	TargetAuditRecords          TargetKind = "AUDIT_RECORDS"
	TargetAuditChain            TargetKind = "AUDIT_CHAIN"
)

const (
	ResultAccepted  Result = "ACCEPTED"
	ResultSucceeded Result = "SUCCEEDED"
	ResultAllowed   Result = "ALLOWED"
	ResultDenied    Result = "DENIED"
)

const (
	IngestionAccepted  IngestionOutcome = "ACCEPTED"
	IngestionDuplicate IngestionOutcome = "DUPLICATE"
)

const RetentionIndefinite RetentionPolicy = "INDEFINITE"

const VerificationVerified VerificationState = "VERIFIED"

const (
	ReadinessReady    ReadinessState = "READY"
	ReadinessNotReady ReadinessState = "NOT_READY"
)

const (
	InstallationVerificationPending  InstallationVerificationState = "PENDING"
	InstallationVerificationVerified InstallationVerificationState = "VERIFIED"
)

// ActionContract is the closed Phase 1 Audit event union. Source is authority
// context supplied by authentication and is never accepted from event JSON.
type ActionContract struct {
	Source               Source
	Target               TargetKind
	Results              []Result
	IAMDecisionPermitted bool
	IAMDecisionRequired  bool
	OperationRequired    bool
}

func AllActions() []Action {
	return append([]Action(nil), allActions...)
}

func ContractForAction(action Action) (ActionContract, bool) {
	contract, known := actionContracts[action]
	contract.Results = append([]Result(nil), contract.Results...)
	if contract.IAMDecisionRequired {
		contract.IAMDecisionPermitted = true
	}
	return contract, known
}

var allActions = []Action{
	ActionIAMOrganizationCreated,
	ActionIAMAccountAliasSet,
	ActionIAMPrincipalStatusSet,
	ActionIAMPasswordReset,
	ActionIAMBootstrapApplied,
	ActionIAMSessionIssued,
	ActionIAMSessionRevoked,
	ActionIAMPasswordChanged,
	ActionIAMPrincipalCreated,
	ActionIAMRoleBindingPut,
	ActionIAMRoleBindingRevoked,
	ActionIAMAuthorizationDecided,
	ActionPaaSApplicationCreated,
	ActionPaaSConfigurationCreated,
	ActionPaaSConfigurationRevisionCreated,
	ActionPaaSApplicationRevisionCreated,
	ActionPaaSDeploymentCreated,
	ActionPaaSDeploymentUpdated,
	ActionPaaSDeploymentStopped,
	ActionPaaSDeploymentRolledBack,
	ActionManagedServiceQuotaEntitlementActivated,
	ActionManagedServiceInstallationCreated,
	ActionManagedServiceInstallationReady,
	ActionAuditRecordsRead,
	ActionAuditIntegrityVerified,
}

var actionContracts = map[Action]ActionContract{
	ActionIAMOrganizationCreated: {
		Source: SourceIAM, Target: TargetOrganization, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionIAMAccountAliasSet: {
		Source: SourceIAM, Target: TargetOrganization, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionIAMPrincipalStatusSet: {
		Source: SourceIAM, Target: TargetPrincipal, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionIAMPasswordReset: {
		Source: SourceIAM, Target: TargetPrincipal, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionIAMBootstrapApplied: {
		Source: SourceIAM, Target: TargetInstallation, Results: []Result{ResultSucceeded},
	},
	ActionIAMSessionIssued: {
		Source: SourceIAM, Target: TargetSession, Results: []Result{ResultSucceeded},
	},
	ActionIAMSessionRevoked: {
		Source: SourceIAM, Target: TargetSession, Results: []Result{ResultSucceeded}, IAMDecisionPermitted: true,
	},
	ActionIAMPasswordChanged: {
		Source: SourceIAM, Target: TargetPrincipal, Results: []Result{ResultSucceeded},
	},
	ActionIAMPrincipalCreated: {
		Source: SourceIAM, Target: TargetPrincipal, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionIAMRoleBindingPut: {
		Source: SourceIAM, Target: TargetRoleBinding, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionIAMRoleBindingRevoked: {
		Source: SourceIAM, Target: TargetRoleBinding, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionIAMAuthorizationDecided: {
		Source: SourceIAM, Target: TargetAuthorizationDecision,
		Results: []Result{ResultAllowed, ResultDenied}, IAMDecisionRequired: true,
	},
	ActionPaaSApplicationCreated: {
		Source: SourcePaaS, Target: TargetApplication, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionPaaSConfigurationCreated: {
		Source: SourcePaaS, Target: TargetConfiguration, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionPaaSConfigurationRevisionCreated: {
		Source: SourcePaaS, Target: TargetConfigurationRevision, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionPaaSApplicationRevisionCreated: {
		Source: SourcePaaS, Target: TargetApplicationRevision, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionPaaSDeploymentCreated: {
		Source: SourcePaaS, Target: TargetDeployment, Results: []Result{ResultAccepted},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionPaaSDeploymentUpdated: {
		Source: SourcePaaS, Target: TargetDeployment, Results: []Result{ResultAccepted},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionPaaSDeploymentStopped: {
		Source: SourcePaaS, Target: TargetDeployment, Results: []Result{ResultAccepted},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionPaaSDeploymentRolledBack: {
		Source: SourcePaaS, Target: TargetDeployment, Results: []Result{ResultAccepted},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionManagedServiceQuotaEntitlementActivated: {
		Source: SourcePaaS, Target: TargetQuotaEntitlement, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true,
	},
	ActionManagedServiceInstallationCreated: {
		Source: SourcePaaS, Target: TargetServiceInstallation, Results: []Result{ResultAccepted},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionManagedServiceInstallationReady: {
		Source: SourcePaaS, Target: TargetServiceInstallation, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true,
	},
	ActionAuditRecordsRead: {
		Source: SourceAudit, Target: TargetAuditRecords, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionAuditIntegrityVerified: {
		Source: SourceAudit, Target: TargetAuditChain, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
}
