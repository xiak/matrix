package auditv1

type Source string
type ActorType string
type Action string
type TargetKind string
type Result string
type Outcome string
type Reason string
type IngestionOutcome string
type RetentionPolicy string
type VerificationState string
type ReadinessState string
type InstallationVerificationState string

const (
	SourceIAM    Source = "IAM"
	SourcePaaS   Source = "PAAS"
	SourceDevOps Source = "DEVOPS"
	SourceAudit  Source = "AUDIT"
)

const (
	ActorUser           ActorType = "USER"
	ActorServiceAccount ActorType = "SERVICE_ACCOUNT"
	ActorSystem         ActorType = "SYSTEM"
)

const (
	ActionIAMBootstrapApplied     Action = "iam.bootstrap.applied"
	ActionIAMSessionIssued        Action = "iam.session.issued"
	ActionIAMSessionRevoked       Action = "iam.session.revoked"
	ActionIAMPasswordChanged      Action = "iam.password.changed"
	ActionIAMPrincipalCreated     Action = "iam.principal.created"
	ActionIAMRoleBindingPut       Action = "iam.role-binding.put"
	ActionIAMRoleBindingRevoked   Action = "iam.role-binding.revoked"
	ActionIAMAuthorizationDecided Action = "iam.authorization.decided"

	ActionPaaSApplicationCreated           Action = "paas.application.created"
	ActionPaaSConfigurationCreated         Action = "paas.configuration.created"
	ActionPaaSConfigurationRevisionCreated Action = "paas.configuration-revision.created"
	ActionPaaSApplicationRevisionCreated   Action = "paas.application-revision.created"
	ActionPaaSDeploymentCreated            Action = "paas.deployment.created"
	ActionPaaSDeploymentUpdated            Action = "paas.deployment.updated"
	ActionPaaSDeploymentStopped            Action = "paas.deployment.stopped"
	ActionPaaSDeploymentRolledBack         Action = "paas.deployment.rolled-back"

	ActionDevOpsProjectCreated                      Action = "devops.project.created"
	ActionDevOpsSourceConnectionCreated             Action = "devops.source-connection.created"
	ActionDevOpsSourceConnectionUpdated             Action = "devops.source-connection.updated"
	ActionDevOpsSourceConnectionHealthTransitioned  Action = "devops.source-connection.health-transitioned"
	ActionDevOpsRepositoryBindingCreated            Action = "devops.repository-binding.created"
	ActionDevOpsRepositoryBindingUpdated            Action = "devops.repository-binding.updated"
	ActionDevOpsRepositoryBindingHealthTransitioned Action = "devops.repository-binding.health-transitioned"
	ActionDevOpsPipelineCreated                     Action = "devops.pipeline.created"
	ActionDevOpsPipelineDraftUpdated                Action = "devops.pipeline.draft-updated"
	ActionDevOpsPipelineRevisionActivated           Action = "devops.pipeline-revision.activated"
	ActionDevOpsSourceEventAdmitted                 Action = "devops.source-event.admitted"
	ActionDevOpsPipelineRunCreated                  Action = "devops.pipeline-run.created"
	ActionDevOpsPipelineRunReplayed                 Action = "devops.pipeline-run.replayed"
	ActionDevOpsPipelineRunCancellationRequested    Action = "devops.pipeline-run.cancellation-requested"
	ActionDevOpsPipelineRunCompleted                Action = "devops.pipeline-run.completed"
	ActionDevOpsPipelineRunLogsRead                 Action = "devops.pipeline-run.logs-read"

	ActionAuditRecordsRead       Action = "audit.records.read"
	ActionAuditIntegrityVerified Action = "audit.integrity.verified"
)

const (
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
	TargetDevOpsProject         TargetKind = "DEVOPS_PROJECT"
	TargetSourceConnection      TargetKind = "SOURCE_CONNECTION"
	TargetRepositoryBinding     TargetKind = "REPOSITORY_BINDING"
	TargetPipeline              TargetKind = "PIPELINE"
	TargetPipelineRevision      TargetKind = "PIPELINE_REVISION"
	TargetSourceEvent           TargetKind = "SOURCE_EVENT"
	TargetPipelineRun           TargetKind = "PIPELINE_RUN"
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
	OutcomeSucceeded          Outcome = "SUCCEEDED"
	OutcomeFailed             Outcome = "FAILED"
	OutcomeCancelled          Outcome = "CANCELLED"
	OutcomeManualIntervention Outcome = "MANUAL_INTERVENTION"
)

const (
	ReasonCompleted               Reason = "COMPLETED"
	ReasonSourceUnavailable       Reason = "SOURCE_UNAVAILABLE"
	ReasonCommitMismatch          Reason = "COMMIT_MISMATCH"
	ReasonExecutorUnavailable     Reason = "EXECUTOR_UNAVAILABLE"
	ReasonVerificationFailed      Reason = "VERIFICATION_FAILED"
	ReasonDeadlineExceeded        Reason = "DEADLINE_EXCEEDED"
	ReasonReportUnavailable       Reason = "REPORT_UNAVAILABLE"
	ReasonReportConflict          Reason = "REPORT_CONFLICT"
	ReasonCancelled               Reason = "CANCELLED"
	ReasonReconciliationExhausted Reason = "RECONCILIATION_EXHAUSTED"
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
	OutcomeRequired      bool
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
	ActionDevOpsProjectCreated,
	ActionDevOpsSourceConnectionCreated,
	ActionDevOpsSourceConnectionUpdated,
	ActionDevOpsSourceConnectionHealthTransitioned,
	ActionDevOpsRepositoryBindingCreated,
	ActionDevOpsRepositoryBindingUpdated,
	ActionDevOpsRepositoryBindingHealthTransitioned,
	ActionDevOpsPipelineCreated,
	ActionDevOpsPipelineDraftUpdated,
	ActionDevOpsPipelineRevisionActivated,
	ActionDevOpsSourceEventAdmitted,
	ActionDevOpsPipelineRunCreated,
	ActionDevOpsPipelineRunReplayed,
	ActionDevOpsPipelineRunCancellationRequested,
	ActionDevOpsPipelineRunCompleted,
	ActionDevOpsPipelineRunLogsRead,
	ActionAuditRecordsRead,
	ActionAuditIntegrityVerified,
}

var actionContracts = map[Action]ActionContract{
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
	ActionDevOpsProjectCreated: {
		Source: SourceDevOps, Target: TargetDevOpsProject, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsSourceConnectionCreated: {
		Source: SourceDevOps, Target: TargetSourceConnection, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsSourceConnectionUpdated: {
		Source: SourceDevOps, Target: TargetSourceConnection, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsSourceConnectionHealthTransitioned: {
		Source: SourceDevOps, Target: TargetSourceConnection, Results: []Result{ResultSucceeded},
		OperationRequired: true,
	},
	ActionDevOpsRepositoryBindingCreated: {
		Source: SourceDevOps, Target: TargetRepositoryBinding, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsRepositoryBindingUpdated: {
		Source: SourceDevOps, Target: TargetRepositoryBinding, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsRepositoryBindingHealthTransitioned: {
		Source: SourceDevOps, Target: TargetRepositoryBinding, Results: []Result{ResultSucceeded},
		OperationRequired: true,
	},
	ActionDevOpsPipelineCreated: {
		Source: SourceDevOps, Target: TargetPipeline, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsPipelineDraftUpdated: {
		Source: SourceDevOps, Target: TargetPipeline, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsPipelineRevisionActivated: {
		Source: SourceDevOps, Target: TargetPipelineRevision, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsSourceEventAdmitted: {
		Source: SourceDevOps, Target: TargetSourceEvent, Results: []Result{ResultAccepted},
		OperationRequired: true,
	},
	ActionDevOpsPipelineRunCreated: {
		Source: SourceDevOps, Target: TargetPipelineRun, Results: []Result{ResultAccepted},
		OperationRequired: true,
	},
	ActionDevOpsPipelineRunReplayed: {
		Source: SourceDevOps, Target: TargetPipelineRun, Results: []Result{ResultAccepted},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsPipelineRunCancellationRequested: {
		Source: SourceDevOps, Target: TargetPipelineRun, Results: []Result{ResultAccepted},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionDevOpsPipelineRunCompleted: {
		Source: SourceDevOps, Target: TargetPipelineRun, Results: []Result{ResultSucceeded},
		OperationRequired: true, OutcomeRequired: true,
	},
	ActionDevOpsPipelineRunLogsRead: {
		Source: SourceDevOps, Target: TargetPipelineRun, Results: []Result{ResultSucceeded},
		IAMDecisionRequired: true, OperationRequired: true,
	},
	ActionAuditRecordsRead: {
		Source: SourceAudit, Target: TargetAuditRecords, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
	ActionAuditIntegrityVerified: {
		Source: SourceAudit, Target: TargetAuditChain, Results: []Result{ResultSucceeded}, IAMDecisionRequired: true,
	},
}
