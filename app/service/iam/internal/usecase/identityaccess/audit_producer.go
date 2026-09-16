package identityaccess

import (
	"context"
	"strings"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

// AuditEvidence is read from IAM's own immutable decision/outbox facts, never
// supplied by a producer. Installation and verifier identity come from sealed
// installation ownership; no current user, session, or role is reauthorized.
type AuditEvidence struct {
	InstallationID string
	Event          auditv1.Event
	Decision       *iamv1.AuthorizationDecision
	// Both fields come only from protected storage metadata and exact archive lookup.
	DecisionContractVersion int
	DecisionProfile         *iamv1.AuthorizationProfile
	VerifierPrincipalID     iamv1.PrincipalID
}

func auditContentDigest(identity iamv1.ServiceIdentity, event auditv1.Event, evidence AuditEvidence) (string, error) {
	if iamv1.ValidateServiceIdentity(identity) != nil || identity.InstallationID != evidence.InstallationID ||
		(event.InstallationID != "" && event.InstallationID != identity.InstallationID) {
		return "", ErrForbidden
	}
	var source auditv1.Source
	switch identity.Purpose {
	case iamv1.ServiceIAM:
		source = auditv1.SourceIAM
	case iamv1.ServicePaaS:
		source = auditv1.SourcePaaS
	case iamv1.ServiceAudit:
		source = auditv1.SourceAudit
	default:
		return "", ErrForbidden
	}
	_, digest, err := auditv1.CanonicalizeEvent(source, event)
	if err != nil {
		return "", ErrForbidden
	}
	if source == auditv1.SourceIAM {
		_, storedDigest, err := auditv1.CanonicalizeEvent(source, evidence.Event)
		if err != nil || digest != storedDigest {
			return "", ErrForbidden
		}
		return digest, nil
	}
	decision := evidence.Decision
	if !validHistoricalDecision(evidence) || !decision.Allowed || decision.Subject == nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, evidence.Event) != nil ||
		evidence.Event.Action != auditv1.ActionIAMAuthorizationDecided || evidence.Event.Result != auditv1.ResultAllowed ||
		evidence.Event.IAMDecisionID != auditv1.DecisionID(decision.ID) || evidence.Event.Target.ID != string(decision.ID) ||
		!evidence.Event.OccurredAt.Equal(decision.DecidedAt) || event.OccurredAt.Before(decision.DecidedAt) ||
		event.IAMDecisionID != auditv1.DecisionID(decision.ID) || event.RequestID != decision.RequestID ||
		evidence.Event.RequestID != decision.RequestID || evidence.Event.CorrelationID != event.CorrelationID ||
		!evidence.Event.Actor.Equal(event.Actor) || event.Actor.ID != auditv1.ActorID(decision.Subject.ID) ||
		string(event.Actor.Type) != string(decision.Subject.Type) ||
		event.TenantID != auditv1.TenantID(decision.TenantID) || event.InstallationID != decision.InstallationID {
		return "", ErrForbidden
	}
	expectedActor, actorErr := auditActorForSubject(*decision.Subject)
	if actorErr != nil || !expectedActor.Equal(event.Actor) {
		return "", ErrForbidden
	}
	if evidence.DecisionContractVersion >= 2 && decision.CorrelationID != evidence.Event.CorrelationID {
		return "", ErrForbidden
	}
	originalTenant := decision.TenantID
	if decision.InstallationID != "" {
		originalTenant = identity.AccountID
	}
	if evidence.Event.TenantID != auditv1.TenantID(originalTenant) || evidence.Event.InstallationID != "" {
		return "", ErrForbidden
	}
	if decision.Action == iamv1.ActionInstallationVerify {
		if decision.Subject.Type != iamv1.SubjectServiceAccount || evidence.VerifierPrincipalID == "" ||
			decision.Subject.ID != string(evidence.VerifierPrincipalID) || decision.Resource.ID != identity.InstallationID ||
			decision.TenantID != identity.AccountID || !fixedVerificationFact(source, event) {
			return "", ErrForbidden
		}
		return digest, nil
	}
	expectedAction, expectedID, mode, usage := auditDecisionTarget(event, decision.Action, evidence.DecisionContractVersion)
	if (decision.Subject.Type != iamv1.SubjectUser && !(evidence.DecisionContractVersion == 3 && decision.Subject.Type == iamv1.SubjectRole)) || decision.Action != expectedAction ||
		decision.Resource.ID != expectedID || !historicalProducerMatches(evidence, identity.Purpose) {
		return "", ErrForbidden
	}
	if evidence.DecisionContractVersion >= 2 && (decision.ResourceMode != mode || decision.CollectionUsage != usage) {
		return "", ErrForbidden
	}
	return digest, nil
}

// Current product heads and the current source catalog cannot redefine a
// producer's historical admission. The closed fact mapping above still selects
// the original action; its calling service and resource kind come from the
// protected original contract, never from the producer request.
func historicalProducerMatches(evidence AuditEvidence, purpose iamv1.ServicePurpose) bool {
	if (evidence.DecisionContractVersion == 2 || evidence.DecisionContractVersion == 3) && evidence.DecisionProfile != nil {
		return evidence.DecisionProfile.CallingService == purpose
	}
	if evidence.DecisionContractVersion == 1 {
		for _, definition := range iamv1.AllRecordedActionDefinitions() {
			if definition.Action == evidence.Decision.Action {
				return definition.CallingService == purpose && definition.ResourceKind == evidence.Decision.Resource.Kind
			}
		}
	}
	return false
}

func validHistoricalDecision(evidence AuditEvidence) bool {
	if evidence.Decision == nil {
		return false
	}
	switch evidence.DecisionContractVersion {
	case 1:
		return evidence.DecisionProfile == nil && iamv1.ValidateLegacyAuthorizationDecision(*evidence.Decision) == nil
	case 2:
		return (evidence.Decision.Subject == nil || evidence.Decision.Subject.Type != iamv1.SubjectRole) && evidence.DecisionProfile != nil && iamv1.ValidateAuthorizationDecisionForProfile(*evidence.Decision, *evidence.DecisionProfile) == nil
	case 3:
		return evidence.DecisionProfile != nil && iamv1.ValidateAuthorizationDecisionForProfile(*evidence.Decision, *evidence.DecisionProfile) == nil
	default:
		return false
	}
}

func auditDecisionTarget(event auditv1.Event, decisionAction iamv1.Action, contractVersion int) (iamv1.Action, string, iamv1.AuthorizationResourceMode, iamv1.AuthorizationCollectionUsage) {
	records, chain := "collection", "collection"
	if contractVersion == 1 {
		records, chain = "records", "chain"
	}
	switch event.Action {
	case auditv1.ActionPaaSApplicationCreated:
		return iamv1.ActionPaaSApplicationCreate, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
	case auditv1.ActionPaaSConfigurationCreated:
		return iamv1.ActionPaaSConfigurationCreate, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
	case auditv1.ActionPaaSConfigurationRevisionCreated:
		return iamv1.ActionPaaSConfigurationRevisionCreate, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
	case auditv1.ActionPaaSApplicationRevisionCreated:
		return iamv1.ActionPaaSApplicationRevisionCreate, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
	case auditv1.ActionPaaSDeploymentCreated:
		return iamv1.ActionPaaSDeploymentCreate, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
	case auditv1.ActionPaaSDeploymentUpdated:
		return iamv1.ActionPaaSDeploymentUpdate, event.Target.ID, iamv1.AuthorizationResourceInstance, ""
	case auditv1.ActionPaaSDeploymentStopped:
		return iamv1.ActionPaaSDeploymentStop, event.Target.ID, iamv1.AuthorizationResourceInstance, ""
	case auditv1.ActionPaaSDeploymentRolledBack:
		return iamv1.ActionPaaSDeploymentRollback, event.Target.ID, iamv1.AuthorizationResourceInstance, ""
	case auditv1.ActionPaaSExecutionPoolCreated:
		return iamv1.ActionPaaSExecutionPoolCreate, event.Target.ID, iamv1.AuthorizationResourceInstance, ""
	case auditv1.ActionPaaSExecutionTargetRegistered:
		// Enrollment authorized its ceremony before the final target existed.
		// The PaaS transaction/outbox, not this authority proof, binds that
		// successful result. Other target mutations never use collection proof.
		if decisionAction == iamv1.ActionPaaSNodeEnrollmentCreate {
			return iamv1.ActionPaaSNodeEnrollmentCreate, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
		}
		return iamv1.ActionPaaSExecutionTargetRegister, event.Target.ID, iamv1.AuthorizationResourceInstance, ""
	case auditv1.ActionPaaSExecutionTargetDrained:
		return iamv1.ActionPaaSExecutionTargetDrain, event.Target.ID, iamv1.AuthorizationResourceInstance, ""
	case auditv1.ActionPaaSExecutionTargetActivated:
		return iamv1.ActionPaaSExecutionTargetActivate, event.Target.ID, iamv1.AuthorizationResourceInstance, ""
	case auditv1.ActionPaaSExecutionTargetRemoved:
		return iamv1.ActionPaaSExecutionTargetRemove, event.Target.ID, iamv1.AuthorizationResourceInstance, ""
	case auditv1.ActionManagedServiceQuotaEntitlementActivated:
		return iamv1.ActionManagedServiceQuotaEntitlementActivate, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
	case auditv1.ActionManagedServiceInstallationCreated, auditv1.ActionManagedServiceInstallationReady:
		return iamv1.ActionManagedServiceInstallationCreate, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate
	case auditv1.ActionAuditRecordsRead:
		return iamv1.ActionAuditRecordRead, records, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList
	case auditv1.ActionAuditIntegrityVerified:
		return iamv1.ActionAuditIntegrityVerify, chain, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList
	case auditv1.ActionAuditPlatformRecordsRead:
		return iamv1.ActionAuditPlatformRecordRead, records, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList
	case auditv1.ActionAuditPlatformIntegrityVerified:
		return iamv1.ActionAuditPlatformIntegrityVerify, chain, iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList
	default:
		return "", "", "", ""
	}
}

// Only the installation verifier's closed probe namespace is admitted. Exact
// generated IDs and business payloads remain the PaaS probe/outbox's contract,
// not a capability to run arbitrary service-account business mutations.
func fixedVerificationFact(source auditv1.Source, event auditv1.Event) bool {
	if source == auditv1.SourceAudit {
		return event.Action == auditv1.ActionAuditIntegrityVerified && event.Target.ID == "installation-verification"
	}
	var prefix string
	switch event.Action {
	case auditv1.ActionPaaSApplicationCreated:
		prefix = "installation-verification-app-"
	case auditv1.ActionPaaSConfigurationCreated:
		prefix = "installation-verification-config-"
	case auditv1.ActionPaaSConfigurationRevisionCreated:
		prefix = "installation-verification-config-rev-"
	case auditv1.ActionPaaSApplicationRevisionCreated:
		prefix = "installation-verification-app-rev-"
	case auditv1.ActionPaaSDeploymentCreated, auditv1.ActionPaaSDeploymentUpdated:
		prefix = "installation-verification-deploy-"
	default:
		return false
	}
	suffix, found := strings.CutPrefix(event.Target.ID, prefix)
	return source == auditv1.SourcePaaS && found && len(suffix) == 24 && strings.Trim(suffix, "0123456789abcdef") == ""
}

func (service *Authority) ResolveAuditProducer(
	ctx context.Context,
	credential iamv1.Secret,
	request iamv1.ResolveAuditProducerRequest,
) (iamv1.AuditProducerAuthorization, error) {
	if iamv1.ValidateResolveAuditProducerRequest(request) != nil {
		return iamv1.AuditProducerAuthorization{}, ErrInvalidArgument
	}
	var result iamv1.AuditProducerAuthorization
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		binding, err := service.authenticateService(transactionContext, transaction, credential)
		if err != nil {
			return err
		}
		if binding.Identity.Purpose != iamv1.ServiceIAM && binding.Identity.Purpose != iamv1.ServicePaaS && binding.Identity.Purpose != iamv1.ServiceAudit {
			return ErrForbidden
		}
		evidence, found, err := transaction.ReadAuditEvidence(transactionContext, binding.Identity, request.Event)
		if err != nil {
			return err
		}
		if !found {
			return ErrForbidden
		}
		digest, err := auditContentDigest(binding.Identity, request.Event, evidence)
		if err != nil {
			return ErrForbidden
		}
		result = iamv1.AuditProducerAuthorization{
			APIVersion: iamv1.APIVersion, Kind: "AuditProducerAuthorization",
			Producer: binding.Identity, TenantID: iamv1.AccountID(request.Event.TenantID),
			InstallationID: request.Event.InstallationID, ContentDigest: digest,
		}
		return nil
	})
	if err != nil {
		return iamv1.AuditProducerAuthorization{}, err
	}
	return result, nil
}
