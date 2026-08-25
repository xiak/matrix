package identityaccess

import (
	"context"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

type authorizationActor struct {
	organizationID iamv1.OrganizationID
	principalID    iamv1.PrincipalID
	principalType  iamv1.PrincipalType
}

func (service *Authority) Authorize(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	subjectCredential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if iamv1.ValidateAuthorizationRequest(request) != nil {
		return iamv1.AuthorizationDecision{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("authorization", request)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	var decision iamv1.AuthorizationDecision
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(
			transactionContext,
			transaction,
			serviceCredential,
		)
		if err != nil {
			return err
		}
		subject, err := service.authenticateSession(
			transactionContext,
			transaction,
			subjectCredential,
			now,
		)
		if err != nil {
			return err
		}
		decision, err = service.decideAndRecord(
			transactionContext,
			transaction,
			request,
			requestDigest,
			now,
			authorizationActor{
				organizationID: subject.Subject.Organization.ID,
				principalID:    subject.Subject.Principal.ID,
				principalType:  subject.Subject.Principal.Type,
			},
			func(decisionID iamv1.DecisionID) (iamv1.AuthorizationDecision, error) {
				return authority.Decide(
					subject.Subject, caller.Identity.Purpose, request, decisionID, now,
				)
			},
		)
		return err
	})
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if iamv1.ValidateAuthorizationDecision(decision) != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	return decision, nil
}

// VerifyInstallation authenticates the verifier service as both caller and
// subject. It cannot be used for a generic IAM, PaaS, or Audit action.
func (service *Authority) VerifyInstallation(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	if iamv1.ValidateAuthorizationRequest(request) != nil ||
		request.Action != iamv1.ActionInstallationVerify {
		return iamv1.AuthorizationDecision{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("installation-verification", request)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	var decision iamv1.AuthorizationDecision
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(
			transactionContext, transaction, serviceCredential,
		)
		if err != nil {
			return err
		}
		roles, err := transaction.LookupServiceRoles(
			transactionContext,
			caller.Identity.OrganizationID,
			caller.Identity.PrincipalID,
		)
		if err != nil {
			return err
		}
		status, err := transaction.BootstrapStatus(transactionContext)
		if err != nil || iamv1.ValidateBootstrapStatus(status) != nil ||
			status.State != iamv1.BootstrapReady ||
			status.OrganizationID != caller.Identity.OrganizationID {
			return ErrUnavailable
		}
		if status.InstallationID != request.Resource.ID {
			roles = nil
		}
		decision, err = service.decideAndRecord(
			transactionContext,
			transaction,
			request,
			requestDigest,
			now,
			authorizationActor{
				organizationID: caller.Identity.OrganizationID,
				principalID:    caller.Identity.PrincipalID,
				principalType:  iamv1.PrincipalServiceAccount,
			},
			func(decisionID iamv1.DecisionID) (iamv1.AuthorizationDecision, error) {
				return authority.DecideService(caller.Identity, roles, request, decisionID, now)
			},
		)
		return err
	})
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if iamv1.ValidateAuthorizationDecision(decision) != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	return decision, nil
}

func (service *Authority) decideAndRecord(
	ctx context.Context,
	transaction Transaction,
	request iamv1.AuthorizationRequest,
	requestDigest string,
	now time.Time,
	actor authorizationActor,
	decide func(iamv1.DecisionID) (iamv1.AuthorizationDecision, error),
) (iamv1.AuthorizationDecision, error) {
	decisionID, err := service.config.NewID("decision")
	if err != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	decision, err := decide(iamv1.DecisionID(decisionID))
	if err != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	eventID, err := service.config.NewID("event")
	if err != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	result := auditv1.ResultDenied
	if decision.Allowed {
		result = auditv1.ResultAllowed
	}
	event, err := newAuditEvent(
		eventID,
		actor.organizationID,
		auditv1.ActorReference{
			Type: auditv1.ActorType(actor.principalType),
			ID:   auditv1.ActorID(actor.principalID),
		},
		auditv1.ActionIAMAuthorizationDecided,
		auditv1.TargetReference{
			Kind: auditv1.TargetAuthorizationDecision,
			ID:   decisionID,
		},
		result,
		decision.ID,
		requestDigest,
		request.RequestID,
		request.CorrelationID,
		now,
	)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if err := transaction.RecordAuthorization(ctx, AuthorizationMutation{
		OrganizationID: actor.organizationID,
		PrincipalID:    actor.principalID,
		Decision:       decision,
		AuditEvent:     event,
	}); err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	return decision, nil
}
