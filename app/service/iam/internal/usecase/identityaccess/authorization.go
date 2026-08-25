package identityaccess

import (
	"context"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

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
		decisionID, err := service.config.NewID("decision")
		if err != nil {
			return ErrUnavailable
		}
		decision, err = authority.Decide(
			subject.Subject,
			caller.Identity.Purpose,
			request,
			iamv1.DecisionID(decisionID),
			now,
		)
		if err != nil {
			return ErrUnavailable
		}
		eventID, err := service.config.NewID("event")
		if err != nil {
			return ErrUnavailable
		}
		result := auditv1.ResultDenied
		if decision.Allowed {
			result = auditv1.ResultAllowed
		}
		event, err := newAuditEvent(
			eventID,
			subject.Subject.Organization.ID,
			auditv1.ActorReference{
				Type: auditv1.ActorType(subject.Subject.Principal.Type),
				ID:   auditv1.ActorID(subject.Subject.Principal.ID),
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
			return err
		}
		return transaction.RecordAuthorization(transactionContext, AuthorizationMutation{
			OrganizationID: subject.Subject.Organization.ID,
			PrincipalID:    subject.Subject.Principal.ID,
			Decision:       decision,
			AuditEvent:     event,
		})
	})
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if iamv1.ValidateAuthorizationDecision(decision) != nil {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	return decision, nil
}
