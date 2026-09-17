package identityaccess

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

type authorizationActor struct {
	organizationID    iamv1.AccountID
	subject           iamv1.Subject
	accessKeyEvidence *AccessKeyAuthorizationEvidence
}

func (service *Authority) AuthorizeAccessKey(ctx context.Context, serviceCredential iamv1.Secret, request iamv1.AccessKeyAuthorizationRequest) (iamv1.AccessKeyAuthorization, error) {
	if iamv1.ValidateAccessKeyAuthorizationRequest(request) != nil {
		return iamv1.AccessKeyAuthorization{}, ErrInvalidArgument
	}
	lookupDigest, err := authority.LookupCredentialDigest(authority.CredentialService, serviceCredential)
	if err != nil {
		return iamv1.AccessKeyAuthorization{}, ErrUnauthenticated
	}
	requestDigest, err := digestSanitized("authorization", request.Authorization)
	if err != nil {
		return iamv1.AccessKeyAuthorization{}, err
	}
	var result iamv1.AccessKeyAuthorization
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		caller, err := service.authenticateService(ctx, tx, serviceCredential)
		if err != nil {
			return err
		}
		parameters := request.SignedRequest.Parameters
		definition, found := iamv1.LookupActionDefinition(request.Authorization.Action)
		if !found || definition.CallingService != caller.Identity.Purpose || definition.Product != parameters.Audience ||
			caller.Identity.InstallationID != parameters.InstallationID {
			return ErrUnauthenticated
		}
		if err := tx.CheckCurrentAuthorizationProfiles(ctx); err != nil {
			return err
		}
		if err := service.checkAccessKeyCustody(ctx, tx); err != nil {
			return err
		}
		credential, found, err := tx.LookupAccessKey(ctx, lookupDigest, parameters.AccessKeyID, parameters.InstallationID, parameters.Audience)
		if err != nil {
			return err
		}
		if !found {
			return ErrUnauthenticated
		}
		defer clear(credential.Material.Nonce)
		defer clear(credential.Material.Ciphertext)
		wrapping := service.accessKeys
		if credential.Subject.InstallationID != wrapping.scope.InstallationID || credential.Material.WrappingKeyID != wrapping.id ||
			subtle.ConstantTimeCompare([]byte(credential.MaterialCommitment), []byte(wrapping.commitment)) != 1 {
			return ErrUnavailable
		}
		secret, err := authority.OpenAccessKeySecret(authority.AccessKeySecretScope{InstallationID: credential.Subject.InstallationID,
			AccountID: credential.Subject.Organization.ID, UserID: credential.Subject.Principal.ID, AccessKeyID: string(credential.Subject.Key.ID)},
			wrapping.id, wrapping.material, credential.Material)
		if err != nil {
			return ErrUnavailable
		}
		verified, err := authority.VerifyAccessKeyRequestSignature(secret, request.SignedRequest)
		if err != nil || !verified {
			return ErrUnauthenticated
		}
		signedDigest, err := iamv1.AccessKeySignedRequestDigest(request.SignedRequest)
		if err != nil {
			return ErrUnavailable
		}
		nonceDigest, err := iamv1.AccessKeyNonceDigest(parameters)
		if err != nil {
			return ErrUnavailable
		}
		evidence := &AccessKeyAuthorizationEvidence{AccessKeyID: credential.Subject.Key.ID, ResourceVersion: credential.Subject.Key.ResourceVersion,
			FormatVersion: credential.Material.FormatVersion, WrappingKeyID: credential.Material.WrappingKeyID, MaterialCommitment: credential.MaterialCommitment,
			InstallationID: credential.Subject.InstallationID, ServiceLookupDigest: lookupDigest, Audience: parameters.Audience,
			SignedRequestDigest: signedDigest, NonceDigest: nonceDigest, SignedAt: parameters.SignedAt}
		decision, err := service.decideAndRecord(ctx, tx, request.Authorization, requestDigest, now,
			authorizationActor{organizationID: credential.Subject.Organization.ID,
				subject: iamv1.Subject{Type: iamv1.SubjectUser, ID: string(credential.Subject.Principal.ID), AccessKeyID: credential.Subject.Key.ID}, accessKeyEvidence: evidence},
			func(id iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
				return authority.DecideAccessKey(credential.Subject, caller.Identity.Purpose, request.Authorization, id, now, parameters.SignedAt)
			})
		if err != nil {
			return err
		}
		result = iamv1.AccessKeyAuthorization{APIVersion: iamv1.APIVersion, Kind: "AccessKeyAuthorization", Decision: decision, SignedRequestDigest: signedDigest}
		// Deny commits exactly like Allow. Returning an authentication error here
		// would roll back its nonce and permit the old packet after a later grant.
		return nil
	})
	if err != nil {
		return iamv1.AccessKeyAuthorization{}, err
	}
	if iamv1.CheckAccessKeyAuthorizationForRequest(result, request) != nil {
		return iamv1.AccessKeyAuthorization{}, ErrUnavailable
	}
	return result, nil
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
			if errors.Is(err, ErrUnauthenticated) {
				role, roleErr := service.authenticateRoleSession(transactionContext, transaction, subjectCredential, now)
				if roleErr != nil {
					return roleErr
				}
				decision, roleErr = service.decideAndRecord(transactionContext, transaction, request, requestDigest, now,
					authorizationActor{organizationID: role.Subject.Session.AccountID, subject: iamv1.Subject{Type: iamv1.SubjectRole, ID: string(role.Subject.Role.ID),
						RoleSession: &iamv1.RoleSessionReference{SessionID: role.Subject.Session.ID, SourceUserID: role.Subject.Session.SourceUserID}}},
					func(id iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
						return authority.DecideRole(role.Subject, caller.Identity.Purpose, request, id, now)
					})
				return roleErr
			}
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
				subject:        iamv1.Subject{Type: iamv1.SubjectType(subject.Subject.Principal.Type), ID: string(subject.Subject.Principal.ID)},
			},
			func(decisionID iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
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
		policies, err := transaction.LookupServicePolicies(
			transactionContext,
			caller.Identity.AccountID,
			caller.Identity.PrincipalID,
		)
		if err != nil {
			return err
		}
		status, err := transaction.BootstrapStatus(transactionContext)
		if err != nil || iamv1.ValidateBootstrapStatus(status) != nil ||
			status.State != iamv1.BootstrapReady ||
			status.AccountID != caller.Identity.AccountID {
			return ErrUnavailable
		}
		if status.InstallationID != request.Resource.ID {
			policies = nil
		}
		decision, err = service.decideAndRecord(
			transactionContext,
			transaction,
			request,
			requestDigest,
			now,
			authorizationActor{
				organizationID: caller.Identity.AccountID,
				subject:        iamv1.Subject{Type: iamv1.SubjectServiceAccount, ID: string(caller.Identity.PrincipalID)},
			},
			func(decisionID iamv1.DecisionID) (authority.AuthorizationEvaluation, error) {
				return authority.DecideService(caller.Identity, policies, request, decisionID, now)
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
	decide func(iamv1.DecisionID) (authority.AuthorizationEvaluation, error),
) (iamv1.AuthorizationDecision, error) {
	if err := transaction.CheckCurrentAuthorizationProfiles(ctx); err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
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
	auditActor, err := auditActorForSubject(actor.subject)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	event, err := newAuditEvent(
		eventID,
		actor.organizationID,
		"",
		auditActor,
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
		AccountID:         actor.organizationID,
		Subject:           actor.subject,
		Request:           request,
		Decision:          decision.AuthorizationDecision,
		PolicyEvidence:    decision.PolicyEvidence,
		BoundaryEvidence:  decision.BoundaryEvidence,
		RoleEvidence:      decision.RoleEvidence,
		AccessKeyEvidence: actor.accessKeyEvidence,
		AuditEvent:        event,
	}); err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	return decision.AuthorizationDecision, nil
}

func auditActorForSubject(subject iamv1.Subject) (auditv1.ActorReference, error) {
	if iamv1.ValidateSubject(subject) != nil {
		return auditv1.ActorReference{}, ErrUnavailable
	}
	actor := auditv1.ActorReference{Type: auditv1.ActorType(subject.Type), ID: auditv1.ActorID(subject.ID), AccessKeyID: string(subject.AccessKeyID)}
	if subject.RoleSession != nil {
		actor.RoleSession = &auditv1.RoleSessionReference{SessionID: string(subject.RoleSession.SessionID), SourceUserID: auditv1.ActorID(subject.RoleSession.SourceUserID)}
	}
	if auditv1.ValidateActor(actor) != nil {
		return auditv1.ActorReference{}, ErrUnavailable
	}
	return actor, nil
}
