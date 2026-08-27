package identityaccess

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

const dummyPasswordHash = authority.PasswordHash(
	"$matrix-iam-v1$argon2id$v=19$m=65536,t=3,p=1$" +
		"AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
)

type loginDigestInput struct {
	LoginName string `json:"loginName"`
	RequestID string `json:"requestId"`
}

func (service *Authority) Login(
	ctx context.Context,
	request iamv1.LoginRequest,
) (iamv1.LoginResponse, error) {
	if iamv1.ValidateLoginRequest(request) != nil {
		return iamv1.LoginResponse{}, ErrInvalidArgument
	}
	requestDigest, err := digestSanitized("login", loginDigestInput{
		LoginName: request.LoginName,
		RequestID: request.RequestID,
	})
	if err != nil {
		return iamv1.LoginResponse{}, err
	}
	var response iamv1.LoginResponse
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		account, found, err := transaction.LookupLogin(transactionContext, request.LoginName)
		if err != nil {
			return err
		}
		stored := dummyPasswordHash
		if found {
			stored = account.PasswordHash
		}
		verified, verifyErr := service.passwords.Verify(request.Password, stored)
		if verifyErr != nil {
			if found {
				return ErrUnavailable
			}
			return ErrUnauthenticated
		}
		if !found || !verified || account.OrganizationStatus != iamv1.OrganizationActive ||
			account.PrincipalStatus != iamv1.PrincipalActive {
			return ErrUnauthenticated
		}
		sessionID, err := service.config.NewID("session")
		if err != nil {
			return ErrUnavailable
		}
		issued, err := service.credentials.Issue(authority.CredentialSession, sessionID)
		if err != nil {
			return ErrUnavailable
		}
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		session := iamv1.Session{
			APIVersion:     iamv1.APIVersion,
			Kind:           "Session",
			ID:             iamv1.SessionID(sessionID),
			OrganizationID: account.OrganizationID,
			PrincipalID:    account.PrincipalID,
			Status:         iamv1.SessionActive,
			IssuedAt:       now,
			ExpiresAt:      now.Add(service.config.SessionLifetime),
		}
		eventID, err := service.config.NewID("event")
		if err != nil {
			return ErrUnavailable
		}
		event, err := newAuditEvent(
			eventID,
			account.OrganizationID,
			auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(account.PrincipalID)},
			auditv1.ActionIAMSessionIssued,
			auditv1.TargetReference{Kind: auditv1.TargetSession, ID: sessionID},
			auditv1.ResultSucceeded,
			"",
			requestDigest,
			request.RequestID,
			request.RequestID,
			now,
		)
		if err != nil {
			return err
		}
		storedSession, err := transaction.IssueSession(transactionContext, SessionMutation{
			Session:            session,
			LookupDigest:       issued.LookupDigest,
			VerificationDigest: issued.VerificationDigest,
			AuditEvent:         event,
		})
		if err != nil {
			return err
		}
		response = iamv1.LoginResponse{
			Session:            storedSession,
			Credential:         issued.Credential,
			MustChangePassword: account.MustChangePassword,
		}
		return nil
	})
	if err != nil {
		return iamv1.LoginResponse{}, err
	}
	if iamv1.ValidateLoginResponse(response) != nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	return response, nil
}

func (service *Authority) ServiceIdentity(
	ctx context.Context,
	credential iamv1.Secret,
) (iamv1.ServiceIdentity, error) {
	var identity iamv1.ServiceIdentity
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		binding, err := service.authenticateService(transactionContext, transaction, credential)
		if err != nil {
			return err
		}
		identity = binding.Identity
		return nil
	})
	if err != nil {
		return iamv1.ServiceIdentity{}, err
	}
	return identity, nil
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
		allowed, err := transaction.CanProduceAudit(transactionContext, binding.Identity, request.OrganizationID)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrForbidden
		}
		result = iamv1.AuditProducerAuthorization{
			APIVersion: iamv1.APIVersion, Kind: "AuditProducerAuthorization",
			Producer: binding.Identity, OrganizationID: request.OrganizationID,
		}
		return nil
	})
	if err != nil {
		return iamv1.AuditProducerAuthorization{}, err
	}
	return result, nil
}

func (service *Authority) authenticateService(
	ctx context.Context,
	transaction Transaction,
	credential iamv1.Secret,
) (ServiceCredential, error) {
	lookupDigest, err := authority.LookupCredentialDigest(authority.CredentialService, credential)
	if err != nil {
		return ServiceCredential{}, ErrUnauthenticated
	}
	binding, found, err := transaction.LookupService(ctx, lookupDigest)
	if err != nil {
		return ServiceCredential{}, err
	}
	if !found {
		return ServiceCredential{}, ErrUnauthenticated
	}
	verified, err := authority.VerifyCredential(
		authority.CredentialService,
		string(binding.Identity.PrincipalID),
		credential,
		binding.VerificationDigest,
	)
	if err != nil {
		return ServiceCredential{}, ErrUnavailable
	}
	if !verified {
		return ServiceCredential{}, ErrUnauthenticated
	}
	if iamv1.ValidateServiceIdentity(binding.Identity) != nil {
		return ServiceCredential{}, ErrUnavailable
	}
	return binding, nil
}

func (service *Authority) authenticateSession(
	ctx context.Context,
	transaction Transaction,
	credential iamv1.Secret,
	now time.Time,
) (SessionCredential, error) {
	lookupDigest, err := authority.LookupCredentialDigest(authority.CredentialSession, credential)
	if err != nil {
		return SessionCredential{}, ErrUnauthenticated
	}
	binding, found, err := transaction.LookupSession(ctx, lookupDigest)
	if err != nil {
		return SessionCredential{}, err
	}
	if !found {
		return SessionCredential{}, ErrUnauthenticated
	}
	if err := authority.AuthenticateSession(
		binding.Subject.Session,
		binding.VerificationDigest,
		credential,
		now,
	); err != nil {
		if errors.Is(err, authority.ErrUnauthenticated) {
			return SessionCredential{}, ErrUnauthenticated
		}
		return SessionCredential{}, ErrUnavailable
	}
	binding.Subject.InstallationID = ""
	for _, role := range binding.Subject.Roles {
		if role != iamv1.RolePlatformOperator {
			continue
		}
		status, err := transaction.BootstrapStatus(ctx)
		if err != nil || iamv1.ValidateBootstrapStatus(status) != nil ||
			status.State != iamv1.BootstrapReady || status.OrganizationID != binding.Subject.Organization.ID {
			return SessionCredential{}, ErrUnavailable
		}
		binding.Subject.InstallationID = status.InstallationID
		break
	}
	return binding, nil
}
