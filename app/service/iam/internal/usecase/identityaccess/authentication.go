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
	if err := service.acquirePasswordWork(ctx); err != nil {
		return iamv1.LoginResponse{}, err
	}
	defer service.releasePasswordWork()
	attemptID, err := service.config.NewID("password-attempt")
	if err != nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	var attempt PasswordAttempt
	var admitted bool
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		var err error
		attempt, admitted, err = tx.ReservePasswordAttempt(ctx, PasswordAttemptRequest{ID: attemptID, LoginName: request.LoginName})
		return err
	})
	if err != nil {
		return iamv1.LoginResponse{}, err
	}
	if err := service.verifyReservedPassword(ctx, request.Password, attempt, admitted); err != nil {
		return iamv1.LoginResponse{}, err
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
			APIVersion:  iamv1.APIVersion,
			Kind:        "Session",
			ID:          iamv1.SessionID(sessionID),
			AccountID:   attempt.AccountID,
			PrincipalID: attempt.PrincipalID,
			Status:      iamv1.SessionActive,
			IssuedAt:    now,
			ExpiresAt:   now.Add(service.config.SessionLifetime),
		}
		eventID, err := service.config.NewID("event")
		if err != nil {
			return ErrUnavailable
		}
		event, err := newAuditEvent(
			eventID,
			attempt.AccountID,
			"",
			auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(attempt.PrincipalID)},
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
			AttemptID:          attempt.ID,
			AttemptSequence:    attempt.Sequence,
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
			MustChangePassword: attempt.MustChangePassword,
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

// This is a per-process memory/CPU bound, not a cluster-wide attempt counter.
// No queue is allocated, and business authorization uses no password slot.
func (service *Authority) acquirePasswordWork(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if service == nil || service.passwordWork == nil {
		return ErrUnavailable
	}
	select {
	case service.passwordWork <- struct{}{}:
		return nil
	default:
		return ErrOverloaded
	}
}

func (service *Authority) releasePasswordWork() { <-service.passwordWork }

func (service *Authority) verifyReservedPassword(ctx context.Context, password iamv1.Secret, attempt PasswordAttempt, admitted bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stored := dummyPasswordHash
	if admitted {
		stored = attempt.PasswordHash
	}
	// Reservation has committed and released every connection/lock before the
	// expensive verifier runs. Unknown, suppressed and inactive users use dummy.
	verified, err := service.passwords.Verify(password, stored)
	if err != nil {
		return ErrUnavailable
	}
	if !admitted {
		return ErrUnauthenticated
	}
	if verified {
		return nil
	}
	// Authentication rejection is an outcome AFTER a successful commit; using
	// ErrUnauthenticated as the callback error would roll back the failure.
	if err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.RejectPasswordAttempt(ctx, attempt)
	}); err != nil {
		return err
	}
	return ErrUnauthenticated
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
	if err := service.resolveSubjectInstallation(ctx, transaction, &binding.Subject); err != nil {
		return SessionCredential{}, err
	}
	return binding, nil
}

func (service *Authority) resolveSubjectInstallation(ctx context.Context, transaction Transaction, subject *authority.SubjectContext) error {
	subject.InstallationID = ""
	for _, policy := range subject.Policies {
		if policy.Attachment.Scope == iamv1.AuthorityScopeTenant {
			continue
		}
		status, err := transaction.BootstrapStatus(ctx)
		if err != nil || iamv1.ValidateBootstrapStatus(status) != nil ||
			status.State != iamv1.BootstrapReady || status.AccountID != subject.Organization.ID {
			return ErrUnavailable
		}
		subject.InstallationID = status.InstallationID
		break
	}
	return nil
}
