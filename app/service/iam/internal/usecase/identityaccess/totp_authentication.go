package identityaccess

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

// These private projections describe a locked ceremony, never a bearer
// identity or cacheable authority. Missing state is not NEVER_BOUND.
type LoginAuthenticationState struct {
	State    string `json:"state"`
	Revision uint64 `json:"revision"`
	FactorID string `json:"factorId,omitempty"`
}

type LoginChallengeCreation struct {
	Attempt                                                        PasswordAttempt
	ID, LookupDigest, VerificationDigest, RequestID, RequestDigest string
}

type AuthenticationChallengeCredential struct {
	AccountID          iamv1.AccountID   `json:"accountId"`
	UserID             iamv1.PrincipalID `json:"userId"`
	ID                 string            `json:"id"`
	Purpose            string            `json:"purpose"`
	NextStep           string            `json:"nextStep"`
	VerificationDigest string            `json:"verificationDigest"`
}

type TOTPAttempt struct {
	AccountID                iamv1.AccountID
	UserID                   iamv1.PrincipalID
	SessionID                iamv1.SessionID
	ReferenceID, Purpose, ID string
	Sequence                 uint64
}

type TOTPVerification struct {
	FactorID, InstallationID string
	Sealed                   authority.SealedTOTPSeed
	LastConsumedStep         int64
	FactorRevision           uint64
	DatabaseTime             time.Time
	MustChangePassword       bool
}

func (TOTPVerification) String() string               { return "[REDACTED]" }
func (TOTPVerification) GoString() string             { return "identityaccess.TOTPVerification{[REDACTED]}" }
func (TOTPVerification) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

type LoginChallengeCompletion struct {
	Attempt      TOTPAttempt
	VerifiedStep int64
	Session      SessionMutation
}

type PasswordChallengeCreation struct {
	Attempt                                                        TOTPAttempt
	VerifiedStep                                                   int64
	ID, LookupDigest, VerificationDigest, RequestID, RequestDigest string
}

type ChallengePasswordMaterial struct {
	PasswordHash         authority.PasswordHash
	CredentialGeneration uint64
}

func (ChallengePasswordMaterial) String() string { return "[REDACTED]" }
func (ChallengePasswordMaterial) GoString() string {
	return "identityaccess.ChallengePasswordMaterial{[REDACTED]}"
}
func (ChallengePasswordMaterial) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

type ChallengePasswordMutation struct {
	Identity    AuthenticationChallengeCredential
	Expected    ChallengePasswordMaterial
	Replacement authority.PasswordHash
	AuditEvent  auditv1.Event
}

func (ChallengePasswordMutation) String() string { return "[REDACTED]" }
func (ChallengePasswordMutation) GoString() string {
	return "identityaccess.ChallengePasswordMutation{[REDACTED]}"
}
func (ChallengePasswordMutation) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

func (service *Authority) createLoginChallenge(ctx context.Context, tx Transaction, attempt PasswordAttempt, requestID, requestDigest string) (iamv1.LoginResponse, error) {
	id, err := service.config.NewID("authentication-challenge")
	if err != nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	issued, err := service.credentials.Issue(authority.CredentialAuthenticationChallenge, id)
	if err != nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	challenge, err := tx.CreateLoginChallenge(ctx, LoginChallengeCreation{Attempt: attempt, ID: id,
		LookupDigest: issued.LookupDigest, VerificationDigest: issued.VerificationDigest, RequestID: requestID, RequestDigest: requestDigest})
	if err != nil {
		return iamv1.LoginResponse{}, err
	}
	if iamv1.ValidateAuthenticationChallenge(challenge) != nil || challenge.ID != id || challenge.Purpose != "LOGIN" ||
		(challenge.NextStep != "TOTP" && challenge.NextStep != "RECOVER") {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	return iamv1.LoginResponse{Outcome: iamv1.LoginChallengeRequired, Challenge: &challenge, ChallengeCredential: issued.Credential}, nil
}

func (service *Authority) authenticateChallenge(ctx context.Context, tx Transaction, id string, credential iamv1.Secret) (AuthenticationChallengeCredential, error) {
	if err := service.checkTOTPCustody(ctx, tx); err != nil {
		return AuthenticationChallengeCredential{}, err
	}
	digest, err := authority.LookupCredentialDigest(authority.CredentialAuthenticationChallenge, credential)
	if err != nil {
		return AuthenticationChallengeCredential{}, ErrUnauthenticated
	}
	stored, found, err := tx.LookupAuthenticationChallenge(ctx, digest)
	if err != nil {
		return AuthenticationChallengeCredential{}, err
	}
	if !found || stored.ID != id {
		return AuthenticationChallengeCredential{}, ErrUnauthenticated
	}
	if iamv1.ValidateID("accountId", string(stored.AccountID)) != nil || iamv1.ValidateID("userId", string(stored.UserID)) != nil ||
		(stored.Purpose != "LOGIN" && stored.Purpose != "RECOVERY" && stored.Purpose != "ENROLLMENT") {
		return AuthenticationChallengeCredential{}, ErrUnavailable
	}
	verified, err := authority.VerifyCredential(authority.CredentialAuthenticationChallenge, id, credential, stored.VerificationDigest)
	if err != nil {
		return AuthenticationChallengeCredential{}, ErrUnavailable
	}
	if !verified {
		return AuthenticationChallengeCredential{}, ErrUnauthenticated
	}
	return stored, nil
}

func (service *Authority) VerifyAuthenticationChallenge(ctx context.Context, id string, request iamv1.VerifyAuthenticationChallengeRequest) (iamv1.LoginResponse, error) {
	if iamv1.ValidateID("challengeId", id) != nil || iamv1.ValidateVerifyAuthenticationChallengeRequest(request) != nil {
		return iamv1.LoginResponse{}, ErrInvalidArgument
	}
	if service == nil || service.totpSeeds == nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	attemptID, err := service.config.NewID("totp-attempt")
	if err != nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	var attempt TOTPAttempt
	var admitted bool
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		stored, err := service.authenticateChallenge(ctx, tx, id, request.ChallengeCredential)
		if err != nil {
			return err
		}
		if stored.Purpose != "LOGIN" || stored.NextStep != "TOTP" {
			return ErrUnauthenticated
		}
		attempt, admitted, err = tx.ReserveTOTPAttempt(ctx, TOTPAttempt{AccountID: stored.AccountID, UserID: stored.UserID,
			ReferenceID: id, Purpose: "LOGIN", ID: attemptID})
		return err
	})
	if err != nil {
		return iamv1.LoginResponse{}, err
	}
	if !admitted {
		return iamv1.LoginResponse{}, ErrUnauthenticated
	}
	requestDigest, err := digestSanitized("login-challenge-verify", struct {
		ChallengeID string `json:"challengeId"`
		RequestID   string `json:"requestId"`
	}{id, request.RequestID})
	if err != nil {
		return iamv1.LoginResponse{}, err
	}
	passwordChallengeID, err := service.config.NewID("authentication-challenge")
	if err != nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	passwordChallengeCredential, err := service.credentials.Issue(authority.CredentialAuthenticationChallenge, passwordChallengeID)
	if err != nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	var response iamv1.LoginResponse
	rejected := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		rejected, response = false, iamv1.LoginResponse{}
		stored, err := service.authenticateChallenge(ctx, tx, id, request.ChallengeCredential)
		if err != nil {
			return err
		}
		if stored.AccountID != attempt.AccountID || stored.UserID != attempt.UserID || stored.Purpose != "LOGIN" || stored.NextStep != "TOTP" {
			return ErrUnavailable
		}
		step, mustChangePassword, err := service.verifyReservedTOTP(ctx, tx, attempt, request.Code)
		if errors.Is(err, authority.ErrTOTPRejected) {
			// Commit rejection and its already charged budget. Returning an auth
			// error from this callback would roll back the failure evidence.
			rejected = true
			return tx.RejectTOTPAttempt(ctx, attempt)
		}
		if err != nil {
			return err
		}
		if mustChangePassword {
			challenge, err := tx.BeginPasswordChallenge(ctx, PasswordChallengeCreation{Attempt: attempt, VerifiedStep: step,
				ID: passwordChallengeID, LookupDigest: passwordChallengeCredential.LookupDigest, VerificationDigest: passwordChallengeCredential.VerificationDigest,
				RequestID: request.RequestID, RequestDigest: requestDigest})
			if err != nil {
				return err
			}
			if challenge.ID != passwordChallengeID || challenge.Purpose != "LOGIN" || challenge.NextStep != "PASSWORD_CHANGE" || iamv1.ValidateAuthenticationChallenge(challenge) != nil {
				return ErrUnavailable
			}
			response = iamv1.LoginResponse{Outcome: iamv1.LoginChallengeRequired, Challenge: &challenge, ChallengeCredential: passwordChallengeCredential.Credential}
			return nil
		}
		mutation, credential, err := service.newSessionMutation(ctx, tx, attempt.AccountID, attempt.UserID, request.RequestID, requestDigest)
		if err != nil {
			return err
		}
		session, err := tx.CompleteLoginChallenge(ctx, LoginChallengeCompletion{Attempt: attempt, VerifiedStep: step, Session: mutation})
		if err != nil {
			return err
		}
		response = iamv1.LoginResponse{Outcome: iamv1.LoginAuthenticated, Session: session, Credential: credential}
		return nil
	})
	if err != nil {
		return iamv1.LoginResponse{}, err
	}
	if rejected {
		return iamv1.LoginResponse{}, ErrUnauthenticated
	}
	if iamv1.ValidateLoginResponse(response) != nil {
		return iamv1.LoginResponse{}, ErrUnavailable
	}
	return response, nil
}

func (service *Authority) verifyReservedTOTP(ctx context.Context, tx Transaction, attempt TOTPAttempt, code iamv1.Secret) (int64, bool, error) {
	factor, err := tx.ReadTOTPAttempt(ctx, attempt)
	if err != nil {
		return 0, false, err
	}
	defer clear(factor.Sealed.Nonce)
	defer clear(factor.Sealed.Ciphertext)
	if service.totpSeeds == nil || factor.InstallationID != service.totp.Scope.InstallationID {
		return 0, false, ErrUnavailable
	}
	seed, err := service.totpSeeds.Open(authority.TOTPSeedScope{Installation: service.totp.Scope,
		AccountID: attempt.AccountID, UserID: attempt.UserID, FactorID: factor.FactorID}, factor.Sealed)
	if err != nil {
		return 0, false, ErrUnavailable
	}
	step, err := authority.VerifyTOTP(seed, code, factor.DatabaseTime, factor.LastConsumedStep)
	if err != nil && !errors.Is(err, authority.ErrTOTPRejected) {
		return 0, false, ErrUnavailable
	}
	return step, factor.MustChangePassword, err
}

func (service *Authority) ChangeChallengePassword(ctx context.Context, id string, request iamv1.ChallengePasswordChangeRequest) (iamv1.ChallengePasswordChangeResponse, error) {
	if iamv1.ValidateID("challengeId", id) != nil || iamv1.ValidateChallengePasswordChangeRequest(request) != nil || authority.ValidatePassword(request.NewPassword) != nil {
		return iamv1.ChallengePasswordChangeResponse{}, ErrInvalidArgument
	}
	if err := service.acquirePasswordWork(ctx); err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, err
	}
	defer service.releasePasswordWork()
	var identity AuthenticationChallengeCredential
	var original ChallengePasswordMaterial
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		var err error
		identity, err = service.authenticateChallenge(ctx, tx, id, request.ChallengeCredential)
		if err != nil {
			return err
		}
		if identity.Purpose != "LOGIN" || identity.NextStep != "PASSWORD_CHANGE" {
			return ErrUnauthenticated
		}
		original, err = tx.ReadPasswordChallenge(ctx, identity)
		return err
	})
	if err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, err
	}
	// The caller has already proved both factors. This comparison rejects a
	// no-op password replacement, not another authentication attempt. Neither
	// expensive operation holds a database connection or a principal lock.
	same, err := service.passwords.Verify(request.NewPassword, original.PasswordHash)
	if err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, ErrUnavailable
	}
	if same {
		return iamv1.ChallengePasswordChangeResponse{}, ErrInvalidArgument
	}
	replacement, err := service.passwords.Hash(request.NewPassword)
	if err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, ErrUnavailable
	}
	digest, err := digestSanitized("challenge-password-change", struct {
		ChallengeID string `json:"challengeId"`
		RequestID   string `json:"requestId"`
	}{id, request.RequestID})
	if err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, ErrUnavailable
	}
	eventID, err := service.config.NewID("event")
	if err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, ErrUnavailable
	}
	var result iamv1.ChallengePasswordChangeResponse
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		current, err := service.authenticateChallenge(ctx, tx, id, request.ChallengeCredential)
		if err != nil {
			return err
		}
		if current != identity {
			return ErrUnauthenticated
		}
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		event, err := newAuditEvent(eventID, identity.AccountID, "", auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(identity.UserID)},
			auditv1.ActionIAMUserPasswordChanged, auditv1.TargetReference{Kind: auditv1.TargetUser, ID: string(identity.UserID)}, auditv1.ResultSucceeded,
			"", digest, request.RequestID, request.RequestID, now)
		if err != nil {
			return err
		}
		result, err = tx.ChangeChallengePassword(ctx, ChallengePasswordMutation{Identity: current, Expected: original, Replacement: replacement, AuditEvent: event})
		return err
	})
	if err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, err
	}
	if iamv1.ValidateChallengePasswordChangeResponse(result) != nil {
		return iamv1.ChallengePasswordChangeResponse{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) newSessionMutation(ctx context.Context, tx Transaction, account iamv1.AccountID, user iamv1.PrincipalID, requestID, requestDigest string) (SessionMutation, iamv1.Secret, error) {
	id, err := service.config.NewID("session")
	if err != nil {
		return SessionMutation{}, iamv1.Secret{}, ErrUnavailable
	}
	issued, err := service.credentials.Issue(authority.CredentialSession, id)
	if err != nil {
		return SessionMutation{}, iamv1.Secret{}, ErrUnavailable
	}
	now, err := transactionTime(ctx, tx)
	if err != nil {
		return SessionMutation{}, iamv1.Secret{}, err
	}
	session := iamv1.Session{APIVersion: iamv1.APIVersion, Kind: "Session", ID: iamv1.SessionID(id), AccountID: account,
		PrincipalID: user, Status: iamv1.SessionActive, IssuedAt: now, ExpiresAt: now.Add(service.config.SessionLifetime)}
	eventID, err := service.config.NewID("event")
	if err != nil {
		return SessionMutation{}, iamv1.Secret{}, ErrUnavailable
	}
	event, err := newAuditEvent(eventID, account, "", auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(user)},
		auditv1.ActionIAMSessionIssued, auditv1.TargetReference{Kind: auditv1.TargetSession, ID: id}, auditv1.ResultSucceeded,
		"", requestDigest, requestID, requestID, now)
	if err != nil {
		return SessionMutation{}, iamv1.Secret{}, err
	}
	return SessionMutation{Session: session, LookupDigest: issued.LookupDigest, VerificationDigest: issued.VerificationDigest, AuditEvent: event}, issued.Credential, nil
}
