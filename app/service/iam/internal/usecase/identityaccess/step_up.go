package identityaccess

import (
	"context"
	"errors"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

var (
	ErrStepUpNotFound                   = errors.New("operation proof was not found")
	ErrRecoveryCodeRegenerationNotFound = errors.New("recovery code regeneration was not found")
)

// This workflow owns an operation proof under an existing login Session. It
// neither authenticates a new identity nor upgrades the Session's MFA facts.
type StepUpStart struct {
	Session iamv1.Session
	ID      string
	Request iamv1.StartStepUpRequest
}

type StepUpVerification struct {
	Password     PasswordAttempt
	OTP          TOTPAttempt
	RequestID    string
	VerifiedStep int64
}

type RecoveryCodeRegenerationMutation struct {
	Session                     iamv1.Session
	Request                     iamv1.RegenerateRecoveryCodesRequest
	ID, BatchID, NotificationID string
	Codes                       []MFARecoveryCodeVerifier
	AuditEvent                  auditv1.Event
}

type RecoveryCodeRegenerationResult struct {
	Outcome      string
	Regeneration iamv1.RecoveryCodeRegeneration
}

func (service *Authority) StartStepUp(ctx context.Context, credential iamv1.Secret, request iamv1.StartStepUpRequest) (iamv1.StepUp, error) {
	if iamv1.ValidateStartStepUpRequest(request) != nil {
		return iamv1.StepUp{}, ErrInvalidArgument
	}
	id, err := service.config.NewID("step-up")
	if err != nil {
		return iamv1.StepUp{}, ErrUnavailable
	}
	var result iamv1.StepUp
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.totpSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		if err := service.checkTOTPCustody(ctx, tx); err != nil {
			return err
		}
		result, err = tx.StartStepUp(ctx, StepUpStart{Session: subject.Subject.Session, ID: id, Request: request})
		return err
	})
	if err != nil {
		return iamv1.StepUp{}, err
	}
	if iamv1.ValidateStepUp(result) != nil || result.RequestID != request.RequestID || result.Operation != request.Operation || result.ExpectedFactorRevision != request.ExpectedFactorRevision {
		return iamv1.StepUp{}, ErrUnavailable
	}
	if (result.SecuritySettings == nil) != (request.SecuritySettings == nil) ||
		(result.SecuritySettings != nil && *result.SecuritySettings != *request.SecuritySettings) {
		return iamv1.StepUp{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) StepUpByRequest(ctx context.Context, credential iamv1.Secret, requestID string) (iamv1.StepUp, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.StepUp{}, ErrInvalidArgument
	}
	var result iamv1.StepUp
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.totpSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		result, err = tx.ReadStepUpByRequest(ctx, subject.Subject.Session, requestID)
		return err
	})
	if err != nil {
		return iamv1.StepUp{}, err
	}
	if iamv1.ValidateStepUp(result) != nil || result.RequestID != requestID {
		return iamv1.StepUp{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) VerifyStepUp(ctx context.Context, credential iamv1.Secret, id string, request iamv1.VerifyStepUpRequest) (iamv1.StepUp, error) {
	if iamv1.ValidateID("stepUpId", id) != nil || iamv1.ValidateVerifyStepUpRequest(request) != nil {
		return iamv1.StepUp{}, ErrInvalidArgument
	}
	if err := service.acquirePasswordWork(ctx); err != nil {
		return iamv1.StepUp{}, err
	}
	defer service.releasePasswordWork()
	passwordID, err := service.config.NewID("password-attempt")
	if err != nil {
		return iamv1.StepUp{}, ErrUnavailable
	}
	otpID, err := service.config.NewID("totp-attempt")
	if err != nil {
		return iamv1.StepUp{}, ErrUnavailable
	}
	var password PasswordAttempt
	var admitted bool
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.totpSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		if err := service.checkTOTPCustody(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ReadStepUpForVerification(ctx, subject.Subject.Session, id); err != nil {
			return err
		}
		digest, err := digestSanitized("step-up-password", struct {
			SessionID           iamv1.SessionID
			StepUpID, RequestID string
		}{subject.Subject.Session.ID, id, request.RequestID})
		if err != nil {
			return err
		}
		password, admitted, err = tx.ReservePasswordAttempt(ctx, PasswordAttemptRequest{ID: passwordID, AccountID: subject.Subject.Organization.ID,
			UserID: subject.Subject.Principal.ID, SessionID: subject.Subject.Session.ID, Purpose: PasswordAttemptStepUp, IntentDigest: digest})
		return err
	})
	if err != nil {
		return iamv1.StepUp{}, err
	}
	if err := service.verifyReservedPassword(ctx, request.Password, password, admitted); err != nil {
		return iamv1.StepUp{}, err
	}
	var otp TOTPAttempt
	admitted = false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.totpSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		if subject.Subject.Organization.ID != password.AccountID || subject.Subject.Principal.ID != password.PrincipalID ||
			subject.Subject.Session.ID != password.SessionID || subject.CredentialGeneration != password.CredentialGeneration {
			return ErrUnauthenticated
		}
		otp, admitted, err = tx.ReserveTOTPAttempt(ctx, TOTPAttempt{AccountID: password.AccountID, UserID: password.PrincipalID,
			SessionID: password.SessionID, ReferenceID: id, Purpose: "STEP_UP", ID: otpID})
		if err != nil {
			return err
		}
		if !admitted {
			return tx.RejectPasswordAttempt(ctx, password)
		}
		return nil
	})
	if err != nil {
		return iamv1.StepUp{}, err
	}
	if !admitted {
		return iamv1.StepUp{}, ErrUnauthenticated
	}
	var result iamv1.StepUp
	rejected := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		rejected, result = false, iamv1.StepUp{}
		subject, err := service.totpSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		if subject.Subject.Organization.ID != password.AccountID || subject.Subject.Principal.ID != password.PrincipalID ||
			subject.Subject.Session.ID != password.SessionID || subject.CredentialGeneration != password.CredentialGeneration {
			return ErrUnauthenticated
		}
		step, forced, err := service.verifyReservedTOTP(ctx, tx, otp, request.Code)
		if errors.Is(err, authority.ErrTOTPRejected) {
			rejected = true
			if err := tx.RejectPasswordAttempt(ctx, password); err != nil {
				return err
			}
			return tx.RejectTOTPAttempt(ctx, otp)
		}
		if err != nil {
			return err
		}
		if forced {
			return ErrUnauthenticated
		}
		result, err = tx.ProveStepUp(ctx, StepUpVerification{Password: password, OTP: otp, RequestID: request.RequestID, VerifiedStep: step})
		return err
	})
	if err != nil {
		return iamv1.StepUp{}, err
	}
	if rejected {
		return iamv1.StepUp{}, ErrUnauthenticated
	}
	if iamv1.ValidateStepUp(result) != nil || result.ID != id || result.ProvedAt == nil || (result.State != "PROVED" && result.State != "EXPIRED") {
		return iamv1.StepUp{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) RegenerateRecoveryCodes(ctx context.Context, credential iamv1.Secret, request iamv1.RegenerateRecoveryCodesRequest) (iamv1.RegenerateRecoveryCodesResponse, error) {
	if iamv1.ValidateRegenerateRecoveryCodesRequest(request) != nil {
		return iamv1.RegenerateRecoveryCodesResponse{}, ErrInvalidArgument
	}
	var caller iamv1.Session
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.totpSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		caller = subject.Subject.Session
		return nil
	})
	if err != nil {
		return iamv1.RegenerateRecoveryCodesResponse{}, err
	}
	batch, codes, verifiers, err := service.newRecoveryBatch(caller.AccountID, caller.PrincipalID)
	if err != nil {
		return iamv1.RegenerateRecoveryCodesResponse{}, err
	}
	var id, eventID, noticeID string
	for prefix, destination := range map[string]*string{"recovery-code-regeneration": &id, "event": &eventID, "notification": &noticeID} {
		*destination, err = service.config.NewID(prefix)
		if err != nil {
			return iamv1.RegenerateRecoveryCodesResponse{}, ErrUnavailable
		}
	}
	digest, err := digestSanitized("recovery-codes-regenerate", request)
	if err != nil {
		return iamv1.RegenerateRecoveryCodesResponse{}, err
	}
	var result RecoveryCodeRegenerationResult
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		result = RecoveryCodeRegenerationResult{}
		subject, err := service.totpSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		if subject.Subject.Session.ID != caller.ID || subject.Subject.Organization.ID != caller.AccountID || subject.Subject.Principal.ID != caller.PrincipalID {
			return ErrUnauthenticated
		}
		if err := service.checkTOTPCustody(ctx, tx); err != nil {
			return err
		}
		if err := service.checkEmailVerificationCustody(ctx, tx); err != nil {
			return err
		}
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		event, err := newAuditEvent(eventID, caller.AccountID, "", auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(caller.PrincipalID)},
			auditv1.ActionIAMRecoveryCodesRegenerated, auditv1.TargetReference{Kind: auditv1.TargetPrincipal, ID: string(caller.PrincipalID)},
			auditv1.ResultSucceeded, "", digest, request.RequestID, request.RequestID, now)
		if err != nil {
			return err
		}
		result, err = tx.RegenerateRecoveryCodes(ctx, RecoveryCodeRegenerationMutation{Session: caller, Request: request,
			ID: id, BatchID: batch, NotificationID: noticeID, Codes: verifiers, AuditEvent: event})
		return err
	})
	if err != nil {
		return iamv1.RegenerateRecoveryCodesResponse{}, err
	}
	response := iamv1.RegenerateRecoveryCodesResponse{Outcome: result.Outcome, Regeneration: result.Regeneration}
	if result.Outcome == "APPLIED" {
		response.RecoveryCodes = codes
	}
	if iamv1.ValidateRegenerateRecoveryCodesResponse(response) != nil || result.Regeneration.RequestID != request.RequestID ||
		result.Regeneration.FactorRevision != request.ExpectedFactorRevision || (result.Outcome == "APPLIED" && result.Regeneration.ID != id) {
		return iamv1.RegenerateRecoveryCodesResponse{}, ErrUnavailable
	}
	return response, nil
}

func (service *Authority) RecoveryCodeRegenerationByRequest(ctx context.Context, credential iamv1.Secret, requestID string) (iamv1.RecoveryCodeRegeneration, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.RecoveryCodeRegeneration{}, ErrInvalidArgument
	}
	var result iamv1.RecoveryCodeRegeneration
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		subject, err := service.totpSession(ctx, tx, credential)
		if err != nil {
			return err
		}
		result, err = tx.ReadRecoveryCodeRegeneration(ctx, subject.Subject.Session, requestID)
		return err
	})
	if err != nil {
		return iamv1.RecoveryCodeRegeneration{}, err
	}
	if iamv1.ValidateRecoveryCodeRegeneration(result) != nil || result.RequestID != requestID {
		return iamv1.RecoveryCodeRegeneration{}, ErrUnavailable
	}
	return result, nil
}
