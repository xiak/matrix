package identityaccess

import (
	"context"
	"errors"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

var ErrAuthenticatorRecoveryNotFound = errors.New("authenticator recovery was not found")

// Recovery is an irreversible two-stage ceremony, not a low-privilege Session.
// Verifiers are read only after the durable USER attempt budget is charged.
type RecoveryCodeVerification struct {
	InstallationID string                  `json:"installationId"`
	BatchID        string                  `json:"batchId"`
	Codes          []RecoveryCodeCandidate `json:"codes"`
}

type RecoveryCodeCandidate struct {
	ID                 string `json:"id"`
	VerificationDigest string `json:"verificationDigest"`
	Consumed           bool   `json:"consumed"`
}

func (RecoveryCodeVerification) String() string { return "[REDACTED]" }
func (RecoveryCodeVerification) GoString() string {
	return "identityaccess.RecoveryCodeVerification{[REDACTED]}"
}
func (RecoveryCodeVerification) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

type AuthenticatorRecoveryStart struct {
	Attempt                                                                     TOTPAttempt
	Code                                                                        MFARecoveryCodeVerifier
	ID, FactorID, ChallengeID, LookupDigest, VerificationDigest, NotificationID string
	Sealed                                                                      authority.SealedTOTPSeed
	AuditEvent                                                                  auditv1.Event
}

type AuthenticatorRecoveryStartResult struct {
	Recovery  iamv1.AuthenticatorRecovery   `json:"recovery"`
	Challenge iamv1.AuthenticationChallenge `json:"challenge"`
}

func (service *Authority) newRecoveryBatch(account iamv1.AccountID, user iamv1.PrincipalID) (string, []iamv1.Secret, []MFARecoveryCodeVerifier, error) {
	batch, err := service.config.NewID("recovery-batch")
	if err != nil {
		return "", nil, nil, ErrUnavailable
	}
	codes, verifiers := make([]iamv1.Secret, 10), make([]MFARecoveryCodeVerifier, 10)
	for i := range codes {
		id, err := service.config.NewID("recovery-code")
		if err != nil {
			return "", nil, nil, ErrUnavailable
		}
		code, err := service.credentials.IssueMFARecoveryCode()
		if err != nil {
			return "", nil, nil, ErrUnavailable
		}
		digest, err := authority.DigestMFARecoveryCode(authority.MFARecoveryCodeScope{InstallationID: service.totp.Scope.InstallationID,
			AccountID: account, UserID: user, BatchID: batch, CodeID: id}, code)
		if err != nil {
			return "", nil, nil, ErrUnavailable
		}
		codes[i], verifiers[i] = code, MFARecoveryCodeVerifier{ID: id, VerificationDigest: digest}
	}
	return batch, codes, verifiers, nil
}

func (service *Authority) reserveRecoveryAttempt(ctx context.Context, id string, credential iamv1.Secret, purpose string) (TOTPAttempt, error) {
	if service == nil || service.totpSeeds == nil {
		return TOTPAttempt{}, ErrUnavailable
	}
	attemptID, err := service.config.NewID("totp-attempt")
	if err != nil {
		return TOTPAttempt{}, ErrUnavailable
	}
	var attempt TOTPAttempt
	admitted := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		identity, err := service.authenticateChallenge(ctx, tx, id, credential)
		if err != nil {
			return err
		}
		if !recoveryStep(identity, purpose) {
			return ErrUnauthenticated
		}
		if err := service.checkEmailVerificationCustody(ctx, tx); err != nil {
			return err
		}
		attempt, admitted, err = tx.ReserveTOTPAttempt(ctx, TOTPAttempt{AccountID: identity.AccountID, UserID: identity.UserID, ReferenceID: id, Purpose: purpose, ID: attemptID})
		return err
	})
	if err != nil {
		return TOTPAttempt{}, err
	}
	if !admitted {
		return TOTPAttempt{}, ErrUnauthenticated
	}
	return attempt, nil
}

func recoveryStep(identity AuthenticationChallengeCredential, purpose string) bool {
	return purpose == "RECOVERY_CODE" && identity.Purpose == "LOGIN" && (identity.NextStep == "TOTP" || identity.NextStep == "RECOVER") ||
		purpose == "RECOVERY_CONFIRM" && identity.Purpose == "RECOVERY" && identity.NextStep == "ENROLLMENT"
}

func (service *Authority) checkRecoveryAttempt(ctx context.Context, tx Transaction, attempt TOTPAttempt, credential iamv1.Secret) error {
	identity, err := service.authenticateChallenge(ctx, tx, attempt.ReferenceID, credential)
	if err != nil {
		return err
	}
	if identity.AccountID != attempt.AccountID || identity.UserID != attempt.UserID || !recoveryStep(identity, attempt.Purpose) {
		return ErrUnauthenticated
	}
	return service.checkEmailVerificationCustody(ctx, tx)
}

func (service *Authority) StartAuthenticatorRecovery(ctx context.Context, id string, request iamv1.StartAuthenticatorRecoveryRequest) (iamv1.StartAuthenticatorRecoveryResponse, error) {
	if iamv1.ValidateID("challengeId", id) != nil || iamv1.ValidateStartAuthenticatorRecoveryRequest(request) != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, ErrInvalidArgument
	}
	attempt, err := service.reserveRecoveryAttempt(ctx, id, request.ChallengeCredential, "RECOVERY_CODE")
	if err != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, err
	}
	mutation := AuthenticatorRecoveryStart{Attempt: attempt}
	for _, target := range []struct {
		kind  string
		value *string
	}{{"authenticator-recovery", &mutation.ID}, {"totp-factor", &mutation.FactorID},
		{"authentication-challenge", &mutation.ChallengeID}, {"notification", &mutation.NotificationID}} {
		*target.value, err = service.config.NewID(target.kind)
		if err != nil {
			return iamv1.StartAuthenticatorRecoveryResponse{}, ErrUnavailable
		}
	}
	issued, err := service.credentials.Issue(authority.CredentialAuthenticationChallenge, mutation.ChallengeID)
	if err != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	mutation.LookupDigest, mutation.VerificationDigest = issued.LookupDigest, issued.VerificationDigest
	seed, err := service.credentials.IssueTOTPSeed()
	if err != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	mutation.Sealed, err = service.totpSeeds.Seal(authority.TOTPSeedScope{Installation: service.totp.Scope, AccountID: attempt.AccountID, UserID: attempt.UserID, FactorID: mutation.FactorID}, seed)
	if err != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	defer clear(mutation.Sealed.Nonce)
	defer clear(mutation.Sealed.Ciphertext)
	uri, err := totpProvisioningURI(attempt.AccountID, attempt.UserID, seed)
	if err != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	eventID, err := service.config.NewID("event")
	if err != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	digest, err := digestSanitized("authenticator-recovery-start", struct{ ChallengeID, RequestID string }{id, request.RequestID})
	if err != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, err
	}
	var result AuthenticatorRecoveryStartResult
	rejected := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		rejected, result = false, AuthenticatorRecoveryStartResult{}
		if err := service.checkRecoveryAttempt(ctx, tx, attempt, request.ChallengeCredential); err != nil {
			return err
		}
		material, err := tx.ReadRecoveryAttempt(ctx, attempt)
		if err != nil {
			return err
		}
		if material.InstallationID != service.totp.Scope.InstallationID {
			return ErrUnavailable
		}
		code, matched, err := matchRecoveryCode(attempt, material, request.RecoveryCode)
		if err != nil {
			return err
		}
		if !matched {
			rejected = true
			return tx.RejectTOTPAttempt(ctx, attempt)
		}
		mutation.Code = code
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		mutation.AuditEvent, err = newAuditEvent(eventID, attempt.AccountID, "", auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(attempt.UserID)},
			auditv1.ActionIAMAuthenticatorRecoveryStarted, auditv1.TargetReference{Kind: auditv1.TargetPrincipal, ID: string(attempt.UserID)}, auditv1.ResultSucceeded, "", digest, request.RequestID, request.RequestID, now)
		if err != nil {
			return err
		}
		result, err = tx.StartAuthenticatorRecovery(ctx, mutation)
		return err
	})
	if err != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, err
	}
	if rejected {
		return iamv1.StartAuthenticatorRecoveryResponse{}, ErrUnauthenticated
	}
	response := iamv1.StartAuthenticatorRecoveryResponse{Recovery: result.Recovery, Challenge: result.Challenge, ChallengeCredential: issued.Credential, Provisioning: iamv1.TOTPProvisioning{Seed: seed, URI: uri}}
	if result.Recovery.ID != mutation.ID || result.Recovery.RequestID != request.RequestID || result.Challenge.ID != mutation.ChallengeID || iamv1.ValidateStartAuthenticatorRecoveryResponse(response) != nil {
		return iamv1.StartAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	return response, nil
}

func matchRecoveryCode(attempt TOTPAttempt, material RecoveryCodeVerification, candidate iamv1.Secret) (MFARecoveryCodeVerifier, bool, error) {
	if len(material.Codes) != 10 || iamv1.ValidateID("batchId", material.BatchID) != nil || iamv1.ValidateID("installationId", material.InstallationID) != nil {
		return MFARecoveryCodeVerifier{}, false, ErrUnavailable
	}
	var matched MFARecoveryCodeVerifier
	count := 0
	seen := make(map[string]bool, 10)
	for _, code := range material.Codes {
		if seen[code.ID] || iamv1.ValidateID("codeId", code.ID) != nil || iamv1.ValidateDigest("verifier", code.VerificationDigest) != nil {
			return MFARecoveryCodeVerifier{}, false, ErrUnavailable
		}
		seen[code.ID] = true
		ok, err := authority.VerifyMFARecoveryCode(authority.MFARecoveryCodeScope{InstallationID: material.InstallationID,
			AccountID: attempt.AccountID, UserID: attempt.UserID, BatchID: material.BatchID, CodeID: code.ID}, candidate, code.VerificationDigest)
		// Malformed nonempty candidates still spend the already committed
		// budget. Compare the whole fixed batch, including consumed entries.
		if err == nil && ok && !code.Consumed {
			count++
			matched = MFARecoveryCodeVerifier{ID: code.ID, VerificationDigest: code.VerificationDigest}
		}
	}
	if count > 1 {
		return MFARecoveryCodeVerifier{}, false, ErrUnavailable
	}
	return matched, count == 1, nil
}

func (service *Authority) ConfirmAuthenticatorRecovery(ctx context.Context, id string, request iamv1.VerifyAuthenticationChallengeRequest) (iamv1.ConfirmAuthenticatorRecoveryResponse, error) {
	if iamv1.ValidateID("challengeId", id) != nil || iamv1.ValidateVerifyAuthenticationChallengeRequest(request) != nil {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, ErrInvalidArgument
	}
	attempt, err := service.reserveRecoveryAttempt(ctx, id, request.ChallengeCredential, "RECOVERY_CONFIRM")
	if err != nil {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, err
	}
	batch, codes, verifiers, err := service.newRecoveryBatch(attempt.AccountID, attempt.UserID)
	if err != nil {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, err
	}
	eventID, err := service.config.NewID("event")
	if err != nil {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	noticeID, err := service.config.NewID("notification")
	if err != nil {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	digest, err := digestSanitized("authenticator-recovery-confirm", struct{ ChallengeID, RequestID string }{id, request.RequestID})
	if err != nil {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, err
	}
	var result iamv1.AuthenticatorRecovery
	rejected := false
	err = service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		rejected, result = false, iamv1.AuthenticatorRecovery{}
		if err := service.checkRecoveryAttempt(ctx, tx, attempt, request.ChallengeCredential); err != nil {
			return err
		}
		step, _, err := service.verifyReservedTOTP(ctx, tx, attempt, request.Code)
		if errors.Is(err, authority.ErrTOTPRejected) {
			rejected = true
			return tx.RejectTOTPAttempt(ctx, attempt)
		}
		if err != nil {
			return err
		}
		now, err := transactionTime(ctx, tx)
		if err != nil {
			return err
		}
		event, err := newAuditEvent(eventID, attempt.AccountID, "", auditv1.ActorReference{Type: auditv1.ActorUser, ID: auditv1.ActorID(attempt.UserID)},
			auditv1.ActionIAMAuthenticatorRecovered, auditv1.TargetReference{Kind: auditv1.TargetPrincipal, ID: string(attempt.UserID)}, auditv1.ResultSucceeded, "", digest, request.RequestID, request.RequestID, now)
		if err != nil {
			return err
		}
		result, err = tx.ConfirmAuthenticatorRecovery(ctx, TOTPBindingConfirmation{Attempt: attempt, VerifiedStep: step, BatchID: batch, Codes: verifiers, NotificationID: noticeID, AuditEvent: event})
		return err
	})
	if err != nil {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, err
	}
	if rejected {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, ErrUnauthenticated
	}
	response := iamv1.ConfirmAuthenticatorRecoveryResponse{Recovery: result, NextStep: "REAUTHENTICATE", RecoveryCodes: codes}
	if iamv1.ValidateConfirmAuthenticatorRecoveryResponse(response) != nil {
		return iamv1.ConfirmAuthenticatorRecoveryResponse{}, ErrUnavailable
	}
	return response, nil
}

func (service *Authority) InspectAuthenticatorRecovery(ctx context.Context, id string, request iamv1.InspectAuthenticatorRecoveryRequest) (iamv1.AuthenticatorRecovery, error) {
	if iamv1.ValidateID("challengeId", id) != nil || iamv1.ValidateInspectAuthenticatorRecoveryRequest(request) != nil {
		return iamv1.AuthenticatorRecovery{}, ErrInvalidArgument
	}
	var result iamv1.AuthenticatorRecovery
	err := service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		identity, err := service.authenticateChallenge(ctx, tx, id, request.ChallengeCredential)
		if err != nil {
			return err
		}
		if !recoveryStep(identity, "RECOVERY_CODE") {
			return ErrUnauthenticated
		}
		result, err = tx.InspectAuthenticatorRecovery(ctx, identity, request.RequestID)
		return err
	})
	if err != nil {
		return iamv1.AuthenticatorRecovery{}, err
	}
	if result.RequestID != request.RequestID || iamv1.ValidateAuthenticatorRecovery(result) != nil {
		return iamv1.AuthenticatorRecovery{}, ErrUnavailable
	}
	return result, nil
}
