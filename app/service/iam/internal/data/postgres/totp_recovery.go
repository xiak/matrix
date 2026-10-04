package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) ReadRecoveryAttempt(ctx context.Context, attempt identityaccess.TOTPAttempt) (identityaccess.RecoveryCodeVerification, error) {
	if attempt.Purpose != "RECOVERY_CODE" || attempt.SessionID != "" {
		return identityaccess.RecoveryCodeVerification{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.read_recovery_attempt($1,$2,$3,$4,$5)", attempt.AccountID, attempt.UserID, attempt.ReferenceID, attempt.ID, attempt.Sequence).Scan(&encoded)
	if err != nil {
		return identityaccess.RecoveryCodeVerification{}, mapSubjectDatabaseError("read recovery attempt", err)
	}
	defer clear(encoded)
	var wire struct {
		InstallationID string `json:"installationId"`
		BatchID        string `json:"batchId"`
		Codes          []struct {
			ID                 string `json:"id"`
			VerificationDigest string `json:"verificationDigest"`
			Consumed           *bool  `json:"consumed"`
		} `json:"codes"`
	}
	if contractjson.DecodeObjectBytes(encoded, 4096, &wire) != nil || len(wire.Codes) != 10 || iamv1.ValidateID("batchId", wire.BatchID) != nil || iamv1.ValidateID("installationId", wire.InstallationID) != nil {
		return identityaccess.RecoveryCodeVerification{}, fmt.Errorf("recovery verification projection: %w", identityaccess.ErrUnavailable)
	}
	result := identityaccess.RecoveryCodeVerification{InstallationID: wire.InstallationID, BatchID: wire.BatchID, Codes: make([]identityaccess.RecoveryCodeCandidate, 10)}
	previous := ""
	for i, code := range wire.Codes {
		if code.Consumed == nil || code.ID <= previous || iamv1.ValidateID("codeId", code.ID) != nil || iamv1.ValidateDigest("verificationDigest", code.VerificationDigest) != nil {
			return identityaccess.RecoveryCodeVerification{}, fmt.Errorf("recovery verification entry: %w", identityaccess.ErrUnavailable)
		}
		previous = code.ID
		result.Codes[i] = identityaccess.RecoveryCodeCandidate{ID: code.ID, VerificationDigest: code.VerificationDigest, Consumed: *code.Consumed}
	}
	return result, nil
}

func recoveryEvent(event auditv1.Event, attempt identityaccess.TOTPAttempt, action auditv1.Action) ([]byte, error) {
	if event.Action != action || auditv1.ValidateEventForSource(auditv1.SourceIAM, event) != nil || string(event.TenantID) != string(attempt.AccountID) || string(event.Actor.ID) != string(attempt.UserID) {
		return nil, identityaccess.ErrInvalidArgument
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, identityaccess.ErrUnavailable
	}
	return encoded, nil
}

func (value *transaction) StartAuthenticatorRecovery(ctx context.Context, mutation identityaccess.AuthenticatorRecoveryStart) (identityaccess.AuthenticatorRecoveryStartResult, error) {
	a := mutation.Attempt
	if a.Purpose != "RECOVERY_CODE" || a.SessionID != "" || mutation.Sealed.FormatVersion != 1 {
		return identityaccess.AuthenticatorRecoveryStartResult{}, identityaccess.ErrInvalidArgument
	}
	event, err := recoveryEvent(mutation.AuditEvent, a, auditv1.ActionIAMAuthenticatorRecoveryStarted)
	if err != nil {
		return identityaccess.AuthenticatorRecoveryStartResult{}, err
	}
	defer clear(event)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.start_authenticator_recovery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb)",
		a.AccountID, a.UserID, a.ReferenceID, a.ID, a.Sequence, mutation.Code.ID, mutation.Code.VerificationDigest, mutation.ID, mutation.FactorID, mutation.ChallengeID,
		mutation.LookupDigest, mutation.VerificationDigest, mutation.Sealed.KeyID, mutation.Sealed.Nonce, mutation.Sealed.Ciphertext, mutation.NotificationID, event).Scan(&encoded)
	if err != nil {
		return identityaccess.AuthenticatorRecoveryStartResult{}, mapSubjectDatabaseError("start authenticator recovery", err)
	}
	var wire struct {
		Recovery  json.RawMessage               `json:"recovery"`
		Challenge iamv1.AuthenticationChallenge `json:"challenge"`
	}
	if contractjson.DecodeObjectBytes(encoded, 2048, &wire) != nil {
		return identityaccess.AuthenticatorRecoveryStartResult{}, identityaccess.ErrUnavailable
	}
	recovery, err := decodeAuthenticatorRecovery(wire.Recovery)
	if err != nil {
		return identityaccess.AuthenticatorRecoveryStartResult{}, err
	}
	result := identityaccess.AuthenticatorRecoveryStartResult{Recovery: recovery, Challenge: wire.Challenge}
	result.Challenge.ExpiresAt = result.Challenge.ExpiresAt.UTC()
	if iamv1.ValidateAuthenticatorRecovery(result.Recovery) != nil || iamv1.ValidateAuthenticationChallenge(result.Challenge) != nil ||
		result.Recovery.ID != mutation.ID || result.Recovery.State != "STARTED" || result.Challenge.Purpose != "RECOVERY" || result.Challenge.ID != mutation.ChallengeID {
		return identityaccess.AuthenticatorRecoveryStartResult{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ConfirmAuthenticatorRecovery(ctx context.Context, mutation identityaccess.TOTPBindingConfirmation) (iamv1.AuthenticatorRecovery, error) {
	a := mutation.Attempt
	if a.Purpose != "RECOVERY_CONFIRM" || a.SessionID != "" || len(mutation.Codes) != 10 {
		return iamv1.AuthenticatorRecovery{}, identityaccess.ErrInvalidArgument
	}
	event, err := recoveryEvent(mutation.AuditEvent, a, auditv1.ActionIAMAuthenticatorRecovered)
	if err != nil {
		return iamv1.AuthenticatorRecovery{}, err
	}
	defer clear(event)
	codes, err := json.Marshal(mutation.Codes)
	if err != nil {
		return iamv1.AuthenticatorRecovery{}, identityaccess.ErrUnavailable
	}
	defer clear(codes)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.confirm_authenticator_recovery($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::jsonb)",
		a.AccountID, a.UserID, a.ReferenceID, a.ID, a.Sequence, mutation.VerifiedStep, mutation.BatchID, codes, mutation.NotificationID, event).Scan(&encoded)
	if err != nil {
		return iamv1.AuthenticatorRecovery{}, mapSubjectDatabaseError("confirm authenticator recovery", err)
	}
	return decodeAuthenticatorRecovery(encoded)
}

func (value *transaction) InspectAuthenticatorRecovery(ctx context.Context, identity identityaccess.AuthenticationChallengeCredential, requestID string) (iamv1.AuthenticatorRecovery, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.inspect_authenticator_recovery($1,$2,$3,$4)", identity.AccountID, identity.UserID, identity.ID, requestID).Scan(&encoded)
	if err != nil {
		return iamv1.AuthenticatorRecovery{}, mapSubjectDatabaseError("inspect authenticator recovery", err)
	}
	if encoded == nil {
		return iamv1.AuthenticatorRecovery{}, identityaccess.ErrAuthenticatorRecoveryNotFound
	}
	return decodeAuthenticatorRecovery(encoded)
}

func decodeAuthenticatorRecovery(encoded []byte) (iamv1.AuthenticatorRecovery, error) {
	// PostgreSQL serializes timestamptz with a numeric offset. Normalize the
	// storage projection before applying the public UTC-only wire contract.
	type storageRecovery iamv1.AuthenticatorRecovery
	var stored storageRecovery
	if contractjson.DecodeObjectBytes(encoded, 1024, &stored) != nil {
		return iamv1.AuthenticatorRecovery{}, identityaccess.ErrUnavailable
	}
	result := iamv1.AuthenticatorRecovery(stored)
	result.CreatedAt, result.ExpiresAt = result.CreatedAt.UTC(), result.ExpiresAt.UTC()
	if result.CompletedAt != nil {
		utc := result.CompletedAt.UTC()
		result.CompletedAt = &utc
	}
	if iamv1.ValidateAuthenticatorRecovery(result) != nil {
		return iamv1.AuthenticatorRecovery{}, identityaccess.ErrUnavailable
	}
	return result, nil
}
