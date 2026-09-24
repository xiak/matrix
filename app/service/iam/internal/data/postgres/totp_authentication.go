package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) ReadLoginAuthenticationState(ctx context.Context, account iamv1.AccountID, user iamv1.PrincipalID) (identityaccess.LoginAuthenticationState, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.login_authentication_state($1,$2)", account, user).Scan(&encoded); err != nil {
		return identityaccess.LoginAuthenticationState{}, mapSubjectDatabaseError("read login authentication state", err)
	}
	var state struct {
		State              string `json:"state"`
		Revision           uint64 `json:"revision"`
		FactorID           string `json:"factorId,omitempty"`
		EnrollmentRequired *bool  `json:"enrollmentRequired"`
	}
	if contractjson.DecodeObjectBytes(encoded, 1024, &state) != nil || state.EnrollmentRequired == nil || state.Revision == 0 || state.Revision > 9007199254740991 ||
		(state.State != "NEVER_BOUND" && state.State != "BOUND" && state.State != "RECOVERY_REQUIRED") ||
		(state.State == "NEVER_BOUND" && (state.Revision != 1 || state.FactorID != "")) ||
		(state.State == "BOUND" && (state.Revision <= 1 || iamv1.ValidateID("factorId", state.FactorID) != nil)) ||
		(state.State != "NEVER_BOUND" && *state.EnrollmentRequired) {
		return identityaccess.LoginAuthenticationState{}, identityaccess.ErrUnavailable
	}
	return identityaccess.LoginAuthenticationState{State: state.State, Revision: state.Revision, FactorID: state.FactorID,
		EnrollmentRequired: *state.EnrollmentRequired}, nil
}

func (value *transaction) CreateLoginChallenge(ctx context.Context, mutation identityaccess.LoginChallengeCreation) (iamv1.AuthenticationChallenge, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.create_login_challenge($1,$2,$3,$4,$5,$6,$7,$8,$9)",
		mutation.Attempt.AccountID, mutation.Attempt.PrincipalID, mutation.Attempt.ID, mutation.Attempt.Sequence,
		mutation.ID, mutation.LookupDigest, mutation.VerificationDigest, mutation.RequestID, mutation.RequestDigest).Scan(&encoded)
	if err != nil {
		return iamv1.AuthenticationChallenge{}, mapSubjectDatabaseError("create login challenge", err)
	}
	var result iamv1.AuthenticationChallenge
	if contractjson.DecodeObjectBytes(encoded, 1024, &result) != nil {
		return iamv1.AuthenticationChallenge{}, identityaccess.ErrUnavailable
	}
	result.ExpiresAt = result.ExpiresAt.UTC()
	if result.ID != mutation.ID || iamv1.ValidateAuthenticationChallenge(result) != nil {
		return iamv1.AuthenticationChallenge{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) LookupAuthenticationChallenge(ctx context.Context, digest string) (identityaccess.AuthenticationChallengeCredential, bool, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.lookup_authentication_challenge($1)", digest).Scan(&encoded)
	if err != nil {
		return identityaccess.AuthenticationChallengeCredential{}, false, mapDatabaseError("lookup authentication challenge", err)
	}
	if encoded == nil {
		return identityaccess.AuthenticationChallengeCredential{}, false, nil
	}
	defer clear(encoded)
	var result identityaccess.AuthenticationChallengeCredential
	if contractjson.DecodeObjectBytes(encoded, 1024, &result) != nil ||
		iamv1.ValidateID("accountId", string(result.AccountID)) != nil || iamv1.ValidateID("userId", string(result.UserID)) != nil ||
		(result.Purpose != "LOGIN" && result.Purpose != "RECOVERY" && result.Purpose != "ENROLLMENT") ||
		(result.NextStep != "TOTP" && result.NextStep != "PASSWORD_CHANGE" && result.NextStep != "RECOVER" && result.NextStep != "ENROLLMENT") ||
		iamv1.ValidateID("id", result.ID) != nil || iamv1.ValidateDigest("verificationDigest", result.VerificationDigest) != nil {
		return identityaccess.AuthenticationChallengeCredential{}, false, identityaccess.ErrUnavailable
	}
	return result, true, nil
}

func (value *transaction) ReserveTOTPAttempt(ctx context.Context, attempt identityaccess.TOTPAttempt) (identityaccess.TOTPAttempt, bool, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.reserve_totp_attempt($1,$2,NULLIF($3,''),$4,$5,$6)", attempt.AccountID, attempt.UserID,
		string(attempt.SessionID), attempt.ReferenceID, attempt.Purpose, attempt.ID).Scan(&encoded)
	if err != nil {
		return identityaccess.TOTPAttempt{}, false, mapSubjectDatabaseError("reserve TOTP attempt", err)
	}
	if encoded == nil {
		return identityaccess.TOTPAttempt{}, false, nil
	}
	var result struct {
		ID       string `json:"id"`
		Sequence uint64 `json:"sequence"`
	}
	if contractjson.DecodeObjectBytes(encoded, 1024, &result) != nil || result.ID != attempt.ID || result.Sequence == 0 || result.Sequence > 9007199254740991 {
		return identityaccess.TOTPAttempt{}, false, identityaccess.ErrUnavailable
	}
	attempt.Sequence = result.Sequence
	return attempt, true, nil
}

func (value *transaction) ReadTOTPAttempt(ctx context.Context, attempt identityaccess.TOTPAttempt) (identityaccess.TOTPVerification, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.read_totp_attempt($1,$2,NULLIF($3,''),$4,$5,$6,$7)", attempt.AccountID, attempt.UserID,
		string(attempt.SessionID), attempt.ReferenceID, attempt.Purpose, attempt.ID, attempt.Sequence).Scan(&encoded)
	if err != nil {
		return identityaccess.TOTPVerification{}, mapSubjectDatabaseError("read TOTP attempt", err)
	}
	defer clear(encoded)
	var result struct {
		FactorID           string    `json:"factorId"`
		InstallationID     string    `json:"installationId"`
		KeyID              string    `json:"keyId"`
		FormatVersion      uint8     `json:"formatVersion"`
		Nonce              []byte    `json:"nonce"`
		Ciphertext         []byte    `json:"ciphertext"`
		LastConsumedStep   *int64    `json:"lastConsumedStep"`
		FactorRevision     uint64    `json:"factorRevision"`
		DatabaseTime       time.Time `json:"databaseTime"`
		MustChangePassword *bool     `json:"mustChangePassword"`
	}
	if contractjson.DecodeObjectBytes(encoded, 2048, &result) != nil || result.FormatVersion != 1 ||
		iamv1.ValidateID("factorId", result.FactorID) != nil || iamv1.ValidateID("installationId", result.InstallationID) != nil ||
		iamv1.ValidateID("keyId", result.KeyID) != nil || len(result.Nonce) != 12 || len(result.Ciphertext) != 36 ||
		result.LastConsumedStep == nil || *result.LastConsumedStep < -1 || *result.LastConsumedStep > 8446743359 ||
		result.FactorRevision == 0 || result.FactorRevision > 9007199254740991 || result.DatabaseTime.IsZero() || result.MustChangePassword == nil {
		clear(result.Nonce)
		clear(result.Ciphertext)
		return identityaccess.TOTPVerification{}, identityaccess.ErrUnavailable
	}
	return identityaccess.TOTPVerification{FactorID: result.FactorID, InstallationID: result.InstallationID,
		Sealed:           authority.SealedTOTPSeed{KeyID: result.KeyID, FormatVersion: result.FormatVersion, Nonce: result.Nonce, Ciphertext: result.Ciphertext},
		LastConsumedStep: *result.LastConsumedStep, FactorRevision: result.FactorRevision, DatabaseTime: result.DatabaseTime.UTC(), MustChangePassword: *result.MustChangePassword}, nil
}

func (value *transaction) BeginPasswordChallenge(ctx context.Context, mutation identityaccess.PasswordChallengeCreation) (iamv1.AuthenticationChallenge, error) {
	attempt := mutation.Attempt
	if attempt.Purpose != "LOGIN" || attempt.SessionID != "" {
		return iamv1.AuthenticationChallenge{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.begin_password_challenge($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
		attempt.AccountID, attempt.UserID, attempt.ReferenceID, attempt.ID, attempt.Sequence, mutation.VerifiedStep,
		mutation.ID, mutation.LookupDigest, mutation.VerificationDigest, mutation.RequestID, mutation.RequestDigest).Scan(&encoded)
	if err != nil {
		return iamv1.AuthenticationChallenge{}, mapSubjectDatabaseError("begin password challenge", err)
	}
	var result iamv1.AuthenticationChallenge
	if contractjson.DecodeObjectBytes(encoded, 1024, &result) != nil {
		return iamv1.AuthenticationChallenge{}, identityaccess.ErrUnavailable
	}
	result.ExpiresAt = result.ExpiresAt.UTC()
	if result.ID != mutation.ID || result.NextStep != "PASSWORD_CHANGE" || iamv1.ValidateAuthenticationChallenge(result) != nil {
		return iamv1.AuthenticationChallenge{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadPasswordChallenge(ctx context.Context, identity identityaccess.AuthenticationChallengeCredential) (identityaccess.ChallengePasswordMaterial, error) {
	if (identity.Purpose != "LOGIN" && identity.Purpose != "ENROLLMENT") || identity.NextStep != "PASSWORD_CHANGE" {
		return identityaccess.ChallengePasswordMaterial{}, identityaccess.ErrUnauthenticated
	}
	var result identityaccess.ChallengePasswordMaterial
	err := value.tx.QueryRow(ctx, "SELECT password_hash,credential_generation FROM iam.read_password_challenge($1,$2,$3)",
		identity.AccountID, identity.UserID, identity.ID).Scan(&result.PasswordHash, &result.CredentialGeneration)
	if err != nil {
		return identityaccess.ChallengePasswordMaterial{}, mapSubjectDatabaseError("read password challenge", err)
	}
	if result.CredentialGeneration == 0 || result.CredentialGeneration >= 9007199254740991 || len(result.PasswordHash) > 512 ||
		!strings.HasPrefix(string(result.PasswordHash), "$matrix-iam-v1$argon2id$v=19$") {
		return identityaccess.ChallengePasswordMaterial{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ChangeChallengePassword(ctx context.Context, mutation identityaccess.ChallengePasswordMutation) (iamv1.ChallengePasswordChangeResponse, error) {
	identity := mutation.Identity
	if (identity.Purpose != "LOGIN" && identity.Purpose != "ENROLLMENT") || identity.NextStep != "PASSWORD_CHANGE" || mutation.AuditEvent.Action != auditv1.ActionIAMUserPasswordChanged ||
		string(mutation.AuditEvent.TenantID) != string(identity.AccountID) || string(mutation.AuditEvent.Actor.ID) != string(identity.UserID) ||
		mutation.AuditEvent.Target.Kind != auditv1.TargetUser || mutation.AuditEvent.Target.ID != string(identity.UserID) ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil {
		return iamv1.ChallengePasswordChangeResponse{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	result := iamv1.ChallengePasswordChangeResponse{NextStep: "REAUTHENTICATE"}
	err = value.tx.QueryRow(ctx, "SELECT iam.change_challenge_password($1,$2,$3,$4,$5,$6,$7::jsonb)",
		identity.AccountID, identity.UserID, identity.ID, mutation.Expected.CredentialGeneration,
		string(mutation.Expected.PasswordHash), string(mutation.Replacement), event).Scan(&result.ChangedAt)
	if err != nil {
		return iamv1.ChallengePasswordChangeResponse{}, mapSubjectDatabaseError("change challenge password", err)
	}
	result.ChangedAt = result.ChangedAt.UTC()
	if result.ChangedAt != mutation.AuditEvent.OccurredAt || iamv1.ValidateChallengePasswordChangeResponse(result) != nil {
		return iamv1.ChallengePasswordChangeResponse{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) RejectTOTPAttempt(ctx context.Context, attempt identityaccess.TOTPAttempt) error {
	_, err := value.tx.Exec(ctx, "SELECT iam.reject_totp_attempt($1,$2,$3,$4)", attempt.AccountID, attempt.UserID, attempt.ID, attempt.Sequence)
	return mapDatabaseError("reject TOTP attempt", err)
}

func (value *transaction) CompleteLoginChallenge(ctx context.Context, completion identityaccess.LoginChallengeCompletion) (iamv1.Session, error) {
	mutation, attempt := completion.Session, completion.Attempt
	if iamv1.ValidateSession(mutation.Session) != nil || auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil ||
		mutation.Session.AccountID != attempt.AccountID || mutation.Session.PrincipalID != attempt.UserID || attempt.Purpose != "LOGIN" || attempt.SessionID != "" {
		return iamv1.Session{}, identityaccess.ErrInvalidArgument
	}
	lifetime := mutation.Session.ExpiresAt.Sub(mutation.Session.IssuedAt)
	if lifetime%time.Second != 0 {
		return iamv1.Session{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.Session{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	var issuedAt, expiresAt time.Time
	err = value.tx.QueryRow(ctx, "SELECT * FROM iam.complete_login_challenge($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)",
		attempt.AccountID, attempt.UserID, attempt.ReferenceID, attempt.ID, attempt.Sequence, completion.VerifiedStep,
		mutation.Session.ID, mutation.LookupDigest, mutation.VerificationDigest, int(lifetime/time.Second), event).Scan(&issuedAt, &expiresAt)
	if err != nil {
		return iamv1.Session{}, mapSubjectDatabaseError("complete login challenge", err)
	}
	stored := mutation.Session
	stored.IssuedAt, stored.ExpiresAt = issuedAt.UTC(), expiresAt.UTC()
	if stored.IssuedAt != mutation.Session.IssuedAt || stored.ExpiresAt != mutation.Session.ExpiresAt || iamv1.ValidateSession(stored) != nil {
		return iamv1.Session{}, identityaccess.ErrUnavailable
	}
	return stored, nil
}
