package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) ReadAuthenticatorState(ctx context.Context, caller iamv1.Session) (iamv1.AuthenticatorState, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.read_authenticator_state($1,$2,$3)", caller.AccountID, caller.PrincipalID, caller.ID).Scan(&encoded)
	if err != nil {
		return iamv1.AuthenticatorState{}, mapSubjectDatabaseError("read authenticator state", err)
	}
	var result iamv1.AuthenticatorState
	if contractjson.DecodeObjectBytes(encoded, 1024, &result) != nil || iamv1.ValidateAuthenticatorState(result) != nil {
		return iamv1.AuthenticatorState{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func decodeTOTPEnrollment(encoded []byte) (iamv1.TOTPEnrollment, error) {
	var result iamv1.TOTPEnrollment
	if contractjson.DecodeObjectBytes(encoded, 2048, &result) != nil {
		return iamv1.TOTPEnrollment{}, identityaccess.ErrUnavailable
	}
	result.CreatedAt, result.ExpiresAt = result.CreatedAt.UTC(), result.ExpiresAt.UTC()
	if result.CompletedAt != nil {
		completed := result.CompletedAt.UTC()
		result.CompletedAt = &completed
	}
	if iamv1.ValidateTOTPEnrollment(result) != nil {
		return iamv1.TOTPEnrollment{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) StartTOTPEnrollment(ctx context.Context, mutation identityaccess.TOTPEnrollmentStart) (identityaccess.TOTPEnrollmentStartResult, error) {
	if mutation.Attempt.Purpose != identityaccess.PasswordAttemptTOTPEnrollment || mutation.Sealed.FormatVersion != 1 {
		return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.start_totp_enrollment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
		mutation.Attempt.AccountID, mutation.Attempt.PrincipalID, mutation.Attempt.SessionID, mutation.ExpectedRevision,
		mutation.RequestID, mutation.Attempt.IntentDigest, mutation.Attempt.ID, mutation.Attempt.Sequence, mutation.FactorID,
		mutation.Scope.InstallationID, mutation.Scope.BootstrapDigest, mutation.Sealed.KeyID, mutation.Sealed.Nonce, mutation.Sealed.Ciphertext).Scan(&encoded)
	if err != nil {
		return identityaccess.TOTPEnrollmentStartResult{}, mapTOTPEnrollmentError("start TOTP enrollment", err)
	}
	var wire struct {
		Outcome    string          `json:"outcome"`
		Enrollment json.RawMessage `json:"enrollment"`
	}
	if contractjson.DecodeObjectBytes(encoded, 3072, &wire) != nil || (wire.Outcome != "APPLIED" && wire.Outcome != "EQUAL_REPLAY") {
		return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrUnavailable
	}
	enrollment, err := decodeTOTPEnrollment(wire.Enrollment)
	if err != nil || enrollment.RequestID != mutation.RequestID || enrollment.FactorRevision != mutation.ExpectedRevision ||
		(wire.Outcome == "APPLIED" && (enrollment.ID != mutation.FactorID || enrollment.State != "PENDING")) {
		return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrUnavailable
	}
	return identityaccess.TOTPEnrollmentStartResult{Outcome: wire.Outcome, Enrollment: enrollment}, nil
}

func (value *transaction) ReadTOTPEnrollment(ctx context.Context, caller iamv1.Session, id string) (iamv1.TOTPEnrollment, error) {
	return value.enrollmentMetadata(ctx, "SELECT iam.read_totp_enrollment($1,$2,$3,$4)", caller, id)
}

func (value *transaction) ReadTOTPEnrollmentByRequest(ctx context.Context, caller iamv1.Session, requestID string) (iamv1.TOTPEnrollment, error) {
	return value.enrollmentMetadata(ctx, "SELECT iam.read_totp_enrollment_by_request($1,$2,$3,$4)", caller, requestID)
}

func (value *transaction) CancelTOTPEnrollment(ctx context.Context, caller iamv1.Session, id string) (iamv1.TOTPEnrollment, error) {
	return value.enrollmentMetadata(ctx, "SELECT iam.cancel_totp_enrollment($1,$2,$3,$4)", caller, id)
}

func (value *transaction) enrollmentMetadata(ctx context.Context, query string, caller iamv1.Session, reference string) (iamv1.TOTPEnrollment, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, query, caller.AccountID, caller.PrincipalID, caller.ID, reference).Scan(&encoded)
	if err != nil {
		return iamv1.TOTPEnrollment{}, mapTOTPEnrollmentError("read TOTP enrollment metadata", err)
	}
	return decodeTOTPEnrollment(encoded)
}

func (value *transaction) ConfirmTOTPEnrollment(ctx context.Context, mutation identityaccess.TOTPBindingConfirmation) (iamv1.TOTPEnrollment, error) {
	a := mutation.Attempt
	if a.Purpose != "ENROLLMENT" || a.SessionID == "" || len(mutation.Codes) != 10 ||
		mutation.AuditEvent.Action != auditv1.ActionIAMAuthenticatorBound ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil ||
		string(mutation.AuditEvent.TenantID) != string(a.AccountID) || string(mutation.AuditEvent.Actor.ID) != string(a.UserID) {
		return iamv1.TOTPEnrollment{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.TOTPEnrollment{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	codes, err := json.Marshal(mutation.Codes)
	if err != nil {
		return iamv1.TOTPEnrollment{}, identityaccess.ErrUnavailable
	}
	defer clear(codes)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.confirm_totp_enrollment($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11::jsonb)",
		a.AccountID, a.UserID, a.SessionID, a.ReferenceID, a.ID, a.Sequence, mutation.VerifiedStep,
		mutation.BatchID, codes, mutation.NotificationID, event).Scan(&encoded)
	if err != nil {
		return iamv1.TOTPEnrollment{}, mapTOTPEnrollmentError("confirm TOTP enrollment", err)
	}
	return decodeTOTPEnrollment(encoded)
}

func mapTOTPEnrollmentError(operation string, err error) error {
	var failure *pgconn.PgError
	if errors.As(err, &failure) {
		switch failure.Code {
		case "23514":
			return identityaccess.ErrConflict
		case "P0002":
			return identityaccess.ErrTOTPEnrollmentNotFound
		}
	}
	return mapSubjectDatabaseError(operation, err)
}
