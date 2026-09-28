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

func (value *transaction) ReadEnrollmentChallenge(ctx context.Context, identity identityaccess.AuthenticationChallengeCredential) (identityaccess.EnrollmentChallengeInspection, error) {
	if identity.Purpose != "ENROLLMENT" || (identity.NextStep != "PASSWORD_CHANGE" && identity.NextStep != "ENROLLMENT") {
		return identityaccess.EnrollmentChallengeInspection{}, identityaccess.ErrUnauthenticated
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.inspect_initial_enrollment_challenge($1,$2,$3,$4)",
		identity.AccountID, identity.UserID, identity.ID, identity.NextStep).Scan(&encoded); err != nil {
		return identityaccess.EnrollmentChallengeInspection{}, mapSubjectDatabaseError("inspect initial enrollment", err)
	}
	// PostgreSQL renders timestamptz with its session offset. Decode this
	// storage projection before applying the public UTC-only observation
	// decoder, then normalize and validate every field below.
	var stored struct {
		State struct {
			Challenge           iamv1.AuthenticationChallenge `json:"challenge"`
			NotificationContact *iamv1.NotificationContact    `json:"notificationContact,omitempty"`
			Enrollment          *iamv1.TOTPEnrollment         `json:"enrollment,omitempty"`
		} `json:"state"`
		CredentialGeneration uint64 `json:"credentialGeneration"`
	}
	if contractjson.DecodeObjectBytes(encoded, 8192, &stored) != nil {
		return identityaccess.EnrollmentChallengeInspection{}, identityaccess.ErrUnavailable
	}
	result := identityaccess.EnrollmentChallengeInspection{CredentialGeneration: stored.CredentialGeneration,
		State: iamv1.EnrollmentChallengeState{Challenge: stored.State.Challenge,
			NotificationContact: stored.State.NotificationContact, Enrollment: stored.State.Enrollment}}
	result.State.Challenge.ExpiresAt = result.State.Challenge.ExpiresAt.UTC()
	if contact := result.State.NotificationContact; contact != nil && contact.VerifiedAt != nil {
		normalized := contact.VerifiedAt.UTC()
		contact.VerifiedAt = &normalized
	}
	if enrollment := result.State.Enrollment; enrollment != nil {
		enrollment.CreatedAt, enrollment.ExpiresAt = enrollment.CreatedAt.UTC(), enrollment.ExpiresAt.UTC()
		if enrollment.CompletedAt != nil {
			normalized := enrollment.CompletedAt.UTC()
			enrollment.CompletedAt = &normalized
		}
	}
	if result.CredentialGeneration == 0 || result.CredentialGeneration > 9007199254740991 ||
		iamv1.ValidateEnrollmentChallengeState(result.State) != nil || result.State.Challenge.ID != identity.ID ||
		result.State.Challenge.Purpose != identity.Purpose || result.State.Challenge.NextStep != identity.NextStep ||
		(result.State.NotificationContact != nil && (result.State.NotificationContact.AccountID != identity.AccountID || result.State.NotificationContact.UserID != identity.UserID)) {
		return identityaccess.EnrollmentChallengeInspection{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) StartTOTPEnrollment(ctx context.Context, mutation identityaccess.TOTPEnrollmentStart) (identityaccess.TOTPEnrollmentStartResult, error) {
	if mutation.Sealed.FormatVersion != 1 {
		return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrInvalidArgument
	}
	account, user, caller := mutation.Attempt.AccountID, mutation.Attempt.PrincipalID, mutation.Attempt.SessionID
	var attemptID, attemptSequence any
	if mutation.Challenge.ID == "" {
		if mutation.Attempt.Purpose != identityaccess.PasswordAttemptTOTPEnrollment || caller == "" || mutation.IntentDigest != mutation.Attempt.IntentDigest {
			return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrInvalidArgument
		}
		attemptID, attemptSequence = mutation.Attempt.ID, mutation.Attempt.Sequence
	} else {
		if mutation.Challenge.Purpose != "ENROLLMENT" || mutation.Challenge.NextStep != "ENROLLMENT" || mutation.ExpectedRevision != 1 ||
			mutation.Attempt.ID != "" || mutation.Attempt.Sequence != 0 || mutation.Attempt.Purpose != "" || caller != "" || account != "" || user != "" {
			return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrInvalidArgument
		}
		account, user = mutation.Challenge.AccountID, mutation.Challenge.UserID
	}
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.start_totp_enrollment($1,$2,NULLIF($3::text,''),NULLIF($4::text,''),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
		account, user, caller, mutation.Challenge.ID, mutation.ExpectedRevision,
		mutation.RequestID, mutation.IntentDigest, attemptID, attemptSequence, mutation.FactorID,
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
	if err != nil || enrollment.Purpose != "INITIAL" || enrollment.RequestID != mutation.RequestID || enrollment.FactorRevision != mutation.ExpectedRevision ||
		(wire.Outcome == "APPLIED" && (enrollment.ID != mutation.FactorID || enrollment.State != "PENDING")) {
		return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrUnavailable
	}
	return identityaccess.TOTPEnrollmentStartResult{Outcome: wire.Outcome, Enrollment: enrollment}, nil
}

func (value *transaction) StartTOTPReplacement(ctx context.Context, mutation identityaccess.TOTPReplacementStart) (identityaccess.TOTPEnrollmentStartResult, error) {
	if mutation.Sealed.FormatVersion != 1 || iamv1.ValidateStartTOTPReplacementRequest(mutation.Request) != nil ||
		iamv1.ValidateID("factorId", mutation.FactorID) != nil {
		return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.start_totp_replacement($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
		mutation.Session.AccountID, mutation.Session.PrincipalID, mutation.Session.ID, mutation.Request.StepUpID,
		mutation.Request.RequestID, mutation.Request.ExpectedFactorRevision, mutation.FactorID,
		mutation.Scope.InstallationID, mutation.Scope.BootstrapDigest, mutation.Sealed.KeyID, mutation.Sealed.Nonce, mutation.Sealed.Ciphertext).Scan(&encoded)
	if err != nil {
		return identityaccess.TOTPEnrollmentStartResult{}, mapTOTPEnrollmentError("start TOTP replacement", err)
	}
	var wire struct {
		Outcome    string          `json:"outcome"`
		Enrollment json.RawMessage `json:"enrollment"`
	}
	if contractjson.DecodeObjectBytes(encoded, 3072, &wire) != nil || (wire.Outcome != "APPLIED" && wire.Outcome != "EQUAL_REPLAY") {
		return identityaccess.TOTPEnrollmentStartResult{}, identityaccess.ErrUnavailable
	}
	enrollment, err := decodeTOTPEnrollment(wire.Enrollment)
	if err != nil || enrollment.Purpose != "REPLACEMENT" || enrollment.RequestID != mutation.Request.RequestID ||
		enrollment.FactorRevision != mutation.Request.ExpectedFactorRevision ||
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
	expectedAction := auditv1.ActionIAMAuthenticatorBound
	if a.Purpose == "REPLACEMENT" {
		expectedAction = auditv1.ActionIAMAuthenticatorReplaced
	}
	if !(((a.Purpose == "ENROLLMENT" || a.Purpose == "REPLACEMENT") && a.SessionID != "") || (a.Purpose == "INITIAL_ENROLLMENT" && a.SessionID == "")) || len(mutation.Codes) != 10 ||
		mutation.AuditEvent.Action != expectedAction ||
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
	err = value.tx.QueryRow(ctx, "SELECT iam.confirm_totp_enrollment($1,$2,NULLIF($3::text,''),$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12::jsonb)",
		a.AccountID, a.UserID, a.SessionID, a.ReferenceID, a.Purpose, a.ID, a.Sequence, mutation.VerifiedStep,
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
