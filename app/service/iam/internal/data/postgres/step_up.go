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

func (value *transaction) StartStepUp(ctx context.Context, mutation identityaccess.StepUpStart) (iamv1.StepUp, error) {
	s, r := mutation.Session, mutation.Request
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.start_step_up($1,$2,$3,$4,$5,$6,$7)", s.AccountID, s.PrincipalID, s.ID,
		mutation.ID, r.RequestID, r.Operation, r.ExpectedFactorRevision).Scan(&encoded)
	if err != nil {
		return iamv1.StepUp{}, mapStepUpError("start operation proof", err)
	}
	var result iamv1.StepUp
	if contractjson.DecodeObjectBytes(encoded, 2048, &result) != nil {
		return iamv1.StepUp{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ReadStepUpByRequest(ctx context.Context, caller iamv1.Session, requestID string) (iamv1.StepUp, error) {
	return value.stepUpMetadata(ctx, "SELECT iam.read_step_up_by_request($1,$2,$3,$4)", caller, requestID)
}

func (value *transaction) ReadStepUpForVerification(ctx context.Context, caller iamv1.Session, id string) (iamv1.StepUp, error) {
	return value.stepUpMetadata(ctx, "SELECT iam.read_step_up_for_verification($1,$2,$3,$4)", caller, id)
}

func (value *transaction) stepUpMetadata(ctx context.Context, query string, caller iamv1.Session, reference string) (iamv1.StepUp, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, query, caller.AccountID, caller.PrincipalID, caller.ID, reference).Scan(&encoded)
	if err != nil {
		return iamv1.StepUp{}, mapStepUpError("read operation proof", err)
	}
	var result iamv1.StepUp
	if contractjson.DecodeObjectBytes(encoded, 2048, &result) != nil {
		return iamv1.StepUp{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ProveStepUp(ctx context.Context, mutation identityaccess.StepUpVerification) (iamv1.StepUp, error) {
	p, a := mutation.Password, mutation.OTP
	if p.Purpose != identityaccess.PasswordAttemptStepUp || a.Purpose != "STEP_UP" || a.SessionID == "" ||
		p.AccountID != a.AccountID || p.PrincipalID != a.UserID || p.SessionID != a.SessionID {
		return iamv1.StepUp{}, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.prove_step_up($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", a.AccountID, a.UserID, a.SessionID,
		a.ReferenceID, mutation.RequestID, p.IntentDigest, p.ID, p.Sequence, a.ID, a.Sequence, mutation.VerifiedStep).Scan(&encoded)
	if err != nil {
		return iamv1.StepUp{}, mapStepUpError("prove operation", err)
	}
	var result iamv1.StepUp
	if contractjson.DecodeObjectBytes(encoded, 2048, &result) != nil {
		return iamv1.StepUp{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) RegenerateRecoveryCodes(ctx context.Context, mutation identityaccess.RecoveryCodeRegenerationMutation) (identityaccess.RecoveryCodeRegenerationResult, error) {
	s, r := mutation.Session, mutation.Request
	if iamv1.ValidateRegenerateRecoveryCodesRequest(r) != nil || len(mutation.Codes) != 10 ||
		mutation.AuditEvent.Action != auditv1.ActionIAMRecoveryCodesRegenerated || auditv1.ValidateEventForSource(auditv1.SourceIAM, mutation.AuditEvent) != nil ||
		string(mutation.AuditEvent.TenantID) != string(s.AccountID) || string(mutation.AuditEvent.Actor.ID) != string(s.PrincipalID) || mutation.AuditEvent.RequestID != r.RequestID {
		return identityaccess.RecoveryCodeRegenerationResult{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return identityaccess.RecoveryCodeRegenerationResult{}, identityaccess.ErrUnavailable
	}
	defer clear(event)
	codes, err := json.Marshal(mutation.Codes)
	if err != nil {
		return identityaccess.RecoveryCodeRegenerationResult{}, identityaccess.ErrUnavailable
	}
	defer clear(codes)
	var encoded []byte
	err = value.tx.QueryRow(ctx, "SELECT iam.regenerate_recovery_codes($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11::jsonb)",
		s.AccountID, s.PrincipalID, s.ID, r.StepUpID, r.RequestID, r.ExpectedFactorRevision, mutation.ID, mutation.BatchID, codes, mutation.NotificationID, event).Scan(&encoded)
	if err != nil {
		return identityaccess.RecoveryCodeRegenerationResult{}, mapStepUpError("regenerate recovery codes", err)
	}
	var wire struct {
		Outcome      string                         `json:"outcome"`
		Regeneration iamv1.RecoveryCodeRegeneration `json:"regeneration"`
	}
	if contractjson.DecodeObjectBytes(encoded, 2048, &wire) != nil || (wire.Outcome != "APPLIED" && wire.Outcome != "EQUAL_REPLAY") {
		return identityaccess.RecoveryCodeRegenerationResult{}, identityaccess.ErrUnavailable
	}
	return identityaccess.RecoveryCodeRegenerationResult{Outcome: wire.Outcome, Regeneration: wire.Regeneration}, nil
}

func (value *transaction) ReadRecoveryCodeRegeneration(ctx context.Context, caller iamv1.Session, requestID string) (iamv1.RecoveryCodeRegeneration, error) {
	var encoded []byte
	err := value.tx.QueryRow(ctx, "SELECT iam.read_recovery_code_regeneration($1,$2,$3,$4)", caller.AccountID, caller.PrincipalID, caller.ID, requestID).Scan(&encoded)
	if err != nil {
		var failure *pgconn.PgError
		if errors.As(err, &failure) && failure.Code == "P0002" {
			return iamv1.RecoveryCodeRegeneration{}, identityaccess.ErrRecoveryCodeRegenerationNotFound
		}
		return iamv1.RecoveryCodeRegeneration{}, mapStepUpError("read recovery code regeneration", err)
	}
	var result iamv1.RecoveryCodeRegeneration
	if contractjson.DecodeObjectBytes(encoded, 2048, &result) != nil {
		return iamv1.RecoveryCodeRegeneration{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func mapStepUpError(operation string, err error) error {
	var failure *pgconn.PgError
	if errors.As(err, &failure) {
		switch failure.Code {
		case "23514":
			return identityaccess.ErrConflict
		case "P0002":
			return identityaccess.ErrStepUpNotFound
		}
	}
	return mapSubjectDatabaseError(operation, err)
}
