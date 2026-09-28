package postgres

import (
	"context"
	"encoding/json"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) InspectLocalCredentialRecovery(ctx context.Context, scope iamv1.LocalCredentialRecoveryScope, query *iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, error) {
	encodedScope, err := json.Marshal(scope)
	if err != nil {
		return iamv1.LocalCredentialRecoveryInspection{}, identityaccess.ErrInvalidArgument
	}
	var commandID, commitment *string
	if query != nil {
		commandID, commitment = &query.CommandID, &query.InputCommitment
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.inspect_local_credential_recovery($1::jsonb,$2,$3)", encodedScope, commandID, commitment).Scan(&encoded); err != nil {
		return iamv1.LocalCredentialRecoveryInspection{}, mapAuthorizationDatabaseError("inspect local IAM recovery", err)
	}
	var result iamv1.LocalCredentialRecoveryInspection
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.LocalCredentialRecoveryInspection{}, identityaccess.ErrUnavailable
	}
	if result.Result != nil {
		result.Result.CompletedAt = result.Result.CompletedAt.UTC()
	}
	if iamv1.ValidateLocalCredentialRecoveryInspection(result) != nil {
		return iamv1.LocalCredentialRecoveryInspection{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) PrepareLocalCredentialRecovery(ctx context.Context, scope iamv1.LocalCredentialRecoveryScope, expected iamv1.LocalCredentialRecoveryExpected, query iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, identityaccess.PasswordReplacementMaterial, error) {
	var inspection iamv1.LocalCredentialRecoveryInspection
	var material identityaccess.PasswordReplacementMaterial
	encodedScope, err := json.Marshal(scope)
	if err != nil {
		return inspection, material, identityaccess.ErrInvalidArgument
	}
	encodedExpected, err := json.Marshal(expected)
	if err != nil {
		return inspection, material, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	var hash, digest *string
	var generation *int64
	var history []string
	if err := value.tx.QueryRow(ctx, "SELECT * FROM iam.prepare_local_credential_recovery($1::jsonb,$2::jsonb,$3,$4)",
		encodedScope, encodedExpected, query.CommandID, query.InputCommitment).Scan(&encoded, &hash, &generation, &history, &digest); err != nil {
		return inspection, material, mapAuthorizationDatabaseError("prepare local IAM recovery", err)
	}
	if json.Unmarshal(encoded, &inspection) != nil {
		return inspection, material, identityaccess.ErrUnavailable
	}
	if inspection.Result != nil {
		inspection.Result.CompletedAt = inspection.Result.CompletedAt.UTC()
	}
	if iamv1.ValidateLocalCredentialRecoveryInspection(inspection) != nil {
		return inspection, material, identityaccess.ErrUnavailable
	}
	if inspection.State == "COMPLETED" {
		if hash != nil || generation != nil || history != nil || digest != nil {
			return inspection, material, identityaccess.ErrUnavailable
		}
		return inspection, material, nil
	}
	if inspection.State != "NOT_FOUND" || hash == nil || generation == nil || *generation <= 0 || digest == nil {
		return inspection, material, identityaccess.ErrUnavailable
	}
	material.PasswordHash = authority.PasswordHash(*hash)
	material.CredentialGeneration, material.HistoryDigest = uint64(*generation), *digest
	material.PasswordHistory, err = passwordHistoryMaterial(history, *digest)
	return inspection, material, err
}

func (value *transaction) RecoverLocalCredentials(ctx context.Context, mutation identityaccess.LocalCredentialRecoveryMutation) (iamv1.LocalCredentialRecoveryResult, error) {
	scope, err := json.Marshal(mutation.Scope)
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, identityaccess.ErrInvalidArgument
	}
	expected, err := json.Marshal(mutation.Expected)
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, identityaccess.ErrInvalidArgument
	}
	event, err := json.Marshal(mutation.AuditEvent)
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, identityaccess.ErrUnavailable
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.recover_local_credentials($1::jsonb,$2::jsonb,$3,$4,$5,$6::jsonb,$7,$8)",
		scope, expected, mutation.CommandID, mutation.InputCommitment, string(mutation.PasswordHash), event,
		string(mutation.ExpectedPassword.PasswordHash), mutation.ExpectedPassword.HistoryDigest).Scan(&encoded); err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, mapAuthorizationDatabaseError("recover local IAM credentials", err)
	}
	var result iamv1.LocalCredentialRecoveryResult
	if json.Unmarshal(encoded, &result) != nil {
		return iamv1.LocalCredentialRecoveryResult{}, identityaccess.ErrUnavailable
	}
	result.CompletedAt = result.CompletedAt.UTC()
	if iamv1.ValidateLocalCredentialRecoveryResult(result) != nil {
		return iamv1.LocalCredentialRecoveryResult{}, identityaccess.ErrUnavailable
	}
	return result, nil
}
