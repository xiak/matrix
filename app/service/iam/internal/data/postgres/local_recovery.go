package postgres

import (
	"context"
	"encoding/json"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
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
	if err := value.tx.QueryRow(ctx, "SELECT iam.recover_local_credentials($1::jsonb,$2::jsonb,$3,$4,$5,$6::jsonb)",
		scope, expected, mutation.CommandID, mutation.InputCommitment, string(mutation.PasswordHash), event).Scan(&encoded); err != nil {
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
