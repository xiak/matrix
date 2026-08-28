package identityaccess

import (
	"context"
	"errors"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

// InspectLocalCredentialRecovery is deliberately absent from the HTTP port.
// The composition root supplies a separate purpose-only database identity.
func (service *Authority) InspectLocalCredentialRecovery(ctx context.Context, local iamv1.LocalCredentialRecoveryAuthority, query *iamv1.LocalCredentialRecoveryReceiptQuery) (iamv1.LocalCredentialRecoveryInspection, error) {
	if iamv1.ValidateLocalCredentialRecoveryAuthority(local) != nil ||
		query != nil && iamv1.ValidateLocalCredentialRecoveryReceiptQuery(*query) != nil {
		return iamv1.LocalCredentialRecoveryInspection{}, ErrInvalidArgument
	}
	var result iamv1.LocalCredentialRecoveryInspection
	err := service.withinTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		var err error
		result, err = transaction.InspectLocalCredentialRecovery(ctx, local.Scope, query)
		return err
	})
	if err != nil {
		return iamv1.LocalCredentialRecoveryInspection{}, err
	}
	if iamv1.ValidateLocalCredentialRecoveryInspection(result) != nil || result.Scope != local.Scope ||
		query == nil && result.State != "ELIGIBLE" ||
		query != nil && (result.CommandID != query.CommandID || result.InputCommitment != query.InputCommitment || result.State == "ELIGIBLE") {
		return iamv1.LocalCredentialRecoveryInspection{}, ErrUnavailable
	}
	return result, nil
}

func (service *Authority) RecoverLocalCredentials(ctx context.Context, local iamv1.LocalCredentialRecoveryAuthority, request iamv1.LocalCredentialRecoveryRequest) (iamv1.LocalCredentialRecoveryResult, error) {
	commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(local, request)
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, ErrForbidden
	}
	if service == nil || service.passwords == nil || service.repository == nil {
		return iamv1.LocalCredentialRecoveryResult{}, ErrUnavailable
	}
	passwordHash, err := service.passwords.Hash(request.NewPassword)
	if err != nil {
		if errors.Is(err, authority.ErrWeakPassword) {
			return iamv1.LocalCredentialRecoveryResult{}, ErrInvalidArgument
		}
		return iamv1.LocalCredentialRecoveryResult{}, ErrUnavailable
	}
	metadata := struct {
		CommandID string                                `json:"commandId"`
		Scope     iamv1.LocalCredentialRecoveryScope    `json:"scope"`
		Expected  iamv1.LocalCredentialRecoveryExpected `json:"expected"`
	}{request.CommandID, request.Scope, request.Expected}
	digest, err := digestSanitized(string(auditv1.ActionIAMInstallationPrimaryCredentialsRecovered), metadata)
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, err
	}
	eventID, err := service.config.NewID("event")
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, ErrUnavailable
	}
	mutation := LocalCredentialRecoveryMutation{
		Scope: request.Scope, Expected: request.Expected, CommandID: request.CommandID,
		InputCommitment: commitment, PasswordHash: passwordHash,
	}
	var result iamv1.LocalCredentialRecoveryResult
	err = service.withinTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		now, err := transactionTime(ctx, transaction)
		if err != nil {
			return err
		}
		mutation.AuditEvent, err = newAuditEvent(eventID, "", request.Scope.InstallationID,
			auditv1.ActorReference{Type: auditv1.ActorSystem, ID: iamv1.LocalCredentialRecoveryActor},
			auditv1.ActionIAMInstallationPrimaryCredentialsRecovered,
			auditv1.TargetReference{Kind: auditv1.TargetPrincipal, ID: string(request.Scope.PrincipalID), TenantID: auditv1.TenantID(request.Scope.OrganizationID)},
			auditv1.ResultSucceeded, "", digest, request.CommandID, request.CommandID, now)
		if err != nil {
			return err
		}
		result, err = transaction.RecoverLocalCredentials(ctx, mutation)
		return err
	})
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, err
	}
	if iamv1.ValidateLocalCredentialRecoveryResult(result) != nil || result.Scope != request.Scope ||
		result.CommandID != request.CommandID || result.InputCommitment != commitment ||
		result.PreviousCredentialGeneration != request.Expected.CredentialGeneration ||
		result.PrincipalResourceVersion != request.Expected.PrincipalResourceVersion+1 {
		return iamv1.LocalCredentialRecoveryResult{}, ErrUnavailable
	}
	return result, nil
}
