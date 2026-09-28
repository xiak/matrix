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
	err := service.withinLocalCredentialRecoveryTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
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
	// Authenticate the private intent first, then reconcile its immutable
	// completion. Old admitted input must not acquire a new write or fail an
	// exact historical replay merely because password rules changed later.
	query := iamv1.LocalCredentialRecoveryReceiptQuery{
		APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryReceiptQuery",
		CommandID: request.CommandID, InputCommitment: commitment,
	}
	inspection, err := service.InspectLocalCredentialRecovery(ctx, local, &query)
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, err
	}
	if inspection.State == "COMPLETED" {
		return localCredentialRecoveryReplay(inspection, request, commitment)
	}
	if err := service.acquirePasswordWork(ctx); err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, err
	}
	defer service.releasePasswordWork()
	var material PasswordReplacementMaterial
	err = service.withinLocalCredentialRecoveryTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		var err error
		inspection, material, err = tx.PrepareLocalCredentialRecovery(ctx, local.Scope, request.Expected, query)
		return err
	})
	if err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, err
	}
	if iamv1.ValidateLocalCredentialRecoveryInspection(inspection) != nil || inspection.Scope != local.Scope ||
		inspection.CommandID != request.CommandID || inspection.InputCommitment != commitment {
		return iamv1.LocalCredentialRecoveryResult{}, ErrUnavailable
	}
	// Another caller can complete this exact intent after the first inspection.
	// Its historical result still precedes current password admission.
	if inspection.State == "COMPLETED" {
		return localCredentialRecoveryReplay(inspection, request, commitment)
	}
	if inspection.State != "NOT_FOUND" || material.CredentialGeneration != request.Expected.CredentialGeneration {
		return iamv1.LocalCredentialRecoveryResult{}, ErrUnavailable
	}
	if err := service.validatePasswordReplacement(ctx, request.NewPassword, material.PasswordHash, material.PasswordHistory, material.HistoryDigest); err != nil {
		return iamv1.LocalCredentialRecoveryResult{}, err
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
		InputCommitment: commitment, PasswordHash: passwordHash, ExpectedPassword: material,
	}
	var result iamv1.LocalCredentialRecoveryResult
	err = service.withinLocalCredentialRecoveryTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		now, err := transactionTime(ctx, transaction)
		if err != nil {
			return err
		}
		mutation.AuditEvent, err = newAuditEvent(eventID, "", request.Scope.InstallationID,
			auditv1.ActorReference{Type: auditv1.ActorSystem, ID: iamv1.LocalCredentialRecoveryActor},
			auditv1.ActionIAMInstallationPrimaryCredentialsRecovered,
			auditv1.TargetReference{Kind: auditv1.TargetPrincipal, ID: string(request.Scope.PrincipalID), TenantID: auditv1.TenantID(request.Scope.AccountID)},
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

func localCredentialRecoveryReplay(inspection iamv1.LocalCredentialRecoveryInspection, request iamv1.LocalCredentialRecoveryRequest, commitment string) (iamv1.LocalCredentialRecoveryResult, error) {
	if inspection.Expected == nil || *inspection.Expected != request.Expected || inspection.Result == nil {
		return iamv1.LocalCredentialRecoveryResult{}, ErrUnavailable
	}
	result := *inspection.Result
	if iamv1.ValidateLocalCredentialRecoveryResult(result) != nil || result.Scope != request.Scope ||
		result.CommandID != request.CommandID || result.InputCommitment != commitment ||
		result.PreviousCredentialGeneration != request.Expected.CredentialGeneration ||
		result.PrincipalResourceVersion != request.Expected.PrincipalResourceVersion+1 {
		return iamv1.LocalCredentialRecoveryResult{}, ErrUnavailable
	}
	result.State = "EQUAL_REPLAY"
	return result, nil
}
