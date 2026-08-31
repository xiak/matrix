package auditlog

import (
	"context"
	"errors"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/authority"
)

func (service *Service) VerifyInstallation(
	ctx context.Context,
	verifierCredential iamv1.Secret,
	requestID string,
	request auditv1.VerifyInstallationRequest,
) (auditv1.InstallationVerification, error) {
	if ctx == nil || !verifierCredential.Present() ||
		auditv1.ValidateID("requestId", requestID) != nil ||
		auditv1.ValidateVerifyInstallationRequest(request) != nil {
		return auditv1.InstallationVerification{}, ErrInvalidArgument
	}
	authorizationRequest := iamv1.AuthorizationRequest{
		Action: iamv1.ActionInstallationVerify,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation,
			ID:   request.InstallationID,
		},
		RequestID:     requestID,
		CorrelationID: requestID,
	}
	decision, err := service.iam.VerifyInstallation(
		ctx, verifierCredential, authorizationRequest,
	)
	if err != nil {
		return auditv1.InstallationVerification{}, err
	}
	if iamv1.ValidateAuthorizationDecision(decision) != nil ||
		decision.Action != authorizationRequest.Action ||
		decision.Resource != authorizationRequest.Resource ||
		decision.RequestID != requestID {
		return auditv1.InstallationVerification{}, ErrUnavailable
	}
	if !decision.Allowed {
		return auditv1.InstallationVerification{}, ErrForbidden
	}
	if decision.Subject == nil || decision.Subject.Type != iamv1.PrincipalServiceAccount {
		return auditv1.InstallationVerification{}, ErrUnavailable
	}
	actor, err := actorForDecision(decision)
	if err != nil {
		return auditv1.InstallationVerification{}, err
	}
	requestDigest, err := digestSanitized("installation-verification", request)
	if err != nil {
		return auditv1.InstallationVerification{}, err
	}

	tenantID := auditv1.TenantID(decision.TenantID)
	chainID := authority.TenantChain(tenantID)
	var verification auditv1.InstallationVerification
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		verification = auditv1.InstallationVerification{
			APIVersion:     auditv1.APIVersion,
			Kind:           "InstallationVerification",
			InstallationID: request.InstallationID,
			OperationID:    request.OperationID,
			DeploymentID:   request.DeploymentID,
			State:          auditv1.InstallationVerificationPending,
			CheckedAt:      now,
		}
		record, found, err := transaction.LookupPaaSOperationRecord(
			transactionContext, chainID, request.OperationID,
		)
		if err != nil || !found {
			return err
		}
		if !installationProbeRecordMatches(record, tenantID, actor, request) {
			return ErrConflict
		}

		fromSequence := uint64(1)
		if record.Sequence > uint64(auditv1.MaxVerifyRecords) {
			fromSequence = record.Sequence - uint64(auditv1.MaxVerifyRecords) + 1
		}
		var checkpoint authority.Checkpoint
		if fromSequence == 1 {
			checkpoint, err = authority.GenesisCheckpoint(chainID)
			if err != nil {
				return ErrUnavailable
			}
		} else {
			var checkpointFound bool
			checkpoint, checkpointFound, err = transaction.ReadCheckpoint(
				transactionContext, chainID, fromSequence-1,
			)
			if err != nil {
				return err
			}
			if !checkpointFound {
				return ErrConflict
			}
		}
		maximumRecords := int(record.Sequence-fromSequence) + 1
		records, err := transaction.ReadChain(
			transactionContext, chainID, fromSequence, maximumRecords,
		)
		if err != nil {
			return err
		}
		targetIndex := -1
		for index := range records {
			if records[index].Sequence == record.Sequence {
				targetIndex = index
				break
			}
		}
		if targetIndex < 0 || records[targetIndex].RecordHash != record.RecordHash ||
			records[targetIndex].Event.EventID != record.Event.EventID {
			return ErrConflict
		}
		selected := records[:targetIndex+1]
		last, err := authority.VerifyChain(checkpoint, selected)
		if errors.Is(err, authority.ErrInvalidChain) {
			return ErrConflict
		}
		if err != nil || last.Sequence != record.Sequence || last.RecordHash != record.RecordHash {
			return ErrUnavailable
		}
		verification.State = auditv1.InstallationVerificationVerified
		verification.EventID = record.Event.EventID
		verification.IAMDecisionID = record.Event.IAMDecisionID
		verification.RecordSequence = record.Sequence
		verification.FromSequence = fromSequence
		verification.ToSequence = record.Sequence
		verification.RecordHash = record.RecordHash
		if auditv1.ValidateInstallationVerification(verification) != nil {
			return ErrUnavailable
		}
		return service.appendAccessEvent(
			transactionContext,
			transaction,
			decision,
			actor,
			auditv1.ActionAuditIntegrityVerified,
			auditv1.TargetAuditChain,
			"installation-verification",
			requestDigest,
			requestID,
			now,
		)
	})
	if err != nil {
		return auditv1.InstallationVerification{}, err
	}
	if auditv1.ValidateInstallationVerification(verification) != nil {
		return auditv1.InstallationVerification{}, ErrUnavailable
	}
	return verification, nil
}

func installationProbeRecordMatches(
	record auditv1.AuditRecord,
	tenantID auditv1.TenantID,
	actor auditv1.ActorReference,
	request auditv1.VerifyInstallationRequest,
) bool {
	if auditv1.ValidateAuditRecord(record) != nil ||
		record.Source != auditv1.SourcePaaS ||
		record.Event.TenantID != tenantID ||
		record.Event.Actor != actor ||
		record.Event.OperationID != request.OperationID ||
		record.Event.Target != (auditv1.TargetReference{
			Kind: auditv1.TargetDeployment,
			ID:   request.DeploymentID,
		}) || record.Event.Result != auditv1.ResultAccepted ||
		record.Event.IAMDecisionID == "" {
		return false
	}
	return record.Event.Action == auditv1.ActionPaaSDeploymentCreated ||
		record.Event.Action == auditv1.ActionPaaSDeploymentUpdated
}
