package auditlog

import (
	"context"
	"errors"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/authority"
)

func (service *Service) QueryRecords(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	requestID string,
	request auditv1.QueryRecordsRequest,
) (auditv1.RecordPage, error) {
	return service.queryRecords(ctx, subjectCredential, requestID, request, false)
}

func (service *Service) QueryPlatformRecords(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	requestID string,
	request auditv1.QueryRecordsRequest,
) (auditv1.RecordPage, error) {
	return service.queryRecords(ctx, subjectCredential, requestID, request, true)
}

func (service *Service) queryRecords(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	requestID string,
	request auditv1.QueryRecordsRequest,
	platform bool,
) (auditv1.RecordPage, error) {
	if auditv1.ValidateID("requestId", requestID) != nil ||
		auditv1.ValidateQueryRecordsRequest(request) != nil {
		return auditv1.RecordPage{}, ErrInvalidArgument
	}
	action, accessAction := iamv1.ActionAuditRecordRead, auditv1.ActionAuditRecordsRead
	if platform {
		action, accessAction = iamv1.ActionAuditPlatformRecordRead, auditv1.ActionAuditPlatformRecordsRead
	}
	decision, err := service.authorize(
		ctx,
		subjectCredential,
		requestID,
		action,
		iamv1.ResourceReference{Kind: iamv1.ResourceAuditRecord, ID: "records"},
	)
	if err != nil {
		return auditv1.RecordPage{}, err
	}
	actor, err := actorForDecision(decision)
	if err != nil {
		return auditv1.RecordPage{}, err
	}
	chainID := authority.ChainFor(auditv1.TenantID(decision.TenantID), decision.InstallationID)
	beforeSequence := maximumSequence + 1
	if request.Cursor != "" {
		beforeSequence, err = service.cursors.Decode(request.Cursor, chainID, request)
		if err != nil {
			return auditv1.RecordPage{}, ErrInvalidArgument
		}
	}
	requestDigest, err := digestSanitized("records-query", request)
	if err != nil {
		return auditv1.RecordPage{}, err
	}
	var page auditv1.RecordPage
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		records, err := transaction.ReadRecords(transactionContext, RecordQuery{
			ChainID:        chainID,
			BeforeSequence: beforeSequence,
			Limit:          request.PageSize + 1,
			From:           request.From,
			To:             request.To,
			Action:         request.Action,
			Actor:          request.Actor,
		})
		if err != nil {
			return err
		}
		if len(records) > request.PageSize+1 {
			return ErrUnavailable
		}
		for _, record := range records {
			if !recordMatchesQuery(record, chainID, request) {
				return ErrUnavailable
			}
		}
		visible := records
		if len(visible) > request.PageSize {
			visible = visible[:request.PageSize]
		}
		page = auditv1.RecordPage{
			APIVersion:     auditv1.APIVersion,
			Kind:           "AuditRecordPage",
			TenantID:       chainID.TenantID(),
			InstallationID: chainID.InstallationID(),
			Records:        append([]auditv1.AuditRecord(nil), visible...),
		}
		if len(records) > request.PageSize {
			page.NextCursor, err = service.cursors.Encode(
				chainID,
				request,
				visible[len(visible)-1].Sequence,
			)
			if err != nil {
				return ErrUnavailable
			}
		}
		return service.appendAccessEvent(
			transactionContext,
			transaction,
			decision,
			actor,
			accessAction,
			auditv1.TargetAuditRecords,
			"records",
			requestDigest,
			requestID,
			now,
		)
	})
	if err != nil {
		return auditv1.RecordPage{}, err
	}
	if auditv1.ValidateRecordPage(page) != nil {
		return auditv1.RecordPage{}, ErrUnavailable
	}
	return page, nil
}

func (service *Service) VerifyChain(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	requestID string,
	request auditv1.VerifyChainRequest,
) (auditv1.ChainVerification, error) {
	return service.verifyChain(ctx, subjectCredential, requestID, request, false)
}

func (service *Service) VerifyPlatformChain(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	requestID string,
	request auditv1.VerifyChainRequest,
) (auditv1.ChainVerification, error) {
	return service.verifyChain(ctx, subjectCredential, requestID, request, true)
}

func (service *Service) verifyChain(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	requestID string,
	request auditv1.VerifyChainRequest,
	platform bool,
) (auditv1.ChainVerification, error) {
	if auditv1.ValidateID("requestId", requestID) != nil ||
		auditv1.ValidateVerifyChainRequest(request) != nil {
		return auditv1.ChainVerification{}, ErrInvalidArgument
	}
	action, accessAction := iamv1.ActionAuditIntegrityVerify, auditv1.ActionAuditIntegrityVerified
	if platform {
		action, accessAction = iamv1.ActionAuditPlatformIntegrityVerify, auditv1.ActionAuditPlatformIntegrityVerified
	}
	decision, err := service.authorize(
		ctx,
		subjectCredential,
		requestID,
		action,
		iamv1.ResourceReference{Kind: iamv1.ResourceAuditChain, ID: "chain"},
	)
	if err != nil {
		return auditv1.ChainVerification{}, err
	}
	actor, err := actorForDecision(decision)
	if err != nil {
		return auditv1.ChainVerification{}, err
	}
	chainID := authority.ChainFor(auditv1.TenantID(decision.TenantID), decision.InstallationID)
	requestDigest, err := digestSanitized("chain-verify", request)
	if err != nil {
		return auditv1.ChainVerification{}, err
	}
	var verification auditv1.ChainVerification
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		now, err := transactionTime(transactionContext, transaction)
		if err != nil {
			return err
		}
		var checkpoint authority.Checkpoint
		if request.FromSequence == 1 {
			checkpoint, err = authority.GenesisCheckpoint(chainID)
			if err != nil {
				return ErrUnavailable
			}
		} else {
			var found bool
			checkpoint, found, err = transaction.ReadCheckpoint(
				transactionContext,
				chainID,
				request.FromSequence-1,
			)
			if err != nil {
				return err
			}
			if !found {
				return ErrConflict
			}
		}
		records, err := transaction.ReadChain(
			transactionContext,
			chainID,
			request.FromSequence,
			request.MaximumRecords+1,
		)
		if err != nil {
			return err
		}
		if len(records) == 0 || len(records) > request.MaximumRecords+1 {
			return ErrConflict
		}
		selected := records
		complete := true
		if len(selected) > request.MaximumRecords {
			selected = selected[:request.MaximumRecords]
			complete = false
		}
		last, err := authority.VerifyChain(checkpoint, selected)
		if errors.Is(err, authority.ErrInvalidChain) {
			return ErrConflict
		}
		if err != nil {
			return ErrUnavailable
		}
		verification = auditv1.ChainVerification{
			APIVersion:        auditv1.APIVersion,
			Kind:              "ChainVerification",
			TenantID:          chainID.TenantID(),
			InstallationID:    chainID.InstallationID(),
			State:             auditv1.VerificationVerified,
			FromSequence:      request.FromSequence,
			ToSequence:        last.Sequence,
			RecordCount:       len(selected),
			FirstPreviousHash: selected[0].PreviousHash,
			LastRecordHash:    last.RecordHash,
			Complete:          complete,
			VerifiedAt:        now,
		}
		if !complete {
			next := last.Sequence + 1
			verification.NextSequence = &next
		}
		if auditv1.ValidateChainVerification(verification) != nil {
			return ErrUnavailable
		}
		return service.appendAccessEvent(
			transactionContext,
			transaction,
			decision,
			actor,
			accessAction,
			auditv1.TargetAuditChain,
			"chain",
			requestDigest,
			requestID,
			now,
		)
	})
	if err != nil {
		return auditv1.ChainVerification{}, err
	}
	return verification, nil
}

func (service *Service) authorize(
	ctx context.Context,
	subjectCredential iamv1.Secret,
	requestID string,
	action iamv1.Action,
	resource iamv1.ResourceReference,
) (iamv1.AuthorizationDecision, error) {
	request := iamv1.AuthorizationRequest{
		Action: action, Resource: resource, RequestID: requestID, CorrelationID: requestID,
	}
	decision, err := service.iam.Authorize(ctx, subjectCredential, request)
	if err != nil {
		return iamv1.AuthorizationDecision{}, err
	}
	if iamv1.ValidateAuthorizationDecision(decision) != nil ||
		decision.Action != action || decision.Resource != resource || decision.RequestID != requestID {
		return iamv1.AuthorizationDecision{}, ErrUnavailable
	}
	if !decision.Allowed {
		return iamv1.AuthorizationDecision{}, ErrForbidden
	}
	return decision, nil
}

func (service *Service) appendAccessEvent(
	ctx context.Context,
	transaction Transaction,
	decision iamv1.AuthorizationDecision,
	actor auditv1.ActorReference,
	action auditv1.Action,
	targetKind auditv1.TargetKind,
	targetID string,
	requestDigest string,
	requestID string,
	now time.Time,
) error {
	eventID, err := service.config.NewID("event")
	if err != nil {
		return ErrUnavailable
	}
	event := auditv1.Event{
		APIVersion:     auditv1.APIVersion,
		Kind:           "AuditEvent",
		EventID:        auditv1.EventID(eventID),
		TenantID:       auditv1.TenantID(decision.TenantID),
		InstallationID: decision.InstallationID,
		Actor:          actor,
		IAMDecisionID:  auditv1.DecisionID(decision.ID),
		Action:         action,
		Target:         auditv1.TargetReference{Kind: targetKind, ID: targetID},
		Result:         auditv1.ResultSucceeded,
		RequestDigest:  requestDigest,
		RequestID:      requestID,
		CorrelationID:  requestID,
		OccurredAt:     now,
	}
	if auditv1.ValidateEventForSource(auditv1.SourceAudit, event) != nil {
		return ErrUnavailable
	}
	if err := transaction.LockEvent(ctx, auditv1.SourceAudit, event.EventID); err != nil {
		return err
	}
	if _, found, err := transaction.LookupRecord(ctx, auditv1.SourceAudit, event.EventID); err != nil {
		return err
	} else if found {
		return ErrUnavailable
	}
	head, ingestedAt, err := transaction.LockChainHead(ctx, authority.ChainFor(event.TenantID, event.InstallationID))
	if err != nil {
		return err
	}
	if ingestedAt != now {
		return ErrUnavailable
	}
	record, fact, err := authority.AppendRecord(
		head,
		head.Sequence+1,
		auditv1.SourceAudit,
		event,
		ingestedAt,
	)
	if err != nil {
		return ErrUnavailable
	}
	outcome, err := transaction.AppendRecord(ctx, AppendMutation{Record: record, Fact: fact})
	if err != nil {
		return err
	}
	if outcome != auditv1.IngestionAccepted {
		return ErrUnavailable
	}
	return nil
}

func recordMatchesQuery(
	record auditv1.AuditRecord,
	chainID authority.ChainID,
	request auditv1.QueryRecordsRequest,
) bool {
	if auditv1.ValidateAuditRecord(record) != nil || authority.ChainFor(record.Event.TenantID, record.Event.InstallationID) != chainID {
		return false
	}
	if request.From != nil && record.Event.OccurredAt.Before(*request.From) {
		return false
	}
	if request.To != nil && record.Event.OccurredAt.After(*request.To) {
		return false
	}
	if request.Action != "" && record.Event.Action != request.Action {
		return false
	}
	if request.Actor != nil && record.Event.Actor != *request.Actor {
		return false
	}
	return true
}
