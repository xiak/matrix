package auditlog

import (
	"context"
	"errors"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/authority"
)

func (service *Service) Ingest(
	ctx context.Context,
	serviceCredential iamv1.Secret,
	event auditv1.Event,
) (auditv1.IngestionResult, error) {
	if auditv1.ValidateEvent(event) != nil {
		return auditv1.IngestionResult{}, ErrInvalidArgument
	}
	producer, err := service.iam.ResolveAuditProducer(ctx, serviceCredential, iamv1.ResolveAuditProducerRequest{
		Event: event,
	})
	if err != nil {
		return auditv1.IngestionResult{}, err
	}
	if iamv1.ValidateAuditProducerAuthorization(producer) != nil || producer.TenantID != iamv1.OrganizationID(event.TenantID) ||
		producer.InstallationID != event.InstallationID {
		return auditv1.IngestionResult{}, ErrUnavailable
	}
	source, err := sourceForIdentity(producer.Producer)
	if err != nil {
		return auditv1.IngestionResult{}, err
	}
	_, digest, err := auditv1.CanonicalizeEvent(source, event)
	if err != nil {
		return auditv1.IngestionResult{}, ErrInvalidArgument
	}
	if digest != producer.ContentDigest {
		return auditv1.IngestionResult{}, ErrUnavailable
	}
	var result auditv1.IngestionResult
	err = service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		if err := transaction.LockEvent(transactionContext, source, event.EventID); err != nil {
			return err
		}
		existing, found, err := transaction.LookupRecord(transactionContext, source, event.EventID)
		if err != nil {
			return err
		}
		if found {
			outcome, _, err := authority.ClassifyReplay(&existing.Replay, source, event)
			if errors.Is(err, authority.ErrReplayConflict) {
				return ErrConflict
			}
			if err != nil || outcome != authority.ReplayEqual ||
				auditv1.ValidateAuditRecord(existing.Record) != nil {
				return ErrUnavailable
			}
			result = auditv1.IngestionResult{
				APIVersion: auditv1.APIVersion,
				Kind:       "IngestionResult",
				Outcome:    auditv1.IngestionDuplicate,
				Record:     existing.Record,
			}
			return nil
		}
		head, ingestedAt, err := transaction.LockChainHead(
			transactionContext, authority.ChainFor(event.TenantID, event.InstallationID),
		)
		if err != nil {
			return err
		}
		record, fact, err := authority.AppendRecord(
			head,
			head.Sequence+1,
			source,
			event,
			ingestedAt,
		)
		if err != nil {
			return ErrUnavailable
		}
		outcome, err := transaction.AppendRecord(transactionContext, AppendMutation{Record: record, Fact: fact})
		if err != nil {
			return err
		}
		if outcome != auditv1.IngestionAccepted {
			return ErrUnavailable
		}
		result = auditv1.IngestionResult{
			APIVersion: auditv1.APIVersion,
			Kind:       "IngestionResult",
			Outcome:    outcome,
			Record:     record,
		}
		return nil
	})
	if err != nil {
		return auditv1.IngestionResult{}, err
	}
	if auditv1.ValidateIngestionResult(result) != nil {
		return auditv1.IngestionResult{}, ErrUnavailable
	}
	return result, nil
}
