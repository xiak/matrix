package auditlog

import (
	"context"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func (service *Service) Readiness(ctx context.Context) (auditv1.Readiness, error) {
	var snapshot ReadinessSnapshot
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		var err error
		snapshot, err = transaction.Readiness(transactionContext)
		return err
	})
	if err != nil {
		return auditv1.Readiness{}, err
	}
	state := auditv1.ReadinessNotReady
	if snapshot.Ready {
		state = auditv1.ReadinessReady
	}
	result := auditv1.Readiness{
		APIVersion:    auditv1.APIVersion,
		Kind:          "Readiness",
		State:         state,
		SchemaVersion: snapshot.SchemaVersion,
		CheckedAt:     snapshot.CheckedAt,
	}
	if auditv1.ValidateReadiness(result) != nil {
		return auditv1.Readiness{}, ErrUnavailable
	}
	return result, nil
}
