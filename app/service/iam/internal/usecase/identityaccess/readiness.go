package identityaccess

import (
	"context"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const SchemaVersion uint64 = 3

func (service *Authority) Readiness(ctx context.Context) (iamv1.Readiness, error) {
	var snapshot ReadinessSnapshot
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		var err error
		snapshot, err = transaction.Readiness(transactionContext)
		return err
	})
	if err != nil {
		return iamv1.Readiness{}, err
	}
	state := iamv1.ReadinessNotReady
	if snapshot.Ready && snapshot.SchemaVersion == SchemaVersion {
		state = iamv1.ReadinessReady
	}
	readiness := iamv1.Readiness{
		APIVersion:    iamv1.APIVersion,
		Kind:          "Readiness",
		State:         state,
		SchemaVersion: snapshot.SchemaVersion,
		CheckedAt:     snapshot.CheckedAt,
	}
	if iamv1.ValidateReadiness(readiness) != nil {
		return iamv1.Readiness{}, ErrUnavailable
	}
	return readiness, nil
}
