package identityaccess

import (
	"context"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const SchemaVersion uint64 = 43

// CheckSchema is startup admission before bootstrap/material registration,
// not network readiness or permission to serve authentication requests.
func (service *Authority) CheckSchema(ctx context.Context) error {
	return service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		snapshot, err := tx.Readiness(ctx)
		if err != nil {
			return err
		}
		if snapshot.SchemaVersion != SchemaVersion {
			return ErrUnavailable
		}
		return nil
	})
}

func (service *Authority) Readiness(ctx context.Context) (iamv1.Readiness, error) {
	var snapshot ReadinessSnapshot
	err := service.withinTransaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		var err error
		snapshot, err = transaction.Readiness(transactionContext)
		if err != nil || !snapshot.Ready || snapshot.SchemaVersion != SchemaVersion {
			return err
		}
		// Network readiness requires custody even when no AccessKey exists.
		// This check reads the complete immutable history in the same snapshot.
		if err := service.checkAccessKeyCustody(transactionContext, transaction); err != nil {
			return err
		}
		if err := service.checkTOTPCustody(transactionContext, transaction); err != nil {
			return err
		}
		mail, err := transaction.ReadEmailVerificationKeyset(transactionContext)
		if err != nil {
			return err
		}
		if mail == nil && service.email == nil {
			return nil
		}
		if service.email == nil || mail == nil || !service.email.Matches(*mail) {
			return ErrUnavailable
		}
		return nil
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
