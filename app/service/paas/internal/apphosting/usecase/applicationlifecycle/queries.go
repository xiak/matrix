package applicationlifecycle

import (
	"context"
	"errors"
	"fmt"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

func (usecase *Usecase) GetApplication(
	ctx context.Context,
	authorization port.Authorization,
	id paasv1.ResourceID,
) (paasv1.Application, error) {
	return readResource(ctx, usecase, authorization, func(ctx context.Context, transaction Transaction) (paasv1.Application, bool, error) {
		return transaction.LoadApplication(ctx, id)
	})
}

func (usecase *Usecase) GetConfiguration(
	ctx context.Context,
	authorization port.Authorization,
	id paasv1.ResourceID,
) (paasv1.Configuration, error) {
	return readResource(ctx, usecase, authorization, func(ctx context.Context, transaction Transaction) (paasv1.Configuration, bool, error) {
		return transaction.LoadConfiguration(ctx, id)
	})
}

func (usecase *Usecase) GetConfigurationRevision(
	ctx context.Context,
	authorization port.Authorization,
	id paasv1.ResourceID,
) (paasv1.ConfigurationRevision, error) {
	return readResource(ctx, usecase, authorization, func(ctx context.Context, transaction Transaction) (paasv1.ConfigurationRevision, bool, error) {
		return transaction.LoadConfigurationRevision(ctx, id)
	})
}

func (usecase *Usecase) GetApplicationRevision(
	ctx context.Context,
	authorization port.Authorization,
	id paasv1.ResourceID,
) (paasv1.ApplicationRevision, error) {
	return readResource(ctx, usecase, authorization, func(ctx context.Context, transaction Transaction) (paasv1.ApplicationRevision, bool, error) {
		value, err := transaction.LoadApplicationRevision(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return paasv1.ApplicationRevision{}, false, nil
		}
		return value, err == nil, err
	})
}

func (usecase *Usecase) GetDeployment(
	ctx context.Context,
	authorization port.Authorization,
	id paasv1.ResourceID,
) (paasv1.Deployment, error) {
	return readResource(ctx, usecase, authorization, func(ctx context.Context, transaction Transaction) (paasv1.Deployment, bool, error) {
		return transaction.LoadDeployment(ctx, id)
	})
}

func (usecase *Usecase) ListDeployments(
	ctx context.Context,
	authorization port.Authorization,
	after paasv1.ResourceID,
) (paasv1.DeploymentList, error) {
	if usecase == nil || usecase.repository == nil {
		return paasv1.DeploymentList{}, errors.New("application lifecycle use case is nil")
	}
	if ctx == nil {
		return paasv1.DeploymentList{}, errors.New("application lifecycle context is nil")
	}
	if err := port.ValidateAuthorization(authorization); err != nil {
		return paasv1.DeploymentList{}, err
	}
	if after != "" && paasv1.ValidateID("after", string(after)) != nil {
		return paasv1.DeploymentList{}, ErrInvalidArgument
	}
	var result paasv1.DeploymentList
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		result = paasv1.DeploymentList{}
		transactionErr = usecase.repository.WithinTransaction(
			ctx,
			authorization.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				items, nextAfter, err := transaction.ListDeployments(
					transactionContext,
					after,
					paasv1.MaximumDeploymentListItems,
				)
				if err != nil {
					return err
				}
				result = paasv1.DeploymentList{
					APIVersion: paasv1.APIVersion,
					Kind:       "DeploymentList",
					Scope: paasv1.ResourceScope{
						Kind: paasv1.AuthorityTenant, TenantID: authorization.TenantID,
					},
					Items: items, NextAfter: nextAfter,
				}
				if paasv1.ValidateDeploymentList(result) != nil {
					return errors.New("stored Deployment list is invalid")
				}
				return nil
			},
		)
		if transactionErr == nil {
			return result, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return paasv1.DeploymentList{}, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return paasv1.DeploymentList{}, err
		}
	}
	return paasv1.DeploymentList{}, fmt.Errorf(
		"application lifecycle read attempts exhausted: %w",
		transactionErr,
	)
}

func (usecase *Usecase) GetDeploymentRuntime(
	ctx context.Context,
	authorization port.Authorization,
	id paasv1.ResourceID,
) (paasv1.DeploymentRuntimeSnapshot, error) {
	return readResource(ctx, usecase, authorization, func(
		ctx context.Context,
		transaction Transaction,
	) (paasv1.DeploymentRuntimeSnapshot, bool, error) {
		return transaction.LoadDeploymentRuntime(ctx, id)
	})
}

func (usecase *Usecase) GetDeploymentGeneration(
	ctx context.Context,
	authorization port.Authorization,
	deploymentID paasv1.ResourceID,
	generation uint64,
) (paasv1.DeploymentGeneration, error) {
	return readResource(ctx, usecase, authorization, func(ctx context.Context, transaction Transaction) (paasv1.DeploymentGeneration, bool, error) {
		value, err := transaction.LoadAcceptedGeneration(ctx, deploymentID, generation)
		if errors.Is(err, ErrNotFound) {
			return paasv1.DeploymentGeneration{}, false, nil
		}
		return value, err == nil, err
	})
}

func (usecase *Usecase) GetOperation(
	ctx context.Context,
	authorization port.Authorization,
	id paasv1.OperationID,
) (paasv1.Operation, error) {
	return readResource(ctx, usecase, authorization, func(ctx context.Context, transaction Transaction) (paasv1.Operation, bool, error) {
		return transaction.LoadOperation(ctx, id)
	})
}

func readResource[T any](
	ctx context.Context,
	usecase *Usecase,
	authorization port.Authorization,
	load func(context.Context, Transaction) (T, bool, error),
) (T, error) {
	var zero T
	if usecase == nil || usecase.repository == nil {
		return zero, errors.New("application lifecycle use case is nil")
	}
	if ctx == nil {
		return zero, errors.New("application lifecycle context is nil")
	}
	if err := port.ValidateAuthorization(authorization); err != nil {
		return zero, err
	}
	if load == nil {
		return zero, errors.New("application lifecycle resource loader is required")
	}

	var value T
	var found bool
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		value, found = zero, false
		transactionErr = usecase.repository.WithinTransaction(
			ctx,
			authorization.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				var err error
				value, found, err = load(transactionContext, transaction)
				return err
			},
		)
		if transactionErr == nil {
			if !found {
				return zero, ErrNotFound
			}
			return value, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return zero, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return zero, err
		}
	}
	return zero, fmt.Errorf("application lifecycle read attempts exhausted: %w", transactionErr)
}
