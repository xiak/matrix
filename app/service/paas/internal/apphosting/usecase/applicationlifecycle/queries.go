package applicationlifecycle

import (
	"context"
	"errors"
	"fmt"
	"maps"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

func (usecase *Usecase) InspectApplicationDirectory(
	ctx context.Context,
	subject port.AuthorizationSubjectContext,
	after paasv1.ResourceID,
) (ApplicationDirectorySnapshot, error) {
	if usecase == nil || usecase.repository == nil || ctx == nil ||
		port.ValidateAuthorizationSubjectContext(subject) != nil ||
		(after != "" && paasv1.ValidateID("after", string(after)) != nil) {
		return ApplicationDirectorySnapshot{}, ErrInvalidArgument
	}
	var applications []paasv1.Application
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		applications = nil
		transactionErr = usecase.repository.WithinReadOnlyTransaction(ctx, subject.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				var err error
				applications, err = transaction.ListApplicationsAfter(transactionContext, after, paasv1.ApplicationDirectoryPageSize+1)
				return err
			})
		if transactionErr == nil {
			hasMore := len(applications) > paasv1.ApplicationDirectoryPageSize
			if hasMore {
				applications = applications[:paasv1.ApplicationDirectoryPageSize]
			}
			candidates := make([]ApplicationAuthorizationSnapshot, len(applications))
			for index, application := range applications {
				candidates[index] = ApplicationAuthorizationSnapshot{ID: application.Metadata.ID,
					ResourceVersion: application.Metadata.ResourceVersion, Labels: maps.Clone(application.Metadata.Labels)}
			}
			return ApplicationDirectorySnapshot{Candidates: candidates, HasMore: hasMore}, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return ApplicationDirectorySnapshot{}, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return ApplicationDirectorySnapshot{}, err
		}
	}
	return ApplicationDirectorySnapshot{}, fmt.Errorf("application directory inspection attempts exhausted: %w", transactionErr)
}

func (usecase *Usecase) ReadApplicationDirectory(
	ctx context.Context,
	command ReadApplicationDirectoryCommand,
) ([]paasv1.Application, error) {
	if usecase == nil || usecase.repository == nil || ctx == nil || validateApplicationDirectoryCommand(command) != nil {
		return nil, ErrInvalidArgument
	}
	ids := make([]paasv1.ResourceID, len(command.Snapshot.Candidates))
	for index, candidate := range command.Snapshot.Candidates {
		ids[index] = candidate.ID
	}
	var applications []paasv1.Application
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		applications = nil
		transactionErr = usecase.repository.WithinReadOnlyTransaction(ctx, command.Subject.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				var err error
				applications, err = transaction.LoadApplications(transactionContext, ids)
				if err != nil {
					return err
				}
				if len(applications) != len(command.Snapshot.Candidates) {
					return ErrAuthorizationSnapshotChanged
				}
				for index, application := range applications {
					candidate := command.Snapshot.Candidates[index]
					decision := command.Decisions.Items[index]
					if application.Metadata.ID != candidate.ID ||
						application.Metadata.ResourceVersion != candidate.ResourceVersion ||
						!maps.Equal(application.Metadata.Labels, candidate.Labels) ||
						port.ValidateAuthorizationResourceTagsForAction(port.Authorization{
							TenantID: command.Decisions.TenantID, Subject: command.Decisions.Subject,
							DecisionID: decision.DecisionID, RequestID: decision.RequestID,
							RequestTags: decision.RequestTags, ResourceTags: decision.ResourceTags,
						}, port.AuthorizeApplicationRead, application.Metadata.Labels) != nil {
						return ErrAuthorizationSnapshotChanged
					}
				}
				return nil
			})
		if transactionErr == nil {
			allowed := make([]paasv1.Application, 0, len(applications))
			for index, application := range applications {
				if command.Decisions.Items[index].Allowed {
					allowed = append(allowed, application)
				}
			}
			return allowed, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return nil, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("application directory read attempts exhausted: %w", transactionErr)
}

func validateApplicationDirectoryCommand(command ReadApplicationDirectoryCommand) error {
	if port.ValidateAuthorizationSubjectContext(command.Subject) != nil ||
		command.Decisions.Items == nil || len(command.Decisions.Items) != len(command.Snapshot.Candidates) ||
		command.Decisions.TenantID != command.Subject.TenantID ||
		!command.Decisions.Subject.Equal(command.Subject.Subject) ||
		len(command.Snapshot.Candidates) > paasv1.ApplicationDirectoryPageSize ||
		(command.Snapshot.HasMore && len(command.Snapshot.Candidates) != paasv1.ApplicationDirectoryPageSize) {
		return ErrInvalidArgument
	}
	previous := paasv1.ResourceID("")
	seenRequests := make(map[string]bool, len(command.Decisions.Items))
	for index, candidate := range command.Snapshot.Candidates {
		decision := command.Decisions.Items[index]
		if paasv1.ValidateID("candidate.id", string(candidate.ID)) != nil ||
			candidate.ResourceVersion == 0 || candidate.ResourceVersion > 9007199254740991 ||
			paasv1.ValidateLabels(candidate.Labels) != nil ||
			(index > 0 && candidate.ID <= previous) ||
			decision.Resource != (paasv1.ResourceRef{Kind: port.ResourceApplication, ID: candidate.ID}) ||
			paasv1.ValidateID("decision.requestId", decision.RequestID) != nil || seenRequests[decision.RequestID] ||
			paasv1.ValidateID("decision.id", decision.DecisionID) != nil || len(decision.RequestTags) != 0 ||
			iamv1.CheckAuthorizationResourceTagsForAction(decision.ResourceTags, port.AuthorizeApplicationRead, candidate.Labels) != nil {
			return ErrInvalidArgument
		}
		seenRequests[decision.RequestID] = true
		previous = candidate.ID
	}
	return nil
}

func (usecase *Usecase) InspectApplicationAuthorization(
	ctx context.Context,
	subject port.AuthorizationSubjectContext,
	id paasv1.ResourceID,
) (ApplicationAuthorizationSnapshot, error) {
	if usecase == nil || usecase.repository == nil || ctx == nil ||
		port.ValidateAuthorizationSubjectContext(subject) != nil || paasv1.ValidateID("application.id", string(id)) != nil {
		return ApplicationAuthorizationSnapshot{}, ErrInvalidArgument
	}
	var application paasv1.Application
	var found bool
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		application, found = paasv1.Application{}, false
		transactionErr = usecase.repository.WithinReadOnlyTransaction(ctx, subject.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				var err error
				application, found, err = transaction.LoadApplication(transactionContext, id)
				return err
			})
		if transactionErr == nil {
			if !found {
				return ApplicationAuthorizationSnapshot{}, ErrNotFound
			}
			return ApplicationAuthorizationSnapshot{ID: application.Metadata.ID,
				ResourceVersion: application.Metadata.ResourceVersion, Labels: maps.Clone(application.Metadata.Labels)}, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return ApplicationAuthorizationSnapshot{}, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return ApplicationAuthorizationSnapshot{}, err
		}
	}
	return ApplicationAuthorizationSnapshot{}, fmt.Errorf("application authorization inspection attempts exhausted: %w", transactionErr)
}

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
