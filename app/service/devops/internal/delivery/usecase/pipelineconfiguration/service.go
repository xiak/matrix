package pipelineconfiguration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

type executionPlan[T any] struct {
	authorization   port.Authorization
	kind            MutationKind
	targetID        devopsv1.ResourceID
	idempotencyKey  string
	requestIdentity any
	resultKind      MutationResultKind
	build           func(context.Context, Transaction, time.Time) (T, error)
	result          func(T) MutationResult
	replay          func(MutationResult) (T, error)
	persist         func(context.Context, Transaction, T, Submission) error
}

func (usecase *Usecase) GetProject(
	ctx context.Context,
	query GetProjectQuery,
) (devopsv1.DevOpsProject, error) {
	return readConfiguration(ctx, usecase, query.Authorization,
		iamv1.ActionDevOpsProjectRead, iamv1.ResourceDevOpsProject, query.ProjectID,
		func(ctx context.Context, tx Transaction) (devopsv1.DevOpsProject, bool, error) {
			return tx.LoadProject(ctx, query.ProjectID)
		})
}

func (usecase *Usecase) GetSourceConnection(
	ctx context.Context,
	query GetSourceConnectionQuery,
) (devopsv1.SourceConnection, error) {
	return readConfiguration(ctx, usecase, query.Authorization,
		iamv1.ActionDevOpsSourceConnectionRead, iamv1.ResourceSourceConnection, query.SourceConnectionID,
		func(ctx context.Context, tx Transaction) (devopsv1.SourceConnection, bool, error) {
			return tx.LoadSourceConnection(ctx, query.SourceConnectionID)
		})
}

func (usecase *Usecase) GetRepositoryBinding(
	ctx context.Context,
	query GetRepositoryBindingQuery,
) (devopsv1.RepositoryBinding, error) {
	return readConfiguration(ctx, usecase, query.Authorization,
		iamv1.ActionDevOpsRepositoryBindingRead, iamv1.ResourceRepositoryBinding, query.RepositoryBindingID,
		func(ctx context.Context, tx Transaction) (devopsv1.RepositoryBinding, bool, error) {
			return tx.LoadRepositoryBinding(ctx, query.RepositoryBindingID)
		})
}

func (usecase *Usecase) GetPipeline(
	ctx context.Context,
	query GetPipelineQuery,
) (devopsv1.Pipeline, error) {
	return readConfiguration(ctx, usecase, query.Authorization,
		iamv1.ActionDevOpsPipelineRead, iamv1.ResourcePipeline, query.PipelineID,
		func(ctx context.Context, tx Transaction) (devopsv1.Pipeline, bool, error) {
			return tx.LoadPipeline(ctx, query.PipelineID)
		})
}

func (usecase *Usecase) GetPipelineRevision(
	ctx context.Context,
	query GetPipelineRevisionQuery,
) (devopsv1.PipelineRevision, error) {
	if err := devopsv1.ValidateID("pipelineRevisionId", string(query.PipelineRevisionID)); err != nil {
		return devopsv1.PipelineRevision{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	value, err := readConfiguration(ctx, usecase, query.Authorization,
		iamv1.ActionDevOpsPipelineRead, iamv1.ResourcePipeline, query.PipelineID,
		func(ctx context.Context, tx Transaction) (devopsv1.PipelineRevision, bool, error) {
			return tx.LoadPipelineRevision(ctx, query.PipelineRevisionID)
		})
	if err != nil {
		return devopsv1.PipelineRevision{}, err
	}
	if value.PipelineID != query.PipelineID {
		return devopsv1.PipelineRevision{}, ErrNotFound
	}
	return value, nil
}

func readConfiguration[T any](
	ctx context.Context,
	usecase *Usecase,
	authorization port.Authorization,
	action iamv1.Action,
	resourceKind iamv1.ResourceKind,
	resourceID devopsv1.ResourceID,
	load func(context.Context, Transaction) (T, bool, error),
) (T, error) {
	var zero T
	if usecase == nil || usecase.repository == nil {
		return zero, errors.New("pipeline configuration use case is nil")
	}
	if ctx == nil {
		return zero, errors.New("pipeline configuration context is nil")
	}
	if load == nil {
		return zero, errors.New("pipeline configuration loader is required")
	}
	if err := errors.Join(
		devopsv1.ValidateID("resourceId", string(resourceID)),
		port.ValidateAuthorizationForRequest(authorization, action, resourceKind, resourceID),
	); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	var result T
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		result = zero
		transactionErr = usecase.repository.WithinTransaction(ctx, authorization.TenantID,
			func(txCtx context.Context, tx Transaction) error {
				value, found, err := load(txCtx, tx)
				if err != nil {
					return err
				}
				if !found {
					return ErrNotFound
				}
				result = value
				return nil
			})
		if transactionErr == nil {
			return result, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return zero, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return zero, err
		}
	}
	return zero, fmt.Errorf("pipeline configuration transaction attempts exhausted: %w", transactionErr)
}

func (usecase *Usecase) CreateProject(
	ctx context.Context,
	command CreateProjectCommand,
) (Result[devopsv1.DevOpsProject], error) {
	if err := validateCommand(command.Authorization, MutationCreateProject, command.Request.ID, command.IdempotencyKey, 0,
		devopsv1.ValidateCreateDevOpsProjectRequest(command.Request)); err != nil {
		return Result[devopsv1.DevOpsProject]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.DevOpsProject]{
		authorization: command.Authorization, kind: MutationCreateProject,
		targetID: command.Request.ID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: command.Request, resultKind: ResultDevOpsProject,
		build: func(ctx context.Context, tx Transaction, now time.Time) (devopsv1.DevOpsProject, error) {
			_, found, err := tx.LoadProject(ctx, command.Request.ID)
			if err != nil {
				return devopsv1.DevOpsProject{}, err
			}
			if found {
				return devopsv1.DevOpsProject{}, ErrAlreadyExists
			}
			return domain.NewDevOpsProject(command.Request, tenantScope(command.Authorization), now)
		},
		result: projectResult,
		replay: replayProject,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.DevOpsProject, submission Submission) error {
			return tx.CreateProject(ctx, value, submission)
		},
	})
}

func (usecase *Usecase) CreateSourceConnection(
	ctx context.Context,
	command CreateSourceConnectionCommand,
) (Result[devopsv1.SourceConnection], error) {
	if err := validateCommand(command.Authorization, MutationCreateSourceConnection, command.Request.ID, command.IdempotencyKey, 0,
		devopsv1.ValidateCreateSourceConnectionRequest(command.Request)); err != nil {
		return Result[devopsv1.SourceConnection]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.SourceConnection]{
		authorization: command.Authorization, kind: MutationCreateSourceConnection,
		targetID: command.Request.ID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: command.Request, resultKind: ResultSourceConnection,
		build: func(ctx context.Context, tx Transaction, now time.Time) (devopsv1.SourceConnection, error) {
			_, found, err := tx.LoadSourceConnection(ctx, command.Request.ID)
			if err != nil {
				return devopsv1.SourceConnection{}, err
			}
			if found {
				return devopsv1.SourceConnection{}, ErrAlreadyExists
			}
			return domain.NewSourceConnection(command.Request, tenantScope(command.Authorization), now)
		},
		result: sourceConnectionResult,
		replay: replaySourceConnection,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.SourceConnection, submission Submission) error {
			return tx.CreateSourceConnection(ctx, value, submission)
		},
	})
}

func (usecase *Usecase) UpdateSourceConnection(
	ctx context.Context,
	command UpdateSourceConnectionCommand,
) (Result[devopsv1.SourceConnection], error) {
	identity := struct {
		ID                      devopsv1.ResourceID                    `json:"id"`
		ExpectedResourceVersion uint64                                 `json:"expectedResourceVersion"`
		Request                 devopsv1.UpdateSourceConnectionRequest `json:"request"`
	}{command.SourceConnectionID, command.ExpectedResourceVersion, command.Request}
	if err := validateCommand(command.Authorization, MutationUpdateSourceConnection, command.SourceConnectionID, command.IdempotencyKey,
		command.ExpectedResourceVersion, devopsv1.ValidateUpdateSourceConnectionRequest(command.Request)); err != nil {
		return Result[devopsv1.SourceConnection]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.SourceConnection]{
		authorization: command.Authorization, kind: MutationUpdateSourceConnection,
		targetID: command.SourceConnectionID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: identity, resultKind: ResultSourceConnection,
		build: func(ctx context.Context, tx Transaction, now time.Time) (devopsv1.SourceConnection, error) {
			current, found, err := tx.LoadSourceConnection(ctx, command.SourceConnectionID)
			if err != nil || !found {
				return devopsv1.SourceConnection{}, missing(err, found)
			}
			return domain.UpdateSourceConnection(current, command.ExpectedResourceVersion, command.Request, now)
		},
		result: sourceConnectionResult,
		replay: replaySourceConnection,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.SourceConnection, submission Submission) error {
			return tx.UpdateSourceConnection(ctx, command.ExpectedResourceVersion, value, submission)
		},
	})
}

func (usecase *Usecase) RecheckSourceConnection(
	ctx context.Context,
	command RecheckSourceConnectionCommand,
) (Result[devopsv1.SourceConnection], error) {
	identity := struct {
		ID                      devopsv1.ResourceID `json:"id"`
		ExpectedResourceVersion uint64              `json:"expectedResourceVersion"`
	}{command.SourceConnectionID, command.ExpectedResourceVersion}
	if err := validateCommand(command.Authorization, MutationRecheckSourceConnection, command.SourceConnectionID,
		command.IdempotencyKey, command.ExpectedResourceVersion, nil); err != nil {
		return Result[devopsv1.SourceConnection]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.SourceConnection]{
		authorization: command.Authorization, kind: MutationRecheckSourceConnection,
		targetID: command.SourceConnectionID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: identity, resultKind: ResultSourceConnection,
		build: func(ctx context.Context, tx Transaction, _ time.Time) (devopsv1.SourceConnection, error) {
			current, found, err := tx.LoadSourceConnection(ctx, command.SourceConnectionID)
			if err != nil || !found {
				return devopsv1.SourceConnection{}, missing(err, found)
			}
			if current.Metadata.ResourceVersion != command.ExpectedResourceVersion {
				return devopsv1.SourceConnection{}, ErrResourceVersionConflict
			}
			return current, nil
		},
		result: sourceConnectionResult,
		replay: replaySourceConnection,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.SourceConnection, submission Submission) error {
			return tx.RecheckSourceConnection(ctx, command.ExpectedResourceVersion, value, submission)
		},
	})
}

func (usecase *Usecase) CreateRepositoryBinding(
	ctx context.Context,
	command CreateRepositoryBindingCommand,
) (Result[devopsv1.RepositoryBinding], error) {
	if err := validateCommand(command.Authorization, MutationCreateRepositoryBinding, command.Request.ID, command.IdempotencyKey, 0,
		devopsv1.ValidateCreateRepositoryBindingRequest(command.Request)); err != nil {
		return Result[devopsv1.RepositoryBinding]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.RepositoryBinding]{
		authorization: command.Authorization, kind: MutationCreateRepositoryBinding,
		targetID: command.Request.ID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: command.Request, resultKind: ResultRepositoryBinding,
		build: func(ctx context.Context, tx Transaction, now time.Time) (devopsv1.RepositoryBinding, error) {
			_, exists, err := tx.LoadRepositoryBinding(ctx, command.Request.ID)
			if err != nil {
				return devopsv1.RepositoryBinding{}, err
			}
			if exists {
				return devopsv1.RepositoryBinding{}, ErrAlreadyExists
			}
			project, found, err := tx.LoadProject(ctx, command.Request.ProjectID)
			if err != nil || !found {
				return devopsv1.RepositoryBinding{}, missing(err, found)
			}
			connection, found, err := tx.LoadSourceConnection(ctx, command.Request.Spec.SourceConnectionID)
			if err != nil || !found {
				return devopsv1.RepositoryBinding{}, missing(err, found)
			}
			return domain.NewRepositoryBinding(command.Request, project, connection, now)
		},
		result: repositoryBindingResult,
		replay: replayRepositoryBinding,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.RepositoryBinding, submission Submission) error {
			return tx.CreateRepositoryBinding(ctx, value, submission)
		},
	})
}

func (usecase *Usecase) UpdateRepositoryBinding(
	ctx context.Context,
	command UpdateRepositoryBindingCommand,
) (Result[devopsv1.RepositoryBinding], error) {
	identity := struct {
		ID                      devopsv1.ResourceID                     `json:"id"`
		ExpectedResourceVersion uint64                                  `json:"expectedResourceVersion"`
		Request                 devopsv1.UpdateRepositoryBindingRequest `json:"request"`
	}{command.RepositoryBindingID, command.ExpectedResourceVersion, command.Request}
	if err := validateCommand(command.Authorization, MutationUpdateRepositoryBinding, command.RepositoryBindingID, command.IdempotencyKey,
		command.ExpectedResourceVersion, devopsv1.ValidateUpdateRepositoryBindingRequest(command.Request)); err != nil {
		return Result[devopsv1.RepositoryBinding]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.RepositoryBinding]{
		authorization: command.Authorization, kind: MutationUpdateRepositoryBinding,
		targetID: command.RepositoryBindingID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: identity, resultKind: ResultRepositoryBinding,
		build: func(ctx context.Context, tx Transaction, now time.Time) (devopsv1.RepositoryBinding, error) {
			current, found, err := tx.LoadRepositoryBinding(ctx, command.RepositoryBindingID)
			if err != nil || !found {
				return devopsv1.RepositoryBinding{}, missing(err, found)
			}
			project, found, err := tx.LoadProject(ctx, current.ProjectID)
			if err != nil || !found {
				return devopsv1.RepositoryBinding{}, missing(err, found)
			}
			connection, found, err := tx.LoadSourceConnection(ctx, command.Request.Spec.SourceConnectionID)
			if err != nil || !found {
				return devopsv1.RepositoryBinding{}, missing(err, found)
			}
			return domain.UpdateRepositoryBinding(current, command.ExpectedResourceVersion, command.Request, project, connection, now)
		},
		result: repositoryBindingResult,
		replay: replayRepositoryBinding,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.RepositoryBinding, submission Submission) error {
			return tx.UpdateRepositoryBinding(ctx, command.ExpectedResourceVersion, value, submission)
		},
	})
}

func (usecase *Usecase) RecheckRepositoryBinding(
	ctx context.Context,
	command RecheckRepositoryBindingCommand,
) (Result[devopsv1.RepositoryBinding], error) {
	identity := struct {
		ID                      devopsv1.ResourceID `json:"id"`
		ExpectedResourceVersion uint64              `json:"expectedResourceVersion"`
	}{command.RepositoryBindingID, command.ExpectedResourceVersion}
	if err := validateCommand(command.Authorization, MutationRecheckRepositoryBinding, command.RepositoryBindingID,
		command.IdempotencyKey, command.ExpectedResourceVersion, nil); err != nil {
		return Result[devopsv1.RepositoryBinding]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.RepositoryBinding]{
		authorization: command.Authorization, kind: MutationRecheckRepositoryBinding,
		targetID: command.RepositoryBindingID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: identity, resultKind: ResultRepositoryBinding,
		build: func(ctx context.Context, tx Transaction, _ time.Time) (devopsv1.RepositoryBinding, error) {
			current, found, err := tx.LoadRepositoryBinding(ctx, command.RepositoryBindingID)
			if err != nil || !found {
				return devopsv1.RepositoryBinding{}, missing(err, found)
			}
			if current.Metadata.ResourceVersion != command.ExpectedResourceVersion {
				return devopsv1.RepositoryBinding{}, ErrResourceVersionConflict
			}
			return current, nil
		},
		result: repositoryBindingResult,
		replay: replayRepositoryBinding,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.RepositoryBinding, submission Submission) error {
			return tx.RecheckRepositoryBinding(ctx, command.ExpectedResourceVersion, value, submission)
		},
	})
}

func (usecase *Usecase) CreatePipeline(
	ctx context.Context,
	command CreatePipelineCommand,
) (Result[devopsv1.Pipeline], error) {
	if err := validateCommand(command.Authorization, MutationCreatePipeline, command.Request.ID, command.IdempotencyKey, 0,
		devopsv1.ValidateCreatePipelineRequest(command.Request)); err != nil {
		return Result[devopsv1.Pipeline]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.Pipeline]{
		authorization: command.Authorization, kind: MutationCreatePipeline,
		targetID: command.Request.ID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: command.Request, resultKind: ResultPipeline,
		build: func(ctx context.Context, tx Transaction, now time.Time) (devopsv1.Pipeline, error) {
			_, exists, err := tx.LoadPipeline(ctx, command.Request.ID)
			if err != nil {
				return devopsv1.Pipeline{}, err
			}
			if exists {
				return devopsv1.Pipeline{}, ErrAlreadyExists
			}
			project, found, err := tx.LoadProject(ctx, command.Request.ProjectID)
			if err != nil || !found {
				return devopsv1.Pipeline{}, missing(err, found)
			}
			binding, found, err := tx.LoadRepositoryBinding(ctx, command.Request.Draft.RepositoryBindingID)
			if err != nil || !found {
				return devopsv1.Pipeline{}, missing(err, found)
			}
			return domain.NewPipeline(command.Request, project, binding, now)
		},
		result: pipelineResult,
		replay: replayPipeline,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.Pipeline, submission Submission) error {
			return tx.CreatePipeline(ctx, value, submission)
		},
	})
}

func (usecase *Usecase) UpdatePipelineDraft(
	ctx context.Context,
	command UpdatePipelineDraftCommand,
) (Result[devopsv1.Pipeline], error) {
	identity := struct {
		ID                      devopsv1.ResourceID                 `json:"id"`
		ExpectedResourceVersion uint64                              `json:"expectedResourceVersion"`
		Request                 devopsv1.UpdatePipelineDraftRequest `json:"request"`
	}{command.PipelineID, command.ExpectedResourceVersion, command.Request}
	if err := validateCommand(command.Authorization, MutationUpdatePipelineDraft, command.PipelineID, command.IdempotencyKey,
		command.ExpectedResourceVersion, devopsv1.ValidateUpdatePipelineDraftRequest(command.Request)); err != nil {
		return Result[devopsv1.Pipeline]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.Pipeline]{
		authorization: command.Authorization, kind: MutationUpdatePipelineDraft,
		targetID: command.PipelineID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: identity, resultKind: ResultPipeline,
		build: func(ctx context.Context, tx Transaction, now time.Time) (devopsv1.Pipeline, error) {
			current, found, err := tx.LoadPipeline(ctx, command.PipelineID)
			if err != nil || !found {
				return devopsv1.Pipeline{}, missing(err, found)
			}
			binding, found, err := tx.LoadRepositoryBinding(ctx, command.Request.Draft.RepositoryBindingID)
			if err != nil || !found {
				return devopsv1.Pipeline{}, missing(err, found)
			}
			return domain.UpdatePipelineDraft(current, command.ExpectedResourceVersion, command.Request, binding, now)
		},
		result: pipelineResult,
		replay: replayPipeline,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.Pipeline, submission Submission) error {
			return tx.UpdatePipelineDraft(ctx, command.ExpectedResourceVersion, value, submission)
		},
	})
}

func (usecase *Usecase) ActivatePipeline(
	ctx context.Context,
	command ActivatePipelineCommand,
) (Result[devopsv1.PipelineActivation], error) {
	identity := struct {
		ID                      devopsv1.ResourceID `json:"id"`
		ExpectedResourceVersion uint64              `json:"expectedResourceVersion"`
	}{command.PipelineID, command.ExpectedResourceVersion}
	if err := validateCommand(command.Authorization, MutationActivatePipeline, command.PipelineID, command.IdempotencyKey,
		command.ExpectedResourceVersion, nil); err != nil {
		return Result[devopsv1.PipelineActivation]{}, err
	}
	return execute(ctx, usecase, executionPlan[devopsv1.PipelineActivation]{
		authorization: command.Authorization, kind: MutationActivatePipeline,
		targetID: command.PipelineID, idempotencyKey: command.IdempotencyKey,
		requestIdentity: identity, resultKind: ResultPipelineActivation,
		build: func(ctx context.Context, tx Transaction, now time.Time) (devopsv1.PipelineActivation, error) {
			current, found, err := tx.LoadPipeline(ctx, command.PipelineID)
			if err != nil || !found {
				return devopsv1.PipelineActivation{}, missing(err, found)
			}
			binding, found, err := tx.LoadRepositoryBinding(ctx, current.Draft.Spec.RepositoryBindingID)
			if err != nil || !found {
				return devopsv1.PipelineActivation{}, missing(err, found)
			}
			return domain.ActivatePipeline(current, command.ExpectedResourceVersion, command.Authorization.Subject, binding, now)
		},
		result: pipelineActivationResult,
		replay: replayPipelineActivation,
		persist: func(ctx context.Context, tx Transaction, value devopsv1.PipelineActivation, submission Submission) error {
			return tx.ActivatePipeline(ctx, command.ExpectedResourceVersion, value, submission)
		},
	})
}

func execute[T any](ctx context.Context, usecase *Usecase, plan executionPlan[T]) (Result[T], error) {
	var zero T
	if usecase == nil || usecase.repository == nil {
		return Result[T]{}, errors.New("pipeline configuration use case is nil")
	}
	if ctx == nil {
		return Result[T]{}, errors.New("pipeline configuration context is nil")
	}
	fingerprint, err := digestJSON(struct {
		TenantID       devopsv1.TenantID   `json:"tenantId"`
		Subject        devopsv1.SubjectRef `json:"subject"`
		Kind           MutationKind        `json:"kind"`
		TargetID       devopsv1.ResourceID `json:"targetId"`
		IdempotencyKey string              `json:"idempotencyKey"`
	}{plan.authorization.TenantID, plan.authorization.Subject, plan.kind, plan.targetID, plan.idempotencyKey})
	if err != nil {
		return Result[T]{}, err
	}
	requestDigest, err := digestJSON(struct {
		Kind    MutationKind `json:"kind"`
		Request any          `json:"request"`
	}{plan.kind, plan.requestIdentity})
	if err != nil {
		return Result[T]{}, err
	}

	var result Result[T]
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		result = Result[T]{}
		transactionErr = usecase.repository.WithinTransaction(ctx, plan.authorization.TenantID,
			func(txCtx context.Context, tx Transaction) error {
				stored, found, err := tx.FindMutation(txCtx, fingerprint)
				if err != nil {
					return err
				}
				if found {
					if err := ValidateStoredMutation(stored); err != nil {
						return fmt.Errorf("validate stored mutation: %w", err)
					}
					if stored.Record.Kind != plan.kind || stored.Record.CommandTargetID != plan.targetID ||
						stored.Record.RequestedBy != plan.authorization.Subject || stored.Record.IAMAction != plan.authorization.Action ||
						stored.Record.IAMResource != plan.authorization.Resource || stored.Record.RequestDigest != requestDigest ||
						stored.Record.ResultKind != plan.resultKind {
						return ErrIdempotencyConflict
					}
					value, err := plan.replay(stored.Result)
					if err != nil {
						return err
					}
					result = Result[T]{Value: value, Replayed: true}
					return nil
				}
				now, err := tx.TransactionTime(txCtx)
				if err != nil {
					return err
				}
				value, err := plan.build(txCtx, tx, now)
				if err != nil {
					return mapDomainError(err)
				}
				mutationResult := plan.result(value)
				contract, _ := ContractForMutation(plan.kind)
				record := MutationRecord{
					SchemaVersion: "v1", ID: operationID(fingerprint), TenantID: plan.authorization.TenantID,
					Kind: plan.kind, CommandTargetID: plan.targetID, RequestedBy: plan.authorization.Subject,
					IAMDecisionID: plan.authorization.DecisionID, IAMAction: plan.authorization.Action,
					IAMResource: plan.authorization.Resource, IdempotencyFingerprint: fingerprint,
					RequestDigest: requestDigest, ResultKind: plan.resultKind,
					Target:    auditv1.TargetReference{Kind: contract.AuditTargetKind, ID: resultTargetID(mutationResult)},
					RequestID: plan.authorization.RequestID, CorrelationID: plan.authorization.CorrelationID,
					TraceParent: plan.authorization.TraceParent, CreatedAt: now,
				}
				auditEvent := newAuditEvent(record, contract.AuditAction)
				submission := Submission{Record: record, Result: mutationResult, AuditEvent: auditEvent}
				if err := ValidateSubmission(submission); err != nil {
					return fmt.Errorf("invalid delivery submission: %w", err)
				}
				if err := plan.persist(txCtx, tx, value, submission); err != nil {
					return err
				}
				result = Result[T]{Value: value}
				return nil
			})
		if transactionErr == nil {
			return result, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return Result[T]{}, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return Result[T]{}, err
		}
	}
	return Result[T]{Value: zero}, fmt.Errorf("pipeline configuration transaction attempts exhausted: %w", transactionErr)
}

func validateCommand(auth port.Authorization, kind MutationKind, targetID devopsv1.ResourceID, idempotencyKey string, expectedVersion uint64, requestErr error) error {
	contract, known := ContractForMutation(kind)
	if !known {
		return fmt.Errorf("%w: unknown mutation kind", ErrInvalidArgument)
	}
	var problems []error
	problems = append(problems, requestErr,
		port.ValidateAuthorizationForRequest(auth, contract.IAMAction, contract.IAMResourceKind, targetID),
		devopsv1.ValidateID("targetId", string(targetID)), validateIdempotencyKey(idempotencyKey),
	)
	if expectedVersion > devopsv1.MaximumContractInteger ||
		(expectedVersion == 0 && (strings.HasPrefix(string(kind), "UPDATE_") ||
			strings.HasPrefix(string(kind), "RECHECK_") || kind == MutationActivatePipeline)) {
		problems = append(problems, errors.New("expected resource version is invalid"))
	}
	if err := errors.Join(problems...); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return nil
}

func validateIdempotencyKey(value string) error {
	if value == "" || len([]byte(value)) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return errors.New("Idempotency-Key is invalid")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("Idempotency-Key is invalid")
		}
	}
	return nil
}

func digestJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode delivery mutation identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func operationID(fingerprint string) string {
	digest := sha256.Sum256([]byte("matrix-devops-operation-v1\x00" + fingerprint))
	return "operation-" + hex.EncodeToString(digest[:])
}

func newAuditEvent(record MutationRecord, action auditv1.Action) auditv1.Event {
	digest := sha256.Sum256([]byte("matrix-devops-audit-event-v1\x00" + record.ID))
	return auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent",
		EventID:       auditv1.EventID("audit-" + hex.EncodeToString(digest[:])),
		TenantID:      auditv1.TenantID(record.TenantID),
		Actor:         auditv1.ActorReference{Type: auditv1.ActorType(record.RequestedBy.Kind), ID: auditv1.ActorID(record.RequestedBy.ID)},
		IAMDecisionID: auditv1.DecisionID(record.IAMDecisionID), Action: action,
		Target: record.Target, Result: auditv1.ResultSucceeded, RequestDigest: record.RequestDigest,
		RequestID: record.RequestID, CorrelationID: record.CorrelationID,
		OperationID: auditv1.OperationID(record.ID), TraceParent: record.TraceParent, OccurredAt: record.CreatedAt,
	}
}

func tenantScope(auth port.Authorization) devopsv1.ResourceScope {
	return devopsv1.ResourceScope{TenantID: auth.TenantID}
}

func missing(err error, found bool) error {
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	return nil
}

func mapDomainError(err error) error {
	switch {
	case errors.Is(err, domain.ErrVersionConflict), errors.Is(err, domain.ErrVersionExhausted):
		return fmt.Errorf("%w: %v", ErrResourceVersionConflict, err)
	case errors.Is(err, domain.ErrUnchangedSpec), errors.Is(err, domain.ErrUnchangedDraft):
		return fmt.Errorf("%w: %v", ErrNoDesiredChange, err)
	case errors.Is(err, domain.ErrImmutableConnectionIdentity), errors.Is(err, domain.ErrReferenceMismatch):
		return fmt.Errorf("%w: %v", ErrPreconditionFailed, err)
	case errors.Is(err, domain.ErrInvalidTime):
		return fmt.Errorf("%w: %v", ErrRetryableTransaction, err)
	default:
		return err
	}
}

func projectResult(value devopsv1.DevOpsProject) MutationResult {
	return MutationResult{Kind: ResultDevOpsProject, Project: &value}
}
func sourceConnectionResult(value devopsv1.SourceConnection) MutationResult {
	return MutationResult{Kind: ResultSourceConnection, SourceConnection: &value}
}
func repositoryBindingResult(value devopsv1.RepositoryBinding) MutationResult {
	return MutationResult{Kind: ResultRepositoryBinding, RepositoryBinding: &value}
}
func pipelineResult(value devopsv1.Pipeline) MutationResult {
	return MutationResult{Kind: ResultPipeline, Pipeline: &value}
}
func pipelineActivationResult(value devopsv1.PipelineActivation) MutationResult {
	return MutationResult{Kind: ResultPipelineActivation, PipelineActivation: &value}
}

func replayProject(value MutationResult) (devopsv1.DevOpsProject, error) {
	if value.Project == nil {
		return devopsv1.DevOpsProject{}, errors.New("stored mutation result is not a DevOpsProject")
	}
	return *value.Project, nil
}
func replaySourceConnection(value MutationResult) (devopsv1.SourceConnection, error) {
	if value.SourceConnection == nil {
		return devopsv1.SourceConnection{}, errors.New("stored mutation result is not a SourceConnection")
	}
	return *value.SourceConnection, nil
}
func replayRepositoryBinding(value MutationResult) (devopsv1.RepositoryBinding, error) {
	if value.RepositoryBinding == nil {
		return devopsv1.RepositoryBinding{}, errors.New("stored mutation result is not a RepositoryBinding")
	}
	return *value.RepositoryBinding, nil
}
func replayPipeline(value MutationResult) (devopsv1.Pipeline, error) {
	if value.Pipeline == nil {
		return devopsv1.Pipeline{}, errors.New("stored mutation result is not a Pipeline")
	}
	return *value.Pipeline, nil
}
func replayPipelineActivation(value MutationResult) (devopsv1.PipelineActivation, error) {
	if value.PipelineActivation == nil {
		return devopsv1.PipelineActivation{}, errors.New("stored mutation result is not a PipelineActivation")
	}
	return *value.PipelineActivation, nil
}
