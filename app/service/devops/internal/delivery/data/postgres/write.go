package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
)

func (transaction *configurationTransaction) CreateProject(ctx context.Context, value devopsv1.DevOpsProject, submission pipelineconfiguration.Submission) error {
	return transaction.commit(ctx, pipelineconfiguration.MutationCreateProject, 0, value, nil, submission)
}

func (transaction *configurationTransaction) CreateSourceConnection(ctx context.Context, value devopsv1.SourceConnection, submission pipelineconfiguration.Submission) error {
	return transaction.commit(ctx, pipelineconfiguration.MutationCreateSourceConnection, 0, value, nil, submission)
}

func (transaction *configurationTransaction) UpdateSourceConnection(ctx context.Context, expected uint64, value devopsv1.SourceConnection, submission pipelineconfiguration.Submission) error {
	return transaction.commit(ctx, pipelineconfiguration.MutationUpdateSourceConnection, expected, value, nil, submission)
}

func (transaction *configurationTransaction) CreateRepositoryBinding(ctx context.Context, value devopsv1.RepositoryBinding, submission pipelineconfiguration.Submission) error {
	return transaction.commit(ctx, pipelineconfiguration.MutationCreateRepositoryBinding, 0, value, nil, submission)
}

func (transaction *configurationTransaction) UpdateRepositoryBinding(ctx context.Context, expected uint64, value devopsv1.RepositoryBinding, submission pipelineconfiguration.Submission) error {
	return transaction.commit(ctx, pipelineconfiguration.MutationUpdateRepositoryBinding, expected, value, nil, submission)
}

func (transaction *configurationTransaction) CreatePipeline(ctx context.Context, value devopsv1.Pipeline, submission pipelineconfiguration.Submission) error {
	return transaction.commit(ctx, pipelineconfiguration.MutationCreatePipeline, 0, value, nil, submission)
}

func (transaction *configurationTransaction) UpdatePipelineDraft(ctx context.Context, expected uint64, value devopsv1.Pipeline, submission pipelineconfiguration.Submission) error {
	return transaction.commit(ctx, pipelineconfiguration.MutationUpdatePipelineDraft, expected, value, nil, submission)
}

func (transaction *configurationTransaction) ActivatePipeline(ctx context.Context, expected uint64, value devopsv1.PipelineActivation, submission pipelineconfiguration.Submission) error {
	return transaction.commit(ctx, pipelineconfiguration.MutationActivatePipeline, expected, value.Pipeline, value.Revision, submission)
}

func (transaction *configurationTransaction) commit(
	ctx context.Context,
	kind pipelineconfiguration.MutationKind,
	expectedResourceVersion uint64,
	resource any,
	secondary any,
	submission pipelineconfiguration.Submission,
) error {
	if err := validateCommit(transaction.tenantID, kind, expectedResourceVersion, resource, secondary, submission); err != nil {
		return err
	}
	resourceDocument, err := json.Marshal(resource)
	if err != nil {
		return fmt.Errorf("encode delivery resource: %w", err)
	}
	var secondaryDocument any
	if secondary != nil {
		secondaryDocument, err = json.Marshal(secondary)
		if err != nil {
			return fmt.Errorf("encode delivery secondary resource: %w", err)
		}
	}
	recordDocument, err := json.Marshal(submission.Record)
	if err != nil {
		return fmt.Errorf("encode delivery mutation: %w", err)
	}
	resultDocument, err := json.Marshal(submission.Result)
	if err != nil {
		return fmt.Errorf("encode delivery mutation result: %w", err)
	}
	auditDocument, err := json.Marshal(submission.AuditEvent)
	if err != nil {
		return fmt.Errorf("encode delivery Audit event: %w", err)
	}
	if _, err := transaction.tx.Exec(ctx,
		`SELECT delivery.commit_configuration_mutation(
		    $1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6::jsonb, $7::jsonb
		)`, string(kind), int64(expectedResourceVersion), resourceDocument, secondaryDocument,
		recordDocument, resultDocument, auditDocument,
	); err != nil {
		return fmt.Errorf("commit %s delivery mutation: %w", kind, err)
	}
	return nil
}

func validateCommit(
	tenantID devopsv1.TenantID,
	kind pipelineconfiguration.MutationKind,
	expectedResourceVersion uint64,
	resource any,
	secondary any,
	submission pipelineconfiguration.Submission,
) error {
	var problems []error
	problems = append(problems, pipelineconfiguration.ValidateSubmission(submission))
	if submission.Record.TenantID != tenantID || submission.Record.Kind != kind {
		problems = append(problems, errors.New("delivery mutation does not match transaction identity"))
	}
	if expectedResourceVersion > devopsv1.MaximumContractInteger {
		problems = append(problems, errors.New("expected resource version exceeds contract"))
	}
	var resourceValidation error
	switch value := resource.(type) {
	case devopsv1.DevOpsProject:
		resourceValidation = devopsv1.ValidateDevOpsProject(value)
	case devopsv1.SourceConnection:
		resourceValidation = devopsv1.ValidateSourceConnection(value)
	case devopsv1.RepositoryBinding:
		resourceValidation = devopsv1.ValidateRepositoryBinding(value)
	case devopsv1.Pipeline:
		resourceValidation = devopsv1.ValidatePipeline(value)
	default:
		resourceValidation = fmt.Errorf("unsupported delivery resource %T", resource)
	}
	problems = append(problems, resourceValidation)
	if secondary != nil {
		revision, ok := secondary.(devopsv1.PipelineRevision)
		if !ok {
			problems = append(problems, fmt.Errorf("unsupported delivery secondary resource %T", secondary))
		} else {
			problems = append(problems, devopsv1.ValidatePipelineRevision(revision))
		}
	}
	resourceDocument, resourceErr := json.Marshal(resource)
	var resultResource any
	switch {
	case submission.Result.Project != nil:
		resultResource = *submission.Result.Project
	case submission.Result.SourceConnection != nil:
		resultResource = *submission.Result.SourceConnection
	case submission.Result.RepositoryBinding != nil:
		resultResource = *submission.Result.RepositoryBinding
	case submission.Result.Pipeline != nil:
		resultResource = *submission.Result.Pipeline
	case submission.Result.PipelineActivation != nil:
		resultResource = submission.Result.PipelineActivation.Pipeline
	}
	resultResourceDocument, resultErr := json.Marshal(resultResource)
	if resourceErr != nil || resultErr != nil || !bytes.Equal(resourceDocument, resultResourceDocument) {
		problems = append(problems, errors.New("delivery mutation result does not contain the submitted resource"))
	}
	return errors.Join(problems...)
}
