package domain

import (
	"errors"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

var (
	ErrVersionConflict  = errors.New("resource version conflict")
	ErrUnchangedDraft   = errors.New("pipeline draft has no activatable change")
	ErrVersionExhausted = errors.New("resource version is exhausted")
	ErrInvalidTime      = errors.New("mutation time is invalid")
)

func NewDevOpsProject(
	request devopsv1.CreateDevOpsProjectRequest,
	scope devopsv1.ResourceScope,
	createdAt time.Time,
) (devopsv1.DevOpsProject, error) {
	if err := devopsv1.ValidateCreateDevOpsProjectRequest(request); err != nil {
		return devopsv1.DevOpsProject{}, err
	}
	project := devopsv1.DevOpsProject{
		APIVersion: devopsv1.APIVersion,
		Kind:       "DevOpsProject",
		Metadata: devopsv1.ResourceMetadata{
			ID: request.ID, Name: request.Name, Scope: scope,
			ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
	}
	if err := devopsv1.ValidateDevOpsProject(project); err != nil {
		return devopsv1.DevOpsProject{}, err
	}
	return project, nil
}

func NewPipeline(
	request devopsv1.CreatePipelineRequest,
	project devopsv1.DevOpsProject,
	binding devopsv1.RepositoryBinding,
	createdAt time.Time,
) (devopsv1.Pipeline, error) {
	if err := devopsv1.ValidateCreatePipelineRequest(request); err != nil {
		return devopsv1.Pipeline{}, err
	}
	if err := validateBindingForProject(project, binding); err != nil ||
		request.ProjectID != project.Metadata.ID ||
		request.Draft.RepositoryBindingID != binding.Metadata.ID {
		return devopsv1.Pipeline{}, ErrReferenceMismatch
	}
	pipeline := devopsv1.Pipeline{
		APIVersion: devopsv1.APIVersion,
		Kind:       "Pipeline",
		Metadata: devopsv1.ResourceMetadata{
			ID: request.ID, Name: request.Name, Scope: project.Metadata.Scope,
			ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		ProjectID: request.ProjectID,
		Draft: devopsv1.PipelineDraft{
			Spec:          request.Draft,
			ContentDigest: devopsv1.PipelineDraftSpecDigest(request.Draft),
		},
	}
	if err := devopsv1.ValidatePipeline(pipeline); err != nil {
		return devopsv1.Pipeline{}, err
	}
	return pipeline, nil
}

func UpdatePipelineDraft(
	current devopsv1.Pipeline,
	expectedResourceVersion uint64,
	request devopsv1.UpdatePipelineDraftRequest,
	binding devopsv1.RepositoryBinding,
	updatedAt time.Time,
) (devopsv1.Pipeline, error) {
	if err := devopsv1.ValidatePipeline(current); err != nil {
		return devopsv1.Pipeline{}, err
	}
	if err := devopsv1.ValidateUpdatePipelineDraftRequest(request); err != nil {
		return devopsv1.Pipeline{}, err
	}
	if devopsv1.ValidateRepositoryBinding(binding) != nil ||
		current.Metadata.Scope != binding.Metadata.Scope ||
		current.ProjectID != binding.ProjectID ||
		request.Draft.RepositoryBindingID != binding.Metadata.ID {
		return devopsv1.Pipeline{}, ErrReferenceMismatch
	}
	if err := validateMutation(current.Metadata, expectedResourceVersion, updatedAt); err != nil {
		return devopsv1.Pipeline{}, err
	}
	digest := devopsv1.PipelineDraftSpecDigest(request.Draft)
	if digest == current.Draft.ContentDigest {
		return devopsv1.Pipeline{}, ErrUnchangedDraft
	}

	updated := clonePipeline(current)
	updated.Metadata.ResourceVersion++
	updated.Metadata.UpdatedAt = updatedAt
	updated.Draft = devopsv1.PipelineDraft{Spec: request.Draft, ContentDigest: digest}
	if err := devopsv1.ValidatePipeline(updated); err != nil {
		return devopsv1.Pipeline{}, err
	}
	return updated, nil
}

func ActivatePipeline(
	current devopsv1.Pipeline,
	expectedResourceVersion uint64,
	actor devopsv1.SubjectRef,
	binding devopsv1.RepositoryBinding,
	activatedAt time.Time,
) (devopsv1.PipelineActivation, error) {
	if err := devopsv1.ValidatePipeline(current); err != nil {
		return devopsv1.PipelineActivation{}, err
	}
	if err := devopsv1.ValidateSubjectRef(actor); err != nil {
		return devopsv1.PipelineActivation{}, err
	}
	if devopsv1.ValidateRepositoryBinding(binding) != nil ||
		current.Metadata.Scope != binding.Metadata.Scope ||
		current.ProjectID != binding.ProjectID ||
		current.Draft.Spec.RepositoryBindingID != binding.Metadata.ID {
		return devopsv1.PipelineActivation{}, ErrReferenceMismatch
	}
	if err := validateMutation(current.Metadata, expectedResourceVersion, activatedAt); err != nil {
		return devopsv1.PipelineActivation{}, err
	}

	revisionNumber := uint64(1)
	if current.ActiveRevision != nil {
		if current.ActiveRevision.Revision >= devopsv1.MaximumContractInteger {
			return devopsv1.PipelineActivation{}, ErrVersionExhausted
		}
		revisionNumber = current.ActiveRevision.Revision + 1
	}
	revisionSpec := resolveRevisionSpec(current.Draft.Spec, binding)
	if err := devopsv1.ValidatePipelineRevisionSpec(revisionSpec); err != nil {
		return devopsv1.PipelineActivation{}, err
	}
	contentDigest := devopsv1.PipelineRevisionSpecDigest(revisionSpec)
	if current.ActiveRevision != nil && current.ActiveRevision.ContentDigest == contentDigest {
		return devopsv1.PipelineActivation{}, ErrUnchangedDraft
	}
	revisionID, err := devopsv1.PipelineRevisionID(
		current.Metadata.Scope,
		current.Metadata.ID,
		revisionNumber,
		contentDigest,
	)
	if err != nil {
		return devopsv1.PipelineActivation{}, err
	}
	revision := devopsv1.PipelineRevision{
		APIVersion:    devopsv1.APIVersion,
		Kind:          "PipelineRevision",
		ID:            revisionID,
		Scope:         current.Metadata.Scope,
		PipelineID:    current.Metadata.ID,
		ProjectID:     current.ProjectID,
		Revision:      revisionNumber,
		Spec:          revisionSpec,
		ContentDigest: contentDigest,
		ActivatedBy:   actor,
		ActivatedAt:   activatedAt,
	}
	updated := current
	updated.Metadata.ResourceVersion++
	updated.Metadata.UpdatedAt = activatedAt
	updated.ActiveRevision = &devopsv1.PipelineRevisionReference{
		ID: revision.ID, Revision: revision.Revision, ContentDigest: revision.ContentDigest,
	}
	activation := devopsv1.PipelineActivation{
		APIVersion: devopsv1.APIVersion,
		Kind:       "PipelineActivation",
		Pipeline:   updated,
		Revision:   revision,
	}
	if err := devopsv1.ValidatePipelineActivation(activation); err != nil {
		return devopsv1.PipelineActivation{}, err
	}
	return activation, nil
}

func resolveRevisionSpec(
	draft devopsv1.PipelineDraftSpec,
	binding devopsv1.RepositoryBinding,
) devopsv1.PipelineRevisionSpec {
	return devopsv1.PipelineRevisionSpec{
		RepositoryBindingID:     draft.RepositoryBindingID,
		RepositoryBindingDigest: binding.ContentDigest,
		TriggerPolicy:           draft.TriggerPolicy,
		VerificationProfile:     draft.VerificationProfile,
		ExecutorProfile:         devopsv1.ExecutorMatrixNativeIsolatedV1,
		ToolchainImageDigest:    devopsv1.Go126OfflineToolchainImageDigest,
		DependencyEgress:        draft.DependencyEgress,
		ReporterPolicy:          draft.ReporterPolicy,
		Steps:                   devopsv1.FixedVerificationSteps(),
		Limits:                  devopsv1.FixedVerificationLimits(),
	}
}

func clonePipeline(value devopsv1.Pipeline) devopsv1.Pipeline {
	cloned := value
	if value.ActiveRevision != nil {
		reference := *value.ActiveRevision
		cloned.ActiveRevision = &reference
	}
	return cloned
}
