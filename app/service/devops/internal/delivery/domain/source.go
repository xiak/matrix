package domain

import (
	"errors"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

var (
	ErrUnchangedSpec               = errors.New("resource specification is unchanged")
	ErrImmutableConnectionIdentity = errors.New("source connection identity is immutable")
	ErrReferenceMismatch           = errors.New("referenced resource does not share the required authority")
	ErrInvalidHealthObservation    = errors.New("source health observation is invalid")
)

type SourceConnectionHealthObservation struct {
	Health devopsv1.SourceConnectionHealth
	Reason devopsv1.SourceConnectionHealthReason
}

type RepositoryBindingHealthObservation struct {
	Health devopsv1.RepositoryBindingHealth
	Reason devopsv1.RepositoryBindingHealthReason
}

func NewSourceConnection(
	request devopsv1.CreateSourceConnectionRequest,
	scope devopsv1.ResourceScope,
	createdAt time.Time,
) (devopsv1.SourceConnection, error) {
	if err := devopsv1.ValidateCreateSourceConnectionRequest(request); err != nil {
		return devopsv1.SourceConnection{}, err
	}
	connection := devopsv1.SourceConnection{
		APIVersion: devopsv1.APIVersion,
		Kind:       "SourceConnection",
		Metadata: devopsv1.ResourceMetadata{
			ID: request.ID, Name: request.Name, Scope: scope,
			ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Spec: request.Spec,
		Status: devopsv1.SourceConnectionStatus{
			Health:     devopsv1.SourceConnectionPending,
			Reason:     devopsv1.SourceConnectionReasonConfigurationChanged,
			ObservedAt: createdAt,
		},
	}
	if err := devopsv1.ValidateSourceConnection(connection); err != nil {
		return devopsv1.SourceConnection{}, err
	}
	return connection, nil
}

func UpdateSourceConnection(
	current devopsv1.SourceConnection,
	expectedResourceVersion uint64,
	request devopsv1.UpdateSourceConnectionRequest,
	updatedAt time.Time,
) (devopsv1.SourceConnection, error) {
	if err := devopsv1.ValidateSourceConnection(current); err != nil {
		return devopsv1.SourceConnection{}, err
	}
	if err := devopsv1.ValidateUpdateSourceConnectionRequest(request); err != nil {
		return devopsv1.SourceConnection{}, err
	}
	if err := validateMutation(current.Metadata, expectedResourceVersion, updatedAt); err != nil {
		return devopsv1.SourceConnection{}, err
	}
	if current.Spec.AdapterID != request.Spec.AdapterID ||
		current.Spec.EndpointOrigin != request.Spec.EndpointOrigin {
		return devopsv1.SourceConnection{}, ErrImmutableConnectionIdentity
	}
	if equalSourceConnectionSpec(current.Spec, request.Spec) {
		return devopsv1.SourceConnection{}, ErrUnchangedSpec
	}

	updated := current
	updated.Metadata.ResourceVersion++
	updated.Metadata.UpdatedAt = updatedAt
	updated.Spec = request.Spec
	updated.Status = devopsv1.SourceConnectionStatus{
		Health:     devopsv1.SourceConnectionPending,
		Reason:     devopsv1.SourceConnectionReasonConfigurationChanged,
		ObservedAt: updatedAt,
	}
	if err := devopsv1.ValidateSourceConnection(updated); err != nil {
		return devopsv1.SourceConnection{}, err
	}
	return updated, nil
}

func NewRepositoryBinding(
	request devopsv1.CreateRepositoryBindingRequest,
	project devopsv1.DevOpsProject,
	connection devopsv1.SourceConnection,
	createdAt time.Time,
) (devopsv1.RepositoryBinding, error) {
	if err := devopsv1.ValidateCreateRepositoryBindingRequest(request); err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	if err := validateConnectionForProject(project, connection); err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	if request.ProjectID != project.Metadata.ID ||
		request.Spec.SourceConnectionID != connection.Metadata.ID {
		return devopsv1.RepositoryBinding{}, ErrReferenceMismatch
	}
	binding := devopsv1.RepositoryBinding{
		APIVersion: devopsv1.APIVersion,
		Kind:       "RepositoryBinding",
		Metadata: devopsv1.ResourceMetadata{
			ID: request.ID, Name: request.Name, Scope: project.Metadata.Scope,
			ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		ProjectID:     project.Metadata.ID,
		Spec:          request.Spec,
		ContentDigest: devopsv1.RepositoryBindingSpecDigest(request.Spec),
		Status: devopsv1.RepositoryBindingStatus{
			Health:     devopsv1.RepositoryBindingPending,
			Reason:     devopsv1.RepositoryBindingReasonConfigurationChanged,
			ObservedAt: createdAt,
		},
	}
	if err := devopsv1.ValidateRepositoryBinding(binding); err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	return binding, nil
}

func UpdateRepositoryBinding(
	current devopsv1.RepositoryBinding,
	expectedResourceVersion uint64,
	request devopsv1.UpdateRepositoryBindingRequest,
	project devopsv1.DevOpsProject,
	connection devopsv1.SourceConnection,
	updatedAt time.Time,
) (devopsv1.RepositoryBinding, error) {
	if err := devopsv1.ValidateRepositoryBinding(current); err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	if err := devopsv1.ValidateUpdateRepositoryBindingRequest(request); err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	if err := validateConnectionForProject(project, connection); err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	if current.Metadata.Scope != project.Metadata.Scope ||
		current.ProjectID != project.Metadata.ID ||
		request.Spec.SourceConnectionID != connection.Metadata.ID {
		return devopsv1.RepositoryBinding{}, ErrReferenceMismatch
	}
	if err := validateMutation(current.Metadata, expectedResourceVersion, updatedAt); err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	digest := devopsv1.RepositoryBindingSpecDigest(request.Spec)
	if digest == current.ContentDigest {
		return devopsv1.RepositoryBinding{}, ErrUnchangedSpec
	}

	updated := current
	updated.Metadata.ResourceVersion++
	updated.Metadata.UpdatedAt = updatedAt
	updated.Spec = request.Spec
	updated.ContentDigest = digest
	updated.Status = devopsv1.RepositoryBindingStatus{
		Health:     devopsv1.RepositoryBindingPending,
		Reason:     devopsv1.RepositoryBindingReasonConfigurationChanged,
		ObservedAt: updatedAt,
	}
	if err := devopsv1.ValidateRepositoryBinding(updated); err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	return updated, nil
}

func ObserveSourceConnectionHealth(
	current devopsv1.SourceConnection,
	expectedResourceVersion uint64,
	observation SourceConnectionHealthObservation,
	observedAt time.Time,
) (devopsv1.SourceConnection, bool, error) {
	if devopsv1.ValidateSourceConnection(current) != nil ||
		observation.Health == devopsv1.SourceConnectionPending {
		return devopsv1.SourceConnection{}, false, ErrInvalidHealthObservation
	}
	if err := validateMutation(current.Metadata, expectedResourceVersion, observedAt); err != nil {
		return devopsv1.SourceConnection{}, false, err
	}
	status := devopsv1.SourceConnectionStatus{
		Health: observation.Health, Reason: observation.Reason, ObservedAt: observedAt,
	}
	if devopsv1.ValidateSourceConnectionStatus(status) != nil {
		return devopsv1.SourceConnection{}, false, ErrInvalidHealthObservation
	}
	transitioned := current.Status.Health != status.Health || current.Status.Reason != status.Reason
	updated := current
	updated.Metadata.ResourceVersion++
	updated.Metadata.UpdatedAt = observedAt
	updated.Status = status
	if devopsv1.ValidateSourceConnection(updated) != nil {
		return devopsv1.SourceConnection{}, false, ErrInvalidHealthObservation
	}
	return updated, transitioned, nil
}

func ObserveRepositoryBindingHealth(
	current devopsv1.RepositoryBinding,
	expectedResourceVersion uint64,
	observation RepositoryBindingHealthObservation,
	observedAt time.Time,
) (devopsv1.RepositoryBinding, bool, error) {
	if devopsv1.ValidateRepositoryBinding(current) != nil ||
		(observation.Health == devopsv1.RepositoryBindingPending &&
			observation.Reason != devopsv1.RepositoryBindingReasonConnectionNotReady) {
		return devopsv1.RepositoryBinding{}, false, ErrInvalidHealthObservation
	}
	if err := validateMutation(current.Metadata, expectedResourceVersion, observedAt); err != nil {
		return devopsv1.RepositoryBinding{}, false, err
	}
	status := devopsv1.RepositoryBindingStatus{
		Health: observation.Health, Reason: observation.Reason, ObservedAt: observedAt,
	}
	if devopsv1.ValidateRepositoryBindingStatus(status) != nil {
		return devopsv1.RepositoryBinding{}, false, ErrInvalidHealthObservation
	}
	transitioned := current.Status.Health != status.Health || current.Status.Reason != status.Reason
	updated := current
	updated.Metadata.ResourceVersion++
	updated.Metadata.UpdatedAt = observedAt
	updated.Status = status
	if devopsv1.ValidateRepositoryBinding(updated) != nil || updated.ContentDigest != current.ContentDigest {
		return devopsv1.RepositoryBinding{}, false, ErrInvalidHealthObservation
	}
	return updated, transitioned, nil
}

func validateConnectionForProject(
	project devopsv1.DevOpsProject,
	connection devopsv1.SourceConnection,
) error {
	if devopsv1.ValidateDevOpsProject(project) != nil ||
		devopsv1.ValidateSourceConnection(connection) != nil {
		return ErrReferenceMismatch
	}
	if project.Metadata.Scope != connection.Metadata.Scope {
		return ErrReferenceMismatch
	}
	return nil
}

func validateBindingForProject(
	project devopsv1.DevOpsProject,
	binding devopsv1.RepositoryBinding,
) error {
	if devopsv1.ValidateDevOpsProject(project) != nil ||
		devopsv1.ValidateRepositoryBinding(binding) != nil {
		return ErrReferenceMismatch
	}
	if project.Metadata.Scope != binding.Metadata.Scope ||
		project.Metadata.ID != binding.ProjectID {
		return ErrReferenceMismatch
	}
	return nil
}

func validateMutation(
	metadata devopsv1.ResourceMetadata,
	expectedResourceVersion uint64,
	updatedAt time.Time,
) error {
	if expectedResourceVersion == 0 || expectedResourceVersion != metadata.ResourceVersion {
		return ErrVersionConflict
	}
	if metadata.ResourceVersion >= devopsv1.MaximumContractInteger {
		return ErrVersionExhausted
	}
	if !updatedAt.After(metadata.UpdatedAt) {
		return ErrInvalidTime
	}
	return nil
}

func equalSourceConnectionSpec(left, right devopsv1.SourceConnectionSpec) bool {
	return left.AdapterID == right.AdapterID &&
		left.EndpointOrigin == right.EndpointOrigin &&
		left.WebhookSecretRef == right.WebhookSecretRef &&
		left.FetchCredentialRef == right.FetchCredentialRef &&
		left.ReportCredentialRef == right.ReportCredentialRef
}
