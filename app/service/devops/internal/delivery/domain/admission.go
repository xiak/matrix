package domain

import (
	"errors"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

var (
	ErrSourceNotReady           = errors.New("source configuration is not ready")
	ErrPipelineNotActive        = errors.New("Pipeline has no matching active revision")
	ErrSourceEventReplayChanged = errors.New("source event replay content changed")
)

// NormalizedChange is the provider-neutral output of a source adapter after
// it has authenticated and bounded the untouched provider request. It carries
// no provider user or role as Matrix authority.
type NormalizedChange struct {
	Scope                           devopsv1.ResourceScope
	SourceConnectionID              devopsv1.ResourceID
	VerifiedSourceConnectionVersion uint64
	ExternalRepositoryID            devopsv1.ResourceID
	TrustedBaseBranch               string
	DeliveryID                      string
	CanonicalPayloadDigest          string
	Change                          devopsv1.ChangeIdentity
}

func NewSourceEvent(
	change NormalizedChange,
	connection devopsv1.SourceConnection,
	binding devopsv1.RepositoryBinding,
	receivedAt time.Time,
) (devopsv1.SourceEvent, error) {
	if err := ValidateNormalizedChange(change); err != nil {
		return devopsv1.SourceEvent{}, err
	}
	if devopsv1.ValidateSourceConnection(connection) != nil ||
		devopsv1.ValidateRepositoryBinding(binding) != nil ||
		connection.Metadata.Scope != change.Scope ||
		binding.Metadata.Scope != change.Scope ||
		connection.Metadata.ID != change.SourceConnectionID ||
		connection.Metadata.ResourceVersion != change.VerifiedSourceConnectionVersion ||
		binding.Spec.SourceConnectionID != connection.Metadata.ID ||
		binding.Spec.ExternalRepositoryID != change.ExternalRepositoryID ||
		binding.Spec.TrustedDefaultBranch != change.TrustedBaseBranch {
		return devopsv1.SourceEvent{}, ErrReferenceMismatch
	}
	if connection.Status.Health != devopsv1.SourceConnectionReady ||
		binding.Status.Health != devopsv1.RepositoryBindingReady {
		return devopsv1.SourceEvent{}, ErrSourceNotReady
	}
	if receivedAt.Before(connection.Metadata.UpdatedAt) ||
		receivedAt.Before(binding.Metadata.UpdatedAt) {
		return devopsv1.SourceEvent{}, ErrInvalidTime
	}
	spec := devopsv1.SourceEventSpec{
		ProjectID:               binding.ProjectID,
		SourceConnectionID:      connection.Metadata.ID,
		RepositoryBindingID:     binding.Metadata.ID,
		RepositoryBindingDigest: binding.ContentDigest,
		ExternalRepositoryID:    binding.Spec.ExternalRepositoryID,
		DeliveryID:              change.DeliveryID,
		CanonicalPayloadDigest:  change.CanonicalPayloadDigest,
		Change:                  change.Change,
	}
	eventID, err := devopsv1.SourceEventID(
		change.Scope,
		change.SourceConnectionID,
		change.DeliveryID,
	)
	if err != nil {
		return devopsv1.SourceEvent{}, err
	}
	event := devopsv1.SourceEvent{
		APIVersion:    devopsv1.APIVersion,
		Kind:          "SourceEvent",
		ID:            eventID,
		Scope:         change.Scope,
		Spec:          spec,
		ContentDigest: devopsv1.SourceEventSpecDigest(spec),
		ReceivedAt:    receivedAt,
	}
	if err := devopsv1.ValidateSourceEvent(event); err != nil {
		return devopsv1.SourceEvent{}, err
	}
	return event, nil
}

// ValidateSourceEventReplay compares only authenticated delivery content. It
// deliberately ignores mutable configuration, the transient verified
// connection version, and the later receipt time so an equal delivery returns
// the original admission after configuration changes. The authenticated raw
// payload digest already seals its transient target branch.
func ValidateSourceEventReplay(event devopsv1.SourceEvent, change NormalizedChange) error {
	if devopsv1.ValidateSourceEvent(event) != nil || ValidateNormalizedChange(change) != nil {
		return ErrSourceEventReplayChanged
	}
	if event.Scope != change.Scope ||
		event.Spec.SourceConnectionID != change.SourceConnectionID ||
		event.Spec.ExternalRepositoryID != change.ExternalRepositoryID ||
		event.Spec.DeliveryID != change.DeliveryID ||
		event.Spec.CanonicalPayloadDigest != change.CanonicalPayloadDigest ||
		event.Spec.Change != change.Change {
		return ErrSourceEventReplayChanged
	}
	return nil
}

func NewPipelineRun(
	event devopsv1.SourceEvent,
	pipeline devopsv1.Pipeline,
	revision devopsv1.PipelineRevision,
) (devopsv1.PipelineRun, error) {
	if devopsv1.ValidateSourceEvent(event) != nil ||
		devopsv1.ValidatePipeline(pipeline) != nil ||
		devopsv1.ValidatePipelineRevision(revision) != nil {
		return devopsv1.PipelineRun{}, ErrReferenceMismatch
	}
	active := pipeline.ActiveRevision
	if active == nil ||
		pipeline.Metadata.Scope != event.Scope || revision.Scope != event.Scope ||
		pipeline.ProjectID != event.Spec.ProjectID || revision.ProjectID != event.Spec.ProjectID ||
		pipeline.Metadata.ID != revision.PipelineID || active.ID != revision.ID ||
		active.Revision != revision.Revision || active.ContentDigest != revision.ContentDigest ||
		revision.Spec.RepositoryBindingID != event.Spec.RepositoryBindingID ||
		revision.Spec.RepositoryBindingDigest != event.Spec.RepositoryBindingDigest ||
		revision.Spec.TriggerPolicy != devopsv1.TriggerChange {
		return devopsv1.PipelineRun{}, ErrPipelineNotActive
	}
	if event.ReceivedAt.Before(revision.ActivatedAt) {
		return devopsv1.PipelineRun{}, ErrInvalidTime
	}
	input := devopsv1.PipelineRunInput{
		SourceEventID:           event.ID,
		SourceEventDigest:       event.ContentDigest,
		PipelineRevisionID:      revision.ID,
		PipelineRevisionDigest:  revision.ContentDigest,
		RepositoryBindingID:     event.Spec.RepositoryBindingID,
		RepositoryBindingDigest: event.Spec.RepositoryBindingDigest,
		Change:                  event.Spec.Change,
	}
	inputDigest := devopsv1.PipelineRunInputDigest(input)
	runID, err := devopsv1.PipelineRunID(
		event.Scope,
		event.ID,
		revision.ID,
		inputDigest,
	)
	if err != nil {
		return devopsv1.PipelineRun{}, err
	}
	run := devopsv1.PipelineRun{
		APIVersion:  devopsv1.APIVersion,
		Kind:        "PipelineRun",
		ID:          runID,
		Scope:       event.Scope,
		ProjectID:   pipeline.ProjectID,
		PipelineID:  pipeline.Metadata.ID,
		Input:       input,
		InputDigest: inputDigest,
		Status: devopsv1.PipelineRunStatus{
			State:           devopsv1.PipelineRunQueued,
			Stage:           devopsv1.PipelineRunStageReceive,
			Reason:          devopsv1.PipelineRunReasonEventAdmitted,
			ResourceVersion: 1,
			ObservedAt:      event.ReceivedAt,
		},
		CreatedAt: event.ReceivedAt,
		UpdatedAt: event.ReceivedAt,
	}
	if err := devopsv1.ValidatePipelineRun(run); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	return run, nil
}

func ValidateNormalizedChange(value NormalizedChange) error {
	_, identityErr := devopsv1.SourceEventID(
		value.Scope,
		value.SourceConnectionID,
		value.DeliveryID,
	)
	if errors.Join(
		identityErr,
		devopsv1.ValidateID("externalRepositoryId", string(value.ExternalRepositoryID)),
		devopsv1.ValidateTrustedDefaultBranch(value.TrustedBaseBranch),
		devopsv1.ValidateDigest("canonicalPayloadDigest", value.CanonicalPayloadDigest),
		devopsv1.ValidateChangeIdentity(value.Change),
	) != nil {
		return errors.New("normalized change is invalid")
	}
	if value.VerifiedSourceConnectionVersion == 0 ||
		value.VerifiedSourceConnectionVersion > devopsv1.MaximumContractInteger {
		return errors.New("normalized change is invalid")
	}
	return nil
}
