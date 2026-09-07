package domain

import (
	"errors"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestAuthenticatedChangeCreatesImmutableEventAndQueuedRun(t *testing.T) {
	connection, binding := readySource(t)
	receivedAt := domainTime().Add(2 * time.Minute)
	change := normalizedChange()
	event, err := NewSourceEvent(change, connection, binding, receivedAt)
	if err != nil {
		t.Fatalf("create SourceEvent: %v", err)
	}
	if err := devopsv1.ValidateSourceEvent(event); err != nil {
		t.Fatalf("validate SourceEvent: %v", err)
	}
	if event.Spec.ProjectID != binding.ProjectID ||
		event.Spec.RepositoryBindingDigest != binding.ContentDigest ||
		event.Spec.ExternalRepositoryID != binding.Spec.ExternalRepositoryID ||
		event.ReceivedAt != receivedAt {
		t.Fatalf("SourceEvent did not seal normalized authority: %#v", event)
	}

	pipeline := mustNewPipeline(t)
	activation, err := ActivatePipeline(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"},
		binding,
		domainTime().Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("activate Pipeline: %v", err)
	}
	run, err := NewPipelineRun(event, activation.Pipeline, activation.Revision)
	if err != nil {
		t.Fatalf("create PipelineRun: %v", err)
	}
	if err := devopsv1.ValidatePipelineRun(run); err != nil {
		t.Fatalf("validate PipelineRun: %v", err)
	}
	if run.Status != (devopsv1.PipelineRunStatus{
		State: devopsv1.PipelineRunQueued, Stage: devopsv1.PipelineRunStageReceive,
		Reason: devopsv1.PipelineRunReasonEventAdmitted, ResourceVersion: 1,
		ObservedAt: receivedAt,
	}) || run.Input.SourceEventID != event.ID ||
		run.Input.PipelineRevisionID != activation.Revision.ID ||
		run.Input.RepositoryBindingDigest != binding.ContentDigest {
		t.Fatalf("queued PipelineRun did not seal admission: %#v", run)
	}

	replayedEvent, err := NewSourceEvent(change, connection, binding, receivedAt)
	if err != nil || replayedEvent != event {
		t.Fatalf("SourceEvent derivation is not deterministic: %#v err=%v", replayedEvent, err)
	}
	replayedRun, err := NewPipelineRun(replayedEvent, activation.Pipeline, activation.Revision)
	if err != nil || replayedRun.ID != run.ID || replayedRun.InputDigest != run.InputDigest {
		t.Fatalf("PipelineRun derivation is not deterministic: %#v err=%v", replayedRun, err)
	}
}

func TestSourceEventAdmissionFailsClosed(t *testing.T) {
	connection, binding := readySource(t)
	change := normalizedChange()
	receivedAt := domainTime().Add(2 * time.Minute)

	pending := connection
	pending.Status.Health = devopsv1.SourceConnectionPending
	if _, err := NewSourceEvent(change, pending, binding, receivedAt); !errors.Is(err, ErrSourceNotReady) {
		t.Fatalf("pending connection error=%v", err)
	}

	mismatched := change
	mismatched.ExternalRepositoryID = "repository-other"
	if _, err := NewSourceEvent(mismatched, connection, binding, receivedAt); !errors.Is(err, ErrReferenceMismatch) {
		t.Fatalf("repository mismatch error=%v", err)
	}

	if _, err := NewSourceEvent(change, connection, binding, domainTime().Add(-time.Minute)); !errors.Is(err, ErrInvalidTime) {
		t.Fatalf("stale receipt time error=%v", err)
	}

	invalid := change
	invalid.DeliveryID = "delivery-provider-native"
	if _, err := NewSourceEvent(invalid, connection, binding, receivedAt); err == nil {
		t.Fatal("non-canonical delivery identity was accepted")
	}
	invalid = change
	invalid.Change.HeadCommit = strings.Repeat("A", 40)
	if _, err := NewSourceEvent(invalid, connection, binding, receivedAt); err == nil {
		t.Fatal("non-canonical commit identity was accepted")
	}
}

func TestPipelineRunAdmissionRequiresExactActiveRevision(t *testing.T) {
	connection, binding := readySource(t)
	event, err := NewSourceEvent(
		normalizedChange(),
		connection,
		binding,
		domainTime().Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	pipeline := mustNewPipeline(t)
	activation, err := ActivatePipeline(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"},
		binding,
		domainTime().Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewPipelineRun(event, pipeline, activation.Revision); !errors.Is(err, ErrPipelineNotActive) {
		t.Fatalf("inactive Pipeline error=%v", err)
	}

	wrongPipeline := activation.Pipeline
	wrongPipeline.ActiveRevision = nil
	if _, err := NewPipelineRun(event, wrongPipeline, activation.Revision); !errors.Is(err, ErrPipelineNotActive) {
		t.Fatalf("missing active revision error=%v", err)
	}

	nextDraft := devopsv1.UpdatePipelineDraftRequest{Draft: activation.Pipeline.Draft.Spec}
	nextDraft.Draft.RepositoryBindingID = "repository-binding-next"
	updatedPipeline, err := UpdatePipelineDraft(
		activation.Pipeline,
		activation.Pipeline.Metadata.ResourceVersion,
		nextDraft,
		mustRepositoryBinding(t, "repository-binding-next"),
		activation.Pipeline.Metadata.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("replace inactive draft: %v", err)
	}
	if _, err := NewPipelineRun(event, updatedPipeline, activation.Revision); err != nil {
		t.Fatalf("updated draft displaced active revision: %v", err)
	}

	event.ReceivedAt = activation.Revision.ActivatedAt.Add(-time.Microsecond)
	if err := devopsv1.ValidateSourceEvent(event); err != nil {
		t.Fatalf("validate pre-activation event fixture: %v", err)
	}
	if _, err := NewPipelineRun(event, activation.Pipeline, activation.Revision); !errors.Is(err, ErrInvalidTime) {
		t.Fatalf("pre-activation event error=%v", err)
	}
}

func readySource(t *testing.T) (devopsv1.SourceConnection, devopsv1.RepositoryBinding) {
	t.Helper()
	connection := mustSourceConnection(t)
	connection.Status.Health = devopsv1.SourceConnectionReady
	binding := mustRepositoryBinding(t, "repository-binding-api")
	binding.Status.Health = devopsv1.RepositoryBindingReady
	return connection, binding
}

func normalizedChange() NormalizedChange {
	return NormalizedChange{
		Scope:                  devopsv1.ResourceScope{TenantID: "organization-acme"},
		SourceConnectionID:     "source-connection-primary",
		ExternalRepositoryID:   "42",
		DeliveryID:             "123e4567-e89b-42d3-a456-426614174000",
		CanonicalPayloadDigest: "sha256:" + strings.Repeat("a", 64),
		Change: devopsv1.ChangeIdentity{
			Number: 42, Action: devopsv1.ChangeOpened,
			HeadCommit:        strings.Repeat("1", 40),
			TrustedBaseCommit: strings.Repeat("2", 40),
		},
	}
}
