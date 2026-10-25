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
	if err := ValidateSourceEventReplay(event, change); err != nil {
		t.Fatalf("equal SourceEvent replay: %v", err)
	}
	rotatedVerification := change
	rotatedVerification.VerifiedSourceConnectionVersion++
	if err := ValidateSourceEventReplay(event, rotatedVerification); err != nil {
		t.Fatalf("connection rotation changed equal replay: %v", err)
	}
	changedFields := []struct {
		name   string
		change func(*NormalizedChange)
	}{
		{name: "tenant", change: func(value *NormalizedChange) { value.Scope.TenantID = "organization-other" }},
		{name: "source connection", change: func(value *NormalizedChange) { value.SourceConnectionID = "source-connection-other" }},
		{name: "external repository", change: func(value *NormalizedChange) { value.ExternalRepositoryID = "43" }},
		{name: "delivery", change: func(value *NormalizedChange) { value.DeliveryID = "123e4567-e89b-42d3-a456-426614174001" }},
		{name: "payload digest", change: func(value *NormalizedChange) { value.CanonicalPayloadDigest = "sha256:" + strings.Repeat("b", 64) }},
		{name: "change number", change: func(value *NormalizedChange) { value.Change.Number++ }},
		{name: "change action", change: func(value *NormalizedChange) { value.Change.Action = devopsv1.ChangeUpdated }},
		{name: "head commit", change: func(value *NormalizedChange) { value.Change.HeadCommit = strings.Repeat("3", 40) }},
		{name: "trusted base commit", change: func(value *NormalizedChange) { value.Change.TrustedBaseCommit = strings.Repeat("4", 40) }},
	}
	for _, test := range changedFields {
		t.Run("changed "+test.name, func(t *testing.T) {
			changed := change
			test.change(&changed)
			if err := ValidateSourceEventReplay(event, changed); !errors.Is(err, ErrSourceEventReplayChanged) {
				t.Fatalf("changed SourceEvent replay error=%v", err)
			}
		})
	}
	laterConfiguration := event
	laterConfiguration.Spec.RepositoryBindingDigest = "sha256:" + strings.Repeat("c", 64)
	laterConfiguration.ContentDigest = devopsv1.SourceEventSpecDigest(laterConfiguration.Spec)
	if err := ValidateSourceEventReplay(laterConfiguration, change); err != nil {
		t.Fatalf("stored configuration snapshot changed replay identity: %v", err)
	}
}

func TestTerminalPipelineRunReplayCopiesSealedInputAndLinksOnlyDirectSource(t *testing.T) {
	source := lifecycleRun(t)
	completedAt := source.UpdatedAt.Add(time.Microsecond)
	source, err := RequestPipelineRunCancellation(
		source, source.Status.ResourceVersion, false, completedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-replay"}
	commandID := devopsv1.ResourceID("operation-" + strings.Repeat("8", 64))
	replayed, err := ReplayPipelineRun(source, commandID, actor, completedAt.Add(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Replay == nil || replayed.Replay.SourceRunID != source.ID ||
		replayed.Replay.CommandID != commandID || replayed.Replay.RequestedBy != actor ||
		replayed.Input != source.Input || replayed.InputDigest != source.InputDigest ||
		replayed.Status.State != devopsv1.PipelineRunQueued || replayed.Status.ResourceVersion != 1 {
		t.Fatalf("replayed PipelineRun did not preserve direct sealed input: %#v", replayed)
	}

	replayedTerminalAt := replayed.UpdatedAt.Add(time.Microsecond)
	replayedTerminal, err := RequestPipelineRunCancellation(
		replayed, replayed.Status.ResourceVersion, false, replayedTerminalAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondCommandID := devopsv1.ResourceID("operation-" + strings.Repeat("9", 64))
	second, err := ReplayPipelineRun(
		replayedTerminal, secondCommandID, actor, replayedTerminalAt.Add(time.Microsecond),
	)
	if err != nil || second.Replay == nil || second.Replay.SourceRunID != replayed.ID ||
		second.Input != source.Input || second.InputDigest != source.InputDigest {
		t.Fatalf("replay descendant=%#v err=%v", second, err)
	}
	if second.Replay.SourceRunID == source.ID {
		t.Fatal("replay embedded the ancestor chain instead of its direct source")
	}
}

func TestPipelineRunReplayRejectsNonterminalOrInvalidCause(t *testing.T) {
	source := lifecycleRun(t)
	actor := devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-replay"}
	commandID := devopsv1.ResourceID("operation-" + strings.Repeat("8", 64))
	if _, err := ReplayPipelineRun(
		source, commandID, actor, source.UpdatedAt.Add(time.Microsecond),
	); !errors.Is(err, ErrPipelineRunNotTerminal) {
		t.Fatalf("nonterminal replay error=%v", err)
	}
	terminalAt := source.UpdatedAt.Add(time.Microsecond)
	source, err := RequestPipelineRunCancellation(
		source, source.Status.ResourceVersion, false, terminalAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayPipelineRun(source, "", actor, terminalAt.Add(time.Microsecond)); !errors.Is(err, ErrReferenceMismatch) {
		t.Fatalf("invalid replay command error=%v", err)
	}
	if _, err := ReplayPipelineRun(source, commandID, actor, terminalAt); !errors.Is(err, ErrInvalidTime) {
		t.Fatalf("nonadvancing replay time error=%v", err)
	}
}

func TestSourceEventAdmissionFailsClosed(t *testing.T) {
	connection, binding := readySource(t)
	change := normalizedChange()
	receivedAt := domainTime().Add(2 * time.Minute)

	pending := connection
	pending.Status.Health = devopsv1.SourceConnectionPending
	pending.Status.Reason = devopsv1.SourceConnectionReasonConfigurationChanged
	if _, err := NewSourceEvent(change, pending, binding, receivedAt); !errors.Is(err, ErrSourceNotReady) {
		t.Fatalf("pending connection error=%v", err)
	}

	if _, err := NewSourceEvent(
		change, connection, binding, receivedAt.Add(time.Microsecond),
	); !errors.Is(err, ErrSourceNotReady) {
		t.Fatalf("stale source health error=%v", err)
	}

	mismatched := change
	mismatched.ExternalRepositoryID = "repository-other"
	if _, err := NewSourceEvent(mismatched, connection, binding, receivedAt); !errors.Is(err, ErrReferenceMismatch) {
		t.Fatalf("repository mismatch error=%v", err)
	}

	staleConnection := change
	staleConnection.VerifiedSourceConnectionVersion++
	if _, err := NewSourceEvent(staleConnection, connection, binding, receivedAt); !errors.Is(err, ErrReferenceMismatch) {
		t.Fatalf("source connection version mismatch error=%v", err)
	}

	wrongBase := change
	wrongBase.TrustedBaseBranch = "release/v2"
	if _, err := NewSourceEvent(wrongBase, connection, binding, receivedAt); !errors.Is(err, ErrReferenceMismatch) {
		t.Fatalf("trusted base branch mismatch error=%v", err)
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
	connection.Status.Reason = devopsv1.SourceConnectionReasonObserved
	binding := mustRepositoryBinding(t, "repository-binding-api")
	binding.Status.Health = devopsv1.RepositoryBindingReady
	binding.Status.Reason = devopsv1.RepositoryBindingReasonObserved
	return connection, binding
}

func normalizedChange() NormalizedChange {
	return NormalizedChange{
		Scope:                           devopsv1.ResourceScope{TenantID: "organization-acme"},
		SourceConnectionID:              "source-connection-primary",
		VerifiedSourceConnectionVersion: 1,
		ExternalRepositoryID:            "42",
		TrustedBaseBranch:               "main",
		DeliveryID:                      "123e4567-e89b-42d3-a456-426614174000",
		CanonicalPayloadDigest:          "sha256:" + strings.Repeat("a", 64),
		Change: devopsv1.ChangeIdentity{
			Number: 42, Action: devopsv1.ChangeOpened,
			HeadCommit:        strings.Repeat("1", 40),
			TrustedBaseCommit: strings.Repeat("2", 40),
		},
	}
}
