package domain

import (
	"errors"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestSourceConnectionCreationAndCredentialRotation(t *testing.T) {
	request := validCreateSourceConnectionRequest()
	connection, err := NewSourceConnection(
		request,
		devopsv1.ResourceScope{TenantID: "organization-acme"},
		domainTime(),
	)
	if err != nil {
		t.Fatalf("create source connection: %v", err)
	}
	if connection.Metadata.ResourceVersion != 1 ||
		connection.Status.Health != devopsv1.SourceConnectionPending ||
		connection.Status.Reason != devopsv1.SourceConnectionReasonConfigurationChanged ||
		connection.Status.ObservedAt != domainTime() {
		t.Fatalf("initial source connection = %#v", connection)
	}

	update := devopsv1.UpdateSourceConnectionRequest{Spec: connection.Spec}
	update.Spec.WebhookSecretRef = "secret-webhook-rotated"
	update.Spec.FetchCredentialRef = "credential-fetch-rotated"
	update.Spec.ReportCredentialRef = "credential-report-rotated"
	updatedAt := domainTime().Add(time.Minute)
	updated, err := UpdateSourceConnection(
		connection, connection.Metadata.ResourceVersion, update, updatedAt,
	)
	if err != nil {
		t.Fatalf("rotate source connection credentials: %v", err)
	}
	if updated.Metadata.ResourceVersion != 2 || updated.Metadata.UpdatedAt != updatedAt ||
		updated.Status.Health != devopsv1.SourceConnectionPending ||
		updated.Status.Reason != devopsv1.SourceConnectionReasonConfigurationChanged ||
		updated.Status.ObservedAt != updatedAt {
		t.Fatalf("rotated source connection = %#v", updated)
	}
	if connection.Spec.WebhookSecretRef == updated.Spec.WebhookSecretRef {
		t.Fatal("source connection rotation did not replace secret references")
	}

	identityChange := update
	identityChange.Spec.AdapterID = "source-adapter-other-v1"
	if _, err := UpdateSourceConnection(
		connection, connection.Metadata.ResourceVersion, identityChange, updatedAt,
	); !errors.Is(err, ErrImmutableConnectionIdentity) {
		t.Fatalf("source identity replacement error=%v", err)
	}
	identityChange = update
	identityChange.Spec.EndpointOrigin = "https://other.internal.example"
	if _, err := UpdateSourceConnection(
		connection, connection.Metadata.ResourceVersion, identityChange, updatedAt,
	); !errors.Is(err, ErrImmutableConnectionIdentity) {
		t.Fatalf("source endpoint replacement error=%v", err)
	}
	if _, err := UpdateSourceConnection(
		updated,
		updated.Metadata.ResourceVersion,
		devopsv1.UpdateSourceConnectionRequest{Spec: updated.Spec},
		updatedAt.Add(time.Minute),
	); !errors.Is(err, ErrUnchangedSpec) {
		t.Fatalf("unchanged source connection error=%v", err)
	}
}

func TestRepositoryBindingSealsIdentityAndTenantReferences(t *testing.T) {
	project := mustDevOpsProject(t)
	connection := mustSourceConnection(t)
	binding, err := NewRepositoryBinding(
		validCreateRepositoryBindingRequest(), project, connection, domainTime(),
	)
	if err != nil {
		t.Fatalf("create repository binding: %v", err)
	}
	if binding.ContentDigest != devopsv1.RepositoryBindingSpecDigest(binding.Spec) ||
		binding.Status.Health != devopsv1.RepositoryBindingPending ||
		binding.Status.Reason != devopsv1.RepositoryBindingReasonConfigurationChanged {
		t.Fatalf("repository binding = %#v", binding)
	}

	update := devopsv1.UpdateRepositoryBindingRequest{Spec: binding.Spec}
	update.Spec.TrustedDefaultBranch = "release/v1"
	updated, err := UpdateRepositoryBinding(
		binding,
		binding.Metadata.ResourceVersion,
		update,
		project,
		connection,
		domainTime().Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("update repository binding: %v", err)
	}
	if updated.ContentDigest == binding.ContentDigest || updated.Metadata.ResourceVersion != 2 ||
		updated.Status.Health != devopsv1.RepositoryBindingPending ||
		updated.Status.Reason != devopsv1.RepositoryBindingReasonConfigurationChanged {
		t.Fatalf("updated repository binding = %#v", updated)
	}

	otherConnection := connection
	otherConnection.Metadata.Scope.TenantID = "organization-other"
	if _, err := NewRepositoryBinding(
		validCreateRepositoryBindingRequest(), project, otherConnection, domainTime(),
	); !errors.Is(err, ErrReferenceMismatch) {
		t.Fatalf("cross-tenant repository binding error=%v", err)
	}
	if _, err := UpdateRepositoryBinding(
		updated,
		updated.Metadata.ResourceVersion,
		devopsv1.UpdateRepositoryBindingRequest{Spec: updated.Spec},
		project,
		connection,
		domainTime().Add(2*time.Minute),
	); !errors.Is(err, ErrUnchangedSpec) {
		t.Fatalf("unchanged repository binding error=%v", err)
	}
}

func TestSourceHealthObservationsAreVersionedAndClosed(t *testing.T) {
	connection := mustSourceConnection(t)
	observedAt := domainTime().Add(time.Minute)
	ready, transitioned, err := ObserveSourceConnectionHealth(
		connection,
		connection.Metadata.ResourceVersion,
		SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionReady,
			Reason: devopsv1.SourceConnectionReasonObserved,
		},
		observedAt,
	)
	if err != nil || !transitioned || ready.Metadata.ResourceVersion != 2 ||
		ready.Metadata.UpdatedAt != observedAt || ready.Status.ObservedAt != observedAt {
		t.Fatalf("ready source observation=%#v transitioned=%t err=%v", ready, transitioned, err)
	}
	refreshed, transitioned, err := ObserveSourceConnectionHealth(
		ready,
		ready.Metadata.ResourceVersion,
		SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionReady,
			Reason: devopsv1.SourceConnectionReasonObserved,
		},
		observedAt.Add(time.Minute),
	)
	if err != nil || transitioned || refreshed.Metadata.ResourceVersion != 3 {
		t.Fatalf("refreshed source observation=%#v transitioned=%t err=%v", refreshed, transitioned, err)
	}
	if _, _, err := ObserveSourceConnectionHealth(
		refreshed,
		refreshed.Metadata.ResourceVersion,
		SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionPending,
			Reason: devopsv1.SourceConnectionReasonConfigurationChanged,
		},
		observedAt.Add(2*time.Minute),
	); !errors.Is(err, ErrInvalidHealthObservation) {
		t.Fatalf("observer-created pending state error=%v", err)
	}
	if _, _, err := ObserveSourceConnectionHealth(
		refreshed,
		ready.Metadata.ResourceVersion,
		SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionUnavailable,
			Reason: devopsv1.SourceConnectionReasonProviderUnavailable,
		},
		observedAt.Add(2*time.Minute),
	); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale source observation error=%v", err)
	}
}

func TestRepositoryHealthObservationPreservesSpecDigest(t *testing.T) {
	binding := mustRepositoryBinding(t, "repository-binding-api")
	digest := binding.ContentDigest
	observedAt := domainTime().Add(time.Minute)
	if _, _, err := ObserveRepositoryBindingHealth(
		binding,
		binding.Metadata.ResourceVersion,
		RepositoryBindingHealthObservation{
			Health: devopsv1.RepositoryBindingPending,
			Reason: devopsv1.RepositoryBindingReasonConfigurationChanged,
		},
		observedAt,
	); !errors.Is(err, ErrInvalidHealthObservation) {
		t.Fatalf("observer-created configuration state error=%v", err)
	}
	ready, transitioned, err := ObserveRepositoryBindingHealth(
		binding,
		binding.Metadata.ResourceVersion,
		RepositoryBindingHealthObservation{
			Health: devopsv1.RepositoryBindingReady,
			Reason: devopsv1.RepositoryBindingReasonObserved,
		},
		observedAt,
	)
	if err != nil || !transitioned || ready.ContentDigest != digest ||
		ready.Metadata.ResourceVersion != 2 || ready.Status.ObservedAt != observedAt {
		t.Fatalf("repository health observation=%#v transitioned=%t err=%v", ready, transitioned, err)
	}
	if _, _, err := ObserveRepositoryBindingHealth(
		ready,
		ready.Metadata.ResourceVersion,
		RepositoryBindingHealthObservation{
			Health: devopsv1.RepositoryBindingUnavailable,
			Reason: devopsv1.RepositoryBindingReasonConnectionNotReady,
		},
		observedAt.Add(time.Minute),
	); !errors.Is(err, ErrInvalidHealthObservation) {
		t.Fatalf("invalid repository health pair error=%v", err)
	}
}
