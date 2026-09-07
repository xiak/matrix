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
		connection.Status.ObservedAt != domainTime() {
		t.Fatalf("initial source connection = %#v", connection)
	}
	request.Spec.AllowedEndpointOrigins[0] = "https://mutated.internal.example"
	if connection.Spec.AllowedEndpointOrigins[0] != "https://git.internal.example" {
		t.Fatal("source connection shared caller-owned endpoint storage")
	}

	update := devopsv1.UpdateSourceConnectionRequest{Spec: connection.Spec}
	update.Spec.AllowedEndpointOrigins = append([]string(nil), connection.Spec.AllowedEndpointOrigins...)
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
		updated.Status.ObservedAt != updatedAt {
		t.Fatalf("rotated source connection = %#v", updated)
	}
	if connection.Spec.WebhookSecretRef == updated.Spec.WebhookSecretRef {
		t.Fatal("source connection rotation did not replace secret references")
	}

	identityChange := update
	identityChange.Spec = cloneSourceConnectionSpec(update.Spec)
	identityChange.Spec.AdapterID = "source-adapter-other-v1"
	if _, err := UpdateSourceConnection(
		connection, connection.Metadata.ResourceVersion, identityChange, updatedAt,
	); !errors.Is(err, ErrImmutableConnectionIdentity) {
		t.Fatalf("source identity replacement error=%v", err)
	}
	if _, err := UpdateSourceConnection(
		updated,
		updated.Metadata.ResourceVersion,
		devopsv1.UpdateSourceConnectionRequest{Spec: cloneSourceConnectionSpec(updated.Spec)},
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
		binding.Status.Health != devopsv1.RepositoryBindingPending {
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
		updated.Status.Health != devopsv1.RepositoryBindingPending {
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
