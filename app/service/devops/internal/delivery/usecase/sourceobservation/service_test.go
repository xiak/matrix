package sourceobservation

import (
	"context"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

func TestObserveOnceCompletesConnectionAndFreshBinding(t *testing.T) {
	base := observationTime()
	connection := observationConnection(t, base)
	repository := &fakeRepository{}
	provider := &fakeProvider{
		connectionObservation: domain.SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionReady,
			Reason: devopsv1.SourceConnectionReasonObserved,
		},
		bindingObservation: domain.RepositoryBindingHealthObservation{
			Health: devopsv1.RepositoryBindingReady,
			Reason: devopsv1.RepositoryBindingReasonObserved,
		},
	}
	service := mustService(t, repository, provider)

	repository.lease = observationLease(connection, nil, base.Add(time.Second))
	result, err := service.ObserveOnce(context.Background())
	if err != nil || !result.Claimed || result.Kind != WorkSourceConnection ||
		repository.connectionCompletion.Health != devopsv1.SourceConnectionReady {
		t.Fatalf("connection cycle result=%#v observation=%#v err=%v", result, repository.connectionCompletion, err)
	}

	ready, _, err := domain.ObserveSourceConnectionHealth(
		connection, connection.Metadata.ResourceVersion,
		provider.connectionObservation, base.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := observationBinding(t, ready, base.Add(time.Second))
	repository.lease = observationLease(ready, &binding, base.Add(2*time.Second))
	result, err = service.ObserveOnce(context.Background())
	if err != nil || !result.Claimed || result.Kind != WorkRepositoryBinding ||
		repository.bindingCompletion.Health != devopsv1.RepositoryBindingReady ||
		provider.bindingCalls != 1 {
		t.Fatalf("binding cycle result=%#v observation=%#v calls=%d err=%v", result, repository.bindingCompletion, provider.bindingCalls, err)
	}
}

func TestBindingSkipsProviderWhenConnectionIsNotReadyOrStale(t *testing.T) {
	base := observationTime()
	connection := observationConnection(t, base)
	binding := observationBinding(t, connection, base)
	repository := &fakeRepository{lease: observationLease(connection, &binding, base.Add(time.Second))}
	provider := &fakeProvider{}
	service := mustService(t, repository, provider)
	if _, err := service.ObserveOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if provider.bindingCalls != 0 ||
		repository.bindingCompletion.Health != devopsv1.RepositoryBindingPending ||
		repository.bindingCompletion.Reason != devopsv1.RepositoryBindingReasonConnectionNotReady {
		t.Fatalf("pending connection observation=%#v calls=%d", repository.bindingCompletion, provider.bindingCalls)
	}

	ready, _, err := domain.ObserveSourceConnectionHealth(
		connection, 1,
		domain.SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionReady,
			Reason: devopsv1.SourceConnectionReasonObserved,
		},
		base.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding = observationBinding(t, ready, base.Add(time.Second))
	repository.lease = observationLease(
		ready, &binding, ready.Status.ObservedAt.Add(domain.MaximumSourceHealthAge+time.Microsecond),
	)
	if _, err := service.ObserveOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if provider.bindingCalls != 0 {
		t.Fatal("stale connection reached the provider")
	}
}

func TestHeartbeatAndLeaseValidationFailClosed(t *testing.T) {
	base := observationTime()
	repository := &fakeRepository{heartbeatAt: base}
	service := mustService(t, repository, &fakeProvider{})
	if observedAt, err := service.Heartbeat(context.Background()); err != nil || observedAt != base {
		t.Fatalf("heartbeat=%s err=%v", observedAt, err)
	}
	bad := observationLease(observationConnection(t, base), nil, base.Add(time.Second))
	bad.FencingToken = 0
	repository.lease = bad
	if _, err := service.ObserveOnce(context.Background()); err == nil {
		t.Fatal("invalid fencing token was accepted")
	}
}

func TestHealthTransitionAuditIsDeterministicAndSanitized(t *testing.T) {
	base := observationTime()
	connection := observationConnection(t, base)
	ready, _, err := domain.ObserveSourceConnectionHealth(
		connection, 1,
		domain.SourceConnectionHealthObservation{
			Health: devopsv1.SourceConnectionReady,
			Reason: devopsv1.SourceConnectionReasonObserved,
		},
		base.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewSourceConnectionHealthEvent(ready)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSourceConnectionHealthEvent(ready)
	if err != nil || first != second {
		t.Fatalf("health Audit fact is not deterministic: first=%#v second=%#v err=%v", first, second, err)
	}
	if first.Actor.ID != ActorID || first.IAMDecisionID != "" || first.Outcome != "" ||
		first.Reason != "" || first.CorrelationID != string(ready.Metadata.ID) {
		t.Fatalf("health Audit fact contains unexpected authority or provider data: %#v", first)
	}
}

type fakeRepository struct {
	lease                Lease
	heartbeatAt          time.Time
	connectionCompletion domain.SourceConnectionHealthObservation
	bindingCompletion    domain.RepositoryBindingHealthObservation
}

func (repository *fakeRepository) Heartbeat(context.Context, string) (time.Time, error) {
	return repository.heartbeatAt, nil
}

func (repository *fakeRepository) Claim(context.Context, string, time.Duration) (Lease, bool, error) {
	return repository.lease, repository.lease.ResourceID != "", nil
}

func (repository *fakeRepository) CompleteSourceConnection(
	_ context.Context,
	lease Lease,
	observation domain.SourceConnectionHealthObservation,
) (devopsv1.SourceConnection, error) {
	repository.connectionCompletion = observation
	updated, _, err := domain.ObserveSourceConnectionHealth(
		lease.Connection, lease.ResourceVersion, observation, lease.ClaimedAt.Add(time.Microsecond),
	)
	return updated, err
}

func (repository *fakeRepository) CompleteRepositoryBinding(
	_ context.Context,
	lease Lease,
	observation domain.RepositoryBindingHealthObservation,
) (devopsv1.RepositoryBinding, error) {
	repository.bindingCompletion = observation
	updated, _, err := domain.ObserveRepositoryBindingHealth(
		*lease.Binding, lease.ResourceVersion, observation, lease.ClaimedAt.Add(time.Microsecond),
	)
	return updated, err
}

func (*fakeRepository) Readiness(context.Context) (devopsv1.Readiness, error) {
	return devopsv1.Readiness{}, nil
}

type fakeProvider struct {
	connectionObservation domain.SourceConnectionHealthObservation
	bindingObservation    domain.RepositoryBindingHealthObservation
	bindingCalls          int
}

func (provider *fakeProvider) ObserveSourceConnection(
	context.Context,
	devopsv1.SourceConnection,
) (domain.SourceConnectionHealthObservation, error) {
	return provider.connectionObservation, nil
}

func (provider *fakeProvider) ObserveRepositoryBinding(
	context.Context,
	devopsv1.SourceConnection,
	devopsv1.RepositoryBinding,
) (domain.RepositoryBindingHealthObservation, error) {
	provider.bindingCalls++
	return provider.bindingObservation, nil
}

func mustService(t *testing.T, repository Repository, provider Provider) *Service {
	t.Helper()
	service, err := NewService(repository, provider, Config{
		WorkerID: "source-observer-test", LeaseDuration: LeaseDuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func observationLease(
	connection devopsv1.SourceConnection,
	binding *devopsv1.RepositoryBinding,
	claimedAt time.Time,
) Lease {
	kind := WorkSourceConnection
	resourceID := connection.Metadata.ID
	resourceVersion := connection.Metadata.ResourceVersion
	if binding != nil {
		kind = WorkRepositoryBinding
		resourceID = binding.Metadata.ID
		resourceVersion = binding.Metadata.ResourceVersion
	}
	return Lease{
		TenantID: connection.Metadata.Scope.TenantID,
		Kind:     kind, ResourceID: resourceID, ResourceVersion: resourceVersion,
		WorkerID: "source-observer-test", FencingToken: 1,
		ClaimedAt: claimedAt, LeaseExpiresAt: claimedAt.Add(LeaseDuration),
		Connection: connection, Binding: binding,
	}
}

func observationConnection(t *testing.T, createdAt time.Time) devopsv1.SourceConnection {
	t.Helper()
	connection, err := domain.NewSourceConnection(
		devopsv1.CreateSourceConnectionRequest{
			ID: "connection-observation", Name: "connection-observation",
			Spec: devopsv1.SourceConnectionSpec{
				AdapterID:           "source-adapter-gitea-v1",
				EndpointOrigin:      "https://gitea.example.com",
				WebhookSecretRef:    "credential-webhook",
				FetchCredentialRef:  "credential-fetch",
				ReportCredentialRef: "credential-report",
			},
		},
		devopsv1.ResourceScope{TenantID: "tenant-observation"},
		createdAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func observationBinding(
	t *testing.T,
	connection devopsv1.SourceConnection,
	createdAt time.Time,
) devopsv1.RepositoryBinding {
	t.Helper()
	project := devopsv1.DevOpsProject{
		APIVersion: devopsv1.APIVersion, Kind: "DevOpsProject",
		Metadata: devopsv1.ResourceMetadata{
			ID: "project-observation", Name: "project-observation",
			Scope: connection.Metadata.Scope, ResourceVersion: 1,
			CreatedAt: createdAt, UpdatedAt: createdAt,
		},
	}
	binding, err := domain.NewRepositoryBinding(
		devopsv1.CreateRepositoryBindingRequest{
			ID: "binding-observation", Name: "binding-observation",
			ProjectID: project.Metadata.ID,
			Spec: devopsv1.RepositoryBindingSpec{
				SourceConnectionID:   connection.Metadata.ID,
				ExternalRepositoryID: "42",
				RepositoryPath:       "matrix/service",
				TrustedDefaultBranch: "main",
			},
		},
		project,
		connection,
		createdAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func observationTime() time.Time {
	return time.Date(2026, 9, 8, 3, 4, 5, 0, time.UTC)
}
