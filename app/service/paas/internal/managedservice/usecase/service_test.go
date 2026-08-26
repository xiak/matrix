package usecase

import (
	"context"
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
)

func TestQuotaActivationEqualReplayAndChangedConflict(t *testing.T) {
	repository := newMemoryRepository()
	service := newTestService(t, repository)
	command := ActivateQuotaCommand{
		Authorization: testAuthorization(), IdempotencyKey: "quota-request-1",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	}
	created, replayed, err := service.ActivateQuota(context.Background(), command)
	if err != nil || replayed {
		t.Fatalf("activate quota = %#v replayed=%v err=%v", created, replayed, err)
	}
	replay, replayed, err := service.ActivateQuota(context.Background(), command)
	if err != nil || !replayed || replay.ID != created.ID {
		t.Fatalf("quota replay = %#v replayed=%v err=%v", replay, replayed, err)
	}
	command.Request.InstanceCount = 2
	if _, _, err := service.ActivateQuota(context.Background(), command); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error=%v", err)
	}
	if len(repository.events) != 1 || repository.events[0].Action != audit.QuotaEntitlementActivated ||
		repository.events[0].Target.ID != audit.ResourceID(created.ID) {
		t.Fatalf("quota Audit events = %#v", repository.events)
	}
}

func TestConcurrentInstallationsCannotExceedQuota(t *testing.T) {
	repository := newMemoryRepository()
	service := newTestService(t, repository)
	entitlement, _, err := service.ActivateQuota(context.Background(), ActivateQuotaCommand{
		Authorization: testAuthorization(), IdempotencyKey: "quota-request-2",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	})
	if err != nil {
		t.Fatalf("activate quota: %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for index, id := range []string{"postgres-one", "postgres-two"} {
		go func(index int, id string) {
			<-start
			_, _, createErr := service.CreateInstallation(context.Background(), CreateInstallationCommand{
				Authorization: testAuthorization(), IdempotencyKey: "install-request-" + id,
				Request: managedservicev1.CreateInstallationRequest{
					ID: id, Name: id, OfferingID: domain.PostgreSQLOfferingID,
					QuotaEntitlementID: entitlement.ID, RegionID: "local-primary",
				},
			})
			_ = index
			results <- createErr
		}(index, id)
	}
	close(start)
	var succeeded, exhausted int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrQuotaExhausted):
			exhausted++
		default:
			t.Fatalf("unexpected create error: %v", err)
		}
	}
	if succeeded != 1 || exhausted != 1 {
		t.Fatalf("succeeded=%d exhausted=%d", succeeded, exhausted)
	}
	if len(repository.events) != 2 || repository.events[1].Action != audit.ServiceInstallationCreated {
		t.Fatalf("transactional Audit events = %#v", repository.events)
	}
}

func TestInstallationRejectsUnavailableRegionBeforePersistence(t *testing.T) {
	repository := newMemoryRepository()
	region := testRegion()
	region.State = managedservicev1.RegionStale
	service, err := NewService(repository, Config{Catalog: domain.DefaultCatalog(), Region: region})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	_, _, err = service.CreateInstallation(context.Background(), CreateInstallationCommand{
		Authorization: testAuthorization(), IdempotencyKey: "install-stale-region",
		Request: managedservicev1.CreateInstallationRequest{
			ID: "postgres-stale", Name: "Postgres stale",
			OfferingID:         domain.PostgreSQLOfferingID,
			QuotaEntitlementID: "quota-stale", RegionID: "local-primary",
		},
	})
	if !errors.Is(err, ErrRegionUnavailable) {
		t.Fatalf("stale region error=%v", err)
	}
}

func newTestService(t *testing.T, repository Repository) *Service {
	t.Helper()
	var operationSequence atomic.Uint32
	service, err := NewService(repository, Config{
		Catalog: domain.DefaultCatalog(), Region: testRegion(),
		NewQuotaID: func() (string, error) { return "quota-test", nil },
		NewOperationID: func() (string, error) {
			if operationSequence.Add(1) == 1 {
				return "operation-one", nil
			}
			return "operation-two", nil
		},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func testAuthorization() port.Authorization {
	return port.Authorization{
		TenantID: "organization-test", SubjectType: port.SubjectUser,
		SubjectID:  "principal-test",
		DecisionID: "decision-test", RequestID: "request-test",
	}
}

func testRegion() managedservicev1.Region {
	inspectedAt := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	return managedservicev1.Region{
		ID: "local-primary", DisplayName: "本机主区域",
		Profile: managedservicev1.RegionLocalMachine,
		State:   managedservicev1.RegionReady, InspectedAt: &inspectedAt,
		Capacity: managedservicev1.RegionCapacity{
			CPUMillicores: 4000, MemoryMiB: 8192, StorageGiB: 100,
		},
	}
}

type memoryRepository struct {
	mu            sync.Mutex
	quotas        map[string]managedservicev1.QuotaEntitlement
	quotaKeys     map[string]memoryReplay
	installations map[string]managedservicev1.ServiceInstallation
	installKeys   map[string]memoryReplay
	events        []audit.Event
}

type memoryReplay struct {
	id     string
	digest string
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		quotas: map[string]managedservicev1.QuotaEntitlement{}, quotaKeys: map[string]memoryReplay{},
		installations: map[string]managedservicev1.ServiceInstallation{}, installKeys: map[string]memoryReplay{},
	}
}

func (repository *memoryRepository) Begin(
	_ context.Context,
	_ string,
	_ TransactionMode,
) (Transaction, error) {
	repository.mu.Lock()
	return &memoryTransaction{
		repository: repository,
		quotas:     maps.Clone(repository.quotas), quotaKeys: maps.Clone(repository.quotaKeys),
		installations: maps.Clone(repository.installations), installKeys: maps.Clone(repository.installKeys),
		events: append([]audit.Event(nil), repository.events...),
	}, nil
}

type memoryTransaction struct {
	repository    *memoryRepository
	quotas        map[string]managedservicev1.QuotaEntitlement
	quotaKeys     map[string]memoryReplay
	installations map[string]managedservicev1.ServiceInstallation
	installKeys   map[string]memoryReplay
	events        []audit.Event
	closed        bool
}

func (transaction *memoryTransaction) ListQuotaEntitlements(context.Context) ([]managedservicev1.QuotaEntitlement, error) {
	result := make([]managedservicev1.QuotaEntitlement, 0, len(transaction.quotas))
	for _, item := range transaction.quotas {
		result = append(result, item)
	}
	return result, nil
}

func (transaction *memoryTransaction) ListServiceInstallations(context.Context) ([]managedservicev1.ServiceInstallation, error) {
	result := make([]managedservicev1.ServiceInstallation, 0, len(transaction.installations))
	for _, item := range transaction.installations {
		result = append(result, item)
	}
	return result, nil
}

func (transaction *memoryTransaction) FindQuotaReplay(
	_ context.Context,
	key string,
) (managedservicev1.QuotaEntitlement, string, bool, error) {
	replay, found := transaction.quotaKeys[key]
	return transaction.quotas[replay.id], replay.digest, found, nil
}

func (transaction *memoryTransaction) InsertQuotaEntitlement(
	_ context.Context,
	draft QuotaDraft,
) (managedservicev1.QuotaEntitlement, error) {
	item := managedservicev1.QuotaEntitlement{
		ID: draft.ID, OfferingID: draft.OfferingID, QuotaShapeID: draft.QuotaShapeID,
		PurchasedCount: draft.PurchasedCount, ResourceVersion: 1,
		ActivatedAt: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
	}
	transaction.quotas[item.ID] = item
	transaction.quotaKeys[draft.IdempotencyKey] = memoryReplay{id: item.ID, digest: draft.RequestDigest}
	return item, nil
}

func (transaction *memoryTransaction) FindInstallationReplay(
	_ context.Context,
	key string,
) (managedservicev1.ServiceInstallation, string, bool, error) {
	replay, found := transaction.installKeys[key]
	return transaction.installations[replay.id], replay.digest, found, nil
}

func (transaction *memoryTransaction) GetQuotaEntitlementForUpdate(
	_ context.Context,
	id string,
) (managedservicev1.QuotaEntitlement, error) {
	item, found := transaction.quotas[id]
	if !found {
		return managedservicev1.QuotaEntitlement{}, ErrNotFound
	}
	return item, nil
}

func (transaction *memoryTransaction) ReserveInstallation(
	_ context.Context,
	draft InstallationDraft,
	expectedQuotaVersion uint64,
) (managedservicev1.ServiceInstallation, error) {
	if _, found := transaction.installations[draft.ID]; found {
		return managedservicev1.ServiceInstallation{}, ErrAlreadyExists
	}
	quota := transaction.quotas[draft.QuotaEntitlementID]
	if quota.ResourceVersion != expectedQuotaVersion ||
		quota.PurchasedCount <= quota.ReservedCount+quota.ConsumedCount {
		return managedservicev1.ServiceInstallation{}, ErrQuotaExhausted
	}
	quota.ReservedCount++
	quota.ResourceVersion++
	transaction.quotas[quota.ID] = quota
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	item := managedservicev1.ServiceInstallation{
		ID: draft.ID, Name: draft.Name, OfferingID: draft.OfferingID,
		EngineVersion: draft.EngineVersion, QuotaEntitlementID: draft.QuotaEntitlementID,
		RegionID: draft.RegionID, Phase: managedservicev1.InstallationPending, CreatedAt: now,
		Operation: managedservicev1.InstallationOperation{
			ID: draft.OperationID, Phase: managedservicev1.InstallationPending, ObservedAt: now,
		},
	}
	transaction.installations[item.ID] = item
	transaction.installKeys[draft.IdempotencyKey] = memoryReplay{id: item.ID, digest: draft.RequestDigest}
	return item, nil
}

func (transaction *memoryTransaction) AppendAuditEvent(_ context.Context, event audit.Event) error {
	if err := audit.ValidateEvent(event); err != nil {
		return err
	}
	transaction.events = append(transaction.events, event)
	return nil
}

func (transaction *memoryTransaction) Commit(context.Context) error {
	if transaction.closed {
		return errors.New("transaction already closed")
	}
	transaction.repository.quotas = transaction.quotas
	transaction.repository.quotaKeys = transaction.quotaKeys
	transaction.repository.installations = transaction.installations
	transaction.repository.installKeys = transaction.installKeys
	transaction.repository.events = transaction.events
	transaction.closed = true
	transaction.repository.mu.Unlock()
	return nil
}

func (transaction *memoryTransaction) Rollback(context.Context) error {
	if transaction.closed {
		return nil
	}
	transaction.closed = true
	transaction.repository.mu.Unlock()
	return nil
}
