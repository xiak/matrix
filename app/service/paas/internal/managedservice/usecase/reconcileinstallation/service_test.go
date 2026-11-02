package reconcileinstallation

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
)

func TestProcessNextCompletesOnlyAfterProvisionerSuccess(t *testing.T) {
	queue := &stubQueue{work: testWorkItem(1), found: true}
	provisioner := &stubProvisioner{result: managedserviceadapterv1.ProvisionResult{
		Endpoint: "127.0.0.1:25432", CredentialReference: "credential-postgres-primary",
	}}
	service := testReconciler(t, queue, provisioner, 3)
	processed, err := service.ProcessNext(context.Background(), "worker-test")
	if err != nil || !processed || queue.completed != 1 || queue.retried != 0 || queue.failed != 0 {
		t.Fatalf("processed=%v err=%v queue=%#v", processed, err, queue)
	}
	if provisioner.request.QuotaShape.ID != "pg-small" ||
		provisioner.request.OfferingID != managedservicev1.PostgreSQLOfferingID {
		t.Fatalf("resolved request=%#v", provisioner.request)
	}
}

func TestProcessNextRetriesSanitizedFailureThenTerminates(t *testing.T) {
	native := errors.New("password secret and C:/host/path must not escape")
	queue := &stubQueue{work: testWorkItem(1), found: true}
	service := testReconciler(t, queue, &stubProvisioner{err: native}, 3)
	processed, err := service.ProcessNext(context.Background(), "worker-test")
	if err != nil || !processed || queue.retried != 1 || queue.failureCode != "" {
		t.Fatalf("retry processed=%v err=%v queue=%#v", processed, err, queue)
	}
	queue = &stubQueue{work: testWorkItem(3), found: true}
	service = testReconciler(t, queue, &stubProvisioner{err: native}, 3)
	processed, err = service.ProcessNext(context.Background(), "worker-test")
	if err != nil || !processed || queue.failed != 1 ||
		queue.failureCode != "PROVIDER_PROVISIONING_FAILED" {
		t.Fatalf("terminal processed=%v err=%v queue=%#v", processed, err, queue)
	}
}

func TestProcessNextTerminatesOnlyAfterProviderDeletion(t *testing.T) {
	work := testWorkItem(1)
	work.Kind = managedservicev1.InstallationOperationTerminate
	work.Installation.Phase = managedservicev1.InstallationTerminating
	work.Installation.Operation.Kind = managedservicev1.InstallationOperationTerminate
	queue := &stubQueue{work: work, found: true}
	provisioner := &stubProvisioner{}
	service := testReconciler(t, queue, provisioner, 3)
	processed, err := service.ProcessNext(context.Background(), "worker-test")
	if err != nil || !processed || queue.completed != 1 || provisioner.deleteCalls != 1 || provisioner.calls != 0 {
		t.Fatalf("processed=%v err=%v queue=%#v provisioner=%#v", processed, err, queue, provisioner)
	}
	if provisioner.deleteRequest.InstallationID != work.Installation.ID ||
		provisioner.deleteRequest.OperationID != work.OperationID ||
		provisioner.deleteRequest.OfferingID != work.Installation.OfferingID {
		t.Fatalf("delete request=%#v", provisioner.deleteRequest)
	}
}

func TestProcessNextRetainsQuotaWhenCleanupOrTerminationFails(t *testing.T) {
	native := errors.New("provider detail must remain private")
	provision := &stubProvisioner{err: native, deleteErr: native}
	queue := &stubQueue{work: testWorkItem(3), found: true}
	service := testReconciler(t, queue, provision, 3)
	processed, err := service.ProcessNext(context.Background(), "worker-test")
	if err != nil || !processed || queue.failed != 1 || queue.failureCode != "PROVIDER_CLEANUP_FAILED" ||
		provision.deleteCalls != 1 {
		t.Fatalf("cleanup processed=%v err=%v queue=%#v provisioner=%#v", processed, err, queue, provision)
	}

	work := testWorkItem(3)
	work.Kind = managedservicev1.InstallationOperationTerminate
	work.Installation.Phase = managedservicev1.InstallationTerminating
	work.Installation.Operation.Kind = managedservicev1.InstallationOperationTerminate
	termination := &stubProvisioner{deleteErr: native}
	queue = &stubQueue{work: work, found: true}
	service = testReconciler(t, queue, termination, 3)
	processed, err = service.ProcessNext(context.Background(), "worker-test")
	if err != nil || !processed || queue.failed != 1 || queue.failureCode != "PROVIDER_TERMINATION_FAILED" ||
		termination.deleteCalls != 1 {
		t.Fatalf("termination processed=%v err=%v queue=%#v provisioner=%#v", processed, err, queue, termination)
	}
}

func TestProcessNextRejectsChangedInstallationProfileWithoutEffect(t *testing.T) {
	work := testWorkItem(1)
	work.Installation.EngineVersion = "19"
	queue := &stubQueue{work: work, found: true}
	provisioner := &stubProvisioner{}
	service := testReconciler(t, queue, provisioner, 3)
	processed, err := service.ProcessNext(context.Background(), "worker-test")
	if err != nil || !processed || queue.failureCode != "INSTALLATION_PROFILE_INVALID" ||
		provisioner.calls != 0 || queue.cleanupFailed != 1 {
		t.Fatalf("processed=%v err=%v queue=%#v calls=%d", processed, err, queue, provisioner.calls)
	}
}

func TestKibanaBindingSurvivesProvisionCompensationAndTermination(t *testing.T) {
	for _, path := range []string{"provision", "compensation", "failed cleanup", "termination"} {
		t.Run(path, func(t *testing.T) {
			work := testWorkItem(3)
			work.QuotaShapeID = "kibana-small"
			work.Installation.ID, work.Installation.OfferingID, work.Installation.EngineVersion = "kibana-one", managedservicev1.KibanaOfferingID, "8.19.23"
			work.Installation.Elasticsearch = &managedservicev1.ElasticsearchReference{InstallationID: "search-one", ResourceVersion: 3}
			queue := &stubQueue{work: work, found: true}
			provider := &stubProvisioner{result: managedserviceadapterv1.ProvisionResult{Endpoint: "http://127.0.0.1:27561", CredentialReference: "credential-kibana-one"}}
			if path == "compensation" || path == "failed cleanup" {
				provider.err = errors.New("native attempt failed")
			}
			if path == "failed cleanup" {
				provider.deleteErr = errors.New("token revocation failed")
			}
			if path == "termination" {
				queue.work.Kind = managedservicev1.InstallationOperationTerminate
			}
			processed, err := testReconciler(t, queue, provider, 3).ProcessNext(t.Context(), "worker-test")
			if err != nil || !processed {
				t.Fatal("dependency reconciliation failed", err)
			}
			dependency := provider.request.Elasticsearch
			if path != "provision" {
				dependency = provider.deleteRequest.Elasticsearch
			}
			want := managedserviceadapterv1.ElasticsearchDependency{InstallationID: "search-one", ResourceVersion: 3, EngineVersion: "8.19.23", RegionID: "local-primary"}
			if dependency == nil || *dependency != want {
				t.Fatal("effect lost or changed its authoritative binding")
			}
			if path == "failed cleanup" && (queue.cleanupFailed != 1 || queue.completed != 0) {
				t.Fatal("failed native cleanup released dependency protection")
			}
		})
	}
}

func TestExpiredClaimCannotBeginCompensatingDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := &stubQueue{work: testWorkItem(1), found: true}
		provider := &stubProvisioner{onEnsure: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}}
		service, err := NewService(queue, provider, Config{LeaseDuration: 2 * time.Second, EffectTimeout: 2 * time.Second, MaximumAttempts: 1})
		if err != nil {
			t.Fatal(err)
		}
		processed, err := service.ProcessNext(t.Context(), "worker-test")
		if !processed || !errors.Is(err, ErrQueueUnavailable) || provider.deleteCalls != 0 ||
			queue.failed != 0 || queue.completed != 0 || queue.retried != 0 {
			t.Fatal("expired worker began compensation or published a stale outcome")
		}
	})
}

func TestCompensationCannotExtendItsOriginalClaim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := &stubQueue{work: testWorkItem(1), found: true}
		provider := &stubProvisioner{
			onEnsure: func(context.Context) error {
				time.Sleep(2 * time.Second)
				return errors.New("uncertain provision")
			},
			onDelete: func(ctx context.Context) error {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > time.Second {
					t.Error("compensation acquired time beyond the original claim")
				}
				<-ctx.Done()
				return ctx.Err()
			},
		}
		service, err := NewService(queue, provider, Config{LeaseDuration: 3 * time.Second, EffectTimeout: 2 * time.Second, MaximumAttempts: 1})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		processed, err := service.ProcessNext(t.Context(), "worker-test")
		if !processed || !errors.Is(err, ErrQueueUnavailable) || time.Since(start) != 3*time.Second ||
			provider.deleteCalls != 1 || queue.failed != 0 || queue.completed != 0 {
			t.Fatal("compensation outlived its claim or published a stale outcome")
		}
	})
}

func TestSlowClaimConsumesTheSameEffectBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := &stubQueue{work: testWorkItem(1), found: true, onClaim: func() { time.Sleep(2 * time.Second) }}
		provider := &stubProvisioner{}
		service, err := NewService(queue, provider, Config{LeaseDuration: 2 * time.Second, EffectTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		processed, err := service.ProcessNext(t.Context(), "worker-test")
		if !processed || !errors.Is(err, ErrQueueUnavailable) || provider.calls != 0 || provider.deleteCalls != 0 {
			t.Fatal("a delayed claim response started effects outside its lease")
		}
	})
}

func testReconciler(
	t *testing.T,
	queue Queue,
	provisioner managedserviceadapterv1.Provisioner,
	maximumAttempts uint32,
) *Service {
	t.Helper()
	service, err := NewService(queue, provisioner, Config{
		Catalog: domain.DefaultCatalog(), LeaseDuration: 30 * time.Second,
		EffectTimeout: time.Second, RetryBackoff: time.Second,
		MaximumAttempts: maximumAttempts,
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	return service
}

func testWorkItem(attempt uint32) WorkItem {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	return WorkItem{
		TenantID: "organization-test", WorkerID: "worker-test",
		OperationID: "operation-test", QuotaShapeID: "pg-small",
		FencingToken: 1, Attempt: attempt, Kind: managedservicev1.InstallationOperationProvision,
		Installation: managedservicev1.ServiceInstallation{
			ID: "postgres-primary", Name: "Postgres primary",
			OfferingID: managedservicev1.PostgreSQLOfferingID, EngineVersion: "18",
			QuotaEntitlementID: "quota-test", RegionID: "local-primary",
			Phase: managedservicev1.InstallationProvisioning, ResourceVersion: 2, CreatedAt: now,
			Operation: managedservicev1.InstallationOperation{
				ID: "operation-test", Kind: managedservicev1.InstallationOperationProvision,
				Phase:      managedservicev1.InstallationProvisioning,
				ObservedAt: now,
			},
		},
	}
}

type stubQueue struct {
	work          WorkItem
	found         bool
	completed     int
	retried       int
	failed        int
	cleanupFailed int
	failureCode   string
	onClaim       func()
}

func (queue *stubQueue) Claim(context.Context, string, time.Duration) (WorkItem, bool, error) {
	if queue.onClaim != nil {
		queue.onClaim()
	}
	return queue.work, queue.found, nil
}

func (queue *stubQueue) CompleteProvision(context.Context, WorkItem, managedserviceadapterv1.ProvisionResult) error {
	queue.completed++
	return nil
}

func (queue *stubQueue) CompleteTermination(context.Context, WorkItem) error {
	queue.completed++
	return nil
}

func (queue *stubQueue) Retry(context.Context, WorkItem, time.Duration) error {
	queue.retried++
	return nil
}

func (queue *stubQueue) Fail(_ context.Context, _ WorkItem, code string) error {
	queue.failed++
	queue.failureCode = code
	return nil
}

func (queue *stubQueue) FailCleanup(_ context.Context, _ WorkItem, code string) error {
	queue.failed++
	queue.cleanupFailed++
	queue.failureCode = code
	return nil
}

type stubProvisioner struct {
	request       managedserviceadapterv1.ProvisionRequest
	deleteRequest managedserviceadapterv1.DeprovisionRequest
	result        managedserviceadapterv1.ProvisionResult
	err           error
	deleteErr     error
	calls         int
	deleteCalls   int
	onEnsure      func(context.Context) error
	onDelete      func(context.Context) error
}

func (provisioner *stubProvisioner) Ensure(
	ctx context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	provisioner.calls++
	provisioner.request = request
	if provisioner.onEnsure != nil {
		return provisioner.result, provisioner.onEnsure(ctx)
	}
	return provisioner.result, provisioner.err
}

func (provisioner *stubProvisioner) Delete(
	ctx context.Context,
	request managedserviceadapterv1.DeprovisionRequest,
) error {
	provisioner.deleteCalls++
	provisioner.deleteRequest = request
	if provisioner.onDelete != nil {
		return provisioner.onDelete(ctx)
	}
	return provisioner.deleteErr
}

func (*stubProvisioner) Ready(context.Context) error { return nil }
