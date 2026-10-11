package reconcileinstallation

import (
	"context"
	"errors"
	"testing"
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
		provisioner.calls != 0 {
		t.Fatalf("processed=%v err=%v queue=%#v calls=%d", processed, err, queue, provisioner.calls)
	}
}

func testReconciler(
	t *testing.T,
	queue Queue,
	provisioner Provisioner,
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
	work        WorkItem
	found       bool
	completed   int
	retried     int
	failed      int
	failureCode string
}

func (queue *stubQueue) Claim(context.Context, string, time.Duration) (WorkItem, bool, error) {
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
}

func (provisioner *stubProvisioner) Ensure(
	_ context.Context,
	request managedserviceadapterv1.ProvisionRequest,
) (managedserviceadapterv1.ProvisionResult, error) {
	provisioner.calls++
	provisioner.request = request
	return provisioner.result, provisioner.err
}

func (provisioner *stubProvisioner) Delete(
	_ context.Context,
	request managedserviceadapterv1.DeprovisionRequest,
) error {
	provisioner.deleteCalls++
	provisioner.deleteRequest = request
	return provisioner.deleteErr
}

func (*stubProvisioner) Ready(context.Context) error { return nil }
