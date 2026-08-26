package reconcileinstallation

import (
	"context"
	"errors"
	"time"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
)

var ErrQueueUnavailable = errors.New("managed-service installation queue is unavailable")

type WorkItem struct {
	TenantID     string
	WorkerID     string
	OperationID  string
	Installation managedservicev1.ServiceInstallation
	QuotaShapeID string
	FencingToken uint64
	Attempt      uint32
}

type Queue interface {
	Claim(context.Context, string, time.Duration) (WorkItem, bool, error)
	Complete(context.Context, WorkItem, managedserviceadapterv1.ProvisionResult) error
	Retry(context.Context, WorkItem, time.Duration) error
	Fail(context.Context, WorkItem, string) error
}

type Provisioner interface {
	Ensure(context.Context, managedserviceadapterv1.ProvisionRequest) (managedserviceadapterv1.ProvisionResult, error)
	Ready(context.Context) error
}

type Config struct {
	Catalog         domain.Catalog
	LeaseDuration   time.Duration
	EffectTimeout   time.Duration
	RetryBackoff    time.Duration
	MaximumAttempts uint32
}

type Service struct {
	queue           Queue
	provisioner     Provisioner
	catalog         domain.Catalog
	leaseDuration   time.Duration
	effectTimeout   time.Duration
	retryBackoff    time.Duration
	maximumAttempts uint32
}

func NewService(queue Queue, provisioner Provisioner, config Config) (*Service, error) {
	if queue == nil || provisioner == nil {
		return nil, errors.New("managed-service reconciler dependencies are required")
	}
	if len(config.Catalog.List()) == 0 {
		config.Catalog = domain.DefaultCatalog()
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = 30 * time.Second
	}
	if config.EffectTimeout == 0 {
		config.EffectTimeout = 2 * time.Minute
	}
	if config.RetryBackoff == 0 {
		config.RetryBackoff = 2 * time.Second
	}
	if config.MaximumAttempts == 0 {
		config.MaximumAttempts = 10
	}
	if config.LeaseDuration < time.Second || config.LeaseDuration > 5*time.Minute ||
		config.EffectTimeout < time.Second || config.EffectTimeout > 5*time.Minute ||
		config.RetryBackoff < time.Second || config.RetryBackoff > time.Minute ||
		config.MaximumAttempts < 1 || config.MaximumAttempts > 100 {
		return nil, errors.New("managed-service reconciler configuration is invalid")
	}
	return &Service{
		queue: queue, provisioner: provisioner, catalog: config.Catalog,
		leaseDuration: config.LeaseDuration, effectTimeout: config.EffectTimeout,
		retryBackoff: config.RetryBackoff, maximumAttempts: config.MaximumAttempts,
	}, nil
}

func (service *Service) ProcessNext(ctx context.Context, workerID string) (bool, error) {
	if ctx == nil || managedservicev1.ValidateID("workerId", workerID) != nil {
		return false, ErrQueueUnavailable
	}
	work, found, err := service.queue.Claim(ctx, workerID, service.leaseDuration)
	if err != nil || !found {
		return found, err
	}
	offering, shape, resolved := service.catalog.Resolve(
		work.Installation.OfferingID,
		work.QuotaShapeID,
	)
	if !resolved || offering.EngineVersion != work.Installation.EngineVersion ||
		work.Installation.RegionID != "local-primary" {
		if failErr := service.queue.Fail(ctx, work, "INSTALLATION_PROFILE_INVALID"); failErr != nil {
			return true, failErr
		}
		return true, nil
	}
	effectContext, cancel := context.WithTimeout(ctx, service.effectTimeout)
	result, effectErr := service.provisioner.Ensure(effectContext, managedserviceadapterv1.ProvisionRequest{
		TenantID: work.TenantID, InstallationID: work.Installation.ID,
		OperationID: work.OperationID, OfferingID: offering.ID,
		EngineVersion: offering.EngineVersion, RegionID: work.Installation.RegionID,
		QuotaShape: shape,
	})
	cancel()
	if effectErr == nil {
		if err := service.queue.Complete(ctx, work, result); err != nil {
			return true, err
		}
		return true, nil
	}
	if work.Attempt >= service.maximumAttempts {
		if err := service.queue.Fail(ctx, work, "POSTGRES_PROVISIONING_FAILED"); err != nil {
			return true, err
		}
		return true, nil
	}
	if err := service.queue.Retry(ctx, work, service.retryBackoff); err != nil {
		return true, err
	}
	return true, nil
}

func (service *Service) Ready(ctx context.Context) error {
	if ctx == nil {
		return errors.New("managed-service reconciler readiness context is required")
	}
	return service.provisioner.Ready(ctx)
}
